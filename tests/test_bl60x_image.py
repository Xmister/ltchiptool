import binascii
import hashlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, Mock

from ltchiptool import Family
from ltchiptool.soc.bl60x.flash import BL60XFlash
from ltchiptool.soc.bl60x.util.image import (
    BL60XImageError,
    BL60XLayout,
    make_bl60x_slot_image,
    make_inactive_slot_table_update,
)
from uf2tool.models import UF2, Image, UploadContext
from uf2tool.models.enums import OTAScheme
from uf2tool.writer import UF2Writer

MINIR3_LAYOUT = BL60XLayout(
    name="generic-bl602",
    flash_size=0x200000,
    fw_addresses=(0x10000, 0x13C000),
    fw_capacities=(0x12C000, 0xB4000),
)

TEST_LAYOUT = BL60XLayout(
    name="test",
    flash_size=0x200000,
    fw_addresses=(0x10000, 0x30000),
    fw_capacities=(0x20000, 0x10000),
)


def make_backup(
    overlap_inactive_slot: bool = False,
    retired_mfg_alias: bool = False,
    overlap_address: int = 0x31000,
    flash_size: int = 0x200000,
    layout: BL60XLayout = TEST_LAYOUT,
) -> bytes:
    backup = bytearray(flash_size)
    old_application = b"stock application"
    old_application += b"\xff" * ((-len(old_application)) % 16)

    boot_header = bytearray(176)
    boot_header[:4] = b"BFNP"
    struct.pack_into("<I", boot_header, 120, len(old_application))
    boot_header[132:164] = hashlib.sha256(old_application).digest()
    struct.pack_into(
        "<I", boot_header, 172, binascii.crc32(boot_header[:172]) & 0xFFFFFFFF
    )
    firmware_offset = layout.fw_addresses[1 if retired_mfg_alias else 0]
    backup[firmware_offset : firmware_offset + 176] = boot_header
    application_offset = firmware_offset + 0x1000
    backup[application_offset : application_offset + len(old_application)] = (
        old_application
    )

    entries = [
        struct.pack(
            "<BBB9s6I",
            0,
            0,
            1 if retired_mfg_alias else 0,
            b"FW",
            layout.fw_addresses[0],
            layout.fw_addresses[1],
            layout.fw_capacities[0],
            layout.fw_capacities[1],
            0x1000 + len(old_application),
            1,
        )
    ]
    if overlap_inactive_slot or retired_mfg_alias:
        entries.append(
            struct.pack(
                "<BBB9s6I",
                2 if retired_mfg_alias else 1,
                0,
                0,
                b"" if retired_mfg_alias else b"mfg",
                overlap_address,
                0,
                0x1000,
                0,
                0,
                0,
            )
        )
    raw_entries = b"".join(entries)
    for offset, age in zip(layout.partition_table_offsets, (14, 13)):
        table_header = bytearray(
            struct.pack("<IHHII", 0x54504642, 0, len(entries), age, 0)
        )
        struct.pack_into(
            "<I", table_header, 12, binascii.crc32(table_header[:12]) & 0xFFFFFFFF
        )
        partition_table = (
            bytes(table_header)
            + raw_entries
            + struct.pack("<I", binascii.crc32(raw_entries) & 0xFFFFFFFF)
        )
        backup[offset : offset + len(partition_table)] = partition_table
    return bytes(backup)


class BL60XImageTest(unittest.TestCase):
    def test_packages_application_for_inactive_slot(self):
        application = b"new application image"

        slot, offset, image = make_bl60x_slot_image(
            make_backup(), application, TEST_LAYOUT
        )

        padded_application = application + b"\xff" * ((-len(application)) % 16)
        header = image[:176]
        self.assertEqual(slot, 1)
        self.assertEqual(offset, 0x30000)
        self.assertEqual(len(image), 0x1000 + len(padded_application))
        self.assertEqual(image[0x1000:], padded_application)
        self.assertEqual(
            struct.unpack_from("<I", header, 120)[0], len(padded_application)
        )
        self.assertEqual(header[132:164], hashlib.sha256(padded_application).digest())
        self.assertEqual(
            struct.unpack_from("<I", header, 172)[0],
            binascii.crc32(header[:172]) & 0xFFFFFFFF,
        )

    def test_packages_backup_for_larger_flash(self):
        larger_layout = BL60XLayout(
            name="test-large",
            flash_size=0x400000,
            fw_addresses=(0x10000, 0x30000),
            fw_capacities=(0x20000, 0x10000),
        )
        _, offset, _ = make_bl60x_slot_image(
            make_backup(flash_size=0x400000), b"new application", larger_layout
        )

        self.assertEqual(offset, 0x30000)

    def test_rejects_backup_that_does_not_match_board_flash_size(self):
        with self.assertRaisesRegex(BL60XImageError, "exactly 0x200000 bytes"):
            make_bl60x_slot_image(b"\xff" * 0x400000, b"new app", TEST_LAYOUT)

    def test_rejects_partition_table_that_does_not_match_board_slots(self):
        with self.assertRaisesRegex(
            BL60XImageError, "does not match the generic-bl602 FW"
        ):
            make_bl60x_slot_image(make_backup(), b"new app", MINIR3_LAYOUT)

    def test_rejects_corrupt_partition_table(self):
        backup = bytearray(make_backup())
        backup[0xE000] = 0
        backup[0xF000] = 0

        with self.assertRaisesRegex(BL60XImageError, "partition table"):
            make_bl60x_slot_image(bytes(backup), b"new app", TEST_LAYOUT)

    def test_rejects_truncated_flash_backup(self):
        with self.assertRaisesRegex(BL60XImageError, "exactly 0x200000 bytes"):
            make_bl60x_slot_image(b"\xff" * 0x30000, b"new app", TEST_LAYOUT)

    def test_rejects_corrupt_active_application_hash(self):
        backup = bytearray(make_backup())
        backup[0x11000] ^= 0x01

        with self.assertRaisesRegex(BL60XImageError, "SHA-256"):
            make_bl60x_slot_image(bytes(backup), b"new app", TEST_LAYOUT)

    def test_rejects_application_larger_than_inactive_slot(self):
        with self.assertRaisesRegex(BL60XImageError, "inactive slot 1 holds"):
            make_bl60x_slot_image(make_backup(), b"x" * 0x1F100, TEST_LAYOUT)

    def test_rejects_inactive_slot_overlapping_another_partition(self):
        with self.assertRaisesRegex(BL60XImageError, "FW slot overlaps partition"):
            make_bl60x_slot_image(
                make_backup(overlap_inactive_slot=True), b"new app", TEST_LAYOUT
            )

    def test_packages_inactive_slot_when_current_slot1_has_retired_mfg_alias(self):
        slot, offset, _ = make_bl60x_slot_image(
            make_backup(retired_mfg_alias=True, overlap_address=0x30000),
            b"new app",
            TEST_LAYOUT,
        )

        self.assertEqual(slot, 0)
        self.assertEqual(offset, 0x10000)

    def test_table_update_targets_older_copy_and_selects_inactive_slot(self):
        slot, offset, table = make_inactive_slot_table_update(
            make_backup(retired_mfg_alias=True, overlap_address=0x30000),
            image_length=0x2000,
            layout=TEST_LAYOUT,
        )

        magic, _, count, age, header_crc = struct.unpack_from("<IHHII", table)
        fw = struct.unpack_from("<BBB9s6I", table, 16)
        self.assertEqual(offset, 0xF000)
        self.assertEqual(slot, 0)
        self.assertEqual(magic, 0x54504642)
        self.assertEqual(count, 2)
        self.assertEqual(age, 15)
        self.assertEqual(header_crc, binascii.crc32(table[:12]) & 0xFFFFFFFF)
        self.assertEqual(fw[2], 0)
        self.assertEqual(fw[8], 0x2000)
        self.assertEqual(
            struct.unpack_from("<I", table, 16 + count * 36)[0],
            binascii.crc32(table[16 : 16 + count * 36]) & 0xFFFFFFFF,
        )

    def test_flash_update_writes_slot_before_activating_it(self):
        flash = BL60XFlash.__new__(BL60XFlash)
        backup = make_backup()
        reads = []

        def read_flash(offset, length, verify):
            reads.append((offset, length))
            return iter([backup[offset : offset + length]])

        flash.tool = SimpleNamespace(
            capacity=0x200000,
            read_flash=read_flash,
            hash_flash=lambda offset, length: hashlib.sha256(
                backup[offset : offset + length]
            ).digest(),
        )
        flash.flash_connect = Mock()
        writes = []

        def record_write(offset, length, data, verify, callback):
            writes.append((offset, data.read(length)))

        flash.flash_write_raw = record_write
        flash.flash_disconnect = Mock()

        slot, slot_offset, table_offset = flash.flash_update_inactive_slot(
            b"new app", TEST_LAYOUT
        )

        self.assertEqual(slot, 1)
        self.assertEqual(slot_offset, 0x30000)
        self.assertEqual([offset for offset, _ in writes], [0x30000, 0xF000])
        self.assertEqual(
            reads,
            [(0xE000, 0x1000), (0xF000, 0x1000), (0x10000, 0x1000)],
        )
        self.assertEqual(flash.flash_connect.call_count, 1)

    def test_generic_uf2_writer_selects_inactive_linked_variant(self):
        for active_slot in (0, 1):
            with self.subTest(active_slot=active_slot):
                backup = make_backup(
                    retired_mfg_alias=active_slot == 1,
                    layout=MINIR3_LAYOUT,
                )
                flash = BL60XFlash.__new__(BL60XFlash)
                flash.tool = SimpleNamespace(
                    capacity=MINIR3_LAYOUT.flash_size,
                    read_flash=lambda offset, length, verify: iter(
                        [backup[offset : offset + length]]
                    ),
                )
                flash.flash_connect = Mock()
                flash.flash_update_inactive_slot = Mock()
                target_slot = 1 - active_slot
                application_offset = MINIR3_LAYOUT.fw_addresses[target_slot] + 0x1000
                context = SimpleNamespace(
                    board_name="generic-bl602",
                    part_table=SimpleNamespace(
                        partitions=[
                            SimpleNamespace(
                                name="app",
                                offset=MINIR3_LAYOUT.fw_addresses[0],
                                length=MINIR3_LAYOUT.fw_capacities[0],
                            ),
                            SimpleNamespace(
                                name="ota",
                                offset=MINIR3_LAYOUT.fw_addresses[1],
                                length=MINIR3_LAYOUT.fw_capacities[1],
                            ),
                        ]
                    ),
                    collect_data=Mock(
                        return_value={application_offset: io.BytesIO(b"app data")}
                    ),
                )

                flash.flash_write_uf2(context)

                scheme = (
                    OTAScheme.FLASHER_DUAL_1
                    if target_slot == 0
                    else OTAScheme.FLASHER_DUAL_2
                )
                context.collect_data.assert_called_once_with(scheme)
                flash.flash_update_inactive_slot.assert_called_once_with(
                    b"app data",
                    MINIR3_LAYOUT,
                    callback=ANY,
                    expected_active_slot=active_slot,
                    verify=True,
                )

    def test_uf2_layout_must_match_live_partition_table(self):
        backup = make_backup(layout=MINIR3_LAYOUT)
        flash = BL60XFlash.__new__(BL60XFlash)
        flash.tool = SimpleNamespace(
            capacity=MINIR3_LAYOUT.flash_size,
            read_flash=lambda offset, length, verify: iter(
                [backup[offset : offset + length]]
            ),
        )
        flash.flash_connect = Mock()
        flash.flash_update_inactive_slot = Mock()
        context = SimpleNamespace(
            board_name="generic-bl602",
            part_table=SimpleNamespace(
                partitions=[
                    SimpleNamespace(name="app", offset=0x10000, length=0x12C000),
                    SimpleNamespace(name="ota", offset=0x140000, length=0xB4000),
                ]
            ),
        )
        with self.assertRaisesRegex(BL60XImageError, "does not match"):
            flash.flash_write_uf2(context)
        flash.flash_update_inactive_slot.assert_not_called()

    def test_dual_slot_uf2_maps_same_app_to_minir3_app_and_ota_regions(self):
        class BoardStub:
            # Board.name is the build variant tag, not the platform board ID.
            name = "generic-bl602"
            flash = {
                "app": (0x10000, 0x12C000),
                "ota": (0x13C000, 0xB4000),
            }

            def __getitem__(self, key):
                if key == "flash":
                    return self.flash
                raise KeyError(key)

            def region(self, name):
                offset, length = self.flash[name]
                return offset, length, offset + length

        family = Family(
            name="boufallo-bl60x",
            parent=None,
            code="bl60x",
            description="Bouffalo BL602/BL604",
            id="0xDE1270B7",
        )
        with tempfile.TemporaryDirectory() as directory:
            application = Path(directory) / "firmware.bin"
            application.write_bytes(b"application payload")
            output = io.BytesIO()
            image = Image(
                f"{application},{application}+0x1000=" "device:app,ota;flasher:app,ota"
            )
            writer = UF2Writer(output, family, legacy=False)
            writer.set_board(BoardStub())
            writer.write((image,))

            output.seek(0)
            uf2 = UF2(output)
            uf2.read()
            context = UploadContext(uf2)
            first_slot = context.collect_data(OTAScheme.FLASHER_DUAL_1)
            context.seq = 0
            second_slot = context.collect_data(OTAScheme.FLASHER_DUAL_2)
            context.seq = 0

            backup = make_backup(layout=MINIR3_LAYOUT)
            flash = BL60XFlash.__new__(BL60XFlash)
            flash.tool = SimpleNamespace(
                capacity=MINIR3_LAYOUT.flash_size,
                read_flash=lambda offset, length, verify: iter(
                    [backup[offset : offset + length]]
                ),
            )
            flash.flash_connect = Mock()
            flash.flash_update_inactive_slot = Mock()
            flash.flash_write_uf2(context)

        self.assertEqual(list(first_slot), [0x11000])
        self.assertEqual(first_slot[0x11000].read(), b"application payload")
        self.assertEqual(list(second_slot), [0x13D000])
        self.assertEqual(second_slot[0x13D000].read(), b"application payload")
        flash.flash_update_inactive_slot.assert_called_once_with(
            b"application payload",
            MINIR3_LAYOUT,
            callback=ANY,
            expected_active_slot=0,
            verify=True,
        )


if __name__ == "__main__":
    unittest.main()
