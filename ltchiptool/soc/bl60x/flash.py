import hashlib
from io import BytesIO
from typing import Generator, IO, List, Optional, Tuple, Union

from ltchiptool import SocInterface
from ltchiptool.util.flash import FlashConnection, FlashFeatures, FlashMemoryType
from ltchiptool.util.streams import ProgressCallback
from uf2tool import UploadContext
from uf2tool.models.enums import OTAScheme

from .util.bl60xtool import BL60XTool, ERASE_SIZE
from .util.image import (
    PARTITION_TABLE_READ_SIZE,
    BL60XLayout,
    active_application_hash_range,
    active_firmware_read_range,
    active_firmware_slot,
    make_bl60x_update_plan,
)

BL60X_GUIDE = [
    "Connect a 3.3 V UART adapter to the BL602:",
    [
        ("PC", "BL602"),
        ("RX", "GPIO16 / TX"),
        ("TX", "GPIO7 / RX"),
        ("GND", "GND"),
    ],
    "With power disconnected, pull GPIO8/BOOT high through a 10 kΩ resistor, "
    "then reset.",
    "For a dual-OTA UF2, `ltchiptool flash write` selects and commits the "
    "inactive MINIR3 slot. For an application-only binary, use "
    "`ltchiptool soc bl60x-flash --board minir3`.",
    "Keep mains disconnected while wiring a mains device.",
]


class BL60XFlash(SocInterface):
    tool: Optional[BL60XTool] = None

    def flash_get_features(self) -> FlashFeatures:
        return FlashFeatures(
            can_write=True,
            can_read=True,
            can_read_rom=False,
            can_read_efuse=False,
            can_read_info=True,
        )

    def flash_get_guide(self) -> List[Union[str, list]]:
        return BL60X_GUIDE

    def flash_get_docs_url(self) -> Optional[str]:
        return (
            "https://github.com/bouffalolab/bl_docs/blob/main/"
            "BL602_ISP/zh_CN/RST/602_isp.rst"
        )

    def flash_set_connection(self, connection: FlashConnection) -> None:
        self.flash_disconnect()
        self.conn = connection
        self.conn.fill_baudrate(115200)

    def flash_build_protocol(self, force: bool = False) -> None:
        if not force and self.tool:
            return
        self.flash_disconnect()
        self.tool = BL60XTool(
            port=self.conn.port,
            baudrate=self.conn.link_baudrate,
            link_timeout=self.conn.link_timeout,
            read_timeout=self.conn.timeout or 0.2,
        )

    def flash_change_timeout(self, timeout: float = 0.0, link_timeout: float = 0.0):
        self.flash_build_protocol()
        if timeout:
            self.conn.timeout = timeout
            self.tool.read_timeout = timeout
        if link_timeout:
            self.conn.link_timeout = link_timeout
            self.tool.link_timeout = link_timeout

    def flash_connect(self) -> None:
        if self.conn.linked:
            return
        self.flash_build_protocol()
        self.tool.connect()
        self.conn.linked = True

    def flash_disconnect(self) -> None:
        if self.tool:
            self.tool.close()
        self.tool = None
        if self.conn:
            self.conn.linked = False

    def flash_get_chip_info(self) -> List[Tuple[str, str]]:
        self.flash_connect()
        return [
            ("Chip", "BL602/BL604"),
            ("JEDEC Flash ID", self.tool.flash_id.hex()),
            ("Flash Size", f"{self.tool.capacity} bytes"),
            ("Access", "Read/write external flash"),
        ]

    def flash_get_chip_info_string(self) -> str:
        self.flash_connect()
        return "BL602/BL604"

    def flash_get_size(self, memory: FlashMemoryType = FlashMemoryType.FLASH) -> int:
        if memory != FlashMemoryType.FLASH:
            raise NotImplementedError(
                "BL602 UART backend only supports external flash operations"
            )
        self.flash_connect()
        return self.tool.capacity

    def flash_read_raw(
        self,
        offset: int,
        length: int,
        verify: bool = True,
        memory: FlashMemoryType = FlashMemoryType.FLASH,
        callback: ProgressCallback = ProgressCallback(),
    ) -> Generator[bytes, None, None]:
        if memory != FlashMemoryType.FLASH:
            raise NotImplementedError(
                "BL602 UART backend only supports external flash operations"
            )
        self.flash_connect()
        if offset < 0 or length < 0 or offset + length > self.tool.capacity:
            raise ValueError("Flash read is outside detected device capacity")
        callback.on_total(length)
        yield from self.tool.read_flash(offset, length, callback, verify=verify)

    def flash_write_raw(
        self,
        offset: int,
        length: int,
        data: IO[bytes],
        verify: bool = True,
        callback: ProgressCallback = ProgressCallback(),
    ) -> None:
        self.flash_connect()
        if offset < 0 or length < 0 or offset + length > self.tool.capacity:
            raise ValueError("Flash write is outside detected device capacity")
        if not length:
            return

        end = offset + length
        first_sector = offset // ERASE_SIZE * ERASE_SIZE
        last_sector = (end + ERASE_SIZE - 1) // ERASE_SIZE * ERASE_SIZE
        changed_sectors = []
        for sector_start in range(first_sector, last_sector, ERASE_SIZE):
            sector_end = sector_start + ERASE_SIZE
            write_start = max(offset, sector_start)
            write_end = min(end, sector_end)
            chunk_length = write_end - write_start
            new_data = bytearray()
            while len(new_data) < chunk_length:
                chunk = data.read(chunk_length - len(new_data))
                if not chunk:
                    raise ValueError("Input ended before the requested write length")
                new_data.extend(chunk)

            callback.on_message(f"Preparing sector 0x{sector_start:06X}")
            old_sector = b"".join(
                self.tool.read_flash(
                    sector_start, ERASE_SIZE, verify=False
                )
            )
            updated_sector = bytearray(old_sector)
            sector_offset = write_start - sector_start
            updated_sector[sector_offset : sector_offset + chunk_length] = new_data

            if old_sector != updated_sector:
                self.tool.erase_flash(sector_start, sector_end)
                self.tool.program_flash(sector_start, bytes(updated_sector))
                changed_sectors.append(
                    (sector_start, bytes(updated_sector), chunk_length)
                )
            else:
                callback.on_update(chunk_length)

        if changed_sectors:
            self.tool.check_flash_program()
            for sector_start, expected_data, chunk_length in changed_sectors:
                if verify:
                    expected_hash = hashlib.sha256(expected_data).digest()
                    if self.tool.hash_flash(sector_start, ERASE_SIZE) != expected_hash:
                        raise RuntimeError(
                            f"BL602 flash verification failed at 0x{sector_start:06X}"
                        )
                callback.on_update(chunk_length)

    def flash_update_inactive_slot(
        self,
        application: bytes,
        layout: BL60XLayout,
        callback: ProgressCallback = ProgressCallback(),
        expected_active_slot: Optional[int] = None,
        verify: bool = True,
    ) -> Tuple[int, int, int]:
        """Write the inactive FW slot, verify it, then select it in the table."""
        self.flash_connect()
        if self.tool.capacity != layout.flash_size:
            raise ValueError(
                f"Detected flash is 0x{self.tool.capacity:x} bytes; "
                f"{layout.name} requires 0x{layout.flash_size:x} bytes"
            )

        callback.on_message("Reading partition tables")
        image_context = bytearray(layout.flash_size)
        table_ranges = tuple(
            (offset, PARTITION_TABLE_READ_SIZE)
            for offset in layout.partition_table_offsets
        )
        for offset, length in table_ranges:
            data = b"".join(
                self.tool.read_flash(offset, length, verify=False)
            )
            if len(data) != length:
                raise RuntimeError(
                    f"BL602 returned a short read at 0x{offset:06X}"
                )
            image_context[offset : offset + length] = data

        active_slot = active_firmware_slot(image_context, layout)
        if (
            expected_active_slot is not None
            and active_slot != expected_active_slot
        ):
            raise RuntimeError(
                "Active FW slot changed while preparing the update"
            )

        active_header_range = active_firmware_read_range(image_context, layout)
        read_ranges = (*table_ranges, active_header_range)
        callback.on_total(sum(length for _, length in read_ranges))
        callback.on_update(sum(length for _, length in table_ranges))
        active_offset, active_header_length = active_header_range
        callback.on_message(
            f"Reading active FW header at 0x{active_offset:06X}"
        )
        active_header = b"".join(
            self.tool.read_flash(active_offset, active_header_length, verify=False)
        )
        if len(active_header) != active_header_length:
            raise RuntimeError(
                f"BL602 returned a short read at 0x{active_offset:06X}"
            )
        image_context[
            active_offset : active_offset + active_header_length
        ] = active_header
        callback.on_update(active_header_length)

        active_application_offset, active_application_length = (
            active_application_hash_range(image_context, layout)
        )
        callback.on_message("Verifying active FW with on-chip SHA-256")
        active_application_hash = self.tool.hash_flash(
            active_application_offset, active_application_length
        )

        plan = make_bl60x_update_plan(
            image_context,
            application,
            layout,
            active_application_hash=active_application_hash,
        )

        callback.on_total(len(plan.slot_image) + len(plan.table_image))
        callback.on_message(
            f"Writing inactive FW slot {plan.slot_index} "
            f"at 0x{plan.slot_offset:06X}"
        )
        self.flash_write_raw(
            plan.slot_offset,
            len(plan.slot_image),
            BytesIO(plan.slot_image),
            verify=verify,
            callback=callback,
        )

        callback.on_message(
            f"Selecting FW slot {plan.slot_index} "
            f"in table at 0x{plan.table_offset:06X}"
        )
        self.flash_write_raw(
            plan.table_offset,
            len(plan.table_image),
            BytesIO(plan.table_image),
            verify=verify,
            callback=callback,
        )
        return plan.slot_index, plan.slot_offset, plan.table_offset

    def flash_write_uf2(
        self,
        ctx: UploadContext,
        verify: bool = True,
        callback: ProgressCallback = ProgressCallback(),
    ) -> None:
        """Select the inactive firmware variant from a dual-OTA UF2 package."""
        from .util.image import BOARD_LAYOUTS, FW_PARTITION_HEADER_SIZE

        layout = None
        if ctx.part_table:
            partitions = {part.name: part for part in ctx.part_table.partitions}
            for candidate in BOARD_LAYOUTS.values():
                app = partitions.get("app")
                ota = partitions.get("ota")
                if (
                    app
                    and ota
                    and (app.offset, app.length)
                    == (candidate.fw_addresses[0], candidate.fw_capacities[0])
                    and (ota.offset, ota.length)
                    == (candidate.fw_addresses[1], candidate.fw_capacities[1])
                ):
                    layout = candidate
                    break
            if layout is None:
                raise ValueError(
                    "UF2 partition table does not match a verified BL60x layout"
                )
        else:
            board_name = ctx.board_name.lower()
            board_aliases = {"sonoff-minir3": "minir3"}
            layout_name = board_aliases.get(board_name, board_name)
            layout = BOARD_LAYOUTS.get(layout_name)
            if layout is None:
                supported = ", ".join(sorted(BOARD_LAYOUTS))
                raise ValueError(
                    f"No verified BL60x flash layout for UF2 board "
                    f"{ctx.board_name!r}; supported layouts: {supported}"
                )

        self.flash_connect()
        if self.tool.capacity != layout.flash_size:
            raise ValueError(
                f"Detected flash is 0x{self.tool.capacity:x} bytes; "
                f"{layout.name} requires 0x{layout.flash_size:x} bytes"
            )

        # Match the AmebaZ flasher: inspect live OTA state, then collect the
        # corresponding linked variant from the UF2 package.
        table_context = bytearray(layout.flash_size)
        callback.on_message("Checking active FW slot")
        for offset in layout.partition_table_offsets:
            length = PARTITION_TABLE_READ_SIZE
            data = b"".join(self.tool.read_flash(offset, length, verify=False))
            if len(data) != length:
                raise RuntimeError(
                    f"BL602 returned a short read at 0x{offset:06X}"
                )
            table_context[offset : offset + length] = data
        active_slot = active_firmware_slot(table_context, layout)
        target_slot = 1 - active_slot
        scheme = (
            OTAScheme.FLASHER_DUAL_1
            if target_slot == 0
            else OTAScheme.FLASHER_DUAL_2
        )
        callback.on_message(
            f"Active FW slot {active_slot}; selecting UF2 OTA{target_slot + 1}"
        )
        parts = ctx.collect_data(scheme)
        if not parts:
            raise ValueError(f"UF2 contains no firmware for {scheme.name}")

        application_offset = (
            layout.fw_addresses[target_slot] + FW_PARTITION_HEADER_SIZE
        )
        application_end = layout.fw_addresses[target_slot] + layout.fw_capacities[
            target_slot
        ]
        segments = []
        for offset, stream in parts.items():
            data = stream.read()
            if not data:
                continue
            end = offset + len(data)
            if offset < application_offset or end > application_end:
                raise ValueError(
                    f"UF2 firmware block 0x{offset:06X}..0x{end:06X} is outside "
                    f"target FW slot {target_slot} application range"
                )
            segments.append((offset, data))
        if not segments:
            raise ValueError(f"UF2 contains no application data for {scheme.name}")

        segments.sort(key=lambda item: item[0])
        for previous, current in zip(segments, segments[1:]):
            if previous[0] + len(previous[1]) > current[0]:
                raise ValueError("UF2 application blocks overlap")

        application_length = (
            segments[-1][0] + len(segments[-1][1]) - application_offset
        )
        application = bytearray(b"\xff" * application_length)
        for offset, data in segments:
            relative = offset - application_offset
            application[relative : relative + len(data)] = data

        callback.on_total(len(application))
        self.flash_update_inactive_slot(
            bytes(application),
            layout,
            callback=callback,
            expected_active_slot=active_slot,
            verify=verify,
        )
        callback.on_message(
            "Update written. Disconnect GPIO8 from high and reset for normal boot."
        )

