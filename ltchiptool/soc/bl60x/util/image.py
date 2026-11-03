"""BL60x image and update-slot helpers."""

from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass
import struct
from typing import Dict, Optional, Tuple

BOOT_HEADER_SIZE = 176
FW_PARTITION_HEADER_SIZE = 0x1000
PARTITION_TABLE_OFFSETS = (0xE000, 0xF000)
PARTITION_TABLE_READ_SIZE = 0x1000
PARTITION_TABLE_MAGIC = 0x54504642
PARTITION_TABLE_HEADER = struct.Struct("<IHHII")
PARTITION_ENTRY = struct.Struct("<BBB9s6I")
MAX_PARTITIONS = 16


@dataclass(frozen=True)
class BL60XLayout:
    """Known BL60x board flash layout used to validate a device backup."""

    name: str
    flash_size: int
    fw_addresses: Tuple[int, int]
    fw_capacities: Tuple[int, int]
    partition_table_offsets: Tuple[int, int] = PARTITION_TABLE_OFFSETS


class BL60XImageError(ValueError):
    """The backup or application cannot produce a safe BL60x image."""


@dataclass(frozen=True)
class BL60XUpdatePlan:
    slot_index: int
    slot_offset: int
    slot_image: bytes
    table_offset: int
    table_image: bytes


def _crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def _read_partition_tables(backup: bytes, layout: BL60XLayout):
    if len(backup) != layout.flash_size:
        raise BL60XImageError(
            f"{layout.name} backup must be exactly 0x{layout.flash_size:x} bytes"
        )
    tables = []
    for offset in layout.partition_table_offsets:
        if offset + PARTITION_TABLE_HEADER.size > len(backup):
            continue
        magic, version, count, age, header_crc = PARTITION_TABLE_HEADER.unpack_from(
            backup, offset
        )
        if magic != PARTITION_TABLE_MAGIC or not 0 < count <= MAX_PARTITIONS:
            continue
        header_data = backup[offset : offset + PARTITION_TABLE_HEADER.size - 4]
        if _crc32(header_data) != header_crc:
            continue

        entries_start = offset + PARTITION_TABLE_HEADER.size
        entries_end = entries_start + count * PARTITION_ENTRY.size
        if entries_end + 4 > len(backup):
            continue
        entries = backup[entries_start:entries_end]
        entries_crc = struct.unpack_from("<I", backup, entries_end)[0]
        if _crc32(entries) != entries_crc:
            continue

        partitions = []
        valid = True
        for index in range(count):
            values = PARTITION_ENTRY.unpack_from(entries, index * PARTITION_ENTRY.size)
            (
                kind,
                _,
                active,
                raw_name,
                addr0,
                addr1,
                size0,
                size1,
                length,
                _,
            ) = values
            if active not in (0, 1):
                valid = False
                break
            partitions.append(
                {
                    "kind": kind,
                    "name": raw_name.split(b"\0", 1)[0].decode("ascii", "replace"),
                    "active": active,
                    "addresses": (addr0, addr1),
                    "sizes": (size0, size1),
                    "length": length,
                    "age": values[9],
                    "raw": values,
                }
            )
        if not valid:
            continue
        tables.append(
            {
                "offset": offset,
                "version": version,
                "count": count,
                "age": age,
                "partitions": partitions,
                "entries": entries,
            }
        )

    if not tables:
        raise BL60XImageError("backup contains no valid BL60x partition table")

    return tables


def _firmware_partition(backup: bytes, layout: BL60XLayout):
    tables = _read_partition_tables(backup, layout)
    table = max(tables, key=lambda item: item["age"])
    partitions = table["partitions"]
    firmware = [part for part in partitions if part["name"] == "FW"]
    if len(firmware) != 1:
        raise BL60XImageError("partition table must contain exactly one FW entry")
    fw = firmware[0]
    fw_addresses = fw["addresses"]
    capacities = fw["sizes"]
    if fw_addresses != layout.fw_addresses or capacities != layout.fw_capacities:
        raise BL60XImageError(
            f"partition table does not match the {layout.name} FW layout"
        )
    # BL602's activeIndex selects the matching Address[index] slot.
    active_slot = fw["active"]
    offset = fw_addresses[active_slot]
    capacity = capacities[active_slot]
    image_length = fw["length"]
    if not offset or not capacity or image_length <= FW_PARTITION_HEADER_SIZE:
        raise BL60XImageError("FW partition has invalid active-slot metadata")
    if offset + capacity > len(backup):
        raise BL60XImageError("active FW slot extends beyond the supplied backup")
    _check_slot_overlaps(partitions, fw_addresses, capacities, active_slot)
    return table, fw, active_slot, offset, capacity, image_length


def active_firmware_read_range(
    sparse_backup: bytes, layout: BL60XLayout
) -> Tuple[int, int]:
    """Return the active FW header range needed to validate its metadata."""
    _, _, _, offset, capacity, image_length = _firmware_partition(sparse_backup, layout)
    if image_length > capacity or offset + image_length > layout.flash_size:
        raise BL60XImageError("active FW image extends beyond its partition")
    return offset, min(FW_PARTITION_HEADER_SIZE, image_length)


def active_firmware_slot(sparse_backup: bytes, layout: BL60XLayout) -> int:
    """Return the currently selected firmware slot from partition metadata."""
    return _firmware_partition(sparse_backup, layout)[2]


def active_application_hash_range(
    sparse_backup: bytes, layout: BL60XLayout
) -> Tuple[int, int]:
    """Return the active app range after validating its locally-read header."""
    _, _, _, offset, capacity, image_length = _firmware_partition(sparse_backup, layout)
    header = sparse_backup[offset : offset + BOOT_HEADER_SIZE]
    if len(header) != BOOT_HEADER_SIZE or header[:4] != b"BFNP":
        raise BL60XImageError("active FW slot has no complete BFNP boot header")
    if struct.unpack_from("<I", header, 172)[0] != _crc32(header[:172]):
        raise BL60XImageError("active FW boot-header CRC does not match")
    if header[116] & 0x0F:
        raise BL60XImageError("signed or encrypted boot headers are not supported")
    application_length = struct.unpack_from("<I", header, 120)[0]
    if (
        image_length != FW_PARTITION_HEADER_SIZE + application_length
        or image_length > capacity
        or offset + image_length > layout.flash_size
    ):
        raise BL60XImageError(
            "active image length disagrees with its partition metadata"
        )
    return offset + FW_PARTITION_HEADER_SIZE, application_length


def _check_slot_overlaps(partitions, fw_addresses, fw_capacities, slot: int) -> None:
    offset = fw_addresses[slot]
    slot_end = offset + fw_capacities[slot]
    for part in partitions:
        if part["name"] == "FW":
            continue
        for address, size in zip(part["addresses"], part["sizes"]):
            if address and size and address < slot_end and offset < address + size:
                # OTA clears the mfg name before it reuses FW slot 1.
                if (
                    part["kind"] == 2
                    and not part["name"]
                    and slot == 1
                    and address == fw_addresses[1]
                    and address + size <= slot_end
                ):
                    continue
                raise BL60XImageError(
                    f"FW slot overlaps partition {part['name']!r} "
                    f"(type {part['kind']})"
                )


def _verified_boot_header(
    backup: bytes,
    offset: int,
    image_length: int,
    active_application_hash: Optional[bytes] = None,
) -> bytes:
    header = backup[offset : offset + BOOT_HEADER_SIZE]
    if len(header) != BOOT_HEADER_SIZE or header[:4] != b"BFNP":
        raise BL60XImageError("active FW slot has no complete BFNP boot header")
    if struct.unpack_from("<I", header, 172)[0] != _crc32(header[:172]):
        raise BL60XImageError("active FW boot-header CRC does not match")
    if header[116] & 0x0F:
        raise BL60XImageError("signed or encrypted boot headers are not supported")

    old_application_length = struct.unpack_from("<I", header, 120)[0]
    if image_length != FW_PARTITION_HEADER_SIZE + old_application_length:
        raise BL60XImageError(
            "active image length disagrees with its partition metadata"
        )
    if active_application_hash is None:
        old_application = backup[
            offset
            + FW_PARTITION_HEADER_SIZE : offset
            + FW_PARTITION_HEADER_SIZE
            + old_application_length
        ]
        if len(old_application) != old_application_length:
            raise BL60XImageError("active application data is incomplete")
        active_application_hash = hashlib.sha256(old_application).digest()
    if active_application_hash != header[132:164]:
        raise BL60XImageError("active application SHA-256 does not match its header")
    return header


def make_inactive_slot_table_update(
    backup: bytes, image_length: int, layout: BL60XLayout
) -> Tuple[int, int, bytes]:
    """Build the inactive table copy that selects the inactive FW slot."""
    tables = _read_partition_tables(backup, layout)
    if not tables:
        raise BL60XImageError("no valid partition-table copy is available to update")
    tables.sort(key=lambda item: item["age"], reverse=True)
    current = tables[0]
    if len(tables) == 2:
        target = tables[1]
        if current["age"] == target["age"]:
            raise BL60XImageError("partition-table copy ages are ambiguous")
        target_offset = target["offset"]
    else:
        # Preserve the only valid copy and restore redundancy by writing its
        # replacement to the other partition-table location.
        target_offset = next(
            offset
            for offset in layout.partition_table_offsets
            if offset != current["offset"]
        )
    if current["age"] == 0xFFFFFFFF:
        raise BL60XImageError("partition-table age cannot be incremented")

    entries = bytearray(current["entries"])
    fw_indexes = [
        index
        for index, part in enumerate(current["partitions"])
        if part["name"] == "FW"
    ]
    if len(fw_indexes) != 1:
        raise BL60XImageError("partition table must contain exactly one FW entry")
    fw_index = fw_indexes[0]
    values = list(PARTITION_ENTRY.unpack_from(entries, fw_index * PARTITION_ENTRY.size))
    if (
        tuple(values[4:6]) != layout.fw_addresses
        or tuple(values[6:8]) != layout.fw_capacities
    ):
        raise BL60XImageError(
            f"partition table does not match the {layout.name} FW layout"
        )
    if values[9] == 0xFFFFFFFF:
        raise BL60XImageError("FW partition age cannot be incremented")
    active_slot = values[2]
    target_slot = 1 - active_slot
    values[2] = target_slot
    values[8] = image_length
    values[9] += 1
    PARTITION_ENTRY.pack_into(entries, fw_index * PARTITION_ENTRY.size, *values)

    header = bytearray(
        PARTITION_TABLE_HEADER.pack(
            PARTITION_TABLE_MAGIC,
            current["version"],
            current["count"],
            current["age"] + 1,
            0,
        )
    )
    struct.pack_into("<I", header, 12, _crc32(header[:12]))
    table_image = bytes(header) + bytes(entries) + struct.pack("<I", _crc32(entries))
    return target_slot, target_offset, table_image


def make_bl60x_slot_image(
    backup: bytes,
    application: bytes,
    layout: BL60XLayout,
    active_application_hash: Optional[bytes] = None,
) -> Tuple[int, int, bytes]:
    """Return the inactive FW slot index, offset, and replacement image."""
    if not application:
        raise BL60XImageError("application binary is empty")
    (
        table,
        _,
        active_slot,
        active_offset,
        _,
        active_image_length,
    ) = _firmware_partition(backup, layout)
    target_slot = 1 - active_slot
    _check_slot_overlaps(
        table["partitions"],
        layout.fw_addresses,
        layout.fw_capacities,
        target_slot,
    )
    template = _verified_boot_header(
        backup, active_offset, active_image_length, active_application_hash
    )

    padded_application = application + b"\xff" * ((-len(application)) % 16)
    slot_image_length = FW_PARTITION_HEADER_SIZE + len(padded_application)
    offset = layout.fw_addresses[target_slot]
    capacity = layout.fw_capacities[target_slot]
    if slot_image_length > capacity:
        raise BL60XImageError(
            f"firmware requires 0x{slot_image_length:x} bytes; "
            f"inactive slot {target_slot} holds 0x{capacity:x}"
        )

    header = bytearray(template)
    struct.pack_into("<I", header, 120, len(padded_application))
    header[132:164] = hashlib.sha256(padded_application).digest()
    struct.pack_into("<I", header, 172, _crc32(header[:172]))
    bootinfo = bytes(header) + b"\xff" * (FW_PARTITION_HEADER_SIZE - BOOT_HEADER_SIZE)
    return target_slot, offset, bootinfo + padded_application


def make_bl60x_slot_image_from_template(
    application: bytes, header_template: bytes
) -> bytes:
    """Build a BL60x FW slot image using its configured BFNP header template.

    This is used when producing the UF2 consumed by LibreTiny's runtime
    Update/UF2 path. The updater chooses the physical slot at runtime, so the
    same image bytes are placed in both logical slot variants.
    """
    if len(header_template) != BOOT_HEADER_SIZE or header_template[:4] != b"BFNP":
        raise BL60XImageError("BL60x boot header template is invalid")
    if struct.unpack_from("<I", header_template, 172)[0] != _crc32(
        header_template[:172]
    ):
        raise BL60XImageError("BL60x boot header template CRC does not match")
    if header_template[116] & 0x0F:
        raise BL60XImageError("signed or encrypted boot headers are not supported")
    if not application:
        raise BL60XImageError("application binary is empty")

    padded_application = application + b"\xff" * ((-len(application)) % 16)
    header = bytearray(header_template)
    struct.pack_into("<I", header, 120, len(padded_application))
    header[132:164] = hashlib.sha256(padded_application).digest()
    struct.pack_into("<I", header, 172, _crc32(header[:172]))
    bootinfo = bytes(header) + b"\xff" * (FW_PARTITION_HEADER_SIZE - BOOT_HEADER_SIZE)
    return bootinfo + padded_application


def make_bl60x_update_plan(
    backup: bytes,
    application: bytes,
    layout: BL60XLayout,
    active_application_hash: Optional[bytes] = None,
) -> BL60XUpdatePlan:
    """Plan an inactive-slot write followed by its partition-table activation."""
    slot_index, slot_offset, slot_image = make_bl60x_slot_image(
        backup, application, layout, active_application_hash
    )
    table_slot, table_offset, table_image = make_inactive_slot_table_update(
        backup, len(slot_image), layout
    )
    if table_slot != slot_index:
        raise BL60XImageError("slot selection changed while planning the update")
    return BL60XUpdatePlan(
        slot_index=slot_index,
        slot_offset=slot_offset,
        slot_image=slot_image,
        table_offset=table_offset,
        table_image=table_image,
    )
