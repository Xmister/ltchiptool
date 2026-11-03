"""BL60x application binary handling."""

import binascii
import struct
from abc import ABC
from pathlib import Path
from subprocess import run
from typing import IO, List, Optional

from ltchiptool import SocInterface
from ltchiptool.soc.common import checkfile, ldargs_parse
from ltchiptool.util.detection import Detection
from ltchiptool.util.fileio import peek
from ltchiptool.util.fwbinary import FirmwareBinary

from .util.image import (
    BOOT_HEADER_SIZE,
    FW_PARTITION_HEADER_SIZE,
    make_bl60x_slot_image_from_template,
)


class BL60XBinary(SocInterface, ABC):
    """Build application-only artifacts and recognize packaged slot images."""

    def link2elf(self, ota1: str, ota2: str, args: List[str]):
        # BL60X links one position-independent application for both slots.
        elf, ldargs = ldargs_parse(args, None, None)[0]
        run([self.board.toolchain.prefix + "gcc", *ldargs], check=True)
        checkfile(elf)
        return {1: elf}

    def elf2bin(self, input: str, ota_idx: int) -> List[FirmwareBinary]:
        app = FirmwareBinary(location=input, name=f"firmware_ota{ota_idx}")
        slot = FirmwareBinary(location=input, name="firmware_slot")
        run(
            [
                self.board.toolchain.prefix + "objcopy",
                "-O",
                "binary",
                "--gap-fill",
                "0xff",
                "-S",
                input,
                app.path,
            ],
            check=True,
        )
        template = Path(__file__).parent / "util" / self.board["build.boot_header"]
        with slot.write() as output:
            output.write(
                make_bl60x_slot_image_from_template(
                    Path(app.path).read_bytes(), template.read_bytes()
                )
            )
        return slot.group()

    def detect_file_type(
        self,
        file: IO[bytes],
        length: int,
    ) -> Optional[Detection]:
        header = peek(file, size=BOOT_HEADER_SIZE)
        if len(header) != BOOT_HEADER_SIZE or header[:4] != b"BFNP":
            return None

        header_crc = struct.unpack_from("<I", header, 172)[0]
        if header_crc != (binascii.crc32(header[:172]) & 0xFFFFFFFF):
            return None
        if header[116] & 0x0F:
            return None

        application_length = struct.unpack_from("<I", header, 120)[0]
        expected_length = FW_PARTITION_HEADER_SIZE + application_length
        if application_length == 0 or length != expected_length:
            return None

        return Detection.make(
            "BL60x Firmware Slot Image (board offset required)",
            offset=None,
            length=length,
        )
