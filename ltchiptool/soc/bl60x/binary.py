"""BL60x application binary handling."""

from abc import ABC
import binascii
import struct
from typing import IO, List, Optional

from ltchiptool import SocInterface
from ltchiptool.util.detection import Detection
from ltchiptool.util.fileio import peek
from ltchiptool.util.fwbinary import FirmwareBinary

from .util.image import BOOT_HEADER_SIZE, FW_PARTITION_HEADER_SIZE


class BL60XBinary(SocInterface, ABC):
    """Build application-only artifacts and recognize packaged slot images."""

    def elf2bin(self, input: str, ota_idx: int) -> List[FirmwareBinary]:
        binary = FirmwareBinary(
            location=input,
            name=f"firmware_ota{ota_idx}",
            title=f"BL60x OTA{ota_idx} Application-only Binary",
            description=(
                "Application payload only; use the board-aware bl60x-flash "
                "command to install it into the inactive firmware slot."
            ),
            public=True,
        )
        binary.graph(1)
        if not binary.isnewer(than=input):
            self.board.toolchain.objcopy(input, binary.path)
        return binary.group()

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
