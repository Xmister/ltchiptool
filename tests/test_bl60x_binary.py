import binascii
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltchiptool import Family, SocInterface
from ltchiptool.util.detection import Detection


class BL60XBinaryTest(unittest.TestCase):
    def setUp(self):
        family = Family(
            name="boufallo-bl60x",
            parent=None,
            code="bl60x",
            description="Bouffalo BL602/BL604",
        )
        self.soc = SocInterface.get(family)

    def test_detects_slot_image_but_requires_board_specific_offset(self):
        application = b"BL60x application"
        application += b"\xff" * ((-len(application)) % 16)
        header = bytearray(176)
        header[:4] = b"BFNP"
        struct.pack_into("<I", header, 120, len(application))
        struct.pack_into("<I", header, 172, binascii.crc32(header[:172]) & 0xFFFFFFFF)
        image = bytes(header) + b"\xff" * (0x1000 - len(header)) + application

        with tempfile.TemporaryFile() as file:
            file.write(image)
            file.seek(0)
            detection = self.soc.detect_file_type(file, len(image))

        self.assertEqual(detection.type, Detection.Type.VALID_NEED_OFFSET)
        self.assertEqual(detection.length, len(image))
        self.assertIn("board offset required", detection.title)

    def test_rejects_invalid_slot_header(self):
        with tempfile.TemporaryFile() as file:
            file.write(b"BFNP" + bytes(4092))
            file.seek(0)
            detection = self.soc.detect_file_type(file, 4096)

        self.assertIsNone(detection)

    def test_elf2bin_generates_application_and_slot(self):
        class Toolchain:
            prefix = "test-"

        class BoardStub:
            toolchain = Toolchain()

            def __getitem__(self, key):
                assert key == "build.boot_header"
                return "bl60x_boot_header.bin"

        def objcopy(args, check):
            Path(args[-1]).write_bytes(b"application payload")

        with tempfile.TemporaryDirectory() as directory, patch(
            "ltchiptool.soc.bl60x.binary.run", side_effect=objcopy
        ):
            elf = Path(directory) / "firmware.elf"
            elf.write_bytes(b"test ELF payload")
            self.soc.board = BoardStub()
            self.soc.elf2bin(str(elf), 1)
            self.assertEqual(
                (Path(directory) / "image_firmware_ota1.bin").read_bytes(),
                b"application payload",
            )
            slot = (Path(directory) / "image_firmware_slot.bin").read_bytes()
            self.assertEqual(slot[:4], b"BFNP")
            self.assertEqual(slot[0x1000:0x1013], b"application payload")


if __name__ == "__main__":
    unittest.main()
