import hashlib
import io
import struct
import unittest
from unittest.mock import Mock

from ltchiptool import Family, SocInterface
from ltchiptool.models import OTAType
from ltchiptool.soc.bl60x.main import BL60XMain
from ltchiptool.soc.bl60x.util.bl60xtool import BL60XProtocolError, BL60XTool
from ltchiptool.util.flash import FlashConnection


class BL60XProtocolTest(unittest.TestCase):
    def make_tool(self) -> BL60XTool:
        tool = BL60XTool.__new__(BL60XTool)
        tool.s = Mock()
        return tool

    def test_family_dispatch_exposes_raw_write_support(self):
        family = Family(
            name="boufallo-bl60x",
            parent=None,
            code="bl60x",
            description="Bouffalo BL602/BL604",
        )

        soc = SocInterface.get(family)

        self.assertEqual(soc.__class__.__name__, "BL60XMain")
        self.assertEqual(soc.ota_type, OTAType.DUAL)
        self.assertTrue(soc.flash_get_features().can_write)
        self.assertTrue(soc.flash_get_features().can_read)

    def test_command_sends_protocol_header_and_reads_response(self):
        tool = self.make_tool()
        tool._read_exact = Mock(side_effect=[b"OK", b"\x03\x00", b"abc"])

        response = tool._command(0x36, response=True)

        self.assertEqual(response, b"abc")
        tool.s.write.assert_called_once_with(b"\x36\x00\x00\x00")

    def test_erase_command_waits_for_pending_ack_before_ok(self):
        tool = self.make_tool()
        tool._read_exact = Mock(side_effect=[b"PD", b"PD", b"OK"])

        tool._command(0x30, struct.pack("<II", 0x1000, 0x2000))

        self.assertEqual(tool._read_exact.call_count, 3)

    def test_command_rejects_unsupported_commands(self):
        tool = self.make_tool()

        with self.assertRaisesRegex(ValueError, "not supported"):
            tool._command(0x40, b"data")

        tool.s.write.assert_not_called()

    def test_write_command_uses_protocol_header(self):
        tool = self.make_tool()
        tool._read_exact = Mock(return_value=b"OK")

        tool._command(0x31, b"addrdata")

        tool.s.write.assert_called_once_with(b"\x31\x00\x08\x00addrdata")

    def test_erase_command_requires_aligned_bounded_range(self):
        tool = self.make_tool()
        tool.capacity = 0x2000
        tool._command = Mock()

        tool.erase_flash(0x1000, 0x2000)

        tool._command.assert_called_once_with(
            0x30, struct.pack("<II", 0x1000, 0x2000), False, 56
        )
        with self.assertRaisesRegex(ValueError, "aligned"):
            tool.erase_flash(1, 0x1000)

    def test_flash_program_uses_loader_chunk_limit(self):
        tool = self.make_tool()
        tool.capacity = 0x4000
        tool._command = Mock()

        tool.program_flash(0x20, b"x" * 4001)

        self.assertEqual(tool._command.call_count, 2)
        first = tool._command.call_args_list[0][0]
        second = tool._command.call_args_list[1][0]
        self.assertEqual(first[0], 0x31)
        self.assertEqual(first[1][:4], struct.pack("<I", 0x20))
        self.assertEqual(len(first[1]), 4004)
        self.assertEqual(second[0], 0x31)
        self.assertEqual(second[1], struct.pack("<I", 0x20 + 4000) + b"x")

    def test_partial_raw_write_preserves_surrounding_sector_bytes(self):
        class MemoryFlash:
            capacity = 0x2000

            def __init__(self):
                self.data = bytearray(b"\xaa" * self.capacity)

            def read_flash(self, offset, length, verify=False):
                yield bytes(self.data[offset : offset + length])

            def erase_flash(self, start, end):
                self.data[start:end] = b"\xff" * (end - start)

            def program_flash(self, offset, data):
                self.data[offset : offset + len(data)] = data

            def check_flash_program(self):
                return None

            def hash_flash(self, offset, length):
                return hashlib.sha256(self.data[offset : offset + length]).digest()

        family = Family("boufallo-bl60x", None, "bl60x", "BL602")
        soc = BL60XMain(family)
        soc.conn = FlashConnection("memory", linked=True)
        soc.tool = MemoryFlash()
        original = bytes(soc.tool.data)

        soc.flash_write_raw(0x0FFF, 3, io.BytesIO(b"\x10\x20\x30"))

        self.assertEqual(soc.tool.data[0x0FFF:0x1002], b"\x10\x20\x30")
        self.assertEqual(soc.tool.data[:0x0FFF], original[:0x0FFF])
        self.assertEqual(soc.tool.data[0x1002:], original[0x1002:])

    def test_full_flash_read_checks_device_sha256(self):
        data = b"flash"
        tool = self.make_tool()
        tool.capacity = len(data)
        tool.loader_command = Mock(
            side_effect=[data, hashlib.sha256(data).digest()]
        )

        self.assertEqual(b"".join(tool.read_flash(0, len(data))), data)
        self.assertEqual(tool.loader_command.call_count, 2)
        tool.loader_command.assert_any_call(
            0x32, struct.pack("<II", 0, len(data)), response=True
        )
        tool.loader_command.assert_any_call(
            0x3D, struct.pack("<II", 0, len(data)), response=True
        )

    def test_full_flash_read_rejects_hash_mismatch(self):
        data = b"flash"
        tool = self.make_tool()
        tool.capacity = len(data)
        tool.loader_command = Mock(side_effect=[data, b"\x00" * 32])

        with self.assertRaisesRegex(BL60XProtocolError, "SHA-256"):
            b"".join(tool.read_flash(0, len(data)))


if __name__ == "__main__":
    unittest.main()
