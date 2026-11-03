"""BL602 UART ISP and RAM flash-loader protocol."""

import hashlib
import struct
import time
from pathlib import Path
from typing import Generator, Optional

from ltchiptool.util.serialtool import SerialToolBase
from ltchiptool.util.streams import ProgressCallback

ROM_BAUD = 115200
READ_CHUNK = 4096
ERASE_SIZE = 4096
PROGRAM_CHUNK = 4000
ERASE_COMMANDS = (0x30, 0x3C)
ERASE_TIMEOUT = 120.0
READ_ONLY_COMMANDS = (0x10, 0x11, 0x17, 0x18, 0x19, 0x1A, 0x32, 0x36, 0x3D)
WRITE_COMMANDS = (0x30, 0x31, 0x3A)


class BL60XProtocolError(RuntimeError):
    pass


class BL60XTool(SerialToolBase):
    """BL602 ISP link using the ROM and RAM flash-loader protocols."""

    def __init__(
        self,
        port: str,
        baudrate: int = ROM_BAUD,
        link_timeout: float = 10.0,
        read_timeout: float = 0.2,
        retry_count: int = 3,
    ):
        super().__init__(port, ROM_BAUD, link_timeout, read_timeout, retry_count)
        self.s.timeout = read_timeout
        self.s.write_timeout = 3
        self.baudrate = baudrate
        self.flash_id: Optional[bytes] = None
        self.capacity: Optional[int] = None
        self.connected = False

    def connect(self) -> None:
        if self.connected:
            return
        self.handshake()
        # The Eflash loader may still be running from a previous invocation.
        # Probe it first so a retry can continue without another GPIO8 reset.
        try:
            self.flash_id = self.loader_command(0x36, response=True)
        except BL60XProtocolError as err:
            message = str(err)
            if (
                "0101" not in message
                and "Timed out waiting for 2 bytes" not in message
            ):
                raise
            # An unknown ROM command may restart the ROM handshake window;
            # synchronize again before starting the normal loader upload.
            self.handshake()
        else:
            self._set_flash_capacity()
            self.connected = True
            return

        # The loader probe did not succeed, so use the ROM loader path.
        self.rom_command(0x10, response=True)  # ROM boot information
        image = Path(__file__).with_name("eflash_loader_rc32m.bin").read_bytes()
        if len(image) < 192 or image[:4] != b"BFNP":
            raise BL60XProtocolError("Invalid bundled BL602 RAM loader")
        if struct.unpack_from("<I", image, 120)[0] != 1:
            raise BL60XProtocolError("Expected one RAM loader segment")
        address, size = struct.unpack_from("<II", image, 176)
        if address != 0x22010000 or size != len(image) - 192:
            raise BL60XProtocolError("Unexpected BL602 RAM loader layout")
        self.rom_command(0x11, image[:176])
        self.rom_command(0x17, image[176:192], response=True)
        for offset in range(192, len(image), 2048):
            self.rom_command(0x18, image[offset : offset + 2048])
        self.rom_command(0x19)
        self.rom_command(0x1A)
        time.sleep(0.2)
        if self.s.baudrate != self.baudrate:
            self.set_baudrate(self.baudrate)
        self.handshake()
        self.flash_id = self.loader_command(0x36, response=True)
        self._set_flash_capacity()

    def _set_flash_capacity(self) -> None:
        if len(self.flash_id) < 3 or not 17 <= self.flash_id[2] <= 26:
            raise BL60XProtocolError("Invalid or unsupported JEDEC flash ID")
        self.capacity = 1 << self.flash_id[2]
        self.connected = True

    def close(self) -> None:
        self.connected = False
        super().close()

    def handshake(self) -> None:
        last = b""
        for _ in range(self.retry_count):
            self.s.reset_input_buffer()
            self.write(b"\x55" * 70)
            self.s.flush()
            deadline = time.monotonic() + min(self.link_timeout, 1.0)
            received = bytearray()
            while time.monotonic() < deadline:
                try:
                    received.extend(self.read(max_count=64))
                except TimeoutError:
                    continue
                if b"OK" in received:
                    time.sleep(0.02)
                    return
            last = bytes(received)
            time.sleep(0.1)
        raise BL60XProtocolError(
            f"BL602 ROM sync failed ({last[:16].hex() or 'no reply'})"
        )

    def _read_exact(self, count: int, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        result = bytearray()
        while len(result) < count and time.monotonic() < deadline:
            try:
                result.extend(self.read(count - len(result)))
            except TimeoutError:
                continue
        if len(result) != count:
            raise BL60XProtocolError(f"Timed out waiting for {count} bytes")
        return bytes(result)

    def _command(
        self,
        command: int,
        payload: bytes = b"",
        response: bool = False,
        checksum: int = 0,
    ) -> bytes:
        if len(payload) > 0xFFFF:
            raise ValueError("BL602 command payload exceeds protocol limit")
        if command not in READ_ONLY_COMMANDS + WRITE_COMMANDS:
            raise ValueError(f"BL602 command 0x{command:02x} is not supported")
        header = bytes(
            (command, checksum & 0xFF, len(payload) & 0xFF, len(payload) >> 8)
        )
        self.write(header + payload)
        self.s.flush()
        deadline = (
            time.monotonic() + ERASE_TIMEOUT
            if command in ERASE_COMMANDS
            else None
        )
        ack = self._read_exact(
            2, timeout=ERASE_TIMEOUT if deadline is not None else 5.0
        )
        while ack == b"PD" and deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BL60XProtocolError(
                    f"BL602 command 0x{command:02x} timed out while erase was pending"
                )
            ack = self._read_exact(2, timeout=remaining)
        if ack != b"OK":
            detail = self._read_exact(2).hex() if ack == b"FL" else ack.hex()
            raise BL60XProtocolError(f"BL602 command 0x{command:02x} failed: {detail}")
        if not response:
            return b""
        length = int.from_bytes(self._read_exact(2), "little")
        if length > 8192:
            raise BL60XProtocolError("BL602 response exceeded 8 KiB")
        return self._read_exact(length, max(5.0, length / 1024))

    def rom_command(
        self, command: int, payload: bytes = b"", response: bool = False
    ) -> bytes:
        return self._command(command, payload, response)

    def loader_command(
        self, command: int, payload: bytes = b"", response: bool = False
    ) -> bytes:
        # Bouffalo's host flasher checksums the length and payload bytes.
        checksum = (len(payload) & 0xFF) + (len(payload) >> 8)
        checksum += sum(payload)
        return self._command(command, payload, response, checksum & 0xFF)

    def read_flash(
        self,
        offset: int,
        length: int,
        callback: Optional[ProgressCallback] = None,
        verify: bool = True,
    ) -> Generator[bytes, None, None]:
        digest = hashlib.sha256()
        for address in range(offset, offset + length, READ_CHUNK):
            count = min(READ_CHUNK, offset + length - address)
            data = self.loader_command(
                0x32, struct.pack("<II", address, count), response=True
            )
            if len(data) != count:
                raise BL60XProtocolError("BL602 returned a short flash read")
            digest.update(data)
            if callback:
                callback.on_update(len(data))
            yield data
        if verify and offset == 0 and length == self.capacity:
            device_hash = self.loader_command(
                0x3D, struct.pack("<II", 0, length), response=True
            )
            if len(device_hash) != 32 or digest.digest() != device_hash:
                raise BL60XProtocolError("BL602 flash read SHA-256 verification failed")

    def erase_flash(self, start: int, end: int) -> None:
        if start < 0 or end <= start or end > self.capacity:
            raise ValueError("BL602 erase range is outside detected flash capacity")
        if start % ERASE_SIZE or end % ERASE_SIZE:
            raise ValueError("BL602 erase range must be aligned to 4 KiB sectors")
        self.loader_command(0x30, struct.pack("<II", start, end))

    def program_flash(self, address: int, data: bytes) -> None:
        if address < 0 or address + len(data) > self.capacity:
            raise ValueError("BL602 program range is outside detected flash capacity")
        for offset in range(0, len(data), PROGRAM_CHUNK):
            chunk = data[offset : offset + PROGRAM_CHUNK]
            self.loader_command(0x31, struct.pack("<I", address + offset) + chunk)

    def check_flash_program(self) -> None:
        self.loader_command(0x3A)

    def hash_flash(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.capacity:
            raise ValueError("BL602 hash range is outside detected flash capacity")
        digest = self.loader_command(
            0x3D, struct.pack("<II", offset, length), response=True
        )
        if len(digest) != 32:
            raise BL60XProtocolError("BL602 returned an invalid flash SHA-256")
        return digest
