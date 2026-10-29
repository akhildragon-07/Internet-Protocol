"""
AKIP Binary Packet Encoding, Decoding, and Header Processing Module.

Defines the binary wire format for AKIP (Akhil's Custom Internet Protocol),
including struct serialization, checksum calculation, validation, and error hierarchy.
"""

import struct
from enum import IntEnum
from typing import Optional, Union
from akip.address import AKIPAddress, InvalidAddressError

AKIP_MAGIC = b"AK"
AKIP_VERSION_1 = 1
HEADER_FORMAT = ">2sBBBBHH4s4sH"
HEADER_LENGTH = struct.calcsize(HEADER_FORMAT)  # 20 bytes


class PacketProtocol(IntEnum):
    """Protocol identifiers encapsulated in the AKIP packet."""
    RESERVED = 0
    ECHO_REQUEST = 1   # Diagnostic ping request
    ECHO_REPLY = 2     # Diagnostic ping reply
    DATA = 3           # Generic upper-layer data
    ROUTER_ALERT = 4   # Routing control / diagnostic alert
    ERROR_REPORT = 5   # Error status / destination unreachable


class PacketFlags(IntEnum):
    """Bitmask flags in the AKIP header."""
    NONE = 0x00
    DONT_FRAGMENT = 0x01
    MORE_FRAGMENTS = 0x02
    PRIORITY_HIGH = 0x80


class AKIPError(Exception):
    """Base exception for all AKIP protocol-related errors."""
    pass


class PacketTooShortError(AKIPError):
    """Raised when wire buffer is smaller than the required 20-byte header."""
    pass


class InvalidMagicError(AKIPError):
    """Raised when magic byte identifier does not match b'AK'."""
    pass


class UnsupportedVersionError(AKIPError):
    """Raised when the packet version is not supported."""
    pass


class ChecksumError(AKIPError):
    """Raised when the received checksum does not match the computed checksum."""
    pass


class LengthMismatchError(AKIPError):
    """Raised when the declared payload length does not match the actual byte buffer length."""
    pass


class HopLimitExpiredError(AKIPError):
    """Raised when a packet's hop limit expires (reaches 0 in transit)."""
    pass


def calculate_checksum(header_bytes_without_checksum: bytes) -> int:
    """
    Computes the standard Internet 16-bit one's complement checksum (RFC 1071)
    over a byte buffer.

    The checksum field itself MUST be zeroed out in the input buffer.
    """
    if len(header_bytes_without_checksum) % 2 != 0:
        header_bytes_without_checksum += b"\x00"

    total = 0
    for i in range(0, len(header_bytes_without_checksum), 2):
        word = (header_bytes_without_checksum[i] << 8) + header_bytes_without_checksum[i + 1]
        total += word

    # Fold 32-bit carry bits into lower 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    # One's complement inversion
    checksum = (~total) & 0xFFFF
    return checksum


class AKIPPacket:
    """
    Represents an AKIP Network Layer Packet.

    Header layout (20 bytes, Big-Endian):
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Magic ('A', 'K')      |    Version    |    Protocol   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Hop Limit   |     Flags     |          Packet ID            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Payload Length        |          Source Address       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Source Address (cont.)   |        Destination Address    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Destination Address (cont.) |           Checksum            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Payload (variable)                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(
        self,
        src: Union[AKIPAddress, str],
        dst: Union[AKIPAddress, str],
        payload: bytes = b"",
        packet_id: int = 1,
        protocol: PacketProtocol = PacketProtocol.DATA,
        hop_limit: int = 64,
        flags: int = PacketFlags.NONE,
        version: int = AKIP_VERSION_1,
        magic: bytes = AKIP_MAGIC,
        checksum: Optional[int] = None,
    ):
        self.magic = magic
        self.version = version
        self.protocol = PacketProtocol(protocol)
        self.hop_limit = hop_limit
        self.flags = flags
        self.packet_id = packet_id
        self.src = AKIPAddress(src) if not isinstance(src, AKIPAddress) else src
        self.dst = AKIPAddress(dst) if not isinstance(dst, AKIPAddress) else dst
        self.payload = payload
        self.checksum = checksum

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def total_length(self) -> int:
        return HEADER_LENGTH + len(self.payload)

    def compute_checksum(self) -> int:
        """
        Packs the 20-byte header with the checksum field set to 0,
        concatenates the payload, and computes the RFC 1071 one's complement checksum
        over the entire packet.
        """
        zero_checksum_header = struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            int(self.protocol),
            self.hop_limit,
            self.flags,
            self.packet_id,
            self.payload_length,
            self.src.to_bytes(),
            self.dst.to_bytes(),
            0,  # checksum placeholder
        )
        return calculate_checksum(zero_checksum_header + self.payload)

    # Alias for backward compatibility
    compute_header_checksum = compute_checksum

    def encode(self, recalculate_checksum: bool = True) -> bytes:
        """
        Serializes the AKIP packet into its complete binary wire representation.
        """
        if recalculate_checksum or self.checksum is None:
            self.checksum = self.compute_checksum()

        header = struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            int(self.protocol),
            self.hop_limit,
            self.flags,
            self.packet_id,
            self.payload_length,
            self.src.to_bytes(),
            self.dst.to_bytes(),
            self.checksum,
        )
        return header + self.payload

    @classmethod
    def decode(cls, raw_data: bytes, verify_checksum: bool = True) -> "AKIPPacket":
        """
        Parses raw binary bytes from a simulated network interface into an AKIPPacket instance.
        Validates magic bytes, version, checksum, and payload length.
        """
        if len(raw_data) < HEADER_LENGTH:
            raise PacketTooShortError(
                f"Packet length {len(raw_data)} bytes is shorter than minimum header size ({HEADER_LENGTH} bytes)"
            )

        (
            magic,
            version,
            proto_val,
            hop_limit,
            flags,
            packet_id,
            payload_len,
            src_bytes,
            dst_bytes,
            rx_checksum,
        ) = struct.unpack(HEADER_FORMAT, raw_data[:HEADER_LENGTH])

        if magic != AKIP_MAGIC:
            raise InvalidMagicError(
                f"Invalid magic identifier: expected {AKIP_MAGIC!r}, got {magic!r}"
            )

        if version != AKIP_VERSION_1:
            raise UnsupportedVersionError(
                f"Unsupported protocol version {version} (expected {AKIP_VERSION_1})"
            )

        actual_payload = raw_data[HEADER_LENGTH:]
        if len(actual_payload) != payload_len:
            raise LengthMismatchError(
                f"Payload length mismatch: header advertised {payload_len} bytes, "
                f"but buffer contains {len(actual_payload)} bytes"
            )

        # Checksum verification across full packet (header with 0 checksum + payload)
        if verify_checksum:
            zero_hdr = struct.pack(
                HEADER_FORMAT,
                magic,
                version,
                proto_val,
                hop_limit,
                flags,
                packet_id,
                payload_len,
                src_bytes,
                dst_bytes,
                0,
            )
            expected_checksum = calculate_checksum(zero_hdr + actual_payload)
            if rx_checksum != expected_checksum:
                raise ChecksumError(
                    f"Checksum validation failed: received 0x{rx_checksum:04X}, "
                    f"computed 0x{expected_checksum:04X}"
                )

        try:
            protocol = PacketProtocol(proto_val)
        except ValueError:
            protocol = PacketProtocol.DATA

        src = AKIPAddress.from_bytes(src_bytes)
        dst = AKIPAddress.from_bytes(dst_bytes)

        return cls(
            src=src,
            dst=dst,
            payload=actual_payload,
            packet_id=packet_id,
            protocol=protocol,
            hop_limit=hop_limit,
            flags=flags,
            version=version,
            magic=magic,
            checksum=rx_checksum,
        )

    def decrement_hop_limit(self) -> int:
        """
        Decrements the hop limit by 1 as required during router forwarding.
        Recomputes the checksum. Raises HopLimitExpiredError if it drops to 0.
        """
        if self.hop_limit <= 1:
            self.hop_limit = 0
            raise HopLimitExpiredError(
                f"Hop limit expired for packet ID {self.packet_id} ({self.src} -> {self.dst})"
            )
        self.hop_limit -= 1
        self.checksum = self.compute_header_checksum()
        return self.hop_limit

    def __repr__(self) -> str:
        return (
            f"<AKIPPacket id={self.packet_id} {self.src}->{self.dst} "
            f"proto={self.protocol.name} hops={self.hop_limit} "
            f"len={self.total_length}b chk=0x{self.checksum or 0:04X}>"
        )
