"""Unit tests for AKIP binary packet serialization, deserialization, and checksum."""

import unittest
from akip.packet import (
    AKIPPacket,
    PacketProtocol,
    PacketFlags,
    calculate_checksum,
    HEADER_LENGTH,
    AKIP_MAGIC,
    AKIP_VERSION_1,
)
from akip.address import AKIPAddress


class TestAKIPPacket(unittest.TestCase):
    def test_checksum_algorithm(self):
        # Test basic one's complement behavior
        data = b"\x00\x01\x00\x02"
        # 1 + 2 = 3 (0x0003) -> complement is 0xFFFC
        chk = calculate_checksum(data)
        self.assertEqual(chk, 0xFFFC)

    def test_encode_and_decode_cycle(self):
        src = AKIPAddress("10.1.0.10")
        dst = AKIPAddress("10.3.0.10")
        payload = b"Hello, AKIP Network World!"

        pkt = AKIPPacket(
            src=src,
            dst=dst,
            payload=payload,
            packet_id=42,
            protocol=PacketProtocol.DATA,
            hop_limit=64,
            flags=PacketFlags.DONT_FRAGMENT,
        )

        raw = pkt.encode()
        self.assertEqual(len(raw), HEADER_LENGTH + len(payload))

        decoded = AKIPPacket.decode(raw, verify_checksum=True)
        self.assertEqual(decoded.magic, AKIP_MAGIC)
        self.assertEqual(decoded.version, AKIP_VERSION_1)
        self.assertEqual(decoded.protocol, PacketProtocol.DATA)
        self.assertEqual(decoded.packet_id, 42)
        self.assertEqual(decoded.hop_limit, 64)
        self.assertEqual(decoded.flags, PacketFlags.DONT_FRAGMENT)
        self.assertEqual(decoded.src, src)
        self.assertEqual(decoded.dst, dst)
        self.assertEqual(decoded.payload, payload)
        self.assertEqual(decoded.payload_length, len(payload))
        self.assertEqual(decoded.checksum, pkt.checksum)

    def test_empty_payload(self):
        pkt = AKIPPacket(
            src="10.1.0.1",
            dst="10.2.0.1",
            payload=b"",
            protocol=PacketProtocol.ECHO_REQUEST,
        )
        raw = pkt.encode()
        self.assertEqual(len(raw), HEADER_LENGTH)
        decoded = AKIPPacket.decode(raw)
        self.assertEqual(decoded.payload, b"")
        self.assertEqual(decoded.protocol, PacketProtocol.ECHO_REQUEST)

    def test_hop_limit_decrement(self):
        pkt = AKIPPacket(
            src="10.1.0.1",
            dst="10.2.0.1",
            payload=b"test",
            hop_limit=5,
        )
        pkt.encode()
        initial_checksum = pkt.checksum

        remaining = pkt.decrement_hop_limit()
        self.assertEqual(remaining, 4)
        self.assertEqual(pkt.hop_limit, 4)
        # Checksum must have been updated
        self.assertNotEqual(pkt.checksum, initial_checksum)

        # Ensure the re-encoded packet decodes and passes checksum
        raw = pkt.encode()
        decoded = AKIPPacket.decode(raw, verify_checksum=True)
        self.assertEqual(decoded.hop_limit, 4)


if __name__ == "__main__":
    unittest.main()
