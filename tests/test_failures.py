"""Tests for network failure modes: malformed packets, invalid lengths, checksum errors, unknown routes, and hop-limit expiry."""

import unittest
from akip.topology import create_reference_topology
from akip.packet import (
    AKIPPacket,
    PacketTooShortError,
    InvalidMagicError,
    UnsupportedVersionError,
    LengthMismatchError,
    ChecksumError,
    HopLimitExpiredError,
    HEADER_LENGTH,
)
from akip.link import MtuExceededError


class TestFailureModes(unittest.TestCase):
    def setUp(self):
        self.topo = create_reference_topology()

    def test_malformed_packet_too_short(self):
        """Buffer smaller than the required 20-byte header should raise PacketTooShortError."""
        short_bytes = b"AKIP_TOO_SHORT"
        with self.assertRaises(PacketTooShortError):
            AKIPPacket.decode(short_bytes)

        # Router receiving short bytes drops as malformed
        r1_eth0 = self.topo.router_1.interfaces["r1-eth0"]
        self.topo.router_1.handle_ingress_packet(r1_eth0, short_bytes)
        self.assertEqual(self.topo.router_1.stats.packets_dropped_malformed, 1)

    def test_invalid_magic_identifier(self):
        """Header with invalid magic (e.g., b'XX' instead of b'AK') should be rejected."""
        pkt = AKIPPacket(src="10.1.0.10", dst="10.3.0.10", payload=b"test", magic=b"XX")
        raw = pkt.encode(recalculate_checksum=False)
        with self.assertRaises(InvalidMagicError):
            AKIPPacket.decode(raw)

        # Transmitting through node to router
        r1_eth0 = self.topo.router_1.interfaces["r1-eth0"]
        self.topo.router_1.handle_ingress_packet(r1_eth0, raw)
        self.assertEqual(self.topo.router_1.stats.packets_dropped_malformed, 1)

    def test_unsupported_version(self):
        """Header with version != 1 should raise UnsupportedVersionError."""
        pkt = AKIPPacket(src="10.1.0.10", dst="10.3.0.10", payload=b"test", version=2)
        raw = pkt.encode(recalculate_checksum=False)
        with self.assertRaises(UnsupportedVersionError):
            AKIPPacket.decode(raw)

    def test_payload_length_mismatch(self):
        """Header declaring 50 bytes payload when wire buffer only has 4 bytes."""
        pkt = AKIPPacket(src="10.1.0.10", dst="10.3.0.10", payload=b"abcd")
        raw = bytearray(pkt.encode())
        # Corrupt payload length field (bytes 8..9 in header)
        raw[8] = 0x00
        raw[9] = 0x32  # 50 in decimal
        with self.assertRaises(LengthMismatchError):
            AKIPPacket.decode(bytes(raw), verify_checksum=False)

    def test_checksum_failure_detection(self):
        """Corrupting a byte in transit causes receiver or router to reject with ChecksumError."""
        pkt = AKIPPacket(src="10.1.0.10", dst="10.3.0.10", payload=b"Uncorrupted Data")
        raw = bytearray(pkt.encode())
        # Flip bit in payload
        raw[-1] ^= 0x01

        with self.assertRaises(ChecksumError):
            AKIPPacket.decode(bytes(raw), verify_checksum=True)

        # Transmit via link with forced bit corruption
        self.topo.link_sub1.trigger_corruption_on_next_packet()
        self.topo.node_a.send(dst="10.3.0.10", payload=b"Important Message")

        # Router 1 received corrupted frame on link_sub1 -> dropped due to checksum
        self.assertEqual(self.topo.router_1.stats.packets_dropped_checksum, 1)
        # Node C never receives the corrupted packet
        self.assertEqual(len(self.topo.node_c.received_packets), 0)

    def test_unknown_destination_no_route(self):
        """Sending to an IP not in any router's forwarding table results in packet drop."""
        unroutable_ip = "192.168.99.1"
        self.topo.node_a.send(dst=unroutable_ip, payload=b"Lost in cyberspace")

        # Router 1 receives packet, looks up 192.168.99.1, finds no route, drops it
        self.assertEqual(self.topo.router_1.stats.packets_dropped_no_route, 1)
        self.assertEqual(self.topo.router_1.stats.packets_forwarded, 0)
        latest_event = self.topo.router_1.event_log[-1]
        self.assertEqual(latest_event.action, "DROPPED_NO_ROUTE")
        self.assertIn("No route to destination", latest_event.detail)

    def test_hop_limit_expiry_at_first_router(self):
        """Packet with hop_limit=1 sent across router should expire and be dropped at Router 1."""
        self.topo.node_a.send(dst="10.3.0.10", payload=b"Expires at R1", hop_limit=1)

        self.assertEqual(self.topo.router_1.stats.packets_dropped_hop_limit, 1)
        self.assertEqual(self.topo.router_1.stats.packets_forwarded, 0)
        self.assertEqual(len(self.topo.node_c.received_packets), 0)
        latest_event = self.topo.router_1.event_log[-1]
        self.assertEqual(latest_event.action, "DROPPED_HOP_LIMIT")

    def test_hop_limit_expiry_at_second_router(self):
        """
        Packet with hop_limit=2 sent to Node C:
        - Router 1 decrements 2 -> 1, forwards to Router 2.
        - Router 2 receives with hop_limit=1, tries to decrement -> expires!
        """
        self.topo.node_a.send(dst="10.3.0.10", payload=b"Expires at R2", hop_limit=2)

        self.assertEqual(self.topo.router_1.stats.packets_forwarded, 1)
        self.assertEqual(self.topo.router_2.stats.packets_dropped_hop_limit, 1)
        self.assertEqual(self.topo.router_2.stats.packets_forwarded, 0)
        self.assertEqual(len(self.topo.node_c.received_packets), 0)

    def test_mtu_exceeded_drop(self):
        """Sending a packet exceeding the link MTU should trigger MtuExceededError and record drop."""
        # Create a small MTU link topology
        small_topo = create_reference_topology(link_mtu=50)
        oversized_payload = b"Z" * 100

        with self.assertRaises(MtuExceededError):
            small_topo.node_a.send(dst="10.3.0.10", payload=oversized_payload)

        self.assertEqual(small_topo.link_sub1.stats.packets_dropped_mtu, 1)


if __name__ == "__main__":
    unittest.main()
