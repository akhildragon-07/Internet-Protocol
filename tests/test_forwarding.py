"""Integration tests for end-to-end packet forwarding across the 3-node, 2-router topology."""

import unittest
from akip.topology import create_reference_topology
from akip.packet import PacketProtocol


class TestTopologyForwarding(unittest.TestCase):
    def setUp(self):
        self.topo = create_reference_topology()

    def test_intra_subnet_forwarding(self):
        """Node A and Node B reside on 10.1.0.0/24. They communicate directly over Subnet 1 link."""
        msg = b"Hello neighbor Node B from Node A!"
        pkt = self.topo.node_a.send(dst="10.1.0.20", payload=msg)

        # Node B should have received the packet
        rx = self.topo.node_b.get_latest_received_packet()
        self.assertIsNotNone(rx)
        self.assertEqual(rx.payload, msg)
        self.assertEqual(rx.src, "10.1.0.10")
        self.assertEqual(rx.dst, "10.1.0.20")
        self.assertEqual(rx.hop_limit, 64)  # No router decrement for direct LAN link

        # Node C should have received nothing
        self.assertEqual(len(self.topo.node_c.received_packets), 0)

        # Router 1 should NOT have re-forwarded this onto another network
        self.assertEqual(self.topo.router_1.stats.packets_forwarded, 0)

    def test_multihop_forwarding_node_a_to_node_c(self):
        """
        Node A (10.1.0.10) sends to Node C (10.3.0.10).
        Path: Node A -> Router 1 -> Router 2 -> Node C (2 router hops).
        """
        payload = b"Cross-network payload from Subnet 1 to Subnet 3"
        sent_pkt = self.topo.node_a.send(dst="10.3.0.10", payload=payload, hop_limit=64)

        # Node C receives the packet
        rx_c = self.topo.node_c.get_latest_received_packet()
        self.assertIsNotNone(rx_c)
        self.assertEqual(rx_c.payload, payload)
        self.assertEqual(rx_c.src, "10.1.0.10")
        self.assertEqual(rx_c.dst, "10.3.0.10")

        # Each router decrements the hop limit: 64 -> R1 (63) -> R2 (62)
        self.assertEqual(rx_c.hop_limit, 62)

        # Check telemetry on both routers
        self.assertEqual(self.topo.router_1.stats.packets_forwarded, 1)
        self.assertEqual(self.topo.router_2.stats.packets_forwarded, 1)

    def test_ping_echo_request_reply_roundtrip(self):
        """
        Node A pings Node C:
        1. Node A transmits ECHO_REQUEST to Node C across R1 and R2.
        2. Node C receives ECHO_REQUEST and sends ECHO_REPLY to Node A.
        3. ECHO_REPLY traverses R2 and R1 back to Node A.
        4. Node A verifies reception of ECHO_REPLY.
        """
        ping_payload = b"PING_ROUND_TRIP_SEQUENCE_101"
        self.topo.node_a.ping(dst="10.3.0.10", payload=ping_payload, hop_limit=64)

        # Node C should have received the ECHO_REQUEST
        self.assertEqual(len(self.topo.node_c.received_packets), 1)
        req = self.topo.node_c.received_packets[0]
        self.assertEqual(req.protocol, PacketProtocol.ECHO_REQUEST)
        self.assertEqual(req.payload, ping_payload)

        # Node A should have received the ECHO_REPLY
        self.assertEqual(len(self.topo.node_a.received_packets), 1)
        reply = self.topo.node_a.received_packets[0]
        self.assertEqual(reply.protocol, PacketProtocol.ECHO_REPLY)
        self.assertEqual(reply.src, "10.3.0.10")
        self.assertEqual(reply.dst, "10.1.0.10")
        self.assertEqual(reply.payload, ping_payload)
        self.assertEqual(reply.hop_limit, 62)  # 64 - 2 hops back

    def test_ping_router_local_interface(self):
        """Node A pings Router 1 interface 10.1.0.1 directly."""
        self.topo.node_a.ping(dst="10.1.0.1", payload=b"HELLO_ROUTER_1")

        self.assertEqual(self.topo.router_1.stats.packets_delivered_local, 1)
        self.assertEqual(len(self.topo.node_a.received_packets), 1)
        reply = self.topo.node_a.received_packets[0]
        self.assertEqual(reply.protocol, PacketProtocol.ECHO_REPLY)
        self.assertEqual(reply.src, "10.1.0.1")


if __name__ == "__main__":
    unittest.main()
