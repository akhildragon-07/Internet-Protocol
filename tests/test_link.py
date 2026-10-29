"""Unit tests for SimulatedLink transmission, MTU, corruption, and telemetry."""

import unittest
from akip.link import SimulatedLink, MtuExceededError


class DummyInterface:
    def __init__(self, name: str):
        self.name = name
        self.received_frames = []

    def receive_from_link(self, raw_bytes: bytes) -> None:
        self.received_frames.append(raw_bytes)


class TestSimulatedLink(unittest.TestCase):
    def test_basic_transmission(self):
        link = SimulatedLink("test-link", mtu=1500)
        ifce1 = DummyInterface("if1")
        ifce2 = DummyInterface("if2")
        link.attach_interface(ifce1)
        link.attach_interface(ifce2)

        data = b"AKIP_PAYLOAD_TEST"
        delivered = link.transmit(ifce1, data)

        self.assertTrue(delivered)
        self.assertEqual(len(ifce2.received_frames), 1)
        self.assertEqual(ifce2.received_frames[0], data)
        self.assertEqual(len(ifce1.received_frames), 0)  # Sender does not receive own frame
        self.assertEqual(link.stats.packets_sent, 1)
        self.assertEqual(link.stats.packets_delivered, 1)

    def test_mtu_enforcement(self):
        link = SimulatedLink("small-mtu-link", mtu=50)
        ifce1 = DummyInterface("if1")
        ifce2 = DummyInterface("if2")
        link.attach_interface(ifce1)
        link.attach_interface(ifce2)

        oversized_data = b"X" * 60
        with self.assertRaises(MtuExceededError):
            link.transmit(ifce1, oversized_data)

        self.assertEqual(link.stats.packets_dropped_mtu, 1)
        self.assertEqual(len(ifce2.received_frames), 0)

    def test_forced_corruption(self):
        link = SimulatedLink("corrupt-link", mtu=1500)
        ifce1 = DummyInterface("if1")
        ifce2 = DummyInterface("if2")
        link.attach_interface(ifce1)
        link.attach_interface(ifce2)

        link.trigger_corruption_on_next_packet()
        original = b"A" * 30
        link.transmit(ifce1, original)

        self.assertEqual(link.stats.packets_corrupted, 1)
        received = ifce2.received_frames[0]
        self.assertNotEqual(received, original)
        self.assertEqual(len(received), len(original))

    def test_forced_drop(self):
        link = SimulatedLink("loss-link", mtu=1500)
        ifce1 = DummyInterface("if1")
        ifce2 = DummyInterface("if2")
        link.attach_interface(ifce1)
        link.attach_interface(ifce2)

        link.trigger_drop_on_next_packet()
        delivered = link.transmit(ifce1, b"lost_data")

        self.assertFalse(delivered)
        self.assertEqual(link.stats.packets_dropped_loss, 1)
        self.assertEqual(len(ifce2.received_frames), 0)


if __name__ == "__main__":
    unittest.main()
