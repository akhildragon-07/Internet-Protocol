"""Unit tests for RoutingTable Longest Prefix Match (LPM) algorithm."""

import unittest
from akip.routing import RoutingTable
from akip.address import AKIPAddress


class TestRoutingTable(unittest.TestCase):
    def setUp(self):
        self.table = RoutingTable()

    def test_longest_prefix_match_hierarchy(self):
        # Default route
        self.table.add_route("0.0.0.0/0", interface_name="eth0", next_hop="192.168.0.1", metric=10)
        # Class A route
        self.table.add_route("10.0.0.0/8", interface_name="eth1", next_hop="10.0.0.1", metric=5)
        # Subnet route
        self.table.add_route("10.1.0.0/16", interface_name="eth2", next_hop="10.1.0.1", metric=2)
        # Specific LAN route
        self.table.add_route("10.1.5.0/24", interface_name="eth3", next_hop="10.1.5.1", metric=1)

        # Lookup 10.1.5.42 -> should match most specific /24 (eth3)
        r1 = self.table.lookup("10.1.5.42")
        self.assertIsNotNone(r1)
        self.assertEqual(r1.interface_name, "eth3")
        self.assertEqual(r1.prefix_len, 24)

        # Lookup 10.1.9.1 -> should match /16 (eth2)
        r2 = self.table.lookup("10.1.9.1")
        self.assertIsNotNone(r2)
        self.assertEqual(r2.interface_name, "eth2")
        self.assertEqual(r2.prefix_len, 16)

        # Lookup 10.8.1.1 -> should match /8 (eth1)
        r3 = self.table.lookup("10.8.1.1")
        self.assertIsNotNone(r3)
        self.assertEqual(r3.interface_name, "eth1")
        self.assertEqual(r3.prefix_len, 8)

        # Lookup 8.8.8.8 -> should fall back to default route 0.0.0.0/0 (eth0)
        r4 = self.table.lookup("8.8.8.8")
        self.assertIsNotNone(r4)
        self.assertEqual(r4.interface_name, "eth0")
        self.assertEqual(r4.prefix_len, 0)

    def test_metric_tie_breaker(self):
        # Two routes with same prefix length /24, different metrics
        self.table.add_route("172.16.1.0/24", interface_name="eth-high-cost", metric=10)
        self.table.add_route("172.16.1.0/24", interface_name="eth-low-cost", metric=2)

        match = self.table.lookup("172.16.1.50")
        self.assertIsNotNone(match)
        self.assertEqual(match.interface_name, "eth-low-cost")
        self.assertEqual(match.metric, 2)

    def test_no_matching_route(self):
        self.table.add_route("10.0.0.0/24", interface_name="eth0")
        match = self.table.lookup("192.168.1.1")
        self.assertIsNone(match)

    def test_remove_route(self):
        self.table.add_route("10.1.0.0/24", interface_name="eth0")
        self.assertIsNotNone(self.table.lookup("10.1.0.5"))
        removed = self.table.remove_route("10.1.0.0/24")
        self.assertTrue(removed)
        self.assertIsNone(self.table.lookup("10.1.0.5"))


if __name__ == "__main__":
    unittest.main()
