"""Unit tests for AKIPAddress and AKIPNetwork."""

import unittest
from akip.address import AKIPAddress, AKIPNetwork, InvalidAddressError


class TestAKIPAddress(unittest.TestCase):
    def test_valid_dotted_decimal(self):
        addr = AKIPAddress("10.1.0.1")
        self.assertEqual(str(addr), "10.1.0.1")
        self.assertEqual(addr.as_int, 0x0A010001)

    def test_from_int(self):
        addr = AKIPAddress(0x0A010001)
        self.assertEqual(str(addr), "10.1.0.1")

    def test_to_and_from_bytes(self):
        addr = AKIPAddress("192.168.1.100")
        raw = addr.to_bytes()
        self.assertEqual(len(raw), 4)
        self.assertEqual(raw, bytes([192, 168, 1, 100]))
        reconstructed = AKIPAddress.from_bytes(raw)
        self.assertEqual(addr, reconstructed)

    def test_equality_and_hashing(self):
        a1 = AKIPAddress("10.0.0.1")
        a2 = AKIPAddress("10.0.0.1")
        a3 = AKIPAddress("10.0.0.2")
        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, a3)
        self.assertEqual(hash(a1), hash(a2))
        self.assertTrue(a1 == "10.0.0.1")

    def test_comparison(self):
        a1 = AKIPAddress("10.0.0.1")
        a2 = AKIPAddress("10.0.0.2")
        self.assertLess(a1, a2)

    def test_loopback_and_broadcast(self):
        loopback = AKIPAddress("127.0.0.1")
        self.assertTrue(loopback.is_loopback())
        broadcast = AKIPAddress("255.255.255.255")
        self.assertTrue(broadcast.is_broadcast())
        normal = AKIPAddress("10.1.0.1")
        self.assertFalse(normal.is_loopback())
        self.assertFalse(normal.is_broadcast())

    def test_invalid_strings(self):
        invalid_cases = [
            "10.1.0",
            "10.1.0.1.5",
            "256.0.0.1",
            "10.-1.0.1",
            "abc.def.ghi.jkl",
            "10.1.0.01a",
            "",
        ]
        for case in invalid_cases:
            with self.assertRaises(InvalidAddressError, msg=f"Failed on case: {case}"):
                AKIPAddress(case)

    def test_invalid_ints_and_bytes(self):
        with self.assertRaises(InvalidAddressError):
            AKIPAddress(-1)
        with self.assertRaises(InvalidAddressError):
            AKIPAddress(0x100000000)
        with self.assertRaises(InvalidAddressError):
            AKIPAddress(b"\x01\x02\x03")  # 3 bytes
        with self.assertRaises(InvalidAddressError):
            AKIPAddress(b"\x01\x02\x03\x04\x05")  # 5 bytes


class TestAKIPNetwork(unittest.TestCase):
    def test_subnet_properties(self):
        net = AKIPNetwork("10.1.0.0/24")
        self.assertEqual(net.prefix_len, 24)
        self.assertEqual(str(net.network_address), "10.1.0.0")
        self.assertEqual(str(net.netmask), "255.255.255.0")
        self.assertEqual(str(net.broadcast_address), "10.1.0.255")

    def test_contains(self):
        net = AKIPNetwork("10.1.0.0/24")
        self.assertTrue(net.contains("10.1.0.1"))
        self.assertTrue(net.contains("10.1.0.254"))
        self.assertTrue("10.1.0.10" in net)
        self.assertFalse("10.1.1.1" in net)
        self.assertFalse("10.2.0.1" in net)

    def test_p2p_transit_subnet(self):
        net = AKIPNetwork("10.2.0.0/30")
        self.assertEqual(net.prefix_len, 30)
        self.assertEqual(str(net.netmask), "255.255.255.252")
        self.assertTrue("10.2.0.1" in net)
        self.assertTrue("10.2.0.2" in net)
        self.assertFalse("10.2.0.4" in net)

    def test_default_route_network(self):
        net = AKIPNetwork("0.0.0.0/0")
        self.assertTrue("10.1.0.1" in net)
        self.assertTrue("192.168.1.1" in net)
        self.assertTrue("8.8.8.8" in net)

    def test_invalid_cidrs(self):
        invalid_cases = [
            "10.1.0.0",
            "10.1.0.0/33",
            "10.1.0.0/-1",
            "10.1.0.0/abc",
        ]
        for case in invalid_cases:
            with self.assertRaises(InvalidAddressError):
                AKIPNetwork(case)


if __name__ == "__main__":
    unittest.main()
