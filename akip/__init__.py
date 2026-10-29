"""
AKIP: Akhil's Custom Internet Protocol
A research-grade educational network-layer protocol simulator.
"""

__version__ = "1.0.0"
__magic__ = b"AK"

from akip.address import AKIPAddress, AKIPNetwork
from akip.packet import (
    AKIPPacket,
    PacketProtocol,
    PacketFlags,
    AKIPError,
    PacketTooShortError,
    InvalidMagicError,
    UnsupportedVersionError,
    ChecksumError,
    LengthMismatchError,
    HopLimitExpiredError,
    InvalidAddressError,
    calculate_checksum,
)
from akip.link import SimulatedLink, LinkStatistics
from akip.routing import RouteEntry, RoutingTable
from akip.router import Router, Interface
from akip.node import Node
from akip.topology import NetworkTopology

__all__ = [
    "AKIPAddress",
    "AKIPNetwork",
    "AKIPPacket",
    "PacketProtocol",
    "PacketFlags",
    "AKIPError",
    "PacketTooShortError",
    "InvalidMagicError",
    "UnsupportedVersionError",
    "ChecksumError",
    "LengthMismatchError",
    "HopLimitExpiredError",
    "InvalidAddressError",
    "calculate_checksum",
    "SimulatedLink",
    "LinkStatistics",
    "RouteEntry",
    "RoutingTable",
    "Router",
    "Interface",
    "Node",
    "NetworkTopology",
]
