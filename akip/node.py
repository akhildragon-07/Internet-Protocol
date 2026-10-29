"""
AKIP End-Host Node Module.

Implements network endpoints (hosts) capable of generating, transmitting,
receiving, validating, and replying to AKIP packets.
"""

from typing import List, Optional, Union, Any, Dict
from akip.address import AKIPAddress, AKIPNetwork
from akip.packet import (
    AKIPPacket,
    PacketProtocol,
    PacketFlags,
    ChecksumError,
    PacketTooShortError,
    InvalidMagicError,
    UnsupportedVersionError,
    LengthMismatchError,
)
from akip.router import Interface
from akip.link import SimulatedLink


class Node:
    """
    Represents an End-Host Network Node in the AKIP simulation.

    Features:
    - Primary network interface bound to an IP address and subnet
    - Configured default gateway IP for off-subnet routing
    - Packet transmission with automatic sequence numbering and checksum computation
    - Built-in Echo Reply (ping response) generator
    - Ingress packet validation and inspection inbox
    """

    def __init__(
        self,
        name: str,
        address: Union[AKIPAddress, str],
        network: Union[AKIPNetwork, str],
        default_gateway: Optional[Union[AKIPAddress, str]] = None,
        link: Optional[SimulatedLink] = None,
    ):
        self.name = name
        self.address = AKIPAddress(address) if not isinstance(address, AKIPAddress) else address
        self.network = AKIPNetwork(network) if not isinstance(network, AKIPNetwork) else network
        self.default_gateway = (
            AKIPAddress(default_gateway)
            if default_gateway is not None and not isinstance(default_gateway, AKIPAddress)
            else default_gateway
        )

        self.interface = Interface(
            name=f"{name}-eth0",
            address=self.address,
            network=self.network,
            owner=self,
            link=link,
        )

        self._next_packet_id: int = 1
        self.received_packets: List[AKIPPacket] = []
        self.sent_packets: List[AKIPPacket] = []
        self.dropped_packets: List[Dict[str, Any]] = []

    def attach_link(self, link: SimulatedLink) -> None:
        """Connects node's interface to a simulated link."""
        self.interface.attach_link(link)

    def send(
        self,
        dst: Union[AKIPAddress, str],
        payload: bytes = b"",
        protocol: PacketProtocol = PacketProtocol.DATA,
        hop_limit: int = 64,
        flags: int = PacketFlags.NONE,
        packet_id: Optional[int] = None,
        override_checksum: Optional[int] = None,
        corrupt_magic: Optional[bytes] = None,
    ) -> AKIPPacket:
        """
        Creates and transmits an AKIP packet.

        Allows intentional corruption parameters (override_checksum, corrupt_magic)
        for testing receiver protocol enforcement.
        """
        if packet_id is None:
            packet_id = self._next_packet_id
            self._next_packet_id = (self._next_packet_id + 1) % 65536
            if self._next_packet_id == 0:
                self._next_packet_id = 1

        dst_addr = AKIPAddress(dst) if not isinstance(dst, AKIPAddress) else dst

        pkt = AKIPPacket(
            src=self.address,
            dst=dst_addr,
            payload=payload,
            packet_id=packet_id,
            protocol=protocol,
            hop_limit=hop_limit,
            flags=flags,
            magic=corrupt_magic if corrupt_magic is not None else b"AK",
            checksum=override_checksum,
        )

        raw_bytes = pkt.encode(recalculate_checksum=(override_checksum is None))
        self.interface.send_raw(raw_bytes)
        self.sent_packets.append(pkt)
        return pkt

    def ping(
        self,
        dst: Union[AKIPAddress, str],
        payload: bytes = b"AKIP_ECHO_PING",
        hop_limit: int = 64,
    ) -> AKIPPacket:
        """Convenience method to transmit an ECHO_REQUEST diagnostic ping."""
        return self.send(
            dst=dst,
            payload=payload,
            protocol=PacketProtocol.ECHO_REQUEST,
            hop_limit=hop_limit,
        )

    def handle_ingress_packet(self, interface: Interface, raw_bytes: bytes) -> None:
        """
        Handles an incoming raw frame received on the node's interface.
        """
        # 1. Packet Decoding and Verification
        try:
            packet = AKIPPacket.decode(raw_bytes, verify_checksum=True)
        except ChecksumError as e:
            self.dropped_packets.append({"reason": "CHECKSUM_FAILED", "detail": str(e), "raw_len": len(raw_bytes)})
            return
        except (PacketTooShortError, InvalidMagicError, UnsupportedVersionError, LengthMismatchError) as e:
            self.dropped_packets.append({"reason": "MALFORMED_HEADER", "detail": str(e), "raw_len": len(raw_bytes)})
            return

        # 2. Destination Address Verification (Unicast filter)
        if packet.dst != self.address and not packet.dst.is_broadcast():
            # Discard packet not intended for this node
            self.dropped_packets.append({
                "reason": "NOT_FOR_THIS_HOST",
                "detail": f"Packet addressed to {packet.dst}, this host is {self.address}",
                "packet_id": packet.packet_id,
            })
            return

        # 3. Store valid accepted packet in inbox
        self.received_packets.append(packet)

        # 4. Built-in ICMP-like Echo Reply handler
        if packet.protocol == PacketProtocol.ECHO_REQUEST:
            self.send(
                dst=packet.src,
                payload=packet.payload,
                protocol=PacketProtocol.ECHO_REPLY,
                hop_limit=64,
            )

    def get_latest_received_packet(self) -> Optional[AKIPPacket]:
        """Returns the most recently received packet, if any."""
        return self.received_packets[-1] if self.received_packets else None

    def clear_buffers(self) -> None:
        """Clears sent, received, and dropped packet logs."""
        self.received_packets.clear()
        self.sent_packets.clear()
        self.dropped_packets.clear()

    def __repr__(self) -> str:
        return f"<Node '{self.name}' ip={self.address} gw={self.default_gateway}>"
