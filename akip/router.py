"""
AKIP Router and Interface Module.

Implements multi-homed routers, network interfaces, forwarding engine,
hop-limit processing, checksum verification/recalculation, and packet forwarding telemetry.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any
from akip.address import AKIPAddress, AKIPNetwork
from akip.packet import (
    AKIPPacket,
    PacketProtocol,
    PacketTooShortError,
    InvalidMagicError,
    UnsupportedVersionError,
    ChecksumError,
    LengthMismatchError,
    HopLimitExpiredError,
)
from akip.routing import RoutingTable, RouteEntry
from akip.link import SimulatedLink, MtuExceededError


@dataclass
class RouterStatistics:
    """Metrics for router packet processing."""
    packets_received: int = 0
    packets_forwarded: int = 0
    packets_delivered_local: int = 0
    packets_dropped_malformed: int = 0
    packets_dropped_checksum: int = 0
    packets_dropped_hop_limit: int = 0
    packets_dropped_no_route: int = 0
    packets_dropped_mtu: int = 0

    def to_dict(self) -> dict:
        return {
            "packets_received": self.packets_received,
            "packets_forwarded": self.packets_forwarded,
            "packets_delivered_local": self.packets_delivered_local,
            "packets_dropped_malformed": self.packets_dropped_malformed,
            "packets_dropped_checksum": self.packets_dropped_checksum,
            "packets_dropped_hop_limit": self.packets_dropped_hop_limit,
            "packets_dropped_no_route": self.packets_dropped_no_route,
            "packets_dropped_mtu": self.packets_dropped_mtu,
        }


@dataclass
class ForwardingEvent:
    """Record of an individual forwarding decision for research analysis and tracing."""
    router_name: str
    ingress_interface: str
    packet_id: int
    src_ip: str
    dst_ip: str
    action: str  # 'FORWARDED', 'DELIVERED_LOCAL', 'DROPPED_HOP_LIMIT', 'DROPPED_NO_ROUTE', etc.
    detail: str
    egress_interface: Optional[str] = None
    remaining_hop_limit: Optional[int] = None


class Interface:
    """
    Represents a physical or virtual network interface on a node or router.
    """

    def __init__(
        self,
        name: str,
        address: Union[AKIPAddress, str],
        network: Union[AKIPNetwork, str],
        owner: Any,
        link: Optional[SimulatedLink] = None,
    ):
        self.name = name
        self.address = AKIPAddress(address) if not isinstance(address, AKIPAddress) else address
        self.network = AKIPNetwork(network) if not isinstance(network, AKIPNetwork) else network
        self.owner = owner  # Router or Node instance
        self.link: Optional[SimulatedLink] = None

        if link is not None:
            self.attach_link(link)

    def attach_link(self, link: SimulatedLink) -> None:
        """Connects this interface to a simulated link."""
        if self.link is not None:
            self.link.detach_interface(self)
        self.link = link
        link.attach_interface(self)

    def send_raw(self, raw_bytes: bytes) -> bool:
        """Transmits raw bytes over the connected link."""
        if self.link is None:
            raise ConnectionError(f"Interface {self.name} is not connected to any link")
        return self.link.transmit(self, raw_bytes)

    def receive_from_link(self, raw_bytes: bytes) -> None:
        """Callback invoked by SimulatedLink when a frame arrives."""
        self.owner.handle_ingress_packet(self, raw_bytes)

    def __repr__(self) -> str:
        return f"<Interface {self.name} {self.address} on {self.network}>"


class Router:
    """
    An AKIP Network Layer Router.

    Performs:
    1. Ingress frame parsing and validation (magic, checksum, length).
    2. Local delivery check (addressed to router itself).
    3. Hop-limit validation and decrement.
    4. Longest-Prefix-Match routing table lookup.
    5. Checksum re-calculation.
    6. Egress link transmission.
    """

    def __init__(self, name: str):
        self.name = name
        self.interfaces: Dict[str, Interface] = {}
        self.routing_table = RoutingTable()
        self.stats = RouterStatistics()
        self.event_log: List[ForwardingEvent] = []

    def add_interface(
        self,
        name: str,
        address: Union[AKIPAddress, str],
        network: Union[AKIPNetwork, str],
        link: Optional[SimulatedLink] = None,
    ) -> Interface:
        """Creates and binds a new interface to this router."""
        if name in self.interfaces:
            raise ValueError(f"Interface '{name}' already exists on router '{self.name}'")
        ifce = Interface(name=name, address=address, network=network, owner=self, link=link)
        self.interfaces[name] = ifce

        # Automatically add directly-connected subnet route to routing table
        self.routing_table.add_route(
            network=ifce.network,
            interface_name=name,
            next_hop=None,
            metric=0,
        )
        return ifce

    def add_static_route(
        self,
        network: Union[AKIPNetwork, str],
        interface_name: str,
        next_hop: Optional[Union[AKIPAddress, str]] = None,
        metric: int = 1,
    ) -> RouteEntry:
        """Configures a static route entry in the router's FIB."""
        if interface_name not in self.interfaces:
            raise ValueError(f"Interface '{interface_name}' not found on router '{self.name}'")
        return self.routing_table.add_route(
            network=network,
            interface_name=interface_name,
            next_hop=next_hop,
            metric=metric,
        )

    def is_local_address(self, address: AKIPAddress) -> bool:
        """Checks if the address belongs to any interface on this router."""
        return any(ifce.address == address for ifce in self.interfaces.values())

    def handle_ingress_packet(self, ingress_ifce: Interface, raw_bytes: bytes) -> None:
        """
        Main router forwarding engine pipeline.
        Invoked when an interface receives raw packet bytes.
        """
        self.stats.packets_received += 1

        # 1. Packet Decoding and Verification
        try:
            packet = AKIPPacket.decode(raw_bytes, verify_checksum=True)
        except ChecksumError as e:
            self.stats.packets_dropped_checksum += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=0,
                    src_ip="unknown",
                    dst_ip="unknown",
                    action="DROPPED_CHECKSUM",
                    detail=str(e),
                )
            )
            return
        except (PacketTooShortError, InvalidMagicError, UnsupportedVersionError, LengthMismatchError) as e:
            self.stats.packets_dropped_malformed += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=0,
                    src_ip="unknown",
                    dst_ip="unknown",
                    action="DROPPED_MALFORMED",
                    detail=str(e),
                )
            )
            return

        # 2. Local Delivery Check
        if self.is_local_address(packet.dst):
            self.stats.packets_delivered_local += 1
            self._handle_local_packet(ingress_ifce, packet)
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DELIVERED_LOCAL",
                    detail=f"Delivered to router local stack (proto={packet.protocol.name})",
                )
            )
            return

        # 3. Hop Limit Decrement Check
        try:
            new_hops = packet.decrement_hop_limit()
        except HopLimitExpiredError as e:
            self.stats.packets_dropped_hop_limit += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DROPPED_HOP_LIMIT",
                    detail=str(e),
                    remaining_hop_limit=0,
                )
            )
            return

        # 4. Longest-Prefix-Match Routing Table Lookup
        route = self.routing_table.lookup(packet.dst)
        if route is None:
            self.stats.packets_dropped_no_route += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DROPPED_NO_ROUTE",
                    detail=f"No route to destination {packet.dst} in FIB",
                    remaining_hop_limit=new_hops,
                )
            )
            return

        # 5. Egress Forwarding
        egress_ifce = self.interfaces.get(route.interface_name)
        if egress_ifce is None:
            self.stats.packets_dropped_no_route += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DROPPED_INVALID_EGRESS",
                    detail=f"Interface {route.interface_name} not available",
                    remaining_hop_limit=new_hops,
                )
            )
            return

        # Hairpinning / Same Interface Check:
        # On a shared multi-access broadcast link (like Ethernet), if destination is
        # directly reachable on the ingress interface, hosts communicate directly at L2.
        # Re-broadcasting would create duplicates and loops (RFC 792 ICMP Redirect scenario).
        if egress_ifce == ingress_ifce:
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DROPPED_SAME_INTERFACE",
                    detail=f"Destination {packet.dst} is on same subnet as ingress {ingress_ifce.name} (hairpinning suppressed)",
                    remaining_hop_limit=new_hops,
                )
            )
            return

        # Re-encode packet with updated hop limit and newly computed checksum
        out_bytes = packet.encode(recalculate_checksum=True)

        try:
            egress_ifce.send_raw(out_bytes)
            self.stats.packets_forwarded += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="FORWARDED",
                    detail=f"Forwarded via route {route.network} (next_hop={route.next_hop or 'direct'})",
                    egress_interface=egress_ifce.name,
                    remaining_hop_limit=new_hops,
                )
            )
        except MtuExceededError as e:
            self.stats.packets_dropped_mtu += 1
            self.event_log.append(
                ForwardingEvent(
                    router_name=self.name,
                    ingress_interface=ingress_ifce.name,
                    packet_id=packet.packet_id,
                    src_ip=str(packet.src),
                    dst_ip=str(packet.dst),
                    action="DROPPED_MTU",
                    detail=str(e),
                    egress_interface=egress_ifce.name,
                    remaining_hop_limit=new_hops,
                )
            )

    def _handle_local_packet(self, ingress_ifce: Interface, packet: AKIPPacket) -> None:
        """Processes packets destined for the router itself."""
        if packet.protocol == PacketProtocol.ECHO_REQUEST:
            # Send ECHO_REPLY back to source
            reply = AKIPPacket(
                src=packet.dst,
                dst=packet.src,
                payload=packet.payload,
                packet_id=packet.packet_id + 1000,
                protocol=PacketProtocol.ECHO_REPLY,
                hop_limit=64,
            )
            route = self.routing_table.lookup(reply.dst)
            if route and route.interface_name in self.interfaces:
                reply_ifce = self.interfaces[route.interface_name]
                reply_ifce.send_raw(reply.encode())

    def get_summary(self) -> dict:
        return {
            "name": self.name,
            "interfaces": {k: str(v.address) for k, v in self.interfaces.items()},
            "routes": [str(r) for r in self.routing_table.all_routes()],
            "stats": self.stats.to_dict(),
        }

    def __repr__(self) -> str:
        return f"<Router '{self.name}' ifces={list(self.interfaces.keys())}>"
