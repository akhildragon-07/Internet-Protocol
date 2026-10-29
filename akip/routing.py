"""
AKIP Routing Table and Forwarding Information Base (FIB) Module.

Implements route table entries and Longest Prefix Match (LPM) forwarding lookup algorithm.
"""

from typing import List, Optional, Union
from akip.address import AKIPAddress, AKIPNetwork


class RouteEntry:
    """
    Represents an entry in an AKIP routing table.
    """

    def __init__(
        self,
        network: Union[AKIPNetwork, str],
        interface_name: str,
        next_hop: Optional[Union[AKIPAddress, str]] = None,
        metric: int = 1,
    ):
        self.network = AKIPNetwork(network) if not isinstance(network, AKIPNetwork) else network
        self.interface_name = interface_name
        self.next_hop = AKIPAddress(next_hop) if next_hop is not None and not isinstance(next_hop, AKIPAddress) else next_hop
        self.metric = metric

    @property
    def prefix_len(self) -> int:
        return self.network.prefix_len

    @property
    def is_direct(self) -> bool:
        """True if route is directly attached (no intermediate next-hop IP)."""
        return self.next_hop is None

    def __repr__(self) -> str:
        nh_str = str(self.next_hop) if self.next_hop else "DIRECT"
        return f"<Route {self.network} via {nh_str} dev {self.interface_name} metric {self.metric}>"


class RoutingTable:
    """
    Forwarding Information Base implementing Longest Prefix Match (LPM).
    """

    def __init__(self):
        self._routes: List[RouteEntry] = []

    def add_route(
        self,
        network: Union[AKIPNetwork, str],
        interface_name: str,
        next_hop: Optional[Union[AKIPAddress, str]] = None,
        metric: int = 1,
    ) -> RouteEntry:
        """Adds a route entry to the table."""
        entry = RouteEntry(
            network=network,
            interface_name=interface_name,
            next_hop=next_hop,
            metric=metric,
        )
        # Avoid duplicate exact matches
        self._routes = [r for r in self._routes if not (r.network == entry.network and r.interface_name == entry.interface_name)]
        self._routes.append(entry)
        return entry

    def remove_route(self, network: Union[AKIPNetwork, str]) -> bool:
        """Removes all routes matching the specified network prefix."""
        target_net = AKIPNetwork(network) if not isinstance(network, AKIPNetwork) else network
        initial_len = len(self._routes)
        self._routes = [r for r in self._routes if r.network != target_net]
        return len(self._routes) < initial_len

    def lookup(self, destination: Union[AKIPAddress, str]) -> Optional[RouteEntry]:
        """
        Performs Longest Prefix Match (LPM) lookup for a destination IP.

        Matches all prefixes that contain the destination, then sorts:
        1. Prefix length descending (most specific / longest prefix wins)
        2. Metric ascending (lower cost wins ties)
        """
        dst_addr = AKIPAddress(destination) if not isinstance(destination, AKIPAddress) else destination

        matching_routes = [r for r in self._routes if r.network.contains(dst_addr)]
        if not matching_routes:
            return None

        # Sort by prefix_len descending, then metric ascending
        matching_routes.sort(key=lambda r: (-r.prefix_len, r.metric))
        return matching_routes[0]

    def all_routes(self) -> List[RouteEntry]:
        """Returns all routes sorted by prefix length descending."""
        return sorted(self._routes, key=lambda r: (-r.prefix_len, r.metric))

    def clear(self) -> None:
        self._routes.clear()

    def __len__(self) -> int:
        return len(self._routes)

    def __repr__(self) -> str:
        return f"<RoutingTable {len(self._routes)} routes>"
