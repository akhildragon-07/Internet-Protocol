"""
AKIP Reference Topology Builder Module.

Constructs a standard three-node, two-router educational internetwork:
[Node A] --+
           +-- [Link 1] -- (r1-eth0) [Router 1] (r1-eth1) -- [Transit Link] -- (r2-eth0) [Router 2] (r2-eth1) -- [Link 3] -- [Node C]
[Node B] --+
"""

from dataclasses import dataclass
from typing import Dict
from akip.address import AKIPAddress, AKIPNetwork
from akip.link import SimulatedLink
from akip.router import Router
from akip.node import Node


@dataclass
class NetworkTopology:
    """
    Encapsulates the nodes, routers, and links of the AKIP educational prototype network.
    """
    node_a: Node
    node_b: Node
    node_c: Node
    router_1: Router
    router_2: Router
    link_sub1: SimulatedLink
    link_transit: SimulatedLink
    link_sub3: SimulatedLink

    @property
    def nodes(self) -> Dict[str, Node]:
        return {
            "node_a": self.node_a,
            "node_b": self.node_b,
            "node_c": self.node_c,
        }

    @property
    def routers(self) -> Dict[str, Router]:
        return {
            "router_1": self.router_1,
            "router_2": self.router_2,
        }

    @property
    def links(self) -> Dict[str, SimulatedLink]:
        return {
            "link_sub1": self.link_sub1,
            "link_transit": self.link_transit,
            "link_sub3": self.link_sub3,
        }

    def reset_all_statistics(self) -> None:
        """Resets all metrics and packet buffers across all network elements."""
        for node in self.nodes.values():
            node.clear_buffers()
        for router in self.routers.values():
            router.stats = type(router.stats)()
            router.event_log.clear()
        for link in self.links.values():
            link.reset_stats()


def create_reference_topology(
    link_mtu: int = 1500,
    transit_loss_rate: float = 0.0,
) -> NetworkTopology:
    """
    Builds and wires up the three-node, two-router AKIP network topology.

    Addressing Plan:
    - Subnet 1 (10.1.0.0/24):
        Node A:     10.1.0.10/24 (Default Gateway: 10.1.0.1)
        Node B:     10.1.0.20/24 (Default Gateway: 10.1.0.1)
        R1 (eth0):  10.1.0.1/24
    - Transit Subnet 2 (10.2.0.0/30):
        R1 (eth1):  10.2.0.1/30
        R2 (eth0):  10.2.0.2/30
    - Subnet 3 (10.3.0.0/24):
        Node C:     10.3.0.10/24 (Default Gateway: 10.3.0.1)
        R2 (eth1):  10.3.0.1/24
    """

    # 1. Create Simulated Links
    link_sub1 = SimulatedLink("Subnet-1-LAN", mtu=link_mtu)
    link_transit = SimulatedLink("Transit-WAN", mtu=link_mtu, loss_rate=transit_loss_rate)
    link_sub3 = SimulatedLink("Subnet-3-LAN", mtu=link_mtu)

    # 2. Instantiate Routers
    router_1 = Router("Router-1")
    router_2 = Router("Router-2")

    # 3. Configure Router 1 Interfaces
    r1_eth0 = router_1.add_interface(
        name="r1-eth0",
        address="10.1.0.1",
        network="10.1.0.0/24",
        link=link_sub1,
    )
    r1_eth1 = router_1.add_interface(
        name="r1-eth1",
        address="10.2.0.1",
        network="10.2.0.0/30",
        link=link_transit,
    )

    # 4. Configure Router 2 Interfaces
    r2_eth0 = router_2.add_interface(
        name="r2-eth0",
        address="10.2.0.2",
        network="10.2.0.0/30",
        link=link_transit,
    )
    r2_eth1 = router_2.add_interface(
        name="r2-eth1",
        address="10.3.0.1",
        network="10.3.0.0/24",
        link=link_sub3,
    )

    # 5. Add Static Inter-network Routes
    # Router 1 routes to Subnet 3 via Router 2 (10.2.0.2) on r1-eth1
    router_1.add_static_route(
        network="10.3.0.0/24",
        interface_name="r1-eth1",
        next_hop="10.2.0.2",
        metric=1,
    )

    # Router 2 routes to Subnet 1 via Router 1 (10.2.0.1) on r2-eth0
    router_2.add_static_route(
        network="10.1.0.0/24",
        interface_name="r2-eth0",
        next_hop="10.2.0.1",
        metric=1,
    )

    # 6. Instantiate Host Nodes
    node_a = Node(
        name="Node-A",
        address="10.1.0.10",
        network="10.1.0.0/24",
        default_gateway="10.1.0.1",
        link=link_sub1,
    )
    node_b = Node(
        name="Node-B",
        address="10.1.0.20",
        network="10.1.0.0/24",
        default_gateway="10.1.0.1",
        link=link_sub1,
    )
    node_c = Node(
        name="Node-C",
        address="10.3.0.10",
        network="10.3.0.0/24",
        default_gateway="10.3.0.1",
        link=link_sub3,
    )

    return NetworkTopology(
        node_a=node_a,
        node_b=node_b,
        node_c=node_c,
        router_1=router_1,
        router_2=router_2,
        link_sub1=link_sub1,
        link_transit=link_transit,
        link_sub3=link_sub3,
    )
