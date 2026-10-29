"""
AKIP Protocol Interactive Demonstration and Research Simulation.

Executes a live walkthrough of packet serialization, multi-hop forwarding across
a three-node, two-router topology, and handles intentional network faults.
"""

import binascii
import sys
from akip.address import AKIPAddress
from akip.packet import AKIPPacket, PacketProtocol, HEADER_LENGTH
from akip.topology import create_reference_topology


def print_banner(title: str):
    print("\n" + "=" * 78)
    print(f" {title.upper()}")
    print("=" * 78)


def print_subbanner(title: str):
    print(f"\n--- [ {title} ] ---")


def demo_packet_wire_format():
    print_banner("1. AKIP Binary Packet Format & Bit-Level Serialization")
    src = "10.1.0.10"
    dst = "10.3.0.10"
    payload = b"Research-Grade AKIP Network Payload"

    pkt = AKIPPacket(
        src=src,
        dst=dst,
        payload=payload,
        packet_id=101,
        protocol=PacketProtocol.DATA,
        hop_limit=64,
    )
    raw = pkt.encode()

    print(f"Source IP:         {pkt.src} (0x{pkt.src.as_int:08X})")
    print(f"Destination IP:    {pkt.dst} (0x{pkt.dst.as_int:08X})")
    print(f"Packet ID:         {pkt.packet_id}")
    print(f"Protocol:          {pkt.protocol.name} (Value: {int(pkt.protocol)})")
    print(f"Hop Limit (TTL):   {pkt.hop_limit}")
    print(f"Payload Length:    {pkt.payload_length} bytes")
    print(f"Checksum (RFC1071):0x{pkt.checksum:04X}")
    print(f"Total Wire Size:   {len(raw)} bytes (20b Header + {len(payload)}b Payload)")

    print("\nRaw Hex Wire Dump (20-byte Header in Big-Endian):")
    hdr_hex = binascii.hexlify(raw[:HEADER_LENGTH]).decode("ascii")
    formatted_hdr = " ".join(hdr_hex[i:i+4] for i in range(0, len(hdr_hex), 4))
    print(f"  Header Bytes:  {formatted_hdr}")
    payload_hex = binascii.hexlify(raw[HEADER_LENGTH:]).decode("ascii")
    print(f"  Payload Bytes: {payload_hex}")


def demo_topology_setup(topo):
    print_banner("2. Reference Network Topology Setup")
    print("""
    [Node-A] (10.1.0.10) --+
                           +-- [Subnet 1 Link] -- (r1-eth0: 10.1.0.1) [Router 1] (r1-eth1: 10.2.0.1)
    [Node-B] (10.1.0.20) --+                                                |
                                                                   [Transit Link: 10.2.0.0/30]
                                                                            |
                                          [Node-C] (10.3.0.10) -- [Subnet 3 Link] -- (r2-eth1: 10.3.0.1) [Router 2] (r2-eth0: 10.2.0.2)
    """)

    print("Router 1 Forwarding Information Base (FIB):")
    for r in topo.router_1.routing_table.all_routes():
        print(f"  {r}")

    print("\nRouter 2 Forwarding Information Base (FIB):")
    for r in topo.router_2.routing_table.all_routes():
        print(f"  {r}")


def demo_intra_subnet(topo):
    print_banner("3. Intra-Subnet Communication (Node A -> Node B)")
    msg = b"Local LAN Greeting: Node A to Node B"
    print(f"Node A ({topo.node_a.address}) transmitting to Node B ({topo.node_b.address}) on Subnet 1...")
    topo.node_a.send(dst=topo.node_b.address, payload=msg)

    rx = topo.node_b.get_latest_received_packet()
    if rx:
        print(f"SUCCESS: Node B received packet ID {rx.packet_id}!")
        print(f"  Payload:          '{rx.payload.decode()}'")
        print(f"  Hop Limit:        {rx.hop_limit} (Untouched by routers)")
    else:
        print("FAILURE: Packet was not received by Node B.")


def demo_multihop_forwarding(topo):
    print_banner("4. Multi-Hop Inter-Network Forwarding (Node A -> Router 1 -> Router 2 -> Node C)")
    msg = b"Inter-network telemetry data payload"
    print(f"Node A ({topo.node_a.address}) sending to remote host Node C ({topo.node_c.address})...")
    topo.node_a.send(dst=topo.node_c.address, payload=msg, hop_limit=64)

    rx = topo.node_c.get_latest_received_packet()
    if rx:
        print(f"SUCCESS: Node C received packet ID {rx.packet_id}!")
        print(f"  Payload:          '{rx.payload.decode()}'")
        print(f"  Hop Limit:        {rx.hop_limit} (Decremented twice: 64 -> R1: 63 -> R2: 62)")
    else:
        print("FAILURE: Packet was not received by Node C.")

    print("\nForwarding Audit Log on Router 1:")
    for ev in topo.router_1.event_log[-2:]:
        print(f"  [{ev.action}] Pkt {ev.packet_id}: {ev.src_ip} -> {ev.dst_ip} via {ev.egress_interface} (Detail: {ev.detail})")

    print("\nForwarding Audit Log on Router 2:")
    for ev in topo.router_2.event_log[-2:]:
        print(f"  [{ev.action}] Pkt {ev.packet_id}: {ev.src_ip} -> {ev.dst_ip} via {ev.egress_interface} (Detail: {ev.detail})")


def demo_ping_roundtrip(topo):
    print_banner("5. Diagnostic Ping Roundtrip (Echo Request & Echo Reply)")
    topo.reset_all_statistics()
    print(f"Node A ({topo.node_a.address}) initiating PING to Node C ({topo.node_c.address})...")
    topo.node_a.ping(dst=topo.node_c.address, payload=b"ROUND_TRIP_PING_DATA")

    rx_c = topo.node_c.get_latest_received_packet()
    rx_a = topo.node_a.get_latest_received_packet()

    if rx_c and rx_c.protocol == PacketProtocol.ECHO_REQUEST:
        print(f"1. Node C received ECHO_REQUEST from {rx_c.src} (Hops remaining: {rx_c.hop_limit})")
    if rx_a and rx_a.protocol == PacketProtocol.ECHO_REPLY:
        print(f"2. Node A received ECHO_REPLY from {rx_a.src} (Hops remaining: {rx_a.hop_limit})")
        print("SUCCESS: 2-way multi-hop ping cycle fully established and verified!")


def demo_fault_scenarios(topo):
    print_banner("6. Network Fault & Error Handling Scenarios")

    # Fault 1: Checksum error (bit corruption in transit)
    print_subbanner("Scenario A: Checksum Failure (Bit-level In-Transit Corruption)")
    topo.reset_all_statistics()
    topo.link_sub1.trigger_corruption_on_next_packet()
    print("Node A transmitting packet across Subnet 1 with forced link corruption...")
    topo.node_a.send(dst=topo.node_c.address, payload=b"Sensitive Data to Corrupt")

    print(f"Router 1 dropped packets due to checksum: {topo.router_1.stats.packets_dropped_checksum}")
    print(f"Node C received packets:                   {len(topo.node_c.received_packets)}")
    if topo.router_1.stats.packets_dropped_checksum > 0:
        print("RESULT: Checksum failure successfully trapped and dropped at ingress interface!")

    # Fault 2: Hop Limit Expiry
    print_subbanner("Scenario B: Hop Limit Expiry (TTL Expired in Transit)")
    topo.reset_all_statistics()
    print("Node A sending packet to Node C with Hop Limit = 1 (insufficient to cross Router 1)...")
    topo.node_a.send(dst=topo.node_c.address, payload=b"Will die at R1", hop_limit=1)

    print(f"Router 1 dropped packets due to hop limit: {topo.router_1.stats.packets_dropped_hop_limit}")
    print(f"Node C received packets:                   {len(topo.node_c.received_packets)}")
    ev = topo.router_1.event_log[-1]
    print(f"Router 1 Audit: [{ev.action}] {ev.detail}")

    # Fault 3: Unknown Destination (No Route)
    print_subbanner("Scenario C: Unknown Destination (FIB Route Miss)")
    topo.reset_all_statistics()
    unroutable = "192.168.99.1"
    print(f"Node A transmitting to unroutable destination {unroutable}...")
    topo.node_a.send(dst=unroutable, payload=b"Destination Unknown")

    print(f"Router 1 dropped packets due to no route:  {topo.router_1.stats.packets_dropped_no_route}")
    ev = topo.router_1.event_log[-1]
    print(f"Router 1 Audit: [{ev.action}] {ev.detail}")


def demo_telemetry_summary(topo):
    print_banner("7. Global Network Telemetry & Statistics Summary")
    print(f"{'Entity':<15} | {'Sent/Rx':<12} | {'Forwarded':<12} | {'Dropped/Errors':<16}")
    print("-" * 65)

    for r_name, router in topo.routers.items():
        st = router.stats
        total_drops = (
            st.packets_dropped_checksum
            + st.packets_dropped_hop_limit
            + st.packets_dropped_no_route
            + st.packets_dropped_malformed
            + st.packets_dropped_mtu
        )
        print(f"{router.name:<15} | Rx: {st.packets_received:<8} | Fwd: {st.packets_forwarded:<8} | Drops: {total_drops:<10}")

    for l_name, link in topo.links.items():
        st = link.stats
        drops = st.packets_dropped_loss + st.packets_dropped_mtu
        print(f"{link.name:<15} | Sent: {st.packets_sent:<6} | Deliv: {st.packets_delivered:<6} | Drops: {drops:<10}")

    print("=" * 78)


def main():
    print("\n==============================================================================")
    print("   AKIP: AKHIL'S CUSTOM INTERNET PROTOCOL SIMULATOR (EDUCATIONAL PROTOTYPE)")
    print("==============================================================================")
    topo = create_reference_topology()

    demo_packet_wire_format()
    demo_topology_setup(topo)
    demo_intra_subnet(topo)
    demo_multihop_forwarding(topo)
    demo_ping_roundtrip(topo)
    demo_fault_scenarios(topo)
    demo_telemetry_summary(topo)


if __name__ == "__main__":
    main()
