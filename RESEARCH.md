# AKIP Protocol: Networking Research Questions & Theoretical Analysis

This document provides a comparative analysis of AKIP (Akhil's Custom Internet Protocol) against industry-standard network protocols (IPv4 and IPv6), examines protocol design tradeoffs, and explores research directions.

---

## 1. Architectural Comparison: AKIP vs. IPv4 vs. IPv6

| Design Attribute | AKIP v1.0 | IPv4 (RFC 791) | IPv6 (RFC 8200) |
|---|---|---|---|
| **Header Size** | Fixed 20 bytes (160 bits) | 20 bytes minimum (up to 60 with options) | Fixed 40 bytes (320 bits) |
| **Address Length** | 32 bits (4 bytes) | 32 bits (4 bytes) | 128 bits (16 bytes) |
| **Address Space** | $2^{32} \approx 4.29 \times 10^9$ | $2^{32} \approx 4.29 \times 10^9$ | $2^{128} \approx 3.4 \times 10^{38}$ |
| **Protocol Discriminator** | Explicit 2-byte Magic (`b"AK"`) | None (EtherType `0x0800` at L2) | None (EtherType `0x86DD` at L2) |
| **Header Checksum** | Yes (RFC 1071 over header + payload) | Yes (RFC 1071 over header only) | None (Eliminated entirely) |
| **Intermediate Fragmentation** | Flags provided (DF, MF) | Yes (Routers fragment unless DF=1) | No (Only source hosts fragment) |
| **Loop Prevention** | Hop Limit (1 byte) | Time to Live (TTL, 1 byte) | Hop Limit (1 byte) |
| **Options Handling** | Fixed header (Flags bitmask) | Variable-length options (requires IHL) | Next Header Daisy-Chaining (Extension Headers)|

---

## 2. Research Questions & Design Tradeoffs

### Q1: Why did IPv4 include a checksum, while IPv6 eliminated it? Where does AKIP stand?
- **The IPv4 Historical Context (1981):** Early physical links (copper telephone lines, serial cables) had high bit error rates. Furthermore, early transport protocols were not universally trusted to verify data integrity. Therefore, IPv4 computed a checksum over the IP header at every hop. Because the TTL decremented at each router, the checksum had to be updated incrementally at every intermediate router.
- **The IPv6 Modern Perspective (1998–Present):** By the late 1990s, Layer 2 technologies (Ethernet CRC-32, Wi-Fi 802.11 FCS, optical fiber) already provided robust frame-level error detection with hardware acceleration. At Layer 4, TCP and UDP (with IPv6 pseudo-header) compute end-to-end checksums. Verifying and recomputing an L3 checksum at line rate (100 Gbps+) on multi-core routers creates unnecessary CPU memory-bus overhead. Consequently, IPv6 **eliminated the L3 checksum entirely**.
- **AKIP's Research Choice:** AKIP computes an RFC 1071 checksum over the entire datagram. In an educational simulator, this allows researchers to observe how bit flips in the network affect routers and end-hosts, and provides a clear model for end-to-end error detection.

---

### Q2: How should MTU fragmentation be handled?
When a packet of 1500 bytes arrives at a WAN transit link with an MTU of 576 bytes, two architectural strategies exist:

1. **Router-Assisted In-Flight Fragmentation (IPv4):**
   - The intermediate router cuts the payload into fragments, copies the header, sets the `More Fragments (MF)` flag and fragment offset, and forwards each fragment independently.
   - *Drawback:* Router memory and CPU exhaustion; if a single fragment is lost, the entire original datagram must be retransmitted by Layer 4. Reassembly at high speeds is fragile and vulnerable to attacks (e.g., *Teardrop* overlapping offset attack).
2. **End-to-End Path MTU Discovery (PMTUD) (IPv6 & Modern IPv4):**
   - Routers **never fragment** in transit. If a packet exceeds the link MTU, the router drops it and sends an ICMP `Packet Too Big` message containing the next-hop MTU.
   - The sending host caches the bottleneck MTU and reduces its transmission size.
- **AKIP Recommendation:** AKIP currently models the clean IPv6 approach: links reject oversized frames with `MtuExceededError`. A future extension could send an `ERROR_REPORT` packet (Protocol 5) containing the bottleneck MTU back to the sender.

---

### Q3: What security vulnerabilities exist in basic network-layer protocols like AKIP?

1. **IP Address Spoofing:**
   - In AKIP, the source address is simply an unauthenticated 32-bit field in the header. Any host can write an arbitrary IP into `src`.
   - *Mitigation:* Implement **BCP 38 (Ingress Filtering)** at Router 1: if a packet arrives on `r1-eth0` with a source IP that does not belong to `10.1.0.0/24`, the router immediately discards it (Reverse Path Forwarding check / uRPF).
2. **Replay & Sequence Attacks:**
   - AKIP datagrams contain a `Packet ID`, but no cryptographic authentication (e.g., HMAC or digital signature). An adversary could capture a valid packet and retransmit it repeatedly.
   - *Mitigation:* Layer 3 security protocols like **IPsec (AH / ESP)** encapsulate the packet with sequence numbers and cryptographic message authentication codes.
3. **Hop-Limit (TTL) Side-Channel Probing:**
   - An attacker can map network topology by transmitting packets with incrementally increasing hop limits ($TTL=1, 2, 3 \dots$) and recording which router responds with an expiration message (the foundation of the `traceroute` utility).

---

### Q4: How could AKIP be upgraded from a Python simulation to a real operating system network interface?

To run AKIP on real physical or virtual network devices without replacing the OS kernel:
1. **TUN/TAP Virtual Network Devices:**
   - On Linux (`/dev/net/tun`) or Windows (OpenVPN `tap-windows` driver), a user-space program can create a virtual Layer 3 (TUN) or Layer 2 (TAP) interface.
   - When the OS kernel or an application routes packets to the `tun0` interface, the raw bytes are delivered to a file descriptor readable by Python (`os.read(tun_fd, 1500)`).
   - AKIP could read and write packets to real network interfaces in user-space without kernel modifications!
2. **Raw Sockets (`SOCK_RAW`):**
   - With administrator privileges, Python can bind `socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)` to construct raw IP headers directly.
3. **eBPF / XDP (Extended Berkeley Packet Filter / eXpress Data Path):**
   - In Linux kernels, high-performance network research compiles C code into kernel bytecode attached directly to the network interface card (NIC) driver. eBPF can parse custom headers like AKIP at the hardware/driver level at millions of packets per second.
