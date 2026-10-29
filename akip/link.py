"""
Simulated Network Link Module.

Provides physical/data-link layer abstraction connecting simulated network interfaces.
Supports configurable MTU, simulated loss, latency, bit-error corruption injection,
and comprehensive link telemetry statistics.
"""

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple, Any
import random


class LinkError(Exception):
    """Base exception for link-layer errors."""
    pass


class MtuExceededError(LinkError):
    """Raised when a transmitted frame exceeds the link's Maximum Transmission Unit (MTU)."""
    pass


@dataclass
class LinkStatistics:
    """Telemetry counters for a simulated network link."""
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_delivered: int = 0
    packets_dropped_mtu: int = 0
    packets_dropped_loss: int = 0
    packets_corrupted: int = 0

    def to_dict(self) -> dict:
        return {
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "packets_delivered": self.packets_delivered,
            "packets_dropped_mtu": self.packets_dropped_mtu,
            "packets_dropped_loss": self.packets_dropped_loss,
            "packets_corrupted": self.packets_corrupted,
        }


class SimulatedLink:
    """
    Simulates a bidirectional physical/data-link channel connecting network interfaces.

    Features:
    - MTU enforcement
    - Probabilistic packet loss injection (loss_rate)
    - Deliberate byte corruption injection (corrupt_next_packet) for checksum testing
    - Telemetry tracking (sent, delivered, dropped, corrupted)
    """

    def __init__(
        self,
        name: str,
        mtu: int = 1500,
        loss_rate: float = 0.0,
        latency_ms: float = 0.0,
        seed: Optional[int] = None,
    ):
        self.name = name
        self.mtu = mtu
        self.loss_rate = loss_rate
        self.latency_ms = latency_ms
        self.stats = LinkStatistics()
        self._endpoints: List[Any] = []  # Interfaces attached to this link
        self._corrupt_next: bool = False
        self._drop_next: bool = False
        self._rng = random.Random(seed)

    def attach_interface(self, interface: Any) -> None:
        """Attaches a network interface to this link."""
        if interface not in self._endpoints:
            self._endpoints.append(interface)

    def detach_interface(self, interface: Any) -> None:
        """Detaches a network interface from this link."""
        if interface in self._endpoints:
            self._endpoints.remove(interface)

    def trigger_corruption_on_next_packet(self) -> None:
        """Force deliberate bit/byte corruption on the very next packet sent across this link."""
        self._corrupt_next = True

    def trigger_drop_on_next_packet(self) -> None:
        """Force dropping the very next packet transmitted on this link."""
        self._drop_next = True

    def transmit(self, sender_interface: Any, raw_data: bytes) -> bool:
        """
        Transmits raw binary frame from sender_interface to all other attached interfaces.
        Returns True if delivered to at least one receiver, False if dropped.
        """
        self.stats.packets_sent += 1
        self.stats.bytes_sent += len(raw_data)

        # 1. MTU Check
        if len(raw_data) > self.mtu:
            self.stats.packets_dropped_mtu += 1
            raise MtuExceededError(
                f"Link '{self.name}' MTU exceeded: packet size {len(raw_data)} bytes > MTU {self.mtu}"
            )

        # 2. Forced Drop or Random Loss Check
        if self._drop_next:
            self._drop_next = False
            self.stats.packets_dropped_loss += 1
            return False

        if self.loss_rate > 0.0 and self._rng.random() < self.loss_rate:
            self.stats.packets_dropped_loss += 1
            return False

        # 3. Forced Corruption Check (for testing receiver checksum verification)
        data_to_deliver = raw_data
        if self._corrupt_next:
            self._corrupt_next = False
            self.stats.packets_corrupted += 1
            # Flip bits in the middle of the frame
            buf = bytearray(raw_data)
            corrupt_idx = len(buf) // 2
            buf[corrupt_idx] ^= 0xFF
            data_to_deliver = bytes(buf)

        # 4. Delivery to other attached interfaces
        delivered = False
        for endpoint in self._endpoints:
            if endpoint is not sender_interface:
                endpoint.receive_from_link(data_to_deliver)
                delivered = True

        if delivered:
            self.stats.packets_delivered += 1

        return delivered

    def reset_stats(self) -> None:
        """Resets all telemetry counters."""
        self.stats = LinkStatistics()

    def __repr__(self) -> str:
        return f"<SimulatedLink '{self.name}' mtu={self.mtu} endpoints={len(self._endpoints)}>"
