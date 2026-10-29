"""
AKIP Address and Subnet Module.

Implements custom 32-bit network-layer addressing for the AKIP protocol.
Provides dotted-decimal notation parsing, binary serialization, and
CIDR subnet prefix matching.
"""

from typing import Union


class InvalidAddressError(ValueError):
    """Raised when an address string or byte sequence cannot be parsed as a valid AKIP address."""
    pass


class AKIPAddress:
    """
    Represents an AKIP 32-bit Internet Protocol Address.

    Internal representation is an unsigned 32-bit integer (0 to 4,294,967,295).
    Can be serialized to and from 4-byte big-endian binary format or
    dotted-decimal string format (e.g., '10.1.0.1').
    """

    def __init__(self, value: Union[str, int, bytes, bytearray, "AKIPAddress"]):
        if isinstance(value, AKIPAddress):
            self._value = value._value
        elif isinstance(value, int):
            if not (0 <= value <= 0xFFFFFFFF):
                raise InvalidAddressError(f"Integer address out of range (0..4294967295): {value}")
            self._value = value
        elif isinstance(value, (bytes, bytearray)):
            if len(value) != 4:
                raise InvalidAddressError(f"Byte address must be exactly 4 bytes, got {len(value)}")
            self._value = int.from_bytes(value, byteorder="big", signed=False)
        elif isinstance(value, str):
            self._value = self._parse_dotted(value.strip())
        else:
            raise InvalidAddressError(f"Unsupported address type: {type(value)}")

    @staticmethod
    def _parse_dotted(addr_str: str) -> int:
        parts = addr_str.split(".")
        if len(parts) != 4:
            raise InvalidAddressError(f"Dotted-decimal address must contain 4 octets: '{addr_str}'")
        val = 0
        for part in parts:
            if not part.isdigit():
                raise InvalidAddressError(f"Non-digit character in octet '{part}' of '{addr_str}'")
            octet = int(part)
            if not (0 <= octet <= 255):
                raise InvalidAddressError(f"Octet value out of range (0..255): {octet} in '{addr_str}'")
            val = (val << 8) | octet
        return val

    @property
    def as_int(self) -> int:
        """Returns the address as an unsigned 32-bit integer."""
        return self._value

    def to_bytes(self) -> bytes:
        """Serializes the address to 4-byte big-endian binary format."""
        return self._value.to_bytes(4, byteorder="big", signed=False)

    @classmethod
    def from_bytes(cls, b: bytes) -> "AKIPAddress":
        """Instantiates an AKIPAddress from 4 big-endian bytes."""
        return cls(b)

    def is_loopback(self) -> bool:
        """Checks if address is in 127.0.0.0/8 loopback block."""
        return (self._value >> 24) == 127

    def is_broadcast(self) -> bool:
        """Checks if address is the limited broadcast address 255.255.255.255."""
        return self._value == 0xFFFFFFFF

    def __str__(self) -> str:
        b0 = (self._value >> 24) & 0xFF
        b1 = (self._value >> 16) & 0xFF
        b2 = (self._value >> 8) & 0xFF
        b3 = self._value & 0xFF
        return f"{b0}.{b1}.{b2}.{b3}"

    def __repr__(self) -> str:
        return f"AKIPAddress('{self.__str__()}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AKIPAddress):
            return self._value == other._value
        if isinstance(other, str):
            try:
                return self._value == AKIPAddress(other)._value
            except InvalidAddressError:
                return False
        return False

    def __hash__(self) -> int:
        return hash(self._value)

    def __lt__(self, other: "AKIPAddress") -> bool:
        if not isinstance(other, AKIPAddress):
            return NotImplemented
        return self._value < other._value


class AKIPNetwork:
    """
    Represents an AKIP Subnet / Prefix defined by CIDR notation (e.g., '10.1.0.0/24').
    """

    def __init__(self, cidr_str: str):
        if "/" not in cidr_str:
            raise InvalidAddressError(f"CIDR format requires '/' (e.g., '10.1.0.0/24'): '{cidr_str}'")
        addr_part, prefix_part = cidr_str.split("/", 1)
        if not prefix_part.isdigit():
            raise InvalidAddressError(f"Prefix length must be integer: '{prefix_part}'")
        prefix_len = int(prefix_part)
        if not (0 <= prefix_len <= 32):
            raise InvalidAddressError(f"Prefix length must be between 0 and 32: {prefix_len}")

        base_addr = AKIPAddress(addr_part.strip())
        self._prefix_len = prefix_len

        # Compute netmask
        if prefix_len == 0:
            self._mask = 0
        else:
            self._mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix_len)) - 1)

        self._network_addr = AKIPAddress(base_addr.as_int & self._mask)
        self._broadcast_addr = AKIPAddress(self._network_addr.as_int | (~self._mask & 0xFFFFFFFF))

    @property
    def prefix_len(self) -> int:
        """Returns the CIDR prefix length (e.g., 24)."""
        return self._prefix_len

    @property
    def netmask(self) -> AKIPAddress:
        """Returns the netmask as an AKIPAddress."""
        return AKIPAddress(self._mask)

    @property
    def network_address(self) -> AKIPAddress:
        """Returns the base network address."""
        return self._network_addr

    @property
    def broadcast_address(self) -> AKIPAddress:
        """Returns the broadcast address for the subnet."""
        return self._broadcast_addr

    def contains(self, address: Union[AKIPAddress, str]) -> bool:
        """Returns True if the given address falls within this subnet."""
        if not isinstance(address, AKIPAddress):
            address = AKIPAddress(address)
        return (address.as_int & self._mask) == self._network_addr.as_int

    def __contains__(self, address: Union[AKIPAddress, str]) -> bool:
        return self.contains(address)

    def __str__(self) -> str:
        return f"{self._network_addr}/{self._prefix_len}"

    def __repr__(self) -> str:
        return f"AKIPNetwork('{self.__str__()}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AKIPNetwork):
            return False
        return self._network_addr == other._network_addr and self._prefix_len == other._prefix_len

    def __hash__(self) -> int:
        return hash((self._network_addr, self._prefix_len))
