from dataclasses import asdict, dataclass
import ipaddress


def address(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IP address without a scope identifier")
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) == "255.255.255.255":
        raise ValueError("Loopback, unspecified, multicast and broadcast addresses are protected")
    return str(ip)


def network(value: str, *, blocking: bool = False) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IP or CIDR")
    if "/" not in value:
        value = address(value)
    net = ipaddress.ip_network(value.strip(), strict=True)
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped:
        if net.prefixlen < 96:
            raise ValueError("Invalid IPv4-mapped network")
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    # Never accept an all-address rule or any network covering protected addresses.
    protected = ["0.0.0.0/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"]
    if net.version == 6:
        protected = ["::/128", "::1/128", "ff00::/8", "::ffff:0:0/96"]
    if net.prefixlen == 0 or any(net.overlaps(ipaddress.ip_network(p)) for p in protected):
        raise ValueError("Network includes protected addresses")
    # Manual subnet bans must remain narrow and explicit; no automatic widening.
    if blocking and net.prefixlen < (24 if net.version == 4 else 64):
        raise ValueError("Manual blocks must be /24 (IPv4), /64 (IPv6), or narrower")
    return str(net)


def overlaps(left: str, right: str) -> bool:
    a, b = ipaddress.ip_network(left), ipaddress.ip_network(right)
    return a.version == b.version and a.overlaps(b)


def contains(net: str, ip: str) -> bool:
    a, b = ipaddress.ip_network(net), ipaddress.ip_address(ip)
    return a.version == b.version and b in a


@dataclass(frozen=True)
class Settings:
    threshold: int = 10
    window_seconds: int = 300
    ban_seconds: tuple[int, ...] = (3600, 86400, 604800)
    include_network_auth: bool = False
    rdp_port: int = 33345
    max_blocks_per_minute: int = 20
    max_block_entries: int = 4000
    batch_size: int = 200
    firewall_interval_seconds: int = 2
    retention_days: int = 30
    rollback_seconds: int = 180

    @classmethod
    def load(cls, values: dict):
        if not isinstance(values, dict) or set(values) - set(cls.__dataclass_fields__):
            raise ValueError("Unknown settings")
        data = asdict(cls()) | values
        bounds = {
            "threshold": (2, 10000), "window_seconds": (10, 3600), "rdp_port": (1, 65535),
            "max_blocks_per_minute": (1, 100), "max_block_entries": (1, 4000),
            "batch_size": (1, 200), "firewall_interval_seconds": (1, 5),
            "retention_days": (1, 365), "rollback_seconds": (120, 600),
        }
        for key, (low, high) in bounds.items():
            if type(data[key]) is not int or not low <= data[key] <= high:
                raise ValueError(f"{key} must be an integer between {low} and {high}")
        if type(data["include_network_auth"]) is not bool:
            raise ValueError("include_network_auth must be boolean")
        if data["max_block_entries"] > data["batch_size"] * 20:
            raise ValueError("max_block_entries/batch_size must fit within 20 batches (40 TCP/UDP rules)")
        bans = data["ban_seconds"]
        if not isinstance(bans, (list, tuple)) or not 1 <= len(bans) <= 10:
            raise ValueError("ban_seconds must contain 1 to 10 durations")
        if any(type(v) is not int or not 60 <= v <= 2592000 for v in bans):
            raise ValueError("Ban durations must be 60 seconds to 30 days")
        if list(bans) != sorted(bans):
            raise ValueError("Ban durations must be non-decreasing")
        data["ban_seconds"] = tuple(bans)
        return cls(**data)


@dataclass(frozen=True)
class AuthEvent:
    key: str
    channel: str
    record_id: int
    timestamp: float
    event_id: int
    ip: str | None
    username: str
    domain: str
    logon_type: int | None
    auth_package: str
    logon_process: str
    status: str
    substatus: str
    source_port: int | None
    category: str
    confidence: str
    reason: str
