from dataclasses import dataclass
import re

from .models import network

GROUP = "RDPGuard.Managed"
PREFIX = "RDPGuard.v1."
OWNER = "RDP Guard managed rule; schema=1"
NAME = re.compile(r"^RDPGuard\.v1\.(TCP|UDP)\.[0-9]{4}$")


@dataclass(frozen=True)
class Rule:
    name: str
    protocol: int
    port: int
    addresses: tuple[str, ...]
    group: str = GROUP
    description: str = OWNER
    direction: int = 1
    action: int = 0
    profiles: int = 2147483647
    enabled: bool = True


def owned(rule: Rule) -> bool:
    return rule.group == GROUP and bool(NAME.fullmatch(rule.name)) and rule.description == OWNER


def plan_rules(addresses: list[str], port: int, batch_size: int = 200) -> list[Rule]:
    if type(port) is not int or not 1 <= port <= 65535 or not 1 <= batch_size <= 200:
        raise ValueError("Invalid firewall parameters")
    normalized = sorted({network(value, blocking=True) for value in addresses})
    if len(normalized) > 4000:
        raise ValueError("Firewall entry capacity exceeded")
    result = []
    for index, offset in enumerate(range(0, len(normalized), batch_size)):
        batch = tuple(normalized[offset:offset + batch_size])
        for protocol, name in ((6, "TCP"), (17, "UDP")):
            result.append(Rule(f"{PREFIX}{name}.{index:04d}", protocol, port, batch))
    return result


class FirewallEngine:
    def __init__(self, backend):
        self.backend = backend

    def clear(self):
        for rule in self.backend.list_rules():
            if owned(rule):
                self.backend.remove(rule.name)
        if any(owned(rule) for rule in self.backend.list_rules()):
            raise RuntimeError("Managed firewall rules remain after removal")

    def reconcile(self, addresses, port, batch_size=200):
        desired = {r.name: r for r in plan_rules(addresses, port, batch_size)}
        current = {r.name: r for r in self.backend.list_rules()}
        for name in desired:
            if name in current and not owned(current[name]):
                raise RuntimeError(f"Refusing to overwrite a foreign rule: {name}")
        # Remove changed rules first, then add fully scoped disabled rules and enable last.
        # A failure can reduce protection; it must never broaden a block.
        for name, rule in current.items():
            if owned(rule) and desired.get(name) != rule:
                self.backend.remove(name)
        for name, rule in desired.items():
            if current.get(name) != rule:
                self.backend.add(rule)
        actual = {r.name: r for r in self.backend.list_rules() if owned(r)}
        if actual != desired:
            raise RuntimeError("Firewall read-back does not match the requested rule set")


class MemoryFirewall:
    """Explicit test backend. Never selected by the Windows service."""
    def __init__(self):
        self.rules = {}
        self.changes = 0

    def list_rules(self):
        return list(self.rules.values())

    def add(self, rule):
        self.rules[rule.name] = rule
        self.changes += 1

    def remove(self, name):
        self.rules.pop(name, None)
        self.changes += 1
