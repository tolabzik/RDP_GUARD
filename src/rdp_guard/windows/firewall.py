import ipaddress

from ..firewall import Rule, owned
from .platform import com


def canonical(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return value.strip()


class WindowsFirewall:
    def list_rules(self):
        with com():
            return self._list_rules()

    def _list_rules(self):
        import win32com.client
        policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        result = []
        for rule in policy.Rules:
            # Non-TCP/UDP rules may reject querying LocalPorts. Preserve ownership metadata anyway.
            ports = rule.LocalPorts if rule.Protocol in (6, 17) else ""
            result.append(Rule(
                name=rule.Name, protocol=rule.Protocol, port=int(ports) if ports.isdigit() else 0,
                addresses=tuple(sorted(canonical(a) for a in rule.RemoteAddresses.split(","))),
                group=rule.Grouping or "", description=rule.Description or "", direction=rule.Direction,
                action=rule.Action, profiles=rule.Profiles, enabled=bool(rule.Enabled),
                local_addresses=rule.LocalAddresses or "*",
                remote_ports=(rule.RemotePorts or "*") if rule.Protocol in (6, 17) else "*",
                application=rule.ApplicationName or "", service=rule.ServiceName or "",
                interface_types=rule.InterfaceTypes, restricted_interfaces=bool(rule.Interfaces),
                edge_traversal=bool(rule.EdgeTraversal)))
        return result

    def add(self, spec):
        with com():
            self._add(spec)

    def _add(self, spec):
        import win32com.client
        from ..firewall import plan_rules
        if not owned(spec) or not spec.addresses:
            raise ValueError("Refusing an unowned or empty rule")
        # Defense in depth if called independently of FirewallEngine.
        validated = plan_rules(list(spec.addresses), spec.port)
        if not validated or spec.protocol not in (6, 17) or spec.direction != 1 or spec.action != 0:
            raise ValueError("Unsafe rule scope")
        rule = win32com.client.Dispatch("HNetCfg.FWRule")
        rule.Enabled = False
        rule.Name, rule.Description, rule.Grouping = spec.name, spec.description, spec.group
        rule.Protocol = spec.protocol
        rule.LocalPorts = str(spec.port)
        rule.RemoteAddresses = ",".join(spec.addresses)
        rule.LocalAddresses = "*"
        rule.RemotePorts = "*"
        rule.Direction, rule.Action, rule.Profiles = 1, 0, 2147483647
        rule.InterfaceTypes = "All"
        rule.EdgeTraversal = False
        # Only fully scoped rules are ever added to the policy.
        rule.Enabled = True
        win32com.client.Dispatch("HNetCfg.FwPolicy2").Rules.Add(rule)

    def remove(self, name):
        with com():
            self._remove(name)

    def _remove(self, name):
        import win32com.client
        policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        candidates = [rule for rule in self._list_rules() if rule.name == name]
        if not candidates or not all(owned(rule) for rule in candidates):
            raise ValueError("Refusing to remove a foreign or ambiguous firewall rule")
        policy.Rules.Remove(name)
