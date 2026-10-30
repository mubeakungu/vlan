"""Helpers shared by the service modules."""
from __future__ import annotations

import ipaddress


def manual(plugin, title: str, steps: list[str]) -> list[str]:
    """Fallback for vendors without generated config: numbered steps as comments."""
    out = [plugin.note(f"{title}: no automatic config for {plugin.title}; do these steps by hand:")]
    out += [plugin.note(f"  {n}. {s}") for n, s in enumerate(steps, 1)]
    return out


def net_of(addr: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_interface(addr).network if "/" in addr else ipaddress.ip_network(addr)


def mask(addr: str) -> str:
    return str(net_of(addr).netmask)


def wildcard(addr: str) -> str:
    return str(net_of(addr).hostmask)


def ip_only(addr: str) -> str:
    return str(ipaddress.ip_interface(addr).ip)


def vlan_for_ip(plugin, ip: str):
    """Routed VLAN on this device whose subnet contains ip."""
    a = ipaddress.ip_address(ip.split("/")[0])
    for v in plugin.routed:
        if a in v.interface.network:
            return v
    return None


def mt_once(find: str, cmd: str) -> str:
    """RouterOS: run cmd only if find matches nothing (safe to paste twice)."""
    return f":if ([:len [{find}]] = 0) do={{ {cmd} }}"


def as_list(value) -> list:
    if value in (None, "", False):
        return []
    return value if isinstance(value, list) else [value]
