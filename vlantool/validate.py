"""Sanity checks run before any config is generated or pushed."""
from __future__ import annotations

import ipaddress
import re

from .model import Network
from .vendors import REGISTRY

_NAME_OK = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def validate(net: Network) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors block generation."""
    errors: list[str] = []
    warnings: list[str] = []

    names: dict[str, int] = {}
    networks: list[tuple[int, ipaddress._BaseNetwork]] = []
    for v in net.vlans.values():
        if not 1 <= v.id <= 4094:
            errors.append(f"VLAN {v.id}: id must be 1-4094")
        if v.id in (1002, 1003, 1004, 1005):
            warnings.append(f"VLAN {v.id}: reserved on Cisco switches")
        if not _NAME_OK.match(v.name):
            errors.append(f"VLAN {v.id}: name {v.name!r} must be 1-32 letters, digits, _ . - (no spaces)")
        if v.name in names:
            errors.append(f"VLAN {v.id}: name {v.name!r} already used by VLAN {names[v.name]}")
        names[v.name] = v.id
        if v.gateway:
            try:
                iface = ipaddress.ip_interface(v.gateway)
            except ValueError:
                errors.append(f"VLAN {v.id}: gateway {v.gateway!r} is not address/prefix (e.g. 192.168.10.1/24)")
                continue
            if iface.version != 4:
                errors.append(f"VLAN {v.id}: only IPv4 gateways are supported for now")
            if "/" not in v.gateway:
                errors.append(f"VLAN {v.id}: gateway {v.gateway!r} needs a prefix length, e.g. /24")
            if iface.ip == iface.network.network_address and iface.network.prefixlen < 31:
                errors.append(f"VLAN {v.id}: gateway {v.gateway} is the network address")
            for other_id, other in networks:
                if iface.network.overlaps(other):
                    errors.append(f"VLAN {v.id}: subnet {iface.network} overlaps VLAN {other_id} ({other})")
            networks.append((v.id, iface.network))
        for r in v.dhcp_relay:
            try:
                ipaddress.ip_address(r)
            except ValueError:
                errors.append(f"VLAN {v.id}: dhcp_relay {r!r} is not an IP address")

    seen_devices: set[str] = set()
    for d in net.devices:
        where = f"device {d.name}"
        if d.name in seen_devices:
            errors.append(f"{where}: duplicate device name")
        seen_devices.add(d.name)
        plugin = REGISTRY.get(d.vendor)
        if plugin is None:
            errors.append(f"{where}: unknown vendor {d.vendor!r} (run 'vlantool vendors')")
            continue
        defined = set(d.vlan_ids)
        for vid in d.vlan_ids:
            if vid not in net.vlans:
                errors.append(f"{where}: VLAN {vid} is not defined in 'vlans'")
        for port, vid in d.access.items():
            if vid not in net.vlans:
                errors.append(f"{where}: access port {port} uses undefined VLAN {vid}")
            elif vid not in defined:
                errors.append(f"{where}: access port {port} uses VLAN {vid}, which is not in this device's 'vlans'")
        trunk_ports = set()
        for t in d.trunks:
            if t.port in d.access:
                errors.append(f"{where}: port {t.port} is both access and trunk")
            if t.port in trunk_ports:
                errors.append(f"{where}: trunk port {t.port} listed twice")
            trunk_ports.add(t.port)
            for vid in t.allowed + ([t.native] if t.native else []):
                if vid not in net.vlans:
                    errors.append(f"{where}: trunk {t.port} uses undefined VLAN {vid}")
                elif vid not in defined:
                    errors.append(f"{where}: trunk {t.port} carries VLAN {vid}, which is not in this device's 'vlans'")
            if t.native and t.native not in t.allowed:
                warnings.append(f"{where}: trunk {t.port} native VLAN {t.native} is not in its allowed list (added automatically)")
                t.allowed = sorted(set(t.allowed) | {t.native})
        for vid in d.routed_vlans:
            if vid not in net.vlans:
                errors.append(f"{where}: routing references undefined VLAN {vid}")
            elif vid not in defined:
                errors.append(f"{where}: routing VLAN {vid} is not in this device's 'vlans'")
        if d.routed_vlans and plugin.requires_parent and not d.parent_interface:
            errors.append(f"{where}: {plugin.title} needs 'parent_interface' (the physical port carrying the VLANs)")
        if (d.access or d.trunks) and not plugin.supports_switching:
            warnings.append(f"{where}: {plugin.title} does not switch ports; access/trunks are ignored")
        if d.policies and not plugin.supports_policies:
            warnings.append(f"{where}: {plugin.title} has no firewall policies; 'policies' are ignored")
        from .services import validate_services
        e, w = validate_services(net, d)
        errors += [x for x in e if x not in errors]
        warnings += [x for x in w if x not in warnings]
        for p in d.policies:
            for vid in (p.src, p.dst):
                if vid not in d.routed_vlans:
                    errors.append(f"{where}: policy VLAN {vid} must be in this device's 'routing'")
    return errors, warnings
