"""Vendor-neutral network model.

A network file (YAML or JSON) defines VLANs once and lists the devices that
carry them. Every vendor plugin renders the same model into its own syntax.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ModelError(ValueError):
    """Raised when the network file cannot be understood."""


@dataclass
class Vlan:
    id: int
    name: str
    description: str = ""
    gateway: str | None = None          # e.g. 192.168.10.1/24
    dhcp_relay: list[str] = field(default_factory=list)

    @property
    def interface(self) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface | None:
        return ipaddress.ip_interface(self.gateway) if self.gateway else None

    @property
    def ip(self) -> str:
        return str(self.interface.ip)

    @property
    def prefixlen(self) -> int:
        return self.interface.network.prefixlen

    @property
    def netmask(self) -> str:
        return str(self.interface.network.netmask)

    @property
    def network(self) -> str:
        return str(self.interface.network)


@dataclass
class Trunk:
    port: str
    allowed: list[int]
    native: int | None = None


@dataclass
class Policy:
    """Firewall rule allowing traffic between two VLANs (firewall vendors only)."""
    src: int
    dst: int
    action: str = "accept"
    service: str = "ALL"


@dataclass
class Device:
    name: str
    vendor: str
    host: str | None = None
    port: int = 22
    username: str | None = None
    vlan_ids: list[int] = field(default_factory=list)   # VLANs defined on this device
    access: dict[str, int] = field(default_factory=dict)  # port -> vlan id
    trunks: list[Trunk] = field(default_factory=list)
    routed_vlans: list[int] = field(default_factory=list)  # VLANs that get an L3 interface
    parent_interface: str | None = None  # set => routed VLANs become subinterfaces
    bridge: str = "bridge1"  # MikroTik only
    policies: list[Policy] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Network:
    vlans: dict[int, Vlan]
    devices: list[Device]
    monitoring: dict[str, Any] = field(default_factory=dict)

    def device(self, name: str) -> Device:
        for d in self.devices:
            if d.name == name:
                return d
        raise ModelError(f"no device named {name!r}")

    def vlans_for(self, device: Device) -> list[Vlan]:
        return [self.vlans[i] for i in device.vlan_ids if i in self.vlans]


# ---------------------------------------------------------------- port ranges

_RANGE = re.compile(r"^(?P<prefix>.*?)(?P<start>\d+)-(?P=prefix)?(?P<end>\d+)$")


def expand_ports(spec: str) -> list[str]:
    """Expand 'Gi1/0/1-4,Gi1/0/10' into individual port names.

    Both 'Gi1/0/1-4' and 'Gi1/0/1-Gi1/0/4' are accepted, as are bare numbers
    ('1-8') and D-Link style unit:port ('1:1-1:8').
    """
    ports: list[str] = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        m = _RANGE.match(part)
        if m and int(m["end"]) >= int(m["start"]):
            width = len(m["start"]) if m["start"].startswith("0") else 0
            for n in range(int(m["start"]), int(m["end"]) + 1):
                ports.append(f"{m['prefix']}{str(n).zfill(width)}")
        else:
            ports.append(part)
    return ports


def parse_vlan_list(value: Any, known: dict[int, Vlan] | None = None) -> list[int]:
    """Accept 'all', 10, '10,20,30-35' or [10, 20] and return sorted ids."""
    if value is None:
        return []
    if value is True or (isinstance(value, str) and value.strip().lower() == "all"):
        return sorted(known or {})
    if value is False:
        return []
    if isinstance(value, int):
        return [value]
    items = value if isinstance(value, list) else str(value).split(",")
    ids: set[int] = set()
    for item in items:
        if isinstance(item, int):
            ids.add(item)
            continue
        item = str(item).strip()
        if not item:
            continue
        if "-" in item:
            a, b = item.split("-", 1)
            ids.update(range(int(a), int(b) + 1))
        elif item.isdigit():
            ids.add(int(item))
        elif known:  # allow VLAN names
            match = [v.id for v in known.values() if v.name == item]
            if not match:
                raise ModelError(f"unknown VLAN {item!r}")
            ids.add(match[0])
        else:
            raise ModelError(f"bad VLAN reference {item!r}")
    return sorted(ids)


def compress_vlans(ids: list[int]) -> str:
    """[10, 11, 12, 20] -> '10-12,20' (Cisco style list)."""
    ids = sorted(set(ids))
    out: list[str] = []
    i = 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        out.append(str(ids[i]) if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ",".join(out)


# ------------------------------------------------------------------- loading

def load(path: str | Path) -> Network:
    text = Path(path).read_text()
    data = json.loads(text) if str(path).endswith(".json") else yaml.safe_load(text)
    return from_dict(data or {})


def from_dict(data: dict) -> Network:
    if not isinstance(data, dict):
        raise ModelError("network file must be a mapping with 'vlans' and 'devices'")
    vlans: dict[int, Vlan] = {}
    for raw in data.get("vlans") or []:
        try:
            vid = int(raw["id"])
        except (KeyError, TypeError, ValueError):
            raise ModelError(f"VLAN entry needs a numeric 'id': {raw!r}") from None
        relay = raw.get("dhcp_relay") or []
        if isinstance(relay, str):
            relay = [relay]
        vlans[vid] = Vlan(
            id=vid,
            name=str(raw.get("name") or f"VLAN{vid}"),
            description=str(raw.get("description") or ""),
            gateway=raw.get("gateway"),
            dhcp_relay=[str(r) for r in relay],
        )

    devices: list[Device] = []
    for raw in data.get("devices") or []:
        if "name" not in raw or "vendor" not in raw:
            raise ModelError(f"device entry needs 'name' and 'vendor': {raw!r}")
        access: dict[str, int] = {}
        for spec, vid in (raw.get("access") or {}).items():
            vid = parse_vlan_list(vid, vlans)
            if len(vid) != 1:
                raise ModelError(f"{raw['name']}: access port {spec} must map to exactly one VLAN")
            for p in expand_ports(spec):
                access[p] = vid[0]
        trunks: list[Trunk] = []
        for spec, t in (raw.get("trunks") or {}).items():
            t = t or {}
            if not isinstance(t, dict):
                t = {"allowed": t}
            allowed = parse_vlan_list(t.get("allowed", "all"), vlans)
            native = t.get("native")
            native = parse_vlan_list(native, vlans)[0] if native not in (None, "") else None
            for p in expand_ports(spec):
                trunks.append(Trunk(port=p, allowed=allowed, native=native))
        policies = [
            Policy(
                src=parse_vlan_list(p["from"], vlans)[0],
                dst=parse_vlan_list(p["to"], vlans)[0],
                action=str(p.get("action", "accept")),
                service=str(p.get("service", "ALL")),
            )
            for p in raw.get("policies") or []
        ]
        known = {k: v for k, v in raw.items() if k not in {
            "name", "vendor", "host", "port", "username", "vlans", "access",
            "trunks", "routing", "parent_interface", "bridge", "policies"}}
        devices.append(Device(
            name=str(raw["name"]),
            vendor=str(raw["vendor"]),
            host=raw.get("host"),
            port=int(raw.get("port", 22)),
            username=raw.get("username"),
            vlan_ids=parse_vlan_list(raw.get("vlans", "all"), vlans),
            access=access,
            trunks=trunks,
            routed_vlans=[v for v in parse_vlan_list(raw.get("routing", False), vlans)
                          if v not in vlans or vlans[v].gateway],
            parent_interface=raw.get("parent_interface"),
            bridge=str(raw.get("bridge", "bridge1")),
            policies=policies,
            options=known,
        ))
    return Network(vlans=vlans, devices=devices, monitoring=dict(data.get("monitoring") or {}))
