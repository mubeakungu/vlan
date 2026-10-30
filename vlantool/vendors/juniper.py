"""Juniper Junos (EX/QFX ELS switching, SRX/MX routing and security policies)."""
from __future__ import annotations

from .base import Vendor


class JuniperJunos(Vendor):
    key = "juniper_junos"
    title = "Juniper Junos"
    covers = "EX/QFX switches (ELS), SRX firewalls, MX/vSRX routers"
    netmiko_type = "juniper_junos"
    comment = "#"
    commit = True
    supports_policies = True
    config_enter = ["configure"]
    config_exit = ["commit and-quit"]

    def members(self, ids) -> str:
        names = [self.vlan(i).name for i in ids]
        return names[0] if len(names) == 1 else "[ " + " ".join(names) + " ]"

    def render(self) -> list[str]:
        out: list[str] = []
        parent = self.dev.parent_interface
        switching = bool(self.dev.access or self.dev.trunks) or not parent
        if switching:
            routed = set(self.dev.routed_vlans) if not parent else set()
            for v in self.vlans:
                out.append(f"set vlans {v.name} vlan-id {v.id}")
                if v.description:
                    out.append(f'set vlans {v.name} description "{v.description}"')
                if v.id in routed:
                    out.append(f"set vlans {v.name} l3-interface irb.{v.id}")
        for port, vid in self.dev.access.items():
            base = f"set interfaces {port} unit 0 family ethernet-switching"
            out += [f"{base} interface-mode access", f"{base} vlan members {self.vlan(vid).name}"]
        for t in self.trunks:
            base = f"set interfaces {t.port} unit 0 family ethernet-switching"
            out += [f"{base} interface-mode trunk", f"{base} vlan members {self.members(t.allowed)}"]
            if t.native:
                out.append(f"set interfaces {t.port} native-vlan-id {t.native}")

        l3_names: dict[int, str] = {}
        if self.routed:
            if parent:
                out.append(f"set interfaces {parent} vlan-tagging")
            for v in self.routed:
                if parent:
                    ifname = f"{parent}.{v.id}"
                    out += [f"set interfaces {parent} unit {v.id} vlan-id {v.id}",
                            f"set interfaces {parent} unit {v.id} description {v.name}",
                            f"set interfaces {parent} unit {v.id} family inet address {v.ip}/{v.prefixlen}"]
                else:
                    ifname = f"irb.{v.id}"
                    out.append(f"set interfaces irb unit {v.id} family inet address {v.ip}/{v.prefixlen}")
                l3_names[v.id] = ifname
            relayed = [v for v in self.routed if v.dhcp_relay]
            if relayed:
                servers = sorted({s for v in relayed for s in v.dhcp_relay})
                for s in servers:
                    out.append(f"set forwarding-options dhcp-relay server-group DHCP-SERVERS {s}")
                out.append("set forwarding-options dhcp-relay group VLANS active-server-group DHCP-SERVERS")
                for v in relayed:
                    out.append(f"set forwarding-options dhcp-relay group VLANS interface {l3_names[v.id]}")

        if self.dev.policies:  # SRX: one security zone per VLAN
            for vid, ifname in l3_names.items():
                zone = self.vlan(vid).name
                out += [f"set security zones security-zone {zone} interfaces {ifname}",
                        f"set security zones security-zone {zone} host-inbound-traffic system-services ping"]
                if self.vlan(vid).dhcp_relay:
                    out.append(f"set security zones security-zone {zone} host-inbound-traffic system-services dhcp")
            for p in self.dev.policies:
                src, dst = self.vlan(p.src).name, self.vlan(p.dst).name
                app = "any" if p.service.upper() == "ALL" else p.service
                act = "permit" if p.action in ("accept", "permit", "allow") else "deny"
                base = f"set security policies from-zone {src} to-zone {dst} policy {src}-to-{dst}"
                out += [f"{base} match source-address any", f"{base} match destination-address any",
                        f"{base} match application {app}", f"{base} then {act}"]
        return out
