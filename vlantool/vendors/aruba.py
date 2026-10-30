"""HPE Aruba: AOS-CX and ArubaOS-Switch (ProCurve)."""
from __future__ import annotations

from ..model import compress_vlans
from .base import Vendor


class ArubaAOSCX(Vendor):
    key = "aruba_aoscx"
    title = "Aruba AOS-CX"
    covers = "Aruba CX 4100i/6000/6100/6200/6300/6400/8xxx"
    netmiko_type = "aruba_aoscx"
    config_enter = ["configure terminal"]
    config_exit = ["end", "write memory"]

    def render(self) -> list[str]:
        i = "    "
        out: list[str] = []
        for v in self.vlans:
            out += [f"vlan {v.id}", f"{i}name {v.name}"]
            if v.description:
                out.append(f"{i}description {v.description}")
        for port, vid in self.dev.access.items():
            out += [f"interface {port}", f"{i}no shutdown", f"{i}no routing", f"{i}vlan access {vid}"]
        for t in self.trunks:
            out += [f"interface {t.port}", f"{i}no shutdown", f"{i}no routing"]
            if t.native:
                out.append(f"{i}vlan trunk native {t.native}")
            out.append(f"{i}vlan trunk allowed {compress_vlans(t.allowed)}")
        parent = self.dev.parent_interface
        for v in self.routed:
            if parent:
                out += [f"interface {parent}.{v.id}", f"{i}encapsulation dot1q {v.id}"]
            else:
                out.append(f"interface vlan {v.id}")
            out += [f"{i}description {v.name}", f"{i}ip address {v.ip}/{v.prefixlen}"]
            out += [f"{i}ip helper-address {r}" for r in v.dhcp_relay]
            out.append(f"{i}no shutdown")
        return out


class ArubaOSSwitch(Vendor):
    key = "hp_procurve"
    title = "HPE ArubaOS-Switch / ProCurve"
    covers = "Aruba 2530/2540/2930F/2930M/3810/5400R, HP ProCurve 2510/2610/2810/2910/5400zl"
    netmiko_type = "hp_procurve"
    config_enter = ["configure terminal"]
    config_exit = ["write memory"]

    def render(self) -> list[str]:
        out: list[str] = []
        routed = set(self.dev.routed_vlans)
        if routed:
            out.append("ip routing")
        for v in self.vlans:
            out += [f"vlan {v.id}", f'   name "{v.name}"']
            untagged = self.untagged_ports(v.id)
            tagged = self.tagged_ports(v.id)
            if untagged:
                out.append(f"   untagged {','.join(untagged)}")
            if tagged:
                out.append(f"   tagged {','.join(tagged)}")
            if v.id in routed:
                out.append(f"   ip address {v.ip} {v.netmask}")
                out += [f"   ip helper-address {r}" for r in v.dhcp_relay]
            out.append("   exit")
        # trunk ports without a native VLAN must leave the default VLAN
        bare = [t.port for t in self.trunks if t.native is None]
        if bare and 1 not in self.dev.vlan_ids:
            out += ["vlan 1", f"   no untagged {','.join(bare)}", "   exit"]
        return out
