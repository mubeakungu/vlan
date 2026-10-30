"""Huawei VRP and HPE/H3C Comware (they share most VLAN syntax)."""
from __future__ import annotations

from .base import Vendor


def to_ranges(ids: list[int]) -> str:
    """[10, 11, 12, 20] -> '10 to 12 20' (VRP/Comware style list)."""
    ids = sorted(set(ids))
    out, i = [], 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        out.append(str(ids[i]) if i == j else f"{ids[i]} to {ids[j]}")
        i = j + 1
    return " ".join(out)


class HuaweiVRP(Vendor):
    key = "huawei_vrp"
    title = "Huawei VRP"
    covers = "Huawei S1700/S2700/S5700/S6700/CE switches, AR routers"
    netmiko_type = "huawei"
    comment = "#"
    config_enter = ["system-view"]
    config_exit = ["return", "save"]
    access_cmd = "port default vlan {id}"
    trunk_cmd = "port trunk allow-pass vlan {ids}"
    svi = "interface Vlanif{id}"
    relay = ["dhcp select relay", "dhcp relay server-ip {ip}"]
    subif_encap = "dot1q termination vid {id}"

    def vlan_lines(self, v) -> list[str]:
        return [f"vlan {v.id}", f" description {v.name}", " quit"]

    def render(self) -> list[str]:
        out: list[str] = []
        if any(v.dhcp_relay for v in self.routed):
            out.append("dhcp enable")
        if self.vlans:
            out.append(f"vlan batch {to_ranges([v.id for v in self.vlans])}")
            for v in self.vlans:
                out += self.vlan_lines(v)
        for port, vid in self.dev.access.items():
            out += [f"interface {port}", " port link-type access",
                    " " + self.access_cmd.format(id=vid), " quit"]
        for t in self.trunks:
            out += [f"interface {t.port}", " port link-type trunk",
                    " " + self.trunk_cmd.format(ids=to_ranges(t.allowed))]
            if t.native:
                out.append(f" port trunk pvid vlan {t.native}")
            out.append(" quit")
        parent = self.dev.parent_interface
        for v in self.routed:
            if parent:
                out += [f"interface {parent}.{v.id}", " " + self.subif_encap.format(id=v.id),
                        " arp broadcast enable"]
            else:
                out.append(self.svi.format(id=v.id))
            out += [f" description {v.name}", f" ip address {v.ip} {v.netmask}"]
            if v.dhcp_relay:
                out.append(" " + self.relay[0])
                out += [" " + self.relay[1].format(ip=r) for r in v.dhcp_relay]
            out.append(" quit")
        return out


class HPComware(HuaweiVRP):
    key = "hp_comware"
    title = "HPE / H3C Comware"
    covers = "HPE OfficeConnect 1920/1950, FlexNetwork 5130/5510/5940, H3C S5xxx"
    netmiko_type = "hp_comware"
    access_cmd = "port access vlan {id}"
    trunk_cmd = "port trunk permit vlan {ids}"
    svi = "interface Vlan-interface{id}"
    relay = ["dhcp select relay", "dhcp relay server-address {ip}"]
    subif_encap = "vlan-type dot1q vid {id}"
    config_exit = ["return", "save force"]

    def vlan_lines(self, v) -> list[str]:
        return [f"vlan {v.id}", f" name {v.name}", " quit"]
