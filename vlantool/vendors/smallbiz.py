"""Small-business managed switches: D-Link (legacy CLI), TP-Link JetStream,
Ubiquiti EdgeSwitch / Netgear (FASTPATH), Extreme EXOS, Ruckus ICX, Zyxel."""
from __future__ import annotations

from ..model import compress_vlans
from .base import Vendor


class DLinkLegacy(Vendor):
    key = "dlink"
    title = "D-Link (legacy DES/DGS CLI)"
    covers = "DES-3028/3200/3526, DGS-3100/3120/3420/3620, xStack (create vlan ... tag ...)"
    netmiko_type = "dlink_ds"
    comment = "#"
    config_exit = ["save"]

    def render(self) -> list[str]:
        out: list[str] = []
        moved = [p for p in self.dev.access] + [t.port for t in self.trunks if t.native and t.native != 1]
        for v in self.vlans:
            if v.id != 1:
                out.append(f"create vlan {v.name} tag {v.id}")
        if moved and 1 not in self.dev.vlan_ids:
            out.append(f"config vlan default delete {','.join(moved)}")
        for v in self.vlans:
            untagged, tagged = self.untagged_ports(v.id), self.tagged_ports(v.id)
            name = "default" if v.id == 1 else v.name
            if untagged:
                out.append(f"config vlan {name} add untagged {','.join(untagged)}")
            if tagged:
                out.append(f"config vlan {name} add tagged {','.join(tagged)}")
        for p in self.dev.access:
            out.append(f"config gvrp {p} pvid {self.dev.access[p]}")
        relayed = []
        for v in self.routed:
            ipif = f"if{v.id}"
            name = "default" if v.id == 1 else v.name
            out.append(f"create ipif {ipif} {v.ip}/{v.prefixlen} {name} state enable")
            for r in v.dhcp_relay:
                out.append(f"config dhcp_relay add ipif {ipif} {r}")
                relayed.append(ipif)
        if relayed:
            out.append("enable dhcp_relay")
        return out


class TPLinkJetStream(Vendor):
    key = "tplink_jetstream"
    title = "TP-Link JetStream / Omada (CLI)"
    covers = "TL-SG2xxx/SG3xxx, T1600G/T1700G/T2500G/T2600G/T2700G, SG2210/SG3428 (standalone mode)"
    netmiko_type = "tplink_jetstream"
    config_enter = ["configure"]
    config_exit = ["end", "copy running-config startup-config"]

    def ifname(self, port: str) -> str:
        # accept "1/0/1" and turn it into "gigabitEthernet 1/0/1"
        if port[:1].isdigit():
            return f"{self.dev.options.get('port_type', 'gigabitEthernet')} {port}"
        return port

    def render(self) -> list[str]:
        out: list[str] = []
        for v in self.vlans:
            out += [f"vlan {v.id}", f' name "{v.name}"', " exit"]
        for port, vid in self.dev.access.items():
            out += [f"interface {self.ifname(port)}",
                    f" switchport general allowed vlan {vid} untagged",
                    f" switchport pvid {vid}"]
            if vid != 1:
                out.append(" no switchport general allowed vlan 1")
            out.append(" exit")
        for t in self.trunks:
            out.append(f"interface {self.ifname(t.port)}")
            tagged = [v for v in t.allowed if v != t.native]
            if tagged:
                out.append(f" switchport general allowed vlan {compress_vlans(tagged)} tagged")
            if t.native:
                out += [f" switchport general allowed vlan {t.native} untagged", f" switchport pvid {t.native}"]
            if t.native != 1 and 1 not in t.allowed:
                out.append(" no switchport general allowed vlan 1")
            out.append(" exit")
        if self.routed:
            out.append("ip routing")
            if any(v.dhcp_relay for v in self.routed):
                out.append("service dhcp relay")
            for v in self.routed:
                out += [f"interface vlan {v.id}", f" description {v.name}", f" ip address {v.ip} {v.netmask}"]
                out += [f" ip helper-address {r}" for r in v.dhcp_relay]
                out.append(" exit")
        return out


class FastPath(Vendor):
    """Broadcom FASTPATH CLI used by Ubiquiti EdgeSwitch and Netgear managed switches."""
    key = "ubiquiti_edgeswitch"
    title = "Ubiquiti EdgeSwitch"
    covers = "EdgeSwitch ES-xx-Lite/ES-xx-250W/500W/750W, EdgeSwitch XP"
    netmiko_type = "ubiquiti_edgeswitch"
    push_enter_config = False  # 'vlan database' lives outside config mode
    config_exit = ["write memory"]

    def render(self) -> list[str]:
        routed = set(self.dev.routed_vlans)
        out = ["vlan database"]
        for v in self.vlans:
            out += [f"vlan {v.id}", f"vlan name {v.id} {v.name}"]
            if v.id in routed:
                out.append(f"vlan routing {v.id}")
        out += ["exit", "configure"]
        for port, vid in self.dev.access.items():
            out += [f"interface {port}", f"vlan pvid {vid}"]
            if vid != 1:
                out.append("vlan participation exclude 1")
            out += [f"vlan participation include {vid}", "exit"]
        for t in self.trunks:
            out += [f"interface {t.port}", f"vlan participation include {compress_vlans(t.allowed)}"]
            tagged = [v for v in t.allowed if v != t.native]
            if tagged:
                out.append(f"vlan tagging {compress_vlans(tagged)}")
            out.append(f"vlan pvid {t.native or 1}")
            if 1 not in t.allowed:
                out.append("vlan participation exclude 1")
            out.append("exit")
        if self.routed:
            out.append("ip routing")
            for v in self.routed:
                out += [f"interface vlan {v.id}", "routing", f"ip address {v.ip} {v.netmask}"]
                out += [f"ip helper-address {r}" for r in v.dhcp_relay]
                out.append("exit")
        out.append("exit")
        return out


class Netgear(FastPath):
    key = "netgear"
    title = "Netgear managed (FASTPATH CLI)"
    covers = "Netgear M4100/M4200/M4300/M4350, GSM7xxx, ProSAFE managed series"
    netmiko_type = "netgear_prosafe"


class ExtremeEXOS(Vendor):
    key = "extreme_exos"
    title = "Extreme EXOS"
    covers = "Extreme X440/X450/X460/X620/X690 (EXOS)"
    netmiko_type = "extreme_exos"
    comment = "#"
    config_exit = ["save configuration"]

    def render(self) -> list[str]:
        out: list[str] = []
        moved = list(self.dev.access) + [t.port for t in self.trunks]
        if moved and 1 not in self.dev.vlan_ids:
            out.append(f"configure vlan Default delete ports {','.join(moved)}")
        for v in self.vlans:
            if v.id != 1:
                out.append(f"create vlan {v.name} tag {v.id}")
            untagged, tagged = self.untagged_ports(v.id), self.tagged_ports(v.id)
            if untagged:
                out.append(f"configure vlan {v.name} add ports {','.join(untagged)} untagged")
            if tagged:
                out.append(f"configure vlan {v.name} add ports {','.join(tagged)} tagged")
        for v in self.routed:
            out += [f"configure vlan {v.name} ipaddress {v.ip}/{v.prefixlen}",
                    f"enable ipforwarding vlan {v.name}"]
        servers = sorted({r for v in self.routed for r in v.dhcp_relay})
        for s in servers:
            out.append(f"configure bootprelay add {s}")
        for v in self.routed:
            if v.dhcp_relay:
                out.append(f"enable bootprelay vlan {v.name}")
        return out


class RuckusICX(Vendor):
    key = "ruckus_icx"
    title = "Ruckus / Brocade ICX (FastIron)"
    covers = "Ruckus ICX 7150/7250/7450/7550/7650/7850, Brocade FastIron"
    netmiko_type = "ruckus_fastiron"
    config_enter = ["configure terminal"]
    config_exit = ["end", "write memory"]

    def eth(self, ports: list[str]) -> str:
        return " ".join(p if p.startswith("eth") else f"ethernet {p}" for p in ports)

    def render(self) -> list[str]:
        routed = set(self.dev.routed_vlans)
        out: list[str] = []
        for v in self.vlans:
            out.append(f"vlan {v.id} name {v.name} by port")
            untagged, tagged = self.untagged_ports(v.id), self.tagged_ports(v.id)
            if tagged:
                out.append(f" tagged {self.eth(tagged)}")
            if untagged:
                out.append(f" untagged {self.eth(untagged)}")
            if v.id in routed:
                out.append(f" router-interface ve {v.id}")
            out.append(" exit")
        for v in self.routed:
            out += [f"interface ve {v.id}", f" ip address {v.ip} {v.netmask}"]
            out += [f" ip helper-address {n} {r}" for n, r in enumerate(v.dhcp_relay, 1)]
            out.append(" exit")
        return out


class Zyxel(Vendor):
    key = "zyxel"
    title = "Zyxel managed (CLI)"
    covers = "Zyxel GS2210/GS2220/XGS2210/XGS2220/XS3800/XGS4600"
    netmiko_type = "zyxel_os"
    config_enter = ["configure"]
    config_exit = ["exit", "write memory"]

    def render(self) -> list[str]:
        routed = set(self.dev.routed_vlans)
        out: list[str] = []
        for v in self.vlans:
            untagged, tagged = self.untagged_ports(v.id), self.tagged_ports(v.id)
            members = untagged + tagged
            out += [f"vlan {v.id}", f" name {v.name}"]
            if members:
                out.append(f" fixed {','.join(members)}")
            if untagged:
                out.append(f" untagged {','.join(untagged)}")
            if tagged:
                out.append(f" no untagged {','.join(tagged)}")
            if v.id in routed:
                out.append(f" ip address {v.ip} {v.netmask}")
            out.append("exit")
        pvid = dict(self.dev.access)
        pvid.update({t.port: t.native for t in self.trunks if t.native})
        for port, vid in pvid.items():
            out += [f"interface port-channel {port}", f" pvid {vid}", "exit"]
        return out
