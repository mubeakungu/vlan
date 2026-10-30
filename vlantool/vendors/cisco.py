"""Cisco-style CLIs: IOS/IOS-XE, NX-OS, Arista EOS, Dell OS10, Cisco SMB, D-Link DGS (new CLI)."""
from __future__ import annotations

from ..model import compress_vlans
from .base import Vendor


class CiscoIOS(Vendor):
    key = "cisco_ios"
    title = "Cisco IOS / IOS-XE"
    covers = "Catalyst 2960/3560/3750/3850/9200/9300, ISR routers (router-on-a-stick)"
    netmiko_type = "cisco_ios"
    config_enter = ["configure terminal"]
    config_exit = ["end", "write memory"]
    indent = " "

    # knobs subclasses override
    ip_style = "mask"            # "mask" -> 1.2.3.4 255.255.255.0, "prefix" -> 1.2.3.4/24
    routing_cmd = "ip routing"
    svi_name = "interface Vlan{id}"
    relay_cmd = "ip helper-address {ip}"
    port_prefix: list[str] = []  # lines added at top of every switch port
    subif_encap = "encapsulation dot1Q {id}"

    def l3_name(self, v) -> str:
        if self.dev.parent_interface:
            return f"{self.dev.parent_interface}.{v.id}"
        return self.svi_name.format(id=v.id).removeprefix("interface ")

    def ip(self, v) -> str:
        return f"{v.ip}/{v.prefixlen}" if self.ip_style == "prefix" else f"{v.ip} {v.netmask}"

    def vlan_block(self, v) -> list[str]:
        return [f"vlan {v.id}", f"{self.indent}name {v.name}"]

    def access_port(self, port, vid) -> list[str]:
        i = self.indent
        return ([f"interface {port}"] + [i + p for p in self.port_prefix] + [
            f"{i}description {self.vlan(vid).name}",
            f"{i}switchport mode access",
            f"{i}switchport access vlan {vid}",
            f"{i}no shutdown",
        ])

    def trunk_port(self, t) -> list[str]:
        i = self.indent
        out = [f"interface {t.port}"] + [i + p for p in self.port_prefix]
        if self.dev.options.get("dot1q_encapsulation"):
            out.append(f"{i}switchport trunk encapsulation dot1q")
        out.append(f"{i}switchport mode trunk")
        if t.native:
            out.append(f"{i}switchport trunk native vlan {t.native}")
        out.append(f"{i}switchport trunk allowed vlan {compress_vlans(t.allowed)}")
        out.append(f"{i}no shutdown")
        return out

    def l3_lines(self, v) -> list[str]:
        i = self.indent
        out = [f"{i}description {v.name}", f"{i}ip address {self.ip(v)}"]
        out += [i + self.relay_cmd.format(ip=r) for r in v.dhcp_relay]
        out.append(f"{i}no shutdown")
        return out

    def svi_preamble(self) -> list[str]:
        return [self.routing_cmd] if self.routing_cmd else []

    def subif_preamble(self) -> list[str]:
        return [f"interface {self.dev.parent_interface}", f"{self.indent}no shutdown"]

    def render(self) -> list[str]:
        out: list[str] = []
        if self.dev.parent_interface is None or self.dev.access or self.dev.trunks:
            for v in self.vlans:
                out += self.vlan_block(v)
        for port, vid in self.dev.access.items():
            out += self.access_port(port, vid)
        for t in self.trunks:
            out += self.trunk_port(t)
        if self.routed:
            if self.dev.parent_interface:
                out += self.subif_preamble()
                for v in self.routed:
                    out.append(f"interface {self.dev.parent_interface}.{v.id}")
                    out.append(self.indent + self.subif_encap.format(id=v.id))
                    out += self.l3_lines(v)
            else:
                out += self.svi_preamble()
                for v in self.routed:
                    out.append(self.svi_name.format(id=v.id))
                    out += self.l3_lines(v)
        return out


class CiscoNXOS(CiscoIOS):
    key = "cisco_nxos"
    title = "Cisco NX-OS"
    covers = "Nexus 3000/5000/7000/9000"
    netmiko_type = "cisco_nxos"
    config_exit = ["end", "copy running-config startup-config"]
    indent = "  "
    ip_style = "prefix"
    routing_cmd = None
    relay_cmd = "ip dhcp relay address {ip}"
    port_prefix = ["switchport"]
    subif_encap = "encapsulation dot1q {id}"

    def svi_preamble(self) -> list[str]:
        out = ["feature interface-vlan"]
        if any(v.dhcp_relay for v in self.routed):
            out.append("feature dhcp")
        return out

    def subif_preamble(self) -> list[str]:
        out = ["feature dhcp"] if any(v.dhcp_relay for v in self.routed) else []
        return out + [f"interface {self.dev.parent_interface}", "  no switchport", "  no shutdown"]


class AristaEOS(CiscoIOS):
    key = "arista_eos"
    title = "Arista EOS"
    covers = "Arista 7000-series and CCS switches"
    netmiko_type = "arista_eos"
    indent = "   "
    ip_style = "prefix"

    def subif_preamble(self) -> list[str]:
        return [f"interface {self.dev.parent_interface}", "   no switchport", "   no shutdown"]


class DellOS10(CiscoIOS):
    key = "dell_os10"
    title = "Dell EMC SmartFabric OS10"
    covers = "Dell S/Z-series (S4100, S5200, ...)"
    netmiko_type = "dell_os10"
    config_exit = ["end", "write memory"]
    ip_style = "prefix"
    routing_cmd = None
    svi_name = "interface vlan{id}"

    def vlan_block(self, v) -> list[str]:
        return [f"interface vlan{v.id}", f" description {v.name}", " no shutdown"]

    def trunk_port(self, t) -> list[str]:
        out = [f"interface {t.port}", " switchport mode trunk"]
        if t.native:
            out.append(f" switchport access vlan {t.native}")
        tagged = [v for v in t.allowed if v != t.native]
        if tagged:
            out.append(f" switchport trunk allowed vlan {compress_vlans(tagged)}")
        out.append(" no shutdown")
        return out

    def l3_lines(self, v) -> list[str]:
        return [f" ip address {self.ip(v)}"] + [f" ip helper-address {r}" for r in v.dhcp_relay] + [" no shutdown"]


class CiscoSMB(CiscoIOS):
    key = "cisco_smb"
    title = "Cisco Small Business"
    covers = "SG300/SG350/SG500/SG550, CBS250/CBS350, Catalyst 1200/1300"
    netmiko_type = "cisco_s300"
    routing_cmd = None  # SG350+ route on SVIs once 'set system mode router' is set

    def render(self) -> list[str]:
        out: list[str] = []
        if self.vlans:
            out += ["vlan database", f"vlan {compress_vlans([v.id for v in self.vlans])}", "exit"]
            for v in self.vlans:
                out += [f"interface vlan {v.id}", f" name {v.name}", "exit"]
        for port, vid in self.dev.access.items():
            out += [f"interface {port}", " switchport mode access", f" switchport access vlan {vid}", "exit"]
        for t in self.trunks:
            out += [f"interface {t.port}", " switchport mode trunk"]
            if t.native:
                out.append(f" switchport trunk native vlan {t.native}")
            tagged = [v for v in t.allowed if v != t.native]
            if tagged:
                out.append(f" switchport trunk allowed vlan add {compress_vlans(tagged)}")
            out.append("exit")
        if self.routed:
            if any(v.dhcp_relay for v in self.routed):
                out.append("ip dhcp relay enable")
            for v in self.routed:
                out += [f"interface vlan {v.id}", f" ip address {self.ip(v)}"]
                out += [f" ip dhcp relay address {r}" for r in v.dhcp_relay]
                out.append("exit")
        return out


class DLinkDGS(CiscoIOS):
    key = "dlink_dgs"
    title = "D-Link (new Cisco-like CLI)"
    covers = "DGS-1250, DGS-1510, DGS-1520, DGS-3130, DXS-3410 and other 'configure terminal' D-Link models"
    netmiko_type = "cisco_ios"  # Netmiko has no class for this CLI; the Cisco driver handles its prompts
    config_exit = ["end", "copy running-config startup-config"]
    svi_name = "interface vlan {id}"
    routing_cmd = None

    def l3_lines(self, v) -> list[str]:
        out = [f" ip address {self.ip(v)}"]
        out += [f" ip helper-address {r}" for r in v.dhcp_relay]
        return out + [" no shutdown"]
