"""Routers and firewalls: MikroTik, EdgeOS/VyOS, FortiGate, pfSense/OPNsense."""
from __future__ import annotations

from xml.sax.saxutils import escape

from .base import Vendor


class MikroTik(Vendor):
    key = "mikrotik_routeros"
    title = "MikroTik RouterOS v7"
    covers = "MikroTik CRS3xx/CRS5xx switches, CCR/RB/hAP/hEX routers (bridge VLAN filtering)"
    netmiko_type = "mikrotik_routeros"
    comment = "#"

    def render(self) -> list[str]:
        out: list[str] = []
        br = self.dev.bridge
        parent = self.dev.parent_interface
        switching = bool(self.dev.access or self.dev.trunks)
        l3_parent = parent or br
        if switching:
            out.append("# VLAN filtering stays off until the end so you are not locked out mid-way")
            if self.dev.options.get("create_bridge", True):
                out.append(f"/interface bridge add name={br} vlan-filtering=no")
            for port, vid in self.dev.access.items():
                out.append(f"/interface bridge port add bridge={br} interface={port} pvid={vid} "
                           f"frame-types=admit-only-untagged-and-priority-tagged")
            for t in self.trunks:
                if t.native:
                    out.append(f"/interface bridge port add bridge={br} interface={t.port} pvid={t.native} frame-types=admit-all")
                else:
                    out.append(f"/interface bridge port add bridge={br} interface={t.port} frame-types=admit-only-vlan-tagged")
            routed = set(self.dev.routed_vlans) if not parent else set()
            for v in self.vlans:
                tagged = self.tagged_ports(v.id) + ([br] if v.id in routed else [])
                untagged = self.untagged_ports(v.id)
                line = f"/interface bridge vlan add bridge={br} vlan-ids={v.id}"
                if tagged:
                    line += f" tagged={','.join(tagged)}"
                if untagged:
                    line += f" untagged={','.join(untagged)}"
                out.append(line + f' comment="{v.name}"')
        for v in self.routed:
            name = f"vlan{v.id}-{v.name}"
            out += [f"/interface vlan add interface={l3_parent} name={name} vlan-id={v.id}",
                    f"/ip address add address={v.ip}/{v.prefixlen} interface={name}"]
            for n, r in enumerate(v.dhcp_relay):
                out.append(f"/ip dhcp-relay add name=relay{v.id}-{n} interface={name} dhcp-server={r} disabled=no")
        if switching:
            out.append(f"/interface bridge set {br} vlan-filtering=yes")
        return out


class EdgeOS(Vendor):
    key = "ubiquiti_edgeos"
    title = "Ubiquiti EdgeRouter (EdgeOS)"
    covers = "EdgeRouter X/4/6P/12/Lite/Pro (switch0 or ethX)"
    netmiko_type = "ubiquiti_edge"
    supports_switching = False
    requires_parent = True
    comment = "#"
    commit = True
    config_enter = ["configure"]
    config_exit = ["commit", "save", "exit"]

    def base(self) -> str:
        p = self.dev.parent_interface or "eth1"
        kind = "switch" if p.startswith("switch") else "bonding" if p.startswith("bond") else "ethernet"
        return f"set interfaces {kind} {p}"

    def render(self) -> list[str]:
        out: list[str] = []
        for v in self.routed:
            out += [f"{self.base()} vif {v.id} description {v.name}",
                    f"{self.base()} vif {v.id} address {v.ip}/{v.prefixlen}"]
        relayed = [v for v in self.routed if v.dhcp_relay]
        for v in relayed:
            out.append(f"set service dhcp-relay interface {self.dev.parent_interface}.{v.id}")
        for s in sorted({r for v in relayed for r in v.dhcp_relay}):
            out.append(f"set service dhcp-relay server {s}")
        return out


class VyOS(EdgeOS):
    key = "vyos"
    title = "VyOS"
    covers = "VyOS 1.3/1.4/1.5 routers"
    netmiko_type = "vyos"

    def render(self) -> list[str]:
        out: list[str] = []
        for v in self.routed:
            out += [f"{self.base()} vif {v.id} description {v.name}",
                    f"{self.base()} vif {v.id} address {v.ip}/{v.prefixlen}"]
        relayed = [v for v in self.routed if v.dhcp_relay]
        for v in relayed:
            out.append(f"set service dhcp-relay listen-interface {self.dev.parent_interface}.{v.id}")
        if relayed:
            out.append(f"set service dhcp-relay upstream-interface {self.dev.options.get('relay_upstream', 'eth0')}")
        for s in sorted({r for v in relayed for r in v.dhcp_relay}):
            out.append(f"set service dhcp-relay server {s}")
        return out


class FortiGate(Vendor):
    key = "fortinet"
    title = "Fortinet FortiGate (FortiOS)"
    covers = "FortiGate 40F-3000F, FortiGate-VM"
    netmiko_type = "fortinet"
    supports_switching = False
    supports_policies = True
    requires_parent = True
    comment = "#"

    def ifname(self, v) -> str:
        return v.name[:15]  # FortiOS interface names max 15 chars

    def render(self) -> list[str]:
        vdom = self.dev.options.get("vdom", "root")
        out = ["config system interface"]
        for v in self.routed:
            out += [f'    edit "{self.ifname(v)}"',
                    f'        set vdom "{vdom}"',
                    f'        set interface "{self.dev.parent_interface}"',
                    f"        set vlanid {v.id}",
                    f"        set ip {v.ip} {v.netmask}",
                    "        set allowaccess ping",
                    "        set role lan"]
            if v.description:
                out.append(f'        set description "{v.description}"')
            if v.dhcp_relay:
                out += ["        set dhcp-relay-service enable",
                        "        set dhcp-relay-ip " + " ".join(f'"{r}"' for r in v.dhcp_relay)]
            out.append("    next")
        out.append("end")
        if self.dev.policies:
            out.append("config firewall policy")
            for p in self.dev.policies:
                src, dst = self.ifname(self.vlan(p.src)), self.ifname(self.vlan(p.dst))
                act = "accept" if p.action in ("accept", "permit", "allow") else "deny"
                out += ["    edit 0",
                        f'        set name "{(src + "-to-" + dst)[:35]}"',
                        f'        set srcintf "{src}"',
                        f'        set dstintf "{dst}"',
                        '        set srcaddr "all"',
                        '        set dstaddr "all"',
                        f"        set action {act}",
                        '        set schedule "always"',
                        f'        set service "{p.service}"',
                        "    next"]
            out.append("end")
        return out


class PfSense(Vendor):
    key = "pfsense"
    title = "pfSense / OPNsense (config.xml)"
    covers = "pfSense CE/Plus, OPNsense (import via Diagnostics > Backup & Restore)"
    netmiko_type = None
    pushable = False
    supports_switching = False
    supports_policies = True
    requires_parent = True
    comment = "<!--"

    def header(self) -> list[str]:
        return [f"<!-- Generated by vlantool for {self.dev.name} ({self.title}).",
                "     Merge each section into the matching section of config.xml, then restore it.",
                "     Or create the same items by hand under Interfaces > Assignments > VLANs. -->"]

    def render(self) -> list[str]:
        parent = self.dev.parent_interface
        start = int(self.dev.options.get("opt_start", 1))
        opt = {v.id: f"opt{start + n}" for n, v in enumerate(self.routed)}
        out = ["<vlans>"]
        for v in self.routed:
            out += ["  <vlan>", f"    <if>{escape(parent)}</if>", f"    <tag>{v.id}</tag>",
                    "    <pcp></pcp>", f"    <descr><![CDATA[{v.name}]]></descr>",
                    f"    <vlanif>{escape(parent)}.{v.id}</vlanif>", "  </vlan>"]
        out += ["</vlans>", "<interfaces>"]
        for v in self.routed:
            out += [f"  <{opt[v.id]}>", f"    <descr><![CDATA[{v.name}]]></descr>",
                    f"    <if>{escape(parent)}.{v.id}</if>", "    <enable></enable>",
                    f"    <ipaddr>{v.ip}</ipaddr>", f"    <subnet>{v.prefixlen}</subnet>",
                    f"  </{opt[v.id]}>"]
        out.append("</interfaces>")
        relayed = [v for v in self.routed if v.dhcp_relay]
        if relayed:
            servers = ",".join(sorted({r for v in relayed for r in v.dhcp_relay}))
            out += ["<dhcrelay>", "  <enable></enable>",
                    f"  <interface>{','.join(opt[v.id] for v in relayed)}</interface>",
                    f"  <server>{servers}</server>", "</dhcrelay>"]
        if self.dev.policies:
            out.append("<filter>")
            for p in self.dev.policies:
                kind = "pass" if p.action in ("accept", "permit", "allow") else "block"
                out += ["  <rule>", f"    <type>{kind}</type>", f"    <interface>{opt[p.src]}</interface>",
                        "    <ipprotocol>inet</ipprotocol>",
                        f"    <source><network>{opt[p.src]}</network></source>",
                        f"    <destination><network>{opt[p.dst]}</network></destination>",
                        f"    <descr><![CDATA[{self.vlan(p.src).name} to {self.vlan(p.dst).name}]]></descr>",
                        "  </rule>"]
            out.append("</filter>")
        return out
