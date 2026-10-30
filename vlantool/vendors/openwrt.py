"""OpenWrt 21.02+ (DSA): VLANs, routing, firewall zones, DHCP and Wi-Fi through `uci`.

Covers routers and access points running OpenWrt (GL.iNet, Linksys, TP-Link Archer
with OpenWrt, Netgear, Xiaomi...). Paste into an SSH shell, or push over SSH.
"""
from __future__ import annotations

from .base import Vendor

DEFAULT_LAN_PORTS = ["lan1", "lan2", "lan3", "lan4"]


class OpenWrt(Vendor):
    key = "openwrt"
    title = "OpenWrt (uci, DSA)"
    covers = "OpenWrt 21.02+ routers and access points (GL.iNet, Linksys, Archer, Netgear, Xiaomi...)"
    netmiko_type = "linux"
    push_enter_config = False
    comment = "#"
    config_exit = []

    def l3_name(self, v) -> str:
        return f"vlan{v.id}"

    @property
    def bridge(self) -> str:
        return self.dev.options.get("bridge_device", "br-lan")

    def render(self) -> list[str]:
        out: list[str] = []
        br = self.bridge
        routed = set(self.dev.routed_vlans)
        switching = bool(self.dev.access or self.dev.trunks)
        lan_ports = self.dev.options.get("lan_ports", DEFAULT_LAN_PORTS)
        if switching:
            used = set(self.dev.access) | {t.port for t in self.trunks}
            keep = [p for p in lan_ports if p not in used]
            # once any bridge-vlan exists, the untouched LAN ports must sit in VLAN 1
            if 1 not in self.dev.vlan_ids:
                out += ["uci set network.bv1=bridge-vlan", f"uci set network.bv1.device='{br}'", "uci set network.bv1.vlan='1'"]
                out += [f"uci add_list network.bv1.ports='{p}:u*'" for p in keep]
                out.append(f"uci set network.lan.device='{br}.1'")
        for v in self.vlans:
            sec = f"network.bv{v.id}"
            if switching:
                out += [f"uci set {sec}=bridge-vlan", f"uci set {sec}.device='{br}'", f"uci set {sec}.vlan='{v.id}'"]
                for p in self.dev.access:
                    if self.dev.access[p] == v.id:
                        out.append(f"uci add_list {sec}.ports='{p}:u*'")
                for t in self.trunks:
                    if t.native == v.id:
                        out.append(f"uci add_list {sec}.ports='{t.port}:u*'")
                    elif v.id in t.allowed:
                        out.append(f"uci add_list {sec}.ports='{t.port}:t'")
            iface = f"network.{self.l3_name(v)}"
            device = f"{self.dev.parent_interface}.{v.id}" if self.dev.parent_interface else f"{br}.{v.id}"
            out += [f"uci set {iface}=interface", f"uci set {iface}.device='{device}'"]
            mgmt = self.dev.options.get("mgmt") or {}
            if v.id in routed:
                out += [f"uci set {iface}.proto='static'", f"uci set {iface}.ipaddr='{v.ip}'", f"uci set {iface}.netmask='{v.netmask}'"]
            elif mgmt.get("vlan") in (v.id, v.name):
                # this device's own management address on the VLAN (APs, switches)
                import ipaddress
                m = ipaddress.ip_interface(mgmt["address"])
                out += [f"uci set {iface}.proto='static'", f"uci set {iface}.ipaddr='{m.ip}'",
                        f"uci set {iface}.netmask='{m.network.netmask}'", f"uci set {iface}.gateway='{mgmt.get('gateway', v.ip if v.gateway else '')}'",
                        f"uci add_list {iface}.dns='{mgmt.get('dns', v.ip if v.gateway else '1.1.1.1')}'"]
            else:
                out.append(f"uci set {iface}.proto='none'")
        return out

    def body(self) -> list[str]:
        lines = super().body()
        return lines + ["uci commit", "reload_config"] if lines else lines


def router_lines(p, c) -> list[str]:
    """OpenWrt part of the router service (called from services.router)."""
    from ..services.router import pool
    out = [p.note("---- router ----")]
    wan = c["wan"]
    if c.get("hostname"):
        out.append(f"uci set system.@system[0].hostname='{c['hostname']}'")
    if wan.get("interface"):
        out += [f"uci set network.wan.device='{wan['interface']}'", f"uci set network.wan.proto='{wan['mode']}'"]
        if wan["mode"] == "static":
            from ..services.common import ip_only, mask
            out += [f"uci set network.wan.ipaddr='{ip_only(wan['address'])}'", f"uci set network.wan.netmask='{mask(wan['address'])}'",
                    f"uci set network.wan.gateway='{wan['gateway']}'"]
        elif wan["mode"] == "pppoe":
            out += [f"uci set network.wan.username='{wan.get('user', '')}'", f"uci set network.wan.password='{wan.get('password', '')}'"]
    out.append("uci set firewall.@zone[1].masq='1'" if c["nat"] else "uci set firewall.@zone[1].masq='0'")
    isolated = set(c["isolate_ids"])
    for v in p.routed:
        name = p.l3_name(v)
        if v.id in isolated:
            z = f"firewall.zone_{name}"
            out += [f"uci set {z}=zone", f"uci set {z}.name='{name}'", f"uci add_list {z}.network='{name}'",
                    f"uci set {z}.input='REJECT'", f"uci set {z}.output='ACCEPT'", f"uci set {z}.forward='REJECT'",
                    f"uci set firewall.fwd_{name}=forwarding", f"uci set firewall.fwd_{name}.src='{name}'",
                    "uci set firewall.fwd_{0}.dest='wan'".format(name)]
            for svc, port, proto in (("dhcp", 67, "udp"), ("dns", 53, "tcpudp")):
                r = f"firewall.allow_{name}_{svc}"
                out += [f"uci set {r}=rule", f"uci set {r}.name='Allow-{svc}-{name}'", f"uci set {r}.src='{name}'",
                        f"uci set {r}.dest_port='{port}'", f"uci set {r}.proto='{proto}'", f"uci set {r}.target='ACCEPT'"]
        else:
            out.append(f"uci add_list firewall.@zone[0].network='{name}'")
    if c["dns"]:
        out += ["uci -q delete dhcp.@dnsmasq[0].server"] + [f"uci add_list dhcp.@dnsmasq[0].server='{s}'" for s in c["dns"]]
        out.append("uci set network.wan.peerdns='0'")
    for vid in c["dhcp_ids"]:
        v = p.vlan(vid)
        start, end = pool(v)
        first = int(start.split(".")[-1])
        last = int(end.split(".")[-1])
        d = f"dhcp.{p.l3_name(v)}"
        out += [f"uci set {d}=dhcp", f"uci set {d}.interface='{p.l3_name(v)}'", f"uci set {d}.start='{first}'",
                f"uci set {d}.limit='{last - first + 1}'", f"uci set {d}.leasetime='12h'"]
    for n, f in enumerate(c["port_forwards"], 1):
        r = f"firewall.pf{n}"
        out += [f"uci set {r}=redirect", f"uci set {r}.name='forward-{f['port']}'", f"uci set {r}.target='DNAT'",
                f"uci set {r}.src='wan'", f"uci set {r}.src_dport='{f['port']}'", f"uci set {r}.dest_ip='{f['to']}'",
                f"uci set {r}.dest_port='{f.get('to_port', f['port'])}'", f"uci set {r}.proto='{f.get('proto', 'tcp')}'"]
    for n, r in enumerate(c["static_routes"], 1):
        from ..services.common import mask, net_of
        s = f"network.route{n}"
        from ..services.common import vlan_for_ip
        gw_vlan = vlan_for_ip(p, r["via"])
        out += [f"uci set {s}=route", f"uci set {s}.interface='{p.l3_name(gw_vlan) if gw_vlan else 'lan'}'", f"uci set {s}.target='{net_of(r['to']).network_address}'",
                f"uci set {s}.netmask='{mask(r['to'])}'", f"uci set {s}.gateway='{r['via']}'"]
    if c["ntp"]:
        out += ["uci -q delete system.ntp.server"] + [f"uci add_list system.ntp.server='{s}'" for s in c["ntp"]]
    return out
