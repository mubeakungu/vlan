"""Point-to-point links between two devices: wired or wireless, routed or bridged.

    links:
      - name: tower
        a: {device: hap, interface: ether3, address: 10.255.0.1/30}
        b: {device: branch-router, interface: eth1, address: 10.255.0.2/30}
        routing: static            # static (default), ospf, or none
        wireless:                  # optional: radio link, side a = AP, side b = station
          ssid: ptp-tower
          passphrase: change-me-please
          frequency: 5745          # MHz
          width: 40                # 20, 40 or 80 MHz
          country: kenya

Without addresses the link is a layer 2 bridge: list the link interface under
the device's `trunks` so the VLANs cross it.
"""
from __future__ import annotations

from .common import ip_only, manual, mask, net_of

WIDTH_MT_WIFI = {20: "20mhz", 40: "20/40mhz", 80: "20/40/80mhz", 160: "20/40/80/160mhz"}
WIDTH_MT_LEGACY = {20: "20mhz", 40: "20/40mhz-XX", 80: "20/40/80mhz-XXXX"}


def sides(plugin):
    """(link, this side, other side, side letter) for every link touching this device."""
    for link in plugin.net.links:
        for me, other in (("a", "b"), ("b", "a")):
            s = link.get(me) or {}
            if s.get("device") == plugin.dev.name:
                yield link, s, link.get(other) or {}, me


def remote_networks(plugin, other: dict) -> list[str]:
    try:
        dev = plugin.net.device(other.get("device"))
    except Exception:
        return []
    nets = [plugin.net.vlans[v].network for v in dev.routed_vlans if v in plugin.net.vlans]
    return nets + [str(n) for n in other.get("networks", [])]


def local_networks(plugin) -> list[str]:
    return [v.network for v in plugin.routed]


# ------------------------------------------------------------ addressing

def addr_lines(p, link, me, other) -> list[str]:
    name, iface, addr = link.get("name", "link"), me.get("interface"), me.get("address")
    if not addr:
        return []
    peer = ip_only(other["address"]) if other.get("address") else None
    routes = remote_networks(p, other) if link.get("routing", "static") == "static" and peer else []
    k = p.key
    out: list[str] = []
    if k == "mikrotik_routeros":
        # a routed port cannot be a bridge member (default hAP/hEX ports are)
        out.append(f"/interface bridge port remove [find interface={iface}]")
        out.append(f'/ip address add address={addr} interface={iface} comment="link {name}"')
        out += [f'/ip route add dst-address={n} gateway={peer} comment="link {name}"' for n in routes]
        if p.dev.options.get("lan_list", True):
            out.append(f"/interface list member add list=LAN interface={iface}")
    elif k in ("cisco_ios", "cisco_nxos", "arista_eos", "dell_os10", "dlink_dgs", "cisco_smb"):
        nx = k in ("cisco_nxos", "arista_eos", "dell_os10")
        out += [f"interface {iface}", f" description link {name}"]
        if nx or p.dev.access or p.dev.trunks:
            out.append(" no switchport")
        ipaddr = f"{addr}" if nx else f"{ip_only(addr)} {mask(addr)}"
        out += [f" ip address {ipaddr}", " no shutdown"]
        out += [f"ip route {n}" + f" {peer}" if nx else f"ip route {net_of(n).network_address} {mask(n)} {peer}" for n in routes]
    elif k == "juniper_junos":
        out.append(f"set interfaces {iface} unit 0 family inet address {addr}")
        out += [f"set routing-options static route {n} next-hop {peer}" for n in routes]
    elif k == "aruba_aoscx":
        out += [f"interface {iface}", "    routing", f"    ip address {addr}", "    no shutdown"]
        out += [f"ip route {n} {peer}" for n in routes]
    elif k in ("huawei_vrp", "hp_comware"):
        out += [f"interface {iface}", " undo portswitch" if k == "huawei_vrp" else " port link-mode route",
                f" ip address {ip_only(addr)} {mask(addr)}", " quit"]
        out += [f"ip route-static {net_of(n).network_address} {mask(n)} {peer}" for n in routes]
    elif k in ("ubiquiti_edgeos", "vyos"):
        out.append(f"set interfaces ethernet {iface} address {addr}")
        out.append(f"set interfaces ethernet {iface} description link-{name}")
        out += [f"set protocols static route {n} next-hop {peer}" for n in routes]
    elif k == "fortinet":
        out += ["config system interface", f'    edit "{iface}"', "        set mode static",
                f"        set ip {ip_only(addr)} {mask(addr)}", "        set allowaccess ping", "    next", "end"]
        if routes:
            out.append("config router static")
            for n in routes:
                out += ["    edit 0", f"        set dst {net_of(n).network_address} {mask(n)}", f"        set gateway {peer}",
                        f'        set device "{iface}"', "    next"]
            out.append("end")
        out.append("config firewall policy")
        for v in p.routed:
            for src, dst in ((p.l3_name(v), iface), (iface, p.l3_name(v))):
                out += ["    edit 0", f'        set name "{(src + "-to-" + dst)[:35]}"', f'        set srcintf "{src}"',
                        f'        set dstintf "{dst}"', '        set srcaddr "all"', '        set dstaddr "all"',
                        "        set action accept", '        set schedule "always"', '        set service "ALL"', "    next"]
        out.append("end")
    elif k == "openwrt":
        sec = f"network.link_{name.replace('-', '_')}"
        out += [f"uci set {sec}=interface", f"uci set {sec}.proto='static'", f"uci set {sec}.device='{iface}'",
                f"uci set {sec}.ipaddr='{ip_only(addr)}'", f"uci set {sec}.netmask='{mask(addr)}'",
                f"uci add_list firewall.@zone[0].network='link_{name.replace('-', '_')}'"]
        for i, n in enumerate(routes, 1):
            r = f"network.link_{name.replace('-', '_')}_r{i}"
            out += [f"uci set {r}=route", f"uci set {r}.interface='link_{name.replace('-', '_')}'",
                    f"uci set {r}.target='{net_of(n).network_address}'", f"uci set {r}.netmask='{mask(n)}'", f"uci set {r}.gateway='{peer}'"]
    else:
        steps = [f"Give {iface} the address {addr}"]
        steps += [f"Add a static route to {n} via {peer}" for n in routes]
        return manual(p, f"Link {name}", steps)
    return out


# ------------------------------------------------------------------- OSPF

def ospf_lines(p, link, me) -> list[str]:
    if link.get("routing") != "ospf" or not me.get("address"):
        return []
    link_net = str(net_of(me["address"]))
    nets = [link_net] + local_networks(p)
    k = p.key
    if k == "mikrotik_routeros":
        from .common import mt_once
        return [mt_once("/routing ospf instance find name=vlantool", "/routing ospf instance add name=vlantool version=2"),
                mt_once("/routing ospf area find name=backbone-vlantool",
                        "/routing ospf area add name=backbone-vlantool area-id=0.0.0.0 instance=vlantool"),
                f"/routing ospf interface-template add area=backbone-vlantool networks={link_net}",
                ] + [f"/routing ospf interface-template add area=backbone-vlantool networks={n} passive" for n in local_networks(p)]
    if k == "cisco_ios":
        return ["router ospf 1"] + [f" network {net_of(n).network_address} {net_of(n).hostmask} area 0" for n in nets] + \
               [f" passive-interface {p.l3_name(v)}" for v in p.routed]
    if k == "vyos":
        return [f"set protocols ospf area 0 network {n}" for n in nets] + \
               [f"set protocols ospf interface {p.l3_name(v)} passive" for v in p.routed]
    if k == "ubiquiti_edgeos":
        return [f"set protocols ospf area 0.0.0.0 network {n}" for n in nets] + \
               [f"set protocols ospf passive-interface {p.l3_name(v)}" for v in p.routed]
    if k == "juniper_junos":
        return [f"set protocols ospf area 0.0.0.0 interface {me['interface']}.0"] + \
               [f"set protocols ospf area 0.0.0.0 interface {p.l3_name(v)} passive" for v in p.routed]
    return manual(p, f"OSPF for link {link.get('name')}", [f"Enable OSPF area 0 on {', '.join(nets)}"])


# --------------------------------------------------------------- wireless

def radio_lines(p, link, me, side) -> list[str]:
    w = link.get("wireless")
    if not w:
        return []
    name, iface = link.get("name", "link"), me.get("interface")
    ap = side == "a"
    freq, width = w.get("frequency"), int(w.get("width", 20))
    country = w.get("country", p.dev.options.get("country", "etsi"))
    k = p.key
    if k == "mikrotik_routeros":
        if p.dev.options.get("wifi_driver", "wifi") == "wireless":
            sp = f"sp-{name}"
            out = [f"/interface wireless security-profiles add name={sp} mode=dynamic-keys authentication-types=wpa2-psk "
                   f'wpa2-pre-shared-key="{w["passphrase"]}"']
            line = (f"/interface wireless set [find default-name={iface}] mode={'bridge' if ap else 'station-bridge'} "
                    f"ssid={w['ssid']} security-profile={sp} country={country} wps-mode=disabled")
            if freq:
                line += f" frequency={freq}"
            if width in WIDTH_MT_LEGACY:
                line += f" channel-width={WIDTH_MT_LEGACY[width]}"
            return out + [line + " disabled=no"]
        line = (f"/interface wifi set [find default-name={iface}] configuration.mode={'ap' if ap else 'station-bridge'} "
                f"configuration.ssid={w['ssid']} configuration.country={country} "
                f'security.authentication-types=wpa2-psk,wpa3-psk security.passphrase="{w["passphrase"]}"')
        if freq:
            line += f" channel.frequency={freq}"
        if width in WIDTH_MT_WIFI:
            line += f" channel.width={WIDTH_MT_WIFI[width]}"
        return [line + " disabled=no"]
    if k == "openwrt":
        sec = f"wireless.ptp_{name.replace('-', '_')}"
        net = f"link_{name.replace('-', '_')}" if me.get("address") else "lan"
        out = [f"uci set wireless.{iface}.disabled='0'", f"uci set wireless.{iface}.country='{w.get('country_code', 'KE')}'"]
        if freq:
            ch = (int(freq) - 5000) // 5 if int(freq) > 5000 else (int(freq) - 2407) // 5
            out.append(f"uci set wireless.{iface}.channel='{ch}'")
        out.append(f"uci set wireless.{iface}.htmode='VHT{width}'" if int(freq or 5000) > 5000 else f"uci set wireless.{iface}.htmode='HT{width}'")
        out += [f"uci set {sec}=wifi-iface", f"uci set {sec}.device='{iface}'", f"uci set {sec}.mode='{'ap' if ap else 'sta'}'",
                f"uci set {sec}.ssid='{w['ssid']}'", f"uci set {sec}.encryption='psk2'", f"uci set {sec}.key='{w['passphrase']}'",
                f"uci set {sec}.network='{net}'", f"uci set {sec}.wds='1'"]
        return out
    return manual(p, f"Radio link {name}", [
        f"Set wireless mode to {'Access Point (PtP / WDS)' if ap else 'Station (WDS / transparent bridge)'}",
        f"SSID {w['ssid']}, WPA2-PSK passphrase {w['passphrase']}",
        f"Frequency {freq or 'auto'} MHz, channel width {width} MHz, country {country}",
        "Enable WDS / transparent bridge mode so the VLANs pass through",
        "Align the antennas for the best signal (aim for -50 to -65 dBm)",
    ])


def render(plugin) -> list[str]:
    out: list[str] = []
    for link, me, other, side in sides(plugin):
        block = radio_lines(plugin, link, me, side) + addr_lines(plugin, link, me, other) + ospf_lines(plugin, link, me)
        if block:
            out += [plugin.note(f"---- link {link.get('name', '')} ----")] + block
    return out


def validate(net, device) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    if device is not net.devices[0]:
        return errors, warnings  # links are checked once
    names = {d.name for d in net.devices}
    for link in net.links:
        where = f"link {link.get('name', '?')}"
        for side in ("a", "b"):
            s = link.get(side) or {}
            if s.get("device") not in names:
                errors.append(f"{where}: side {side} device {s.get('device')!r} is not in 'devices'")
            if not s.get("interface"):
                errors.append(f"{where}: side {side} needs 'interface'")
            if s.get("address"):
                try:
                    net_of(s["address"])
                    if "/" not in s["address"]:
                        raise ValueError
                except ValueError:
                    errors.append(f"{where}: side {side} address {s['address']!r} must look like 10.255.0.1/30")
        a, b = link.get("a") or {}, link.get("b") or {}
        if bool(a.get("address")) != bool(b.get("address")):
            errors.append(f"{where}: give both sides an address (routed) or neither (bridged)")
        elif a.get("address") and b.get("address") and net_of(a["address"]) != net_of(b["address"]):
            errors.append(f"{where}: both addresses must be in the same subnet")
        if link.get("routing", "static") not in ("static", "ospf", "none"):
            errors.append(f"{where}: routing must be static, ospf or none")
        w = link.get("wireless")
        if w:
            if not w.get("ssid") or len(str(w.get("passphrase", ""))) < 8:
                errors.append(f"{where}: wireless needs 'ssid' and a 'passphrase' of 8+ characters")
        if not a.get("address"):
            for s in (a, b):
                try:
                    dev = net.device(s.get("device"))
                except Exception:
                    continue
                if s.get("interface") not in {t.port for t in dev.trunks}:
                    warnings.append(f"{where}: bridged link; add {s.get('interface')} to {dev.name}'s trunks so VLANs cross it")
    return errors, warnings
