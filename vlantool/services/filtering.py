"""Block unwanted sites per device, by MAC address, on routers and firewalls.

    devices:
      - name: hap
        vendor: mikrotik_routeros
        routing: all
        filtering:
          - name: kids-tablet
            mac: AA:BB:CC:DD:EE:01
            vlan: USERS                 # which VLAN the device sits on (for its static IP)
            block: [facebook.com, tiktok.com, instagram.com]
            categories: [adult, gambling, social]    # built-in domain lists (see CATEGORIES)
            schedule: {days: [mon,tue,wed,thu,fri], from: "22:00", to: "06:30"}   # optional
          - name: guest-laptop
            mac: AA:BB:CC:DD:EE:02
            ip: 192.168.20.50            # give the IP yourself instead of a VLAN
            categories: [adult]

A device is pinned to a static IP (by its MAC) and traffic from that IP to the
blocked domains is dropped. FortiGate matches the MAC directly.
"""
from __future__ import annotations

import ipaddress
import re

from ..model import parse_vlan_list
from .common import manual, mt_once

# small built-in category lists; extend freely
CATEGORIES = {
    "adult": ["pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "onlyfans.com", "redtube.com"],
    "gambling": ["bet365.com", "betway.com", "888casino.com", "pokerstars.com", "sportpesa.com", "1xbet.com"],
    "social": ["facebook.com", "instagram.com", "tiktok.com", "twitter.com", "x.com", "snapchat.com"],
    "streaming": ["netflix.com", "youtube.com", "twitch.tv", "hulu.com", "disneyplus.com"],
    "ads": ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com"],
}
DAYS = {"mon": "mon", "tue": "tue", "wed": "wed", "thu": "thu", "fri": "fri", "sat": "sat", "sun": "sun"}


def clients(p) -> list[dict]:
    """Normalised filtering entries for this device, each with a resolved IP where needed."""
    raw = p.dev.options.get("filtering")
    if not raw:
        return []
    out = []
    taken: dict[int, int] = {}  # vlan id -> next host offset
    for i, c in enumerate(raw if isinstance(raw, list) else [raw]):
        c = dict(c)
        domains = list(c.get("block") or [])
        for cat in (c.get("categories") or []):
            domains += CATEGORIES.get(cat, [])
        c["domains"] = sorted(set(d.lower().lstrip("*.") for d in domains))
        if not c.get("ip") and c.get("vlan") not in (None, ""):
            vid = parse_vlan_list(c["vlan"], p.net.vlans)
            v = p.net.vlans.get(vid[0]) if vid else None
            if v and v.gateway:
                off = taken.get(v.id, 240)
                taken[v.id] = off + 1
                c["ip"] = str(v.interface.network.network_address + off)
        c["slug"] = re.sub(r"[^a-z0-9]+", "-", str(c.get("name", c.get("mac", f"client{i}"))).lower()).strip("-")
        c["schedule"] = c.get("schedule")
        out.append(c)
    return out


def _sched_mt(s) -> str:
    if not s:
        return ""
    days = ",".join(DAYS[d[:3].lower()] for d in s.get("days", []) if d[:3].lower() in DAYS)
    span = f"{s['from']}:00-{s['to']}:00" if s.get("from") and s.get("to") else "0s-1d"
    if not days and span == "0s-1d":
        return ""
    return f" time={span}" + (f",{days}" if days else "")


# ------------------------------------------------------------------ MikroTik

def mikrotik(p, cs) -> list[str]:
    out = []
    for c in cs:
        if not c.get("ip"):
            out.append(p.note(f"filter {c['slug']}: give it an 'ip' or a 'vlan' so it has a fixed address"))
            continue
        if c.get("mac"):
            out.append(mt_once(f'/ip dhcp-server lease find address={c["ip"]}',
                               f'/ip dhcp-server lease add address={c["ip"]} mac-address={c["mac"]} comment="vlantool: {c["slug"]}"'))
        # layer7 regexp matching the domain in the TLS SNI / HTTP host
        for d in c["domains"]:
            name = f"vt-{c['slug']}-{re.sub(r'[^a-z0-9]+', '', d)[:16]}"
            rx = r"^.*\\b" + re.escape(d).replace(r"\\.", r"\\.") + r".*$"
            out.append(mt_once(f'/ip firewall layer7-protocol find name={name}',
                               f'/ip firewall layer7-protocol add name={name} regexp="{rx}"'))
            out.append(f'/ip firewall filter add chain=forward src-address={c["ip"]} layer7-protocol={name} '
                       f'action=drop comment="vlantool: block {d} for {c["slug"]}"{_sched_mt(c["schedule"])}')
        # also blackhole via DNS-independent address drop is impractical; note it
    if cs:
        out.append(p.note("layer7 matches the hostname in the TLS ClientHello; for HTTPS this blocks most sites. "
                          "For airtight filtering, point these clients' DNS at a filtering resolver."))
    return out


# ------------------------------------------------------------------ FortiGate

def fortinet(p, cs) -> list[str]:
    out = ["config firewall address"]
    for c in cs:
        if c.get("mac"):
            out += [f'    edit "mac-{c["slug"]}"', "        set type mac", f'        set macaddr "{c["mac"]}"', "    next"]
        elif c.get("ip"):
            out += [f'    edit "ip-{c["slug"]}"', "        set subnet " + f"{c['ip']} 255.255.255.255", "    next"]
    out.append("end")
    out.append("config webfilter urlfilter")
    for i, c in enumerate(cs, 1):
        out += [f"    edit {i}", f'        set name "vt-{c["slug"]}"', "        config entries"]
        for j, d in enumerate(c["domains"], 1):
            out += [f"            edit {j}", f'                set url "{d}"', "                set type wildcard",
                    "                set action block", "            next"]
        out += ["        end", "    next"]
    out.append("end")
    out.append("config webfilter profile")
    for c in cs:
        out += [f'    edit "vt-{c["slug"]}"', "        config web", f'            set urlfilter-table {cs.index(c) + 1}',
                "        end", "        set web-url-log enable", "    next"]
    out.append("end")
    out.append("config firewall policy")
    wan = (p.dev.options.get("router") or {}).get("wan") or {}
    wif = wan.get("interface") if isinstance(wan, dict) else wan
    for c in cs:
        src = f'mac-{c["slug"]}' if c.get("mac") else f'ip-{c["slug"]}'
        out += ["    edit 0", f'        set name "filter-{c["slug"]}"[:35]'.replace("[:35]", ""),
                "        set srcintf \"any\"", f'        set dstintf "{wif or "any"}"',
                f'        set srcaddr "{src}"', '        set dstaddr "all"', "        set action accept",
                '        set schedule "always"', '        set service "ALL"', "        set utm-status enable",
                f'        set webfilter-profile "vt-{c["slug"]}"', '        set ssl-ssh-profile "deep-inspection"',
                "        set nat enable", "    next"]
    return out + ["end", p.note("deep-inspection sees HTTPS URLs; install the FortiGate CA on the devices to avoid cert warnings")]


# ------------------------------------------------------------------- OpenWrt

def openwrt(p, cs) -> list[str]:
    out = ["# domains resolve into an nftables set; blocked clients are dropped to it",
           "uci set firewall.vt_blocked=ipset", "uci set firewall.vt_blocked.name='vt_blocked'",
           "uci set firewall.vt_blocked.family='ipv4'", "uci set firewall.vt_blocked.match='dest_ip'",
           "uci add_list firewall.vt_blocked.entry='0.0.0.0/32'"]
    all_domains = sorted({d for c in cs for d in c["domains"]})
    for d in all_domains:
        out.append(f"uci add_list dhcp.@dnsmasq[0].ipset='/{d}/vt_blocked'")
    for c in cs:
        if c.get("mac") and c.get("ip"):
            out += [f"uci set dhcp.lease_{c['slug']}=host", f"uci set dhcp.lease_{c['slug']}.mac='{c['mac']}'",
                    f"uci set dhcp.lease_{c['slug']}.ip='{c['ip']}'", f"uci set dhcp.lease_{c['slug']}.name='{c['slug']}'"]
        if not c.get("ip"):
            out.append(p.note(f"filter {c['slug']}: give it an 'ip' or a 'vlan'"))
            continue
        r = f"firewall.vtf_{c['slug'].replace('-', '_')}"
        out += [f"uci set {r}=rule", f"uci set {r}.name='block-{c['slug']}'", f"uci set {r}.src='lan'",
                f"uci set {r}.src_ip='{c['ip']}'", f"uci set {r}.ipset='vt_blocked'", f"uci set {r}.target='REJECT'"]
        s = c.get("schedule")
        if s:
            if s.get("from") and s.get("to"):
                out.append(f"uci set {r}.start_time='{s['from']}:00'")
                out.append(f"uci set {r}.stop_time='{s['to']}:00'")
            if s.get("days"):
                out.append(f"uci set {r}.weekdays='{' '.join(DAYS[d[:3].lower()] for d in s['days'] if d[:3].lower() in DAYS)}'")
    return out



# -------------------------------------------------------------------- Sophos

def sophos(p, cs) -> list[str]:
    out = [p.note("Protect > Web > URL groups, then a web policy and a firewall rule per client:")]
    for c in cs:
        who = c.get("name") or c.get("mac")
        src = (f'MAC host "{c["slug"]}" = {c["mac"]} (Hosts and services > MAC host)' if c.get("mac")
               else f'IP host "{c["slug"]}" = {c["ip"]} (Hosts and services > IP host)')
        out += [
            p.note(f"  {who}:"),
            p.note(f"    1. {src}"),
            p.note(f"    2. URL group 'vt-{c['slug']}' containing: {', '.join(c['domains'])}"),
            p.note(f"    3. Web policy 'vt-{c['slug']}': rule Deny the 'vt-{c['slug']}' URL group"),
            p.note(f"    4. Firewall rule for source {c['slug']}: enable 'Scan HTTP & HTTPS' and apply web policy 'vt-{c['slug']}'"),
        ]
        s3 = c.get("schedule")
        if s3:
            days = ", ".join(s3.get("days", [])) or "every day"
            out.append(p.note(f"    5. Attach a schedule ({s3.get('from')}-{s3.get('to')} on {days}) to that firewall rule "
                              "(System services > Schedule)"))
    out.append(p.note("HTTPS filtering needs decryption: Protect > Web > Decryption, and install the SFOS CA on the clients"))
    return out


def render(plugin) -> list[str]:
    cs = clients(plugin)
    if not cs:
        return []
    out = [plugin.note("---- content filtering ----")]
    if plugin.key == "mikrotik_routeros":
        return out + mikrotik(plugin, cs)
    if plugin.key == "fortinet":
        return out + fortinet(plugin, cs)
    if plugin.key == "openwrt":
        return out + openwrt(plugin, cs)
    if plugin.key == "sophos":
        return out + sophos(plugin, cs)
    steps = []
    for c in cs:
        who = c.get("name") or c.get("mac")
        steps.append(f"Block these domains for {who} ({c.get('mac') or c.get('ip')}): {', '.join(c['domains'])}")
        if c.get("schedule"):
            steps.append(f"  only during {c['schedule'].get('from')}-{c['schedule'].get('to')} on {', '.join(c['schedule'].get('days', []))}")
    steps.append("Do this with the device's web/content filter, or point these clients at a filtering DNS resolver")
    return out + manual(plugin, "Content filtering", steps)


def validate(net, device) -> tuple[list[str], list[str]]:
    raw = device.options.get("filtering")
    if not raw:
        return [], []
    errors, warnings = [], []
    where = f"device {device.name}: filtering"
    mac_re = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
    for c in (raw if isinstance(raw, list) else [raw]):
        if not c.get("block") and not c.get("categories"):
            errors.append(f"{where}: entry {c.get('name', c.get('mac'))} needs 'block' domains or 'categories'")
        if c.get("mac") and not mac_re.match(str(c["mac"])):
            errors.append(f"{where}: {c.get('name')} mac {c['mac']!r} is not a MAC address")
        if not c.get("mac") and not c.get("ip"):
            errors.append(f"{where}: {c.get('name')} needs a 'mac' (and 'vlan' or 'ip') or an 'ip'")
        if c.get("ip"):
            try:
                ipaddress.ip_address(c["ip"])
            except ValueError:
                errors.append(f"{where}: {c.get('name')} ip {c['ip']!r} is not an IP address")
        if c.get("vlan") not in (None, ""):
            try:
                vid = parse_vlan_list(c["vlan"], net.vlans)
                if not vid or vid[0] not in device.routed_vlans:
                    warnings.append(f"{where}: {c.get('name')} vlan {c['vlan']} is not routed by this device; give an 'ip' instead")
            except ValueError as exc:
                errors.append(f"{where}: {c.get('name')}: {exc}")
        for cat in (c.get("categories") or []):
            if cat not in CATEGORIES:
                warnings.append(f"{where}: unknown category {cat!r} (known: {', '.join(CATEGORIES)})")
    from ..vendors import REGISTRY
    plugin = REGISTRY.get(device.vendor)
    if plugin and plugin.key not in ("mikrotik_routeros", "fortinet", "openwrt", "sophos"):
        warnings.append(f"{where}: {plugin.title} gets manual steps for content filtering")
    return errors, warnings
