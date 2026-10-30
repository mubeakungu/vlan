"""Router / edge router basics: WAN, NAT, DNS, DHCP, firewall, isolation, port forwards, routes, NTP.

    router:
      hostname: edge1
      wan: {interface: ether1, mode: dhcp}        # or static (address, gateway) or pppoe (user, password)
      nat: true                                    # masquerade everything out of the WAN (default true)
      dns: [1.1.1.1, 8.8.8.8]                      # upstream DNS; the router answers LAN clients
      dhcp_server: all                             # routed VLANs that get a DHCP server
      firewall: true                               # block unsolicited traffic from the WAN (default true)
      isolate: [GUEST]                             # these VLANs reach the internet only
      port_forwards:
        - {proto: tcp, port: 443, to: 192.168.10.5, to_port: 443}
      static_routes:
        - {to: 10.20.0.0/16, via: 10.255.0.2}
      ntp: [pool.ntp.org]
"""
from __future__ import annotations

import ipaddress

from ..model import parse_vlan_list
from .common import as_list, ip_only, manual, mask, mt_once, net_of, vlan_for_ip, wildcard

PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def cfg(plugin) -> dict | None:
    raw = plugin.dev.options.get("router")
    if not raw:
        return None
    c = dict(raw)
    wan = c.get("wan") or {}
    if isinstance(wan, str):
        wan = {"interface": wan}
    wan.setdefault("mode", "dhcp")
    c["wan"] = wan
    c.setdefault("nat", bool(wan.get("interface")))
    c.setdefault("firewall", True)
    c["dns"] = as_list(c.get("dns"))
    c["ntp"] = as_list(c.get("ntp"))
    c["dhcp_ids"] = [v for v in parse_vlan_list(c.get("dhcp_server"), plugin.net.vlans) if v in plugin.dev.routed_vlans]
    c["isolate_ids"] = [v for v in parse_vlan_list(c.get("isolate"), plugin.net.vlans) if v in plugin.dev.routed_vlans]
    # A DMZ VLAN is isolated from the LAN exactly like an isolated VLAN, but it also
    # hosts services reachable from the WAN (via port_forwards). So it reuses the
    # tested "block traffic to private networks" rules, and we track it separately
    # for labelling and the scanner.
    c["dmz_ids"] = [v for v in parse_vlan_list(c.get("dmz"), plugin.net.vlans) if v in plugin.dev.routed_vlans]
    for vid in c["dmz_ids"]:
        if vid not in c["isolate_ids"]:
            c["isolate_ids"].append(vid)
    c["port_forwards"] = as_list(c.get("port_forwards"))
    c["static_routes"] = as_list(c.get("static_routes"))
    return c


def pool(v) -> tuple[str, str]:
    net = v.interface.network
    first, last = net.network_address + 1, net.broadcast_address - 1
    start = first + 9 if net.num_addresses > 32 else first
    if v.interface.ip >= start:  # keep the gateway out of the pool
        start = first if v.interface.ip != first else first + 1
    return str(start), str(last)


def dns_for(c, v) -> str:
    return v.ip if c["dns"] else "1.1.1.1"


# ------------------------------------------------------------------ MikroTik

def mikrotik(p, c) -> list[str]:
    out = [p.note("---- router ----")]
    wan = c["wan"]
    wif = wan.get("interface")
    if c.get("hostname"):
        out.append(f"/system identity set name={c['hostname']}")
    if wif:
        out.append(mt_once('/interface list find name=WAN', '/interface list add name=WAN'))
        out.append(mt_once('/interface list find name=LAN', '/interface list add name=LAN'))
        if wan["mode"] == "pppoe":
            out.append(mt_once("/interface pppoe-client find name=pppoe-out1",
                               f'/interface pppoe-client add name=pppoe-out1 interface={wif} user="{wan.get("user", "")}" '
                               f'password="{wan.get("password", "")}" add-default-route=yes use-peer-dns=yes disabled=no'))
            wif = "pppoe-out1"
        elif wan["mode"] == "static":
            out.append(f"/ip address add address={wan['address']} interface={wif}")
            out.append(f"/ip route add dst-address=0.0.0.0/0 gateway={wan['gateway']}")
        else:
            out.append(mt_once(f"/ip dhcp-client find interface={wif}", f"/ip dhcp-client add interface={wif} disabled=no"))
        out.append(mt_once(f"/interface list member find list=WAN interface={wif}",
                           f"/interface list member add list=WAN interface={wif}"))
    if c["nat"]:
        out.append(mt_once('/ip firewall nat find comment="vlantool: masquerade"',
                           '/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="vlantool: masquerade"'))
    if c["dns"]:
        out.append(f"/ip dns set servers={','.join(c['dns'])} allow-remote-requests=yes")
    if c["firewall"]:
        rules = [
            ("input", "connection-state=established,related,untracked action=accept", "in: established"),
            ("input", "connection-state=invalid action=drop", "in: drop invalid"),
            ("input", "protocol=icmp action=accept", "in: icmp"),
            ("input", "in-interface-list=!LAN action=drop", "in: drop not from LAN"),
            ("forward", "connection-state=established,related,untracked action=accept", "fwd: established"),
            ("forward", "connection-state=invalid action=drop", "fwd: drop invalid"),
            ("forward", "connection-state=new connection-nat-state=!dstnat in-interface-list=WAN action=drop", "fwd: drop WAN not dstnat"),
        ]
        for chain, rule, name in rules:
            out.append(mt_once(f'/ip firewall filter find comment="vlantool: {name}"',
                               f'/ip firewall filter add chain={chain} {rule} comment="vlantool: {name}"'))
    # DMZ interfaces are kept out of the LAN list (see the vendor render), so the router
    # would also block their DHCP/DNS/ping. Allow just those to the router, nothing else.
    for vid in c["dmz_ids"]:
        v = p.vlan(vid)
        out.append(mt_once(f'/ip firewall filter find comment="vlantool: dmz svc {v.name}"',
                           f'/ip firewall filter add chain=input in-interface={p.l3_name(v)} protocol=udp '
                           f'dst-port=53,67 action=accept comment="vlantool: dmz svc {v.name}" place-before=0'))
    for vid in c["isolate_ids"]:
        v = p.vlan(vid)
        for net in PRIVATE:
            out.append(f'/ip firewall filter add chain=forward in-interface={p.l3_name(v)} dst-address={net} '
                       f'connection-state=new action=drop comment="vlantool: isolate {v.name}" place-before=0')
    for n, f in enumerate(c["port_forwards"], 1):
        out.append(f'/ip firewall nat add chain=dstnat in-interface-list=WAN protocol={f.get("proto", "tcp")} '
                   f'dst-port={f["port"]} action=dst-nat to-addresses={f["to"]} to-ports={f.get("to_port", f["port"])} '
                   f'comment="vlantool: forward {f.get("name", f["port"])}"')
    for r in c["static_routes"]:
        out.append(f"/ip route add dst-address={r['to']} gateway={r['via']}")
    if c["ntp"]:
        out.append(f"/system ntp client set enabled=yes servers={','.join(c['ntp'])}")
    return out


# ----------------------------------------------------------------- Cisco IOS

def cisco(p, c) -> list[str]:
    from .vpn import ipsec_pairs
    out = [p.note("---- router ----")]
    wan = c["wan"]
    wif = wan.get("interface")
    inside = [p.l3_name(v) for v in p.routed]
    if c.get("hostname"):
        out.append(f"hostname {c['hostname']}")
    if wif:
        out += [f"interface {wif}", " description WAN"]
        if wan["mode"] == "pppoe":
            out += [" pppoe enable group global", " pppoe-client dial-pool-number 1", " no shutdown",
                    "interface Dialer1", " description WAN-PPPoE", " ip address negotiated", " ip mtu 1492",
                    " ip tcp adjust-mss 1452", " encapsulation ppp", " dialer pool 1",
                    f" ppp chap hostname {wan.get('user', '')}", f" ppp chap password {wan.get('password', '')}",
                    f" ppp pap sent-username {wan.get('user', '')} password {wan.get('password', '')}"]
            wif = "Dialer1"
            out += [" ip nat outside", "ip route 0.0.0.0 0.0.0.0 Dialer1"]
        else:
            if wan["mode"] == "static":
                out.append(f" ip address {ip_only(wan['address'])} {mask(wan['address'])}")
            else:
                out.append(" ip address dhcp")
            out += [" ip nat outside", " no shutdown"]
            if wan["mode"] == "static":
                out.append(f"ip route 0.0.0.0 0.0.0.0 {wan['gateway']}")
    if c["nat"] and wif:
        out += [f"interface {i}\n ip nat inside" for i in inside]
        out.append("ip access-list extended VLANTOOL-NAT")
        for local, remote in ipsec_pairs(p):
            out.append(f" deny ip {net_of(local).network_address} {wildcard(local)} {net_of(remote).network_address} {wildcard(remote)}")
        for v in p.routed:
            out.append(f" permit ip {v.interface.network.network_address} {wildcard(v.network)} any")
        out.append(f"ip nat inside source list VLANTOOL-NAT interface {wif} overload")
    if c["dns"]:
        out += [f"ip name-server {' '.join(c['dns'])}", "ip domain lookup", "ip dns server"]
    for vid in c["dhcp_ids"]:
        v = p.vlan(vid)
        start, end = pool(v)
        first = str(v.interface.network.network_address + 1)
        before_start = str(ipaddress.ip_address(start) - 1)
        if ipaddress.ip_address(before_start) >= ipaddress.ip_address(first):
            out.append(f"ip dhcp excluded-address {first} {before_start}")
        out.append(f"ip dhcp excluded-address {v.ip}")
        out += [f"ip dhcp pool {v.name}", f" network {v.interface.network.network_address} {v.netmask}",
                f" default-router {v.ip}", f" dns-server {dns_for(c, v)}"]
    for vid in c["isolate_ids"]:
        v = p.vlan(vid)
        acl = f"VLANTOOL-ISOLATE-{v.name}"
        out += [f"ip access-list extended {acl}",
                " permit udp any any eq bootps",
                f" permit udp any host {v.ip} eq domain", f" permit tcp any host {v.ip} eq domain"]
        out += [f" deny ip any {net_of(n).network_address} {wildcard(n)}" for n in PRIVATE]
        out += [" permit ip any any", f"interface {p.l3_name(v)}", f" ip access-group {acl} in"]
    if c["firewall"] and wif:
        out += ["zone security INSIDE", "zone security OUTSIDE",
                "class-map type inspect match-any VLANTOOL-ALL",
                " match protocol tcp", " match protocol udp", " match protocol icmp",
                "policy-map type inspect VLANTOOL-IN-OUT", " class type inspect VLANTOOL-ALL", "  inspect",
                " class class-default", "  drop",
                "zone-pair security IN-OUT source INSIDE destination OUTSIDE",
                " service-policy type inspect VLANTOOL-IN-OUT"]
        if c["port_forwards"]:
            out.append("ip access-list extended VLANTOOL-PORT-FORWARDS")
            out += [f" permit {f.get('proto', 'tcp')} any host {f['to']} eq {f.get('to_port', f['port'])}" for f in c["port_forwards"]]
            out += ["class-map type inspect match-all VLANTOOL-PF", " match access-group name VLANTOOL-PORT-FORWARDS",
                    "policy-map type inspect VLANTOOL-OUT-IN", " class type inspect VLANTOOL-PF", "  inspect",
                    " class class-default", "  drop",
                    "zone-pair security OUT-IN source OUTSIDE destination INSIDE",
                    " service-policy type inspect VLANTOOL-OUT-IN"]
        out += [f"interface {wif}", " zone-member security OUTSIDE"]
        out += [f"interface {i}\n zone-member security INSIDE" for i in inside]
    for f in c["port_forwards"]:
        out.append(f"ip nat inside source static {f.get('proto', 'tcp')} {f['to']} {f.get('to_port', f['port'])} "
                   f"interface {wif} {f['port']}")
    for r in c["static_routes"]:
        out.append(f"ip route {net_of(r['to']).network_address} {mask(r['to'])} {r['via']}")
    out += [f"ntp server {s}" for s in c["ntp"]]
    # "interface X\n sub" entries above keep related lines together; flatten them
    return [line for item in out for line in item.split("\n")]


# ------------------------------------------------------------ EdgeOS / VyOS

def edgeos(p, c) -> list[str]:
    out = [p.note("---- router ----")]
    wan = c["wan"]
    wif = wan.get("interface")
    kind = "switch" if (wif or "").startswith("switch") else "ethernet"
    if c.get("hostname"):
        out.append(f"set system host-name {c['hostname']}")
    if wif:
        base = f"set interfaces {kind} {wif}"
        if wan["mode"] == "pppoe":
            out += [f"{base} pppoe 0 user-id {wan.get('user', '')}", f"{base} pppoe 0 password {wan.get('password', '')}",
                    f"{base} pppoe 0 default-route auto", f"{base} pppoe 0 name-server auto", f"{base} pppoe 0 mtu 1492"]
            out_if = "pppoe0"
        elif wan["mode"] == "static":
            out += [f"{base} address {wan['address']}", f"set protocols static route 0.0.0.0/0 next-hop {wan['gateway']}"]
            out_if = wif
        else:
            out.append(f"{base} address dhcp")
            out_if = wif
        if c["nat"]:
            out += ["set service nat rule 5010 description masquerade-WAN", f"set service nat rule 5010 outbound-interface {out_if}",
                    "set service nat rule 5010 type masquerade"]
        if c["firewall"]:
            for name, default in (("WAN_IN", "drop"), ("WAN_LOCAL", "drop")):
                fw = f"set firewall name {name}"
                out += [f"{fw} default-action {default}",
                        f"{fw} rule 10 action accept", f"{fw} rule 10 state established enable", f"{fw} rule 10 state related enable",
                        f"{fw} rule 20 action drop", f"{fw} rule 20 state invalid enable"]
            out += [f"set interfaces {kind} {wif} firewall in name WAN_IN" if wan["mode"] != "pppoe"
                    else f"set interfaces {kind} {wif} pppoe 0 firewall in name WAN_IN",
                    f"set interfaces {kind} {wif} firewall local name WAN_LOCAL" if wan["mode"] != "pppoe"
                    else f"set interfaces {kind} {wif} pppoe 0 firewall local name WAN_LOCAL"]
        if c["port_forwards"]:
            out += ["set port-forward auto-firewall enable", "set port-forward hairpin-nat enable",
                    f"set port-forward wan-interface {out_if}"]
            out += [f"set port-forward lan-interface {p.l3_name(v)}" for v in p.routed]
            for n, f in enumerate(c["port_forwards"], 1):
                pf = f"set port-forward rule {n}"
                out += [f"{pf} description {f.get('name', 'forward-' + str(f['port']))}", f"{pf} original-port {f['port']}",
                        f"{pf} protocol {f.get('proto', 'tcp')}", f"{pf} forward-to address {f['to']}",
                        f"{pf} forward-to port {f.get('to_port', f['port'])}"]
    if c["dns"]:
        out += [f"set system name-server {s}" for s in c["dns"]]
        out += ["set service dns forwarding cache-size 1000"] + [f"set service dns forwarding listen-on {p.l3_name(v)}" for v in p.routed]
    for vid in c["dhcp_ids"]:
        v = p.vlan(vid)
        start, end = pool(v)
        sn = f"set service dhcp-server shared-network-name {v.name} subnet {v.network}"
        out += [f"{sn} default-router {v.ip}", f"{sn} dns-server {dns_for(c, v)}", f"{sn} start {start} stop {end}"]
    for vid in c["isolate_ids"]:
        v = p.vlan(vid)
        fw = f"set firewall name ISOLATE_{v.name}"
        out.append(f"{fw} default-action accept")
        for n, net in enumerate(PRIVATE, 1):
            out += [f"{fw} rule {n * 10} action drop", f"{fw} rule {n * 10} destination address {net}"]
        out.append(f"set interfaces {_kind(p.dev.parent_interface)} {p.dev.parent_interface} vif {v.id} "
                   f"firewall in name ISOLATE_{v.name}")
    out += [f"set protocols static route {r['to']} next-hop {r['via']}" for r in c["static_routes"]]
    out += [f"set system ntp server {s}" for s in c["ntp"]]
    return out


def _kind(iface: str) -> str:
    return "switch" if iface.startswith("switch") else "bonding" if iface.startswith("bond") else "ethernet"


def vyos(p, c) -> list[str]:
    """VyOS 1.4+ syntax."""
    out = [p.note("---- router ----")]
    wan = c["wan"]
    wif = wan.get("interface")
    if c.get("hostname"):
        out.append(f"set system host-name {c['hostname']}")
    out_if = wif
    if wif:
        if wan["mode"] == "pppoe":
            out += [f"set interfaces pppoe pppoe0 source-interface {wif}",
                    f"set interfaces pppoe pppoe0 authentication username {wan.get('user', '')}",
                    f"set interfaces pppoe pppoe0 authentication password {wan.get('password', '')}",
                    "set interfaces pppoe pppoe0 mtu 1492"]
            out_if = "pppoe0"
        elif wan["mode"] == "static":
            out += [f"set interfaces ethernet {wif} address {wan['address']}",
                    f"set protocols static route 0.0.0.0/0 next-hop {wan['gateway']}"]
        else:
            out.append(f"set interfaces ethernet {wif} address dhcp")
        if c["nat"]:
            out += [f"set nat source rule 100 outbound-interface name {out_if}",
                    "set nat source rule 100 translation address masquerade"]
        if c["firewall"]:
            for chain in ("forward", "input"):
                fw = f"set firewall ipv4 {chain} filter"
                out += [f"{fw} default-action accept",
                        f"{fw} rule 10 action accept", f"{fw} rule 10 state established", f"{fw} rule 10 state related",
                        f"{fw} rule 20 action drop", f"{fw} rule 20 state invalid"]
                if chain == "forward" and c["port_forwards"]:
                    out += [f"{fw} rule 30 action accept", f"{fw} rule 30 connection-status nat destination"]
                out += [f"{fw} rule 90 action drop", f"{fw} rule 90 inbound-interface name {out_if}", f"{fw} rule 90 state new"]
                if chain == "input":
                    out[-3:-3] = [f"{fw} rule 40 action accept", f"{fw} rule 40 protocol icmp"]
        for n, f in enumerate(c["port_forwards"], 1):
            r = f"set nat destination rule {n * 10}"
            out += [f"{r} description {f.get('name', 'forward-' + str(f['port']))}", f"{r} inbound-interface name {out_if}",
                    f"{r} protocol {f.get('proto', 'tcp')}", f"{r} destination port {f['port']}",
                    f"{r} translation address {f['to']}", f"{r} translation port {f.get('to_port', f['port'])}"]
    if c["dns"]:
        out += [f"set system name-server {s}" for s in c["dns"]]
        out += ["set service dns forwarding system"]
        for v in p.routed:
            out += [f"set service dns forwarding listen-address {v.ip}", f"set service dns forwarding allow-from {v.network}"]
    for vid in c["dhcp_ids"]:
        v = p.vlan(vid)
        start, end = pool(v)
        sn = f"set service dhcp-server shared-network-name {v.name} subnet {v.network}"
        out += [f"{sn} subnet-id {v.id}", f"{sn} option default-router {v.ip}", f"{sn} option name-server {dns_for(c, v)}",
                f"{sn} range 0 start {start}", f"{sn} range 0 stop {end}"]
    for i, vid in enumerate(c["isolate_ids"]):
        v = p.vlan(vid)
        for n, net in enumerate(PRIVATE):
            r = f"set firewall ipv4 forward filter rule {50 + i * 5 + n}"
            out += [f"{r} action drop", f"{r} inbound-interface name {p.l3_name(v)}", f"{r} destination address {net}"]
    out += [f"set protocols static route {r['to']} next-hop {r['via']}" for r in c["static_routes"]]
    out += [f"set service ntp server {s}" for s in c["ntp"]]
    return out


# --------------------------------------------------------------- FortiGate

def fortinet(p, c) -> list[str]:
    out = [p.note("---- router ----")]
    wan = c["wan"]
    wif = wan.get("interface")
    if c.get("hostname"):
        out += ["config system global", f'    set hostname "{c["hostname"]}"', "end"]
    if wif:
        out += ["config system interface", f'    edit "{wif}"', "        set role wan", "        set allowaccess ping"]
        if wan["mode"] == "pppoe":
            out += ["        set mode pppoe", f'        set username "{wan.get("user", "")}"', f'        set password "{wan.get("password", "")}"']
        elif wan["mode"] == "static":
            out += ["        set mode static", f"        set ip {ip_only(wan['address'])} {mask(wan['address'])}"]
        else:
            out += ["        set mode dhcp"]
        out += ["    next", "end"]
        if wan["mode"] == "static":
            out += ["config router static", "    edit 0", f"        set gateway {wan['gateway']}",
                    f'        set device "{wif}"', "    next", "end"]
    if c["dns"]:
        out += ["config system dns", f"    set primary {c['dns'][0]}"]
        if len(c["dns"]) > 1:
            out.append(f"    set secondary {c['dns'][1]}")
        out.append("end")
        if c["dhcp_ids"]:
            out.append("config system dns-server")
            out += [f'    edit "{p.l3_name(p.vlan(v))}"\n        set mode recursive\n    next' for v in c["dhcp_ids"]]
            out.append("end")
    if c["dhcp_ids"]:
        out.append("config system dhcp server")
        for vid in c["dhcp_ids"]:
            v = p.vlan(vid)
            start, end = pool(v)
            out += ["    edit 0", f'        set interface "{p.l3_name(v)}"', f"        set default-gateway {v.ip}",
                    f"        set netmask {v.netmask}",
                    "        set dns-service local" if c["dns"] else "        set dns-service default",
                    "        config ip-range", "            edit 1", f"                set start-ip {start}",
                    f"                set end-ip {end}", "            next", "        end", "    next"]
        out.append("end")
    if wif and c["nat"]:
        out.append("config firewall policy")
        for v in p.routed:
            out += ["    edit 0", f'        set name "{p.l3_name(v)}-to-internet"', f'        set srcintf "{p.l3_name(v)}"',
                    f'        set dstintf "{wif}"', '        set srcaddr "all"', '        set dstaddr "all"',
                    "        set action accept", '        set schedule "always"', '        set service "ALL"',
                    "        set nat enable", "    next"]
        out.append("end")
    if c["port_forwards"]:
        out.append("config firewall vip")
        for f in c["port_forwards"]:
            out += [f'    edit "PF-{f["port"]}"', f'        set extintf "{wif}"', "        set portforward enable",
                    f'        set mappedip "{f["to"]}"', f"        set extport {f['port']}",
                    f"        set mappedport {f.get('to_port', f['port'])}", f"        set protocol {f.get('proto', 'tcp')}", "    next"]
        out += ["end", "config firewall policy"]
        for f in c["port_forwards"]:
            v = vlan_for_ip(p, f["to"])
            out += ["    edit 0", f'        set name "forward-{f["port"]}"', f'        set srcintf "{wif}"',
                    f'        set dstintf "{p.l3_name(v) if v else "any"}"', '        set srcaddr "all"',
                    f'        set dstaddr "PF-{f["port"]}"', "        set action accept", '        set schedule "always"',
                    '        set service "ALL"', "    next"]
        out.append("end")
    if c["static_routes"]:
        out.append("config router static")
        for r in c["static_routes"]:
            out += ["    edit 0", f"        set dst {net_of(r['to']).network_address} {mask(r['to'])}",
                    f"        set gateway {r['via']}"]
            v = vlan_for_ip(p, r["via"])
            if v:
                out.append(f'        set device "{p.l3_name(v)}"')
            out.append("    next")
        out.append("end")
    if c["ntp"]:
        out += ["config system ntp", "    set ntpsync enable", "    set type custom", "    config ntpserver"]
        for n, s in enumerate(c["ntp"], 1):
            out += [f"        edit {n}", f'            set server "{s}"', "        next"]
        out += ["    end", "end"]
    if c["isolate_ids"]:
        out.append(p.note("isolation: FortiGate blocks VLAN-to-VLAN traffic unless a policy allows it, so isolated VLANs need nothing extra"))
    if c["dmz_ids"]:
        # FortiGate denies inter-VLAN by default, so DMZ is already walled off from the LAN.
        # Add LAN -> DMZ allow policies so you can still administer the servers from inside.
        lan = [v for v in p.routed if v.id not in c["dmz_ids"]]
        if lan:
            out.append("config firewall policy")
            for d in c["dmz_ids"]:
                dz = p.l3_name(p.vlan(d))
                for v in lan:
                    out += ["    edit 0", f'        set name "{(p.l3_name(v) + "-to-" + dz)[:35]}"',
                            f'        set srcintf "{p.l3_name(v)}"', f'        set dstintf "{dz}"',
                            '        set srcaddr "all"', '        set dstaddr "all"', "        set action accept",
                            '        set schedule "always"', '        set service "ALL"', "    next"]
            out.append("end")
    return [line for item in out for line in item.split("\n")]


def openwrt(p, c) -> list[str]:
    from ..vendors.openwrt import router_lines
    return router_lines(p, c)


HANDLERS = {
    "mikrotik_routeros": mikrotik,
    "cisco_ios": cisco,
    "ubiquiti_edgeos": edgeos,
    "vyos": vyos,
    "fortinet": fortinet,
    "openwrt": openwrt,
}


def render(plugin) -> list[str]:
    c = cfg(plugin)
    if not c:
        return []
    handler = HANDLERS.get(plugin.key)
    if handler:
        lines = handler(plugin, c)
        if c["dmz_ids"]:
            names = ", ".join(f"{plugin.vlan(v).id} {plugin.vlan(v).name}" for v in c["dmz_ids"])
            note = plugin.note(f"DMZ: VLAN(s) {names} can reach the internet and be reached from the WAN "
                               "via port_forwards, but are blocked from the rest of the LAN.")
            lines = [lines[0], note] + lines[1:] if lines else [note]
        return lines
    wan = c["wan"]
    steps = []
    if wan.get("interface"):
        steps.append(f"WAN on {wan['interface']}: {wan['mode']}" + (f" {wan.get('address')} gw {wan.get('gateway')}" if wan["mode"] == "static" else ""))
    if c["nat"]:
        steps.append("Enable NAT / masquerade from all LAN VLANs to the WAN")
    if c["dns"]:
        steps.append(f"DNS servers: {', '.join(c['dns'])}")
    for vid in c["dhcp_ids"]:
        v = plugin.vlan(vid)
        steps.append(f"DHCP on VLAN {vid} {v.name}: {pool(v)[0]}-{pool(v)[1]}, gateway {v.ip}")
    for vid in c["isolate_ids"]:
        steps.append(f"Block VLAN {vid} from reaching private networks (internet only)")
    for f in c["port_forwards"]:
        steps.append(f"Port forward {f.get('proto', 'tcp')}/{f['port']} -> {f['to']}:{f.get('to_port', f['port'])}")
    for r in c["static_routes"]:
        steps.append(f"Static route {r['to']} via {r['via']}")
    return manual(plugin, "Router setup", steps)


def validate(net, device) -> tuple[list[str], list[str]]:
    raw = device.options.get("router")
    if not raw:
        return [], []
    errors, warnings = [], []
    where = f"device {device.name}: router"
    wan = raw.get("wan") or {}
    if isinstance(wan, str):
        wan = {"interface": wan}
    mode = wan.get("mode", "dhcp")
    if wan and mode not in ("dhcp", "static", "pppoe"):
        errors.append(f"{where}: wan mode must be dhcp, static or pppoe")
    if mode == "static" and not (wan.get("address") and wan.get("gateway")):
        errors.append(f"{where}: static WAN needs 'address' (e.g. 203.0.113.2/30) and 'gateway'")
    if mode == "pppoe" and not wan.get("user"):
        errors.append(f"{where}: PPPoE WAN needs 'user' and 'password'")
    for f in as_list(raw.get("port_forwards")):
        if not all(k in f for k in ("port", "to")):
            errors.append(f"{where}: port forward needs 'port' and 'to': {f}")
    for r in as_list(raw.get("static_routes")):
        if not all(k in r for k in ("to", "via")):
            errors.append(f"{where}: static route needs 'to' and 'via': {r}")
    for key in ("dhcp_server", "isolate", "dmz"):
        if raw.get(key) is True or str(raw.get(key)).lower() == "all":
            continue
        try:
            ids = parse_vlan_list(raw.get(key), net.vlans)
        except ValueError as exc:
            errors.append(f"{where}: {key}: {exc}")
            continue
        for vid in ids:
            if vid not in device.routed_vlans:
                warnings.append(f"{where}: {key} VLAN {vid} is not in this device's 'routing', skipped")
    from ..vendors import REGISTRY
    plugin = REGISTRY.get(device.vendor)
    if plugin and plugin.key not in HANDLERS:
        warnings.append(f"{where}: {plugin.title} gets manual steps for router setup (no automatic config yet)")
    return errors, warnings
