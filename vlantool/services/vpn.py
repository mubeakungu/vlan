"""VPN: WireGuard (remote access and site peers) and IPsec IKEv2 site-to-site.

    vpn:
      wireguard:
        address: 10.100.0.1/24        # tunnel subnet, router side
        port: 51820
        endpoint: myhome.ddns.net     # public name/IP clients dial (needed for client files)
        full_tunnel: true             # clients send all traffic through home (false = only your VLANs)
        peers:
          - name: phone               # keys generated, ready-to-import file written by `generate -o`
          - name: laptop
          - name: branch              # a site with its own key
            public_key: "base64..."
            allowed_ips: [192.168.50.0/24]
            endpoint: 198.51.100.7:51820
      ipsec:
        - name: branch
          peer: 198.51.100.7
          psk: a-long-shared-secret
          local: [192.168.10.0/24]    # default: this device's routed VLANs
          remote: [192.168.50.0/24]

Private keys live in <network>.secrets.json next to your network file.
"""
from __future__ import annotations

import ipaddress

from ..secrets import wg_public_key
from .common import as_list, ip_only, manual, mask, mt_once, net_of, wildcard


# ------------------------------------------------------------------ model

def wg_cfg(p) -> dict | None:
    raw = (p.dev.options.get("vpn") or {}).get("wireguard")
    if not raw:
        return None
    c = dict(raw)
    c.setdefault("interface", "wg0")
    c.setdefault("port", 51820)
    c.setdefault("full_tunnel", True)
    iface = ipaddress.ip_interface(c["address"])
    ident = f"wg/{p.dev.name}/{c['interface']}"
    c["private_key"] = c.get("private_key") or p.net.secrets.wg_key(ident)
    c["public_key"] = wg_public_key(c["private_key"])
    raw_peers = [dict(x) for x in as_list(c.get("peers"))]
    used = {iface.ip} | {ipaddress.ip_interface(x["address"]).ip for x in raw_peers if x.get("address")}
    free = (h for h in iface.network.hosts() if h not in used)
    peers = []
    for peer in raw_peers:
        if not peer.get("address"):
            peer["address"] = str(next(free))
        if "/" not in str(peer["address"]):
            peer["address"] = f"{peer['address']}/32"
        if not peer.get("public_key"):
            peer["private_key"] = p.net.secrets.wg_key(f"{ident}/{peer['name']}")
            peer["public_key"] = wg_public_key(peer["private_key"])
            peer["client"] = True
        peer["allowed"] = [peer["address"]] + [str(x) for x in as_list(peer.get("allowed_ips"))]
        peers.append(peer)
    c["peers"] = peers
    return c


def ipsec_cfg(p) -> list[dict]:
    out = []
    router = p.dev.options.get("router") or {}
    wan = router.get("wan") or {}
    for raw in as_list((p.dev.options.get("vpn") or {}).get("ipsec")):
        t = dict(raw)
        t["local"] = [str(x) for x in as_list(t.get("local"))] or [v.network for v in p.routed]
        t["remote"] = [str(x) for x in as_list(t.get("remote"))]
        t["interface"] = t.get("interface") or (wan.get("interface") if isinstance(wan, dict) else wan)
        out.append(t)
    return out


def ipsec_pairs(p) -> list[tuple[str, str]]:
    return [(l, r) for t in ipsec_cfg(p) for l in t["local"] for r in t["remote"]]


# -------------------------------------------------------------- WireGuard

def wg_mikrotik(p, c) -> list[str]:
    i = c["interface"]
    out = [mt_once(f"/interface wireguard find name={i}",
                   f'/interface wireguard add name={i} listen-port={c["port"]} private-key="{c["private_key"]}"'),
           f"/ip address add address={c['address']} interface={i}",
           mt_once(f'/ip firewall filter find comment="vlantool: wireguard {i}"',
                   f'/ip firewall filter add chain=input protocol=udp dst-port={c["port"]} action=accept '
                   f'comment="vlantool: wireguard {i}" place-before=0'),
           f"/interface list member add list=LAN interface={i}"]
    for peer in c["peers"]:
        line = (f'/interface wireguard peers add interface={i} name={peer["name"]} public-key="{peer["public_key"]}" '
                f"allowed-address={','.join(peer['allowed'])}")
        if peer.get("endpoint"):
            host, _, port = peer["endpoint"].rpartition(":")
            line += f" endpoint-address={host} endpoint-port={port} persistent-keepalive=25s"
        out.append(line)
    return out


def wg_vyos(p, c) -> list[str]:
    i = c["interface"]
    b = f"set interfaces wireguard {i}"
    out = [f"{b} address {c['address']}", f"{b} port {c['port']}", f"{b} private-key {c['private_key']}"]
    for peer in c["peers"]:
        pb = f"{b} peer {peer['name']}"
        out.append(f"{pb} public-key {peer['public_key']}")
        out += [f"{pb} allowed-ips {a}" for a in peer["allowed"]]
        if peer.get("endpoint"):
            host, _, port = peer["endpoint"].rpartition(":")
            out += [f"{pb} address {host}", f"{pb} port {port}", f"{pb} persistent-keepalive 25"]
    fw = "set firewall ipv4 input filter rule 15"
    out += [f"{fw} action accept", f"{fw} protocol udp", f"{fw} destination port {c['port']}"]
    if (p.dev.options.get("router") or {}).get("dns"):
        out.append(f"set service dns forwarding listen-address {ip_only(c['address'])}")
        out.append(f"set service dns forwarding allow-from {net_of(c['address'])}")
    return out


def wg_edgeos(p, c) -> list[str]:
    i = c["interface"]
    b = f"set interfaces wireguard {i}"
    out = [f"{b} address {c['address']}", f"{b} listen-port {c['port']}", f"{b} route-allowed-ips true",
           f"{b} private-key {c['private_key']}"]
    for peer in c["peers"]:
        pb = f"{b} peer {peer['public_key']}"
        out.append(f"{pb} description {peer['name']}")
        out += [f"{pb} allowed-ips {a}" for a in peer["allowed"]]
        if peer.get("endpoint"):
            out += [f"{pb} endpoint {peer['endpoint']}", f"{pb} persistent-keepalive 25"]
    fw = "set firewall name WAN_LOCAL rule 30"
    out += [f"{fw} action accept", f"{fw} protocol udp", f"{fw} destination port {c['port']}", f"{fw} description wireguard"]
    return out


def wg_openwrt(p, c) -> list[str]:
    i = c["interface"]
    out = [f"uci set network.{i}=interface", f"uci set network.{i}.proto='wireguard'",
           f"uci set network.{i}.private_key='{c['private_key']}'", f"uci set network.{i}.listen_port='{c['port']}'",
           f"uci add_list network.{i}.addresses='{c['address']}'", f"uci add_list firewall.@zone[0].network='{i}'",
           f"uci set firewall.allow_{i}=rule", f"uci set firewall.allow_{i}.name='Allow-WireGuard'",
           f"uci set firewall.allow_{i}.src='wan'", f"uci set firewall.allow_{i}.dest_port='{c['port']}'",
           f"uci set firewall.allow_{i}.proto='udp'", f"uci set firewall.allow_{i}.target='ACCEPT'"]
    for peer in c["peers"]:
        s = f"network.wgpeer_{peer['name'].replace('-', '_')}"
        out += [f"uci set {s}=wireguard_{i}", f"uci set {s}.description='{peer['name']}'",
                f"uci set {s}.public_key='{peer['public_key']}'", f"uci set {s}.route_allowed_ips='1'"]
        out += [f"uci add_list {s}.allowed_ips='{a}'" for a in peer["allowed"]]
        if peer.get("endpoint"):
            host, _, port = peer["endpoint"].rpartition(":")
            out += [f"uci set {s}.endpoint_host='{host}'", f"uci set {s}.endpoint_port='{port}'",
                    f"uci set {s}.persistent_keepalive='25'"]
    return out


WG = {"mikrotik_routeros": wg_mikrotik, "vyos": wg_vyos, "ubiquiti_edgeos": wg_edgeos, "openwrt": wg_openwrt}


def client_conf(p, c, peer) -> str:
    router = p.dev.options.get("router") or {}
    dns = c.get("dns") or (ip_only(c["address"]) if router.get("dns") else "1.1.1.1")
    if c["full_tunnel"]:
        allowed = "0.0.0.0/0"
    else:
        allowed = ", ".join([str(net_of(c["address"]))] + [v.network for v in p.routed])
    endpoint = c.get("endpoint", "YOUR-PUBLIC-IP-OR-DDNS")
    return "\n".join([
        f"# {peer['name']} -> {p.dev.name}. Import into the WireGuard app (file or QR code).",
        "[Interface]",
        f"PrivateKey = {peer['private_key']}",
        f"Address = {peer['address']}",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {c['public_key']}",
        f"Endpoint = {endpoint}:{c['port']}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
        "",
    ])


# ------------------------------------------------------------------ IPsec

def ipsec_mikrotik(p, t) -> list[str]:
    n = f"vt-{t['name']}"
    out = [f"/ip ipsec profile add name={n} hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=modp2048",
           f"/ip ipsec peer add name={n} address={t['peer']}/32 exchange-mode=ike2 profile={n}",
           f"/ip ipsec proposal add name={n} auth-algorithms=sha256 enc-algorithms=aes-256-cbc pfs-group=modp2048",
           f'/ip ipsec identity add peer={n} auth-method=pre-shared-key secret="{t["psk"]}"',
           mt_once('/ip firewall filter find comment="vlantool: ipsec"',
                   '/ip firewall filter add chain=input protocol=udp dst-port=500,4500 action=accept comment="vlantool: ipsec" place-before=0'),
           mt_once('/ip firewall filter find comment="vlantool: ipsec esp"',
                   '/ip firewall filter add chain=input protocol=ipsec-esp action=accept comment="vlantool: ipsec esp" place-before=0'),
           # decrypted traffic arrives on the WAN; let it through the "drop WAN not dstnat" rule
           mt_once('/ip firewall filter find comment="vlantool: ipsec in"',
                   '/ip firewall filter add chain=forward ipsec-policy=in,ipsec action=accept comment="vlantool: ipsec in" place-before=0'),
           mt_once('/ip firewall filter find comment="vlantool: ipsec out"',
                   '/ip firewall filter add chain=forward ipsec-policy=out,ipsec action=accept comment="vlantool: ipsec out" place-before=0')]
    for l in t["local"]:
        for r in t["remote"]:
            out += [f"/ip ipsec policy add peer={n} tunnel=yes src-address={l} dst-address={r} proposal={n}",
                    f'/ip firewall nat add chain=srcnat src-address={l} dst-address={r} action=accept '
                    f'comment="vlantool: no NAT to {t["name"]}" place-before=0']
    return out


def ipsec_cisco(p, t, idx) -> list[str]:
    n = f"VT-{t['name'].upper()}"
    out = [f"crypto ikev2 proposal {n}", " encryption aes-cbc-256", " integrity sha256", " group 14",
           f"crypto ikev2 policy {n}", f" proposal {n}",
           f"crypto ikev2 keyring {n}", f" peer {t['name']}", f"  address {t['peer']}", f"  pre-shared-key {t['psk']}",
           f"crypto ikev2 profile {n}", f" match identity remote address {t['peer']} 255.255.255.255",
           " authentication remote pre-share", " authentication local pre-share", f" keyring local {n}",
           f"crypto ipsec transform-set {n} esp-aes 256 esp-sha256-hmac", " mode tunnel",
           f"ip access-list extended {n}-TRAFFIC"]
    for l in t["local"]:
        for r in t["remote"]:
            out.append(f" permit ip {net_of(l).network_address} {wildcard(l)} {net_of(r).network_address} {wildcard(r)}")
    out += [f"crypto map VLANTOOL-VPN {idx * 10} ipsec-isakmp", f" set peer {t['peer']}", f" set transform-set {n}",
            f" set ikev2-profile {n}", f" match address {n}-TRAFFIC"]
    if t["interface"]:
        out += [f"interface {t['interface']}", " crypto map VLANTOOL-VPN"]
    return out


def ipsec_fortinet(p, t) -> list[str]:
    n = t["name"][:15]
    out = ["config vpn ipsec phase1-interface", f'    edit "{n}"', f'        set interface "{t["interface"]}"',
           "        set ike-version 2", "        set peertype any", "        set net-device disable",
           "        set proposal aes256-sha256", "        set dhgrp 14", f"        set remote-gw {t['peer']}",
           f'        set psksecret "{t["psk"]}"', "    next", "end", "config vpn ipsec phase2-interface"]
    k = 0
    for l in t["local"]:
        for r in t["remote"]:
            k += 1
            out += [f'    edit "{n}-{k}"', f'        set phase1name "{n}"', "        set proposal aes256-sha256",
                    "        set dhgrp 14", f"        set src-subnet {net_of(l).network_address} {mask(l)}",
                    f"        set dst-subnet {net_of(r).network_address} {mask(r)}", "    next"]
    out += ["end", "config router static"]
    for r in t["remote"]:
        out += ["    edit 0", f"        set dst {net_of(r).network_address} {mask(r)}", f'        set device "{n}"', "    next"]
    out += ["end", "config firewall policy"]
    for v in p.routed:
        if any(ipaddress.ip_network(v.network).subnet_of(net_of(l)) for l in t["local"]):
            for src, dst in ((p.l3_name(v), n), (n, p.l3_name(v))):
                out += ["    edit 0", f'        set name "{(src + "-to-" + dst)[:35]}"', f'        set srcintf "{src}"',
                        f'        set dstintf "{dst}"', '        set srcaddr "all"', '        set dstaddr "all"',
                        "        set action accept", '        set schedule "always"', '        set service "ALL"', "    next"]
    return out + ["end"]


def ipsec_vyos(p, t, idx) -> list[str]:
    b = "set vpn ipsec"
    n = t["name"]
    out = [f"{b} ike-group VT-IKE key-exchange ikev2", f"{b} ike-group VT-IKE proposal 1 dh-group 14",
           f"{b} ike-group VT-IKE proposal 1 encryption aes256", f"{b} ike-group VT-IKE proposal 1 hash sha256",
           f"{b} esp-group VT-ESP pfs dh-group14", f"{b} esp-group VT-ESP proposal 1 encryption aes256",
           f"{b} esp-group VT-ESP proposal 1 hash sha256", f"{b} interface {t['interface']}",
           f"{b} authentication psk {n} id {t['peer']}", f"{b} authentication psk {n} secret {t['psk']}",
           f"{b} site-to-site peer {n} remote-address {t['peer']}", f"{b} site-to-site peer {n} local-address any",
           f"{b} site-to-site peer {n} authentication mode pre-shared-secret",
           f"{b} site-to-site peer {n} ike-group VT-IKE", f"{b} site-to-site peer {n} default-esp-group VT-ESP"]
    k = 0
    for l in t["local"]:
        for r in t["remote"]:
            k += 1
            out += [f"{b} site-to-site peer {n} tunnel {k} local prefix {l}",
                    f"{b} site-to-site peer {n} tunnel {k} remote prefix {r}"]
            rule = f"set nat source rule {10 + idx * 10 + k}"
            out += [f"{rule} source address {l}", f"{rule} destination address {r}", f"{rule} exclude",
                    f"{rule} outbound-interface name {t['interface']}"]
    return out


def ipsec_edgeos(p, t, idx) -> list[str]:
    b = "set vpn ipsec"
    pb = f"{b} site-to-site peer {t['peer']}"
    out = [f"{b} auto-firewall-nat-exclude enable", f"{b} ike-group VT-IKE key-exchange ikev2",
           f"{b} ike-group VT-IKE proposal 1 dh-group 14", f"{b} ike-group VT-IKE proposal 1 encryption aes256",
           f"{b} ike-group VT-IKE proposal 1 hash sha256", f"{b} esp-group VT-ESP pfs dh-group14",
           f"{b} esp-group VT-ESP proposal 1 encryption aes256", f"{b} esp-group VT-ESP proposal 1 hash sha256",
           f"{b} ipsec-interfaces interface {t['interface']}", f"{pb} description {t['name']}",
           f"{pb} authentication mode pre-shared-secret", f"{pb} authentication pre-shared-secret {t['psk']}",
           f"{pb} ike-group VT-IKE", f"{pb} local-address any"]
    k = 0
    for l in t["local"]:
        for r in t["remote"]:
            k += 1
            out += [f"{pb} tunnel {k} esp-group VT-ESP", f"{pb} tunnel {k} local prefix {l}", f"{pb} tunnel {k} remote prefix {r}"]
    return out


def render(plugin) -> list[str]:
    out: list[str] = []
    c = wg_cfg(plugin)
    if c:
        out.append(plugin.note(f"---- WireGuard {c['interface']} (public key {c['public_key']}) ----"))
        if plugin.key in WG:
            out += WG[plugin.key](plugin, c)
        else:
            out += manual(plugin, "WireGuard", [
                f"Create WireGuard interface {c['interface']} on UDP {c['port']} with private key {c['private_key']}",
                f"Give it address {c['address']}",
                *[f"Add peer {peer['name']}: public key {peer['public_key']}, allowed IPs {', '.join(peer['allowed'])}"
                  for peer in c["peers"]],
                f"Allow UDP {c['port']} in from the internet",
            ] if plugin.key not in ("fortinet", "cisco_ios") else [
                f"{plugin.title} has no WireGuard; use the vpn.ipsec section for site-to-site instead"])
        clients = [peer for peer in c["peers"] if peer.get("client")]
        if clients:
            out.append(plugin.note("client files: run 'vlantool generate <file> -o out/' to get "
                                   + ", ".join(f"{plugin.dev.name}-{peer['name']}.conf" for peer in clients)))
    for idx, t in enumerate(ipsec_cfg(plugin), 1):
        out.append(plugin.note(f"---- IPsec {t['name']} -> {t['peer']} ----"))
        k = plugin.key
        if k == "mikrotik_routeros":
            out += ipsec_mikrotik(plugin, t)
        elif k == "cisco_ios":
            out += ipsec_cisco(plugin, t, idx)
        elif k == "fortinet":
            out += ipsec_fortinet(plugin, t)
        elif k == "vyos":
            out += ipsec_vyos(plugin, t, idx)
        elif k == "ubiquiti_edgeos":
            out += ipsec_edgeos(plugin, t, idx)
        else:
            out += manual(plugin, f"IPsec {t['name']}", [
                f"IKEv2 to {t['peer']}, pre-shared key {t['psk']}",
                "Phase 1: AES-256, SHA-256, DH group 14; Phase 2: AES-256, SHA-256, PFS group 14",
                f"Local networks {', '.join(t['local'])}, remote networks {', '.join(t['remote'])}",
                "Exempt this traffic from NAT and allow UDP 500/4500 and ESP from the peer",
            ])
    return out


def files(plugin) -> dict[str, str]:
    c = wg_cfg(plugin)
    if not c:
        return {}
    return {f"{plugin.dev.name}-{peer['name']}.conf": client_conf(plugin, c, peer)
            for peer in c["peers"] if peer.get("client")}


def validate(net, device) -> tuple[list[str], list[str]]:
    vpn = device.options.get("vpn") or {}
    errors, warnings = [], []
    where = f"device {device.name}: vpn"
    wg = vpn.get("wireguard")
    if wg:
        try:
            iface = ipaddress.ip_interface(wg.get("address", ""))
            if "/" not in str(wg.get("address")):
                raise ValueError
        except ValueError:
            errors.append(f"{where}: wireguard needs 'address' like 10.100.0.1/24")
            iface = None
        names = set()
        for peer in as_list(wg.get("peers")):
            if not peer.get("name"):
                errors.append(f"{where}: every wireguard peer needs a 'name'")
            elif peer["name"] in names:
                errors.append(f"{where}: wireguard peer {peer['name']} listed twice")
            names.add(peer.get("name"))
            if not peer.get("public_key") and not wg.get("endpoint"):
                warnings.append(f"{where}: set wireguard 'endpoint' (your public IP or DDNS name) so client files work")
        if iface and len(as_list(wg.get("peers"))) >= iface.network.num_addresses - 2:
            errors.append(f"{where}: wireguard subnet is too small for {len(as_list(wg.get('peers')))} peers")
    for t in as_list(vpn.get("ipsec")):
        if not all(t.get(k) for k in ("name", "peer", "psk", "remote")):
            errors.append(f"{where}: ipsec entries need name, peer, psk and remote")
        elif len(str(t["psk"])) < 8:
            errors.append(f"{where}: ipsec {t['name']} psk must be 8+ characters")
        wan = (device.options.get("router") or {}).get("wan") or {}
        if not t.get("interface") and not (wan.get("interface") if isinstance(wan, dict) else wan) \
                and device.vendor in ("cisco_ios", "fortinet", "vyos", "ubiquiti_edgeos"):
            errors.append(f"{where}: ipsec {t.get('name')} needs 'interface' (the WAN port) or a router.wan section")
    return errors, warnings
