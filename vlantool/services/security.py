"""Security on network devices: IPS/IDS and log forwarding to a SIEM (Wazuh).

Network-wide (top level of the file):

    security:
      siem: 192.168.99.50          # syslog collector, usually the Wazuh manager
      syslog_port: 514

Per device:

    security:
      ips: prevent                 # prevent (block attacks) or detect (alert only)
      syslog: true                 # send logs to the SIEM (default: on when 'siem' is set)
      brute_force: true            # MikroTik: ban IPs that hammer SSH/WinBox (default on with ips)
      sensor: 192.168.99.60        # MikroTik: stream WAN traffic (TZSP) to a Suricata/Zeek sensor
"""
from __future__ import annotations

from .common import manual, mt_once

IPS_SENSOR = "vlantool-ips"


def cfg(p) -> dict:
    raw = dict(p.dev.options.get("security") or {})
    net = p.net.security or {}
    ips = raw.get("ips")
    if isinstance(ips, dict):
        mode = ips.get("mode", "prevent")
    else:
        mode = ips if ips in ("prevent", "detect") else ("prevent" if ips else None)
    return {
        "ips": mode,
        "syslog": net.get("siem") if raw.get("syslog", True) and net.get("siem") else None,
        "port": int(net.get("syslog_port", 514)),
        "brute_force": raw.get("brute_force", bool(mode)),
        "sensor": raw.get("sensor"),
        "interfaces": (ips or {}).get("interfaces") if isinstance(ips, dict) else None,
    }


def wan_of(p) -> str | None:
    wan = (p.dev.options.get("router") or {}).get("wan") or {}
    return wan.get("interface") if isinstance(wan, dict) else wan


# ------------------------------------------------------------------ syslog

def syslog_lines(p, ip: str, port: int) -> list[str]:
    k = p.key
    if k == "mikrotik_routeros":
        out = [mt_once("/system logging action find name=vlantool-siem",
                       f"/system logging action add name=vlantool-siem target=remote remote={ip} remote-port={port}")]
        for topic in ("critical", "error", "warning", "info", "account", "firewall"):
            out.append(mt_once(f"/system logging find action=vlantool-siem topics~\"{topic}\"",
                               f"/system logging add topics={topic} action=vlantool-siem"))
        return out
    if k in ("cisco_ios", "arista_eos", "ruckus_icx", "cisco_smb"):
        return [f"logging host {ip}", "logging trap informational", "service timestamps log datetime msec"
                ] if k == "cisco_ios" else [f"logging host {ip}"]
    if k in ("cisco_nxos", "dell_os10", "dlink_dgs"):
        return [f"logging server {ip}"]
    if k == "juniper_junos":
        return [f"set system syslog host {ip} any info", f"set system syslog host {ip} authorization info",
                f"set system syslog host {ip} port {port}"]
    if k == "aruba_aoscx":
        return [f"logging {ip} severity info"]
    if k == "hp_procurve":
        return [f"logging {ip}", "logging severity info"]
    if k in ("huawei_vrp", "hp_comware"):
        return [f"info-center loghost {ip}"]
    if k == "fortinet":
        return ["config log syslogd setting", "    set status enable", f'    set server "{ip}"', f"    set port {port}", "end"]
    if k in ("vyos", "ubiquiti_edgeos"):
        return [f"set system syslog host {ip} facility all level info"]
    if k == "openwrt":
        return [f"uci set system.@system[0].log_ip='{ip}'", f"uci set system.@system[0].log_port='{port}'",
                "uci set system.@system[0].log_proto='udp'"]
    if k == "tplink_jetstream":
        return [f"logging host index 1 {ip} 6"]
    if k == "dlink":
        return [f"create syslog host 1 ipaddress {ip} severity all state enable", "enable syslog"]
    if k in ("ubiquiti_edgeswitch", "netgear"):
        return [f"logging host {ip} ipv4 {port} info"]
    if k == "extreme_exos":
        return [f"configure syslog add {ip}:{port} vr VR-Default local0", "enable syslog"]
    return manual(p, "Log forwarding", [f"Send syslog (UDP {port}, level info) to {ip}"])


# --------------------------------------------------------------------- IPS

def ips_mikrotik(p, c) -> list[str]:
    out = [p.note("RouterOS has no signature IPS: this adds brute-force and port-scan banning;"
                  " set 'sensor' to mirror WAN traffic to a Suricata box for full IDS")]
    if c["brute_force"]:
        out += [
            mt_once('/ip firewall filter find comment="vlantool: drop brute force"',
                    '/ip firewall filter add chain=input src-address-list=vt-bruteforce action=drop '
                    'comment="vlantool: drop brute force" place-before=0'),
            '/ip firewall filter add chain=input protocol=tcp dst-port=22,8291,21,23 connection-state=new '
            'src-address-list=vt-bf-stage2 action=add-src-to-address-list address-list=vt-bruteforce '
            'address-list-timeout=1d comment="vlantool: brute force stage 3"',
            '/ip firewall filter add chain=input protocol=tcp dst-port=22,8291,21,23 connection-state=new '
            'src-address-list=vt-bf-stage1 action=add-src-to-address-list address-list=vt-bf-stage2 '
            'address-list-timeout=1m comment="vlantool: brute force stage 2"',
            '/ip firewall filter add chain=input protocol=tcp dst-port=22,8291,21,23 connection-state=new '
            'action=add-src-to-address-list address-list=vt-bf-stage1 address-list-timeout=1m '
            'comment="vlantool: brute force stage 1"',
        ]
    out += [
        mt_once('/ip firewall raw find comment="vlantool: drop port scanners"',
                '/ip firewall raw add chain=prerouting src-address-list=vt-portscan action=drop '
                'comment="vlantool: drop port scanners"'),
        '/ip firewall filter add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list '
        'address-list=vt-portscan address-list-timeout=1d comment="vlantool: detect port scan" place-before=0',
        '/ip firewall filter add chain=forward protocol=tcp psd=21,3s,3,1 in-interface-list=WAN '
        'action=add-src-to-address-list address-list=vt-portscan address-list-timeout=1d comment="vlantool: detect port scan"',
    ]
    if c["ips"] == "detect":  # detect only: log instead of dropping
        out = [line.replace("action=drop", "action=log log-prefix=vlantool-ids") for line in out]
    if c["sensor"]:
        wan = wan_of(p) or "ether1"
        out += [f"/tool sniffer set filter-interface={wan} streaming-enabled=yes streaming-server={c['sensor']}",
                "/tool sniffer start"]
    return out


def ips_fortinet(p, c) -> list[str]:
    block = c["ips"] == "prevent"
    return ["config ips sensor", f'    edit "{IPS_SENSOR}"', '        set comment "generated by vlantool"',
            "        config entries", "            edit 1", "                set severity medium high critical",
            "                set status enable", f"                set action {'block' if block else 'pass'}",
            "                set log-packet enable", "            next", "        end", "    next", "end"]


def ips_openwrt(p, c) -> list[str]:
    home = " ".join(v.network for v in p.routed) or "192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"
    prevent = c["ips"] == "prevent"
    return [p.note("Snort 3 needs ~512 MB RAM; check your router has enough before enabling"),
            "opkg update && opkg install snort3",
            "uci set snort.snort.enabled='1'",
            f"uci set snort.snort.mode='{'ips' if prevent else 'ids'}'",
            f"uci set snort.snort.method='{'nfq' if prevent else 'pcap'}'",
            f"uci set snort.snort.action='{'block' if prevent else 'alert'}'",
            f"uci set snort.snort.interface='{wan_of(p) or 'wan'}'",
            f"uci set snort.snort.home_net='{home}'",
            "uci commit snort", "snort-rules", "/etc/init.d/snort enable", "/etc/init.d/snort restart"]


IPS_STEPS = {
    "pfsense": ["Install the Suricata package (System > Package Manager); OPNsense has it built in under "
                "Services > Intrusion Detection",
                "Enable it on the WAN interface; tick IPS mode (inline) to block, leave it off to only alert",
                "Download the ET Open rulesets and enable the 'emerging-*' categories",
                "Set the policy to drop alerts with severity medium and above"],
    "cisco_ios": ["On ISR 1000/4000 routers: install the UTD Snort container (app-hosting / utd engine standard)",
                  "utd threat-inspection whitelist; threat-inspection profile with 'policy security' and 'threat protection'",
                  "Apply 'utd all-interfaces' and 'engine standard' under 'utd'"],
    "juniper_junos": ["SRX needs an IDP licence: 'request security idp security-package download' then install",
                      "Use the template 'Recommended' policy: set security idp active-policy Recommended",
                      "Add 'then permit application-services idp-policy Recommended' to the internet policies"],
    "vyos": ["VyOS has no built-in IPS: mirror the WAN port to a Suricata box "
             "(set interfaces ethernet eth0 mirror ingress ethX) and run Suricata there"],
    "ubiquiti_edgeos": ["EdgeOS has no IPS (UniFi gateways do: Settings > Security > Intrusion Prevention)",
                        "Or mirror the WAN port to a Suricata sensor"],
}


def ips_lines(p, c) -> list[str]:
    if p.key == "mikrotik_routeros":
        return ips_mikrotik(p, c)
    if p.key == "fortinet":  # the sensor itself is placed at the top by postprocess()
        return [p.note(f"IPS sensor {IPS_SENSOR} is defined at the top and attached to every firewall policy")]
    if p.key == "openwrt":
        return ips_openwrt(p, c)
    steps = IPS_STEPS.get(p.key, [
        f"Turn on the {'IPS (prevention)' if c['ips'] == 'prevent' else 'IDS (detection)'} feature of {p.title} "
        "if it has one, or mirror the uplink port to a Suricata sensor"])
    return manual(p, "IPS", steps)


def render(plugin) -> list[str]:
    c = cfg(plugin)
    if not (c["ips"] or c["syslog"] or c["sensor"]):
        return []
    out = [plugin.note("---- security ----")]
    if c["ips"] or c["sensor"]:
        out += ips_lines(plugin, c)
    if c["syslog"]:
        out += syslog_lines(plugin, c["syslog"], c["port"])
    return out


def postprocess(plugin, lines: list[str]) -> list[str]:
    """FortiGate: switch on IPS in every firewall policy."""
    c = cfg(plugin)
    if plugin.key != "fortinet" or not c["ips"]:
        return lines
    out, in_policy = ips_fortinet(plugin, c), False  # sensor must exist before policies use it
    for line in lines:
        if line.strip() == "config firewall policy":
            in_policy = True
        elif line.strip() == "end" and not line.startswith(" "):
            in_policy = False
        if in_policy and line == "    next":
            out += ["        set utm-status enable", f'        set ips-sensor "{IPS_SENSOR}"',
                    '        set ssl-ssh-profile "certificate-inspection"']
        out.append(line)
    return out


def validate(net, device) -> tuple[list[str], list[str]]:
    raw = device.options.get("security")
    errors, warnings = [], []
    if raw:
        ips = raw.get("ips")
        mode = ips.get("mode") if isinstance(ips, dict) else ips
        if mode not in (None, False, True, "prevent", "detect"):
            errors.append(f"device {device.name}: security ips must be prevent or detect")
        if raw.get("syslog") and not (net.security or {}).get("siem"):
            warnings.append(f"device {device.name}: security syslog is on but no top-level security.siem address is set")
    return errors, warnings
