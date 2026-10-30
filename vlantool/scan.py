"""Security scanner for your own network: audits the config you wrote and probes
the devices listed in the file. Report-only by default; it changes nothing.

    vlantool scan network.yaml                 # config audit + live port scan, prints a report
    vlantool scan network.yaml -o report.html  # also write an HTML report
    vlantool scan network.yaml --check-passwords   # also test devices for default/weak SSH passwords

Only hosts named in the network file are probed, so the scan stays inside your
own network. Default-password testing logs in and logs straight back out; it
never changes anything.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html import escape

from .model import Network, parse_vlan_list
from .services import filtering, vpn
from .services.security import cfg as sec_cfg
from .vendors import get

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# insecure / notable management ports to look for
NOTABLE_PORTS = {
    21: ("FTP", "high", "clear-text file transfer"),
    23: ("Telnet", "critical", "clear-text remote login"),
    80: ("HTTP", "medium", "unencrypted management, if this is a device web UI"),
    161: ("SNMP", "medium", "often left on the 'public' community"),
    2000: ("Cisco SCCP", "low", ""),
    3389: ("RDP", "high", "remote desktop, a common attack target"),
    5900: ("VNC", "high", "remote desktop, often unauthenticated"),
    8080: ("HTTP-alt", "medium", "unencrypted management"),
    8291: ("MikroTik WinBox", "medium", "management port; should not face the internet"),
    8728: ("MikroTik API", "high", "clear-text API"),
    23023: ("Telnet-alt", "critical", "clear-text remote login"),
}
SECURE_MGMT = {22, 443, 8443, 8729}

# vendor default credentials, for the opt-in password test (your own gear only)
DEFAULT_CREDS = {
    "mikrotik_routeros": [("admin", "")],
    "ubiquiti_edgeos": [("ubnt", "ubnt")], "ubiquiti_edgeswitch": [("ubnt", "ubnt")],
    "cisco_ios": [("cisco", "cisco"), ("admin", "admin")], "cisco_smb": [("cisco", "cisco")],
    "fortinet": [("admin", "")], "hp_procurve": [("admin", "")], "aruba_aoscx": [("admin", "")],
    "tplink_jetstream": [("admin", "admin")], "dlink": [("admin", "")], "dlink_dgs": [("admin", "")],
    "netgear": [("admin", "password")], "zyxel": [("admin", "1234")], "huawei_vrp": [("admin", "admin@huawei.com")],
    "openwrt": [("root", "")], "vyos": [("vyos", "vyos")],
}


@dataclass
class Finding:
    severity: str
    device: str
    title: str
    detail: str
    fix: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY.get(self.severity, 0)


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)

    def add(self, *a, **k):
        self.findings.append(Finding(*a, **k))

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.rank, f.device, f.title))


# -------------------------------------------------------------- config audit

def audit_config(net: Network, report: ScanReport) -> None:
    seen_psk: dict[str, str] = {}
    weak_words = {"password", "123456", "12345678", "admin", "changeme", "change-me-please",
                  "change-this-shared-secret", "letmein", "qwerty", "guest"}
    for v in net.vlans.values():
        pass
    for d in net.devices:
        name = d.name
        opt = d.options
        router = opt.get("router") or {}
        wan = router.get("wan") or {}
        wan = wan if isinstance(wan, dict) else {"interface": wan}
        if wan.get("interface") and not router.get("firewall", True):
            report.add("high", name, "Router firewall disabled",
                       "This device has a WAN uplink but router.firewall is off.",
                       "Set router.firewall: true (the default) so unsolicited WAN traffic is dropped.")
        if wan.get("mode") == "pppoe" and str(wan.get("password", "")) in weak_words:
            report.add("low", name, "Weak PPPoE password", "The PPPoE password looks like a placeholder.", "Use the real ISP password.")
        # Wi-Fi passphrases
        for s in (opt.get("wireless") or {}).get("ssids", []) or []:
            p = str(s.get("passphrase", ""))
            if len(p) < 12 or p.lower() in weak_words:
                report.add("high" if len(p) < 8 else "medium", name, f"Weak Wi-Fi passphrase on '{s.get('ssid')}'",
                           f"The passphrase is {'too short' if len(p) < 12 else 'a common word'} ({len(p)} chars).",
                           "Use a random passphrase of 12+ characters.")
        up = (opt.get("wireless") or {}).get("uplink")
        # VPN secrets
        v = opt.get("vpn") or {}
        for t in (v.get("ipsec") or []):
            psk = str(t.get("psk", ""))
            if psk.lower() in weak_words or len(psk) < 12:
                report.add("high", name, f"Weak IPsec pre-shared key ({t.get('name')})",
                           "The PSK is a placeholder or shorter than 12 characters.",
                           "Use a long random pre-shared key (20+ characters).")
            if psk in seen_psk and seen_psk[psk] != name:
                report.add("medium", name, "Reused IPsec pre-shared key",
                           f"The same PSK is used on {seen_psk[psk]} and {name}.", "Use a unique PSK per tunnel.")
            seen_psk.setdefault(psk, name)
        wg = v.get("wireguard")
        if wg and wg.get("full_tunnel") is False and not net.security:
            pass
        # DMZ hygiene: a VLAN that looks like a DMZ but isn't walled off from the LAN
        if router:
            walled = set(parse_vlan_list(router.get("dmz"), net.vlans)) | set(parse_vlan_list(router.get("isolate"), net.vlans))
            for v in net.vlans_for(d):
                if "dmz" in v.name.lower() or v.name.lower() in ("servers", "public"):
                    if v.id not in walled:
                        report.add("high", name, f"DMZ VLAN '{v.name}' can reach the LAN",
                                   f"VLAN {v.id} looks like a DMZ but is not under router.dmz or router.isolate, "
                                   "so a compromised server there can attack your internal network.",
                                   f"Add {v.name} to router.dmz so it is blocked from the LAN.")
        # management exposure: router with no isolate and a guest VLAN
        if router and not router.get("isolate") and not router.get("dmz") and any(x.name.lower() in ("guest", "guests") for x in net.vlans_for(d)):
            report.add("medium", name, "Guest VLAN not isolated",
                       "A GUEST VLAN exists but router.isolate does not list it, so guests can reach your LAN.",
                       "Add the guest VLAN to router.isolate.")
        # security posture
        sc = sec_cfg(get(d.vendor)(net, d)) if get(d.vendor).netmiko_type else None
        if wan.get("interface") and get(d.vendor).supports_policies and not (opt.get("security") or {}).get("ips"):
            report.add("low", name, "No IPS on the firewall",
                       "This firewall faces the internet but has no IPS configured.",
                       "Add security: {ips: prevent} to this device.")
        if net.security and net.security.get("siem") and (opt.get("security") or {}).get("syslog") is False:
            report.add("info", name, "Not sending logs to the SIEM", "security.syslog is off for this device.", "Turn syslog on so attacks are logged centrally.")
    if net.endpoints and not ((net.security or {}).get("wazuh") or {}).get("manager"):
        report.add("medium", "network", "Endpoints without EDR management",
                   "Endpoints are listed but no Wazuh manager is set.", "Add security.wazuh.manager.")


# ---------------------------------------------------------------- live probe

def scan_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    open_ports = []

    def check(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=min(64, len(ports))) as pool:
        for r in pool.map(check, ports):
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports)


def probe(net: Network, report: ScanReport, extra_ports: list[int] | None = None) -> None:
    ports = sorted(set(NOTABLE_PORTS) | SECURE_MGMT | set(extra_ports or []))
    hosts = {d.name: d.host for d in net.devices if d.host}

    def one(item):
        name, host = item
        return name, host, scan_ports(host, ports)

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as pool:
        for name, host, found in pool.map(one, hosts.items()):
            report.open_ports[name] = found
            for p in found:
                if p in NOTABLE_PORTS:
                    label, sev, why = NOTABLE_PORTS[p]
                    report.add(sev, name, f"{label} open (port {p})",
                               f"{host}:{p} is reachable" + (f" — {why}." if why else "."),
                               "Disable the service if unused, or restrict it to your management VLAN/VPN.")
            if not found:
                report.add("info", name, "No scanned ports open", f"{host} answered nothing on the scanned ports (or blocked the scan).", "")


def check_passwords(net: Network, report: ScanReport) -> None:
    """Opt-in: try each device's known default credentials over SSH (read-only)."""
    try:
        from netmiko import ConnectHandler
    except ImportError:
        report.add("info", "network", "Password test skipped", "Netmiko is not installed.", "pip install netmiko")
        return

    def one(d):
        plugin = get(d.vendor)
        creds = DEFAULT_CREDS.get(d.vendor)
        if not d.host or not plugin.netmiko_type or not creds:
            return
        for user, pw in creds:
            try:
                conn = ConnectHandler(device_type=plugin.netmiko_type, host=d.host, port=d.port,
                                      username=user, password=pw, timeout=8, fast_cli=False)
                conn.disconnect()
            except Exception:
                continue
            report.add("critical", d.name, "Default credentials accepted",
                       f"{d.host} still accepts the factory login {user!r}/{pw or '(blank)'}.",
                       "Set a strong unique password on this device now.")
            return

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(one, net.devices))


# ------------------------------------------------------------------- report

def run_scan(net: Network, ports: bool = True, passwords: bool = False) -> ScanReport:
    report = ScanReport()
    audit_config(net, report)
    if ports:
        probe(net, report)
    if passwords:
        check_passwords(net, report)
    return report


def text_report(report: ScanReport) -> str:
    out = ["VLANTOOL SECURITY SCAN", "=" * 60]
    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("Findings: " + (", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)) or "none"))
    out.append("")
    for f in report.sorted():
        out.append(f"[{f.severity.upper():<8}] {f.device}: {f.title}")
        out.append(f"           {f.detail}")
        if f.fix:
            out.append(f"           fix: {f.fix}")
    if report.open_ports:
        out += ["", "Open ports:"]
        for dev, ports in sorted(report.open_ports.items()):
            out.append(f"  {dev:<20} {', '.join(map(str, ports)) or '(none)'}")
    return "\n".join(out) + "\n"


def html_report(report: ScanReport) -> str:
    colors = {"critical": "#b42318", "high": "#d9480f", "medium": "#9a6700", "low": "#3b7a57", "info": "#667085"}
    rows = "".join(
        f'<tr><td><span class="sev" style="background:{colors[f.severity]}">{f.severity}</span></td>'
        f"<td>{escape(f.device)}</td><td><b>{escape(f.title)}</b><br><span class=d>{escape(f.detail)}</span>"
        + (f'<br><span class=f>Fix: {escape(f.fix)}</span>' if f.fix else "") + "</td></tr>"
        for f in report.sorted())
    ports = "".join(f"<tr><td>{escape(d)}</td><td>{', '.join(map(str, p)) or '-'}</td></tr>"
                    for d, p in sorted(report.open_ports.items()))
    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    tiles = "".join(f'<div class=tile style="border-color:{colors[s]}"><div class=n>{counts.get(s, 0)}</div>'
                    f"<div class=l>{s}</div></div>" for s in ("critical", "high", "medium", "low", "info"))
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1"><title>Security scan</title><style>
body{{font:14px system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}}
@media(prefers-color-scheme:dark){{body{{background:#111418;color:#e6e8ec}}table,.tile{{background:#1a1e24;border-color:#2c323b}}}}
h1{{font-size:18px}}main{{max-width:900px;margin:0 auto;padding:20px}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
.tile{{border:1px solid #ddd;border-left-width:4px;border-radius:8px;padding:8px 14px;background:#fff;min-width:80px}}
.tile .n{{font-size:22px;font-weight:600}}.tile .l{{font-size:12px;color:#667085;text-transform:capitalize}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd;border-radius:8px;overflow:hidden;margin-bottom:20px}}
td,th{{padding:8px 10px;border-top:1px solid #e5e7eb;text-align:left;vertical-align:top;font-size:13px}}
.sev{{color:#fff;padding:1px 8px;border-radius:10px;font-size:11px;text-transform:uppercase}}
.d{{color:#667085}}.f{{color:#3b7a57}}
</style></head><body><main>
<h1>Network security scan</h1><div class=tiles>{tiles}</div>
<table><thead><tr><th>Severity</th><th>Device</th><th>Finding</th></tr></thead><tbody>{rows or '<tr><td colspan=3>No findings.</td></tr>'}</tbody></table>
<h2 style=font-size:15px>Open ports</h2>
<table><thead><tr><th>Device</th><th>Open ports</th></tr></thead><tbody>{ports or '<tr><td colspan=2>not scanned</td></tr>'}</tbody></table>
<p class=d>Generated by vlantool. Report-only: nothing was changed.</p>
</main></body></html>"""
