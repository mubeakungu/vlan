"""Individual health checks: ping, TCP ports, and vendor stats over SSH."""
from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import time

_WINDOWS = platform.system() == "Windows"
_LATENCY = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)


def ping(host: str, timeout: float = 2.0) -> float | None:
    """Return round-trip time in ms, or None if the host did not answer."""
    if _WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    start = time.monotonic()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (OSError, subprocess.TimeoutExpired):
        return tcp_ping(host, timeout)  # no ping binary / no permission: fall back to TCP
    # Windows returns 0 for "Destination host unreachable", so also look for a reply time
    m = _LATENCY.search(out.stdout)
    if out.returncode != 0 or (_WINDOWS and not m):
        return None
    return float(m.group(1)) if m else round((time.monotonic() - start) * 1000, 1)


def tcp_ping(host: str, timeout: float = 2.0, ports=(22, 80, 443, 8291)) -> float | None:
    """Reachability without ICMP: an open port or a refused connection both mean the host is alive."""
    for port in ports:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except ConnectionRefusedError:
            pass
        except OSError:
            continue
        return round((time.monotonic() - start) * 1000, 1)
    return None


def tcp_check(host: str, port: int, timeout: float = 2.0) -> float | None:
    """Return connect time in ms, or None if the port is closed or filtered."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return None


# ---------------------------------------------------------------- SSH stats
# vendor key -> (command, parser). Parsers return a dict of display fields.

def _mikrotik(text: str) -> dict:
    out = {}
    for key, label in (("uptime", "uptime"), ("cpu-load", "cpu"), ("free-memory", "free_memory"),
                       ("total-memory", "total_memory"), ("version", "version"), ("board-name", "model")):
        m = re.search(rf"^\s*{key}:\s*(.+)$", text, re.M)
        if m:
            out[label] = m.group(1).strip()
    return out


def _cisco(text: str) -> dict:
    out = {}
    m = re.search(r"uptime is (.+)", text)
    if m:
        out["uptime"] = m.group(1).strip()
    m = re.search(r"CPU utilization for five seconds: (\d+)%", text)
    if m:
        out["cpu"] = m.group(1) + "%"
    m = re.search(r"Version ([^,\s]+)", text)
    if m:
        out["version"] = m.group(1)
    return out


def _junos(text: str) -> dict:
    out = {}
    m = re.search(r"System booted:.*\((.+?) ago\)", text)
    if m:
        out["uptime"] = m.group(1)
    m = re.search(r"Idle\s+(\d+) percent", text)
    if m:
        out["cpu"] = f"{100 - int(m.group(1))}%"
    return out


def _linuxish(text: str) -> dict:  # EdgeOS / VyOS
    m = re.search(r"up\s+(.+?),\s+\d+ users?", text) or re.search(r"up\s+(.+?),\s+load", text)
    return {"uptime": m.group(1).strip()} if m else {}


STATS = {
    "mikrotik_routeros": (["/system resource print"], _mikrotik),
    "cisco_ios": (["show version | include uptime|Version", "show processes cpu | include CPU"], _cisco),
    "cisco_nxos": (["show version | include uptime|version"], _cisco),
    "arista_eos": (["show version | include Uptime|version"], _cisco),
    "juniper_junos": (["show system uptime", "show chassis routing-engine | match Idle"], _junos),
    "ubiquiti_edgeos": (["uptime"], _linuxish),
    "vyos": (["uptime"], _linuxish),
}


def ssh_stats(device, timeout: int = 15) -> dict:
    """Log in with Netmiko and collect uptime/CPU/etc. Raises on failure."""
    from netmiko import ConnectHandler

    from ..vendors import get

    plugin = get(device.vendor)
    if plugin.key not in STATS or not plugin.netmiko_type:
        return {}
    commands, parser = STATS[plugin.key]
    params = {
        "device_type": plugin.netmiko_type, "host": device.host, "port": device.port,
        "username": device.username or os.environ.get("VLANTOOL_USERNAME"),
        "password": os.environ.get("VLANTOOL_PASSWORD", ""),
        "timeout": timeout,
    }
    with ConnectHandler(**params) as conn:
        text = "\n".join(conn.send_command(c) for c in commands)
    return parser(text)


# ------------------------------------------------- interface traffic counters
# vendor key -> (commands, parser). Parsers return {iface: (rx_bytes, tx_bytes)}.

def _mt_counters(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) == 4 and parts[0] == "":
            name, rx, tx = parts[1], parts[2], parts[3]
            if rx.isdigit() and tx.isdigit():
                out[name] = (int(rx), int(tx))
    return out


def _cisco_counters(text: str) -> dict:
    """Parse 'show interfaces' for input/output byte counters."""
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^(\S+) is (?:up|down|administratively down),", line)
        if m:
            cur = m.group(1)
        m = re.search(r"(\d+) packets input, (\d+) bytes", line)
        if m and cur:
            out.setdefault(cur, [0, 0])[0] = int(m.group(2))
        m = re.search(r"(\d+) packets output, (\d+) bytes", line)
        if m and cur:
            out.setdefault(cur, [0, 0])[1] = int(m.group(2))
    return {k: (v[0], v[1]) for k, v in out.items()}


def _linux_counters(text: str) -> dict:
    """Parse /proc/net/dev (EdgeOS/VyOS/OpenWrt over SSH)."""
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        cols = rest.split()
        if len(cols) >= 9 and cols[0].isdigit():
            out[name.strip()] = (int(cols[0]), int(cols[8]))  # rx bytes, tx bytes
    return out


IFACE_COUNTERS = {
    "mikrotik_routeros": ([':foreach i in=[/interface find] do={:put ("|".([/interface get $i name])."|".'
                           '([/interface get $i rx-byte])."|".([/interface get $i tx-byte]))}'], _mt_counters),
    "cisco_ios": (["show interfaces"], _cisco_counters),
    "arista_eos": (["show interfaces"], _cisco_counters),
    "ubiquiti_edgeos": (["cat /proc/net/dev"], _linux_counters),
    "vyos": (["cat /proc/net/dev"], _linux_counters),
    "openwrt": (["cat /proc/net/dev"], _linux_counters),
}


# ------------------------------------------------------- connected devices
# vendor key -> (commands, parser). Parsers return a list of client dicts:
#   {ip, mac, host, iface, source}   (source: dhcp / arp / wifi)

def _kv(line: str, key: str) -> str | None:
    m = re.search(rf'{key}=("[^"]*"|\S+)', line)
    return m.group(1).strip('"') if m else None


def _mt_clients(text: str) -> list[dict]:
    """Three terse blocks joined by markers: leases, arp, wireless registrations."""
    out: dict[str, dict] = {}
    section = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("### "):
            section = s[4:]
            continue
        mac = _kv(line, "mac-address")
        if not mac:
            continue
        mac = mac.upper()
        c = out.setdefault(mac, {"mac": mac, "ip": None, "host": None, "iface": None, "source": None})
        if section == "leases":
            c["ip"] = _kv(line, "active-address") or _kv(line, "address") or c["ip"]
            c["host"] = _kv(line, "host-name") or c["host"]
            c["iface"] = _kv(line, "server") or c["iface"]
            c["source"] = "dhcp"
        elif section == "arp":
            c["ip"] = c["ip"] or _kv(line, "address")
            c["iface"] = c["iface"] or _kv(line, "interface")
            c["source"] = c["source"] or "arp"
        elif section == "wifi":
            c["iface"] = _kv(line, "interface") or c["iface"]
            c["source"] = "wifi"
            sig = _kv(line, "signal-strength")
            if sig:
                c["signal"] = sig
    return list(out.values())


def _cisco_clients(text: str) -> list[dict]:
    out: dict[str, dict] = {}
    for line in text.splitlines():
        # show ip dhcp binding: IP   MAC(aabb.ccdd.eeff)   lease   type
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F.:]{12,17})", line)
        if m:
            mac = _norm_mac(m.group(2))
            out.setdefault(mac, {"mac": mac, "ip": None, "host": None, "iface": None, "source": "dhcp"})["ip"] = m.group(1)
        # show ip arp: Protocol Address Age Hardware-Addr Type Interface
        m = re.search(r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F.]{14})\s+\S+\s+(\S+)", line)
        if m:
            mac = _norm_mac(m.group(2))
            c = out.setdefault(mac, {"mac": mac, "ip": None, "host": None, "iface": None, "source": "arp"})
            c["ip"] = c["ip"] or m.group(1)
            c["iface"] = c["iface"] or m.group(3)
    return list(out.values())


def _norm_mac(raw: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", raw).upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else raw.upper()


CLIENTS = {
    "mikrotik_routeros": ([':put "### leases"', "/ip dhcp-server lease print terse",
                           ':put "### arp"', "/ip arp print terse",
                           ':put "### wifi"', "/interface wireless registration-table print terse"], _mt_clients),
    "cisco_ios": (["show ip dhcp binding", "show ip arp"], _cisco_clients),
}


# --------------------------------------------- traffic by source (top talkers)
# Per-host traffic, so the dashboard can show WHERE traffic is coming from.
# MikroTik: /ip accounting records bytes per src/dst IP pair. We take a fresh
# snapshot each round, so the bytes are the traffic since the last round.

def _mt_sources(text: str) -> dict:
    """Sum accounting bytes per host: out = bytes it sent, in = bytes it received."""
    out: dict[str, list] = {}
    for line in text.splitlines():
        b = _kv(line, "bytes")
        if not b or not b.isdigit():
            continue
        nbytes = int(b)
        src, dst = _kv(line, "src-address"), _kv(line, "dst-address")
        if src:
            out.setdefault(src, [0, 0])[1] += nbytes   # this host sent -> upload/out
        if dst:
            out.setdefault(dst, [0, 0])[0] += nbytes   # this host received -> download/in
    return {ip: (v[0], v[1]) for ip, v in out.items()}


TRAFFIC_SOURCES = {
    # take a fresh snapshot, then read it; empty output => accounting is disabled
    "mikrotik_routeros": (["/ip accounting snapshot take",
                           "/ip accounting snapshot print terse"], _mt_sources),
}


def ssh_collect(device, timeout: int = 15, want=("stats", "traffic", "clients", "sessions")) -> dict:
    """One Netmiko session: device stats, interface byte counters, and connected clients."""
    from netmiko import ConnectHandler

    from ..vendors import get

    plugin = get(device.vendor)
    if not plugin.netmiko_type:
        return {}
    params = {
        "device_type": plugin.netmiko_type, "host": device.host, "port": device.port,
        "username": device.username or os.environ.get("VLANTOOL_USERNAME"),
        "password": os.environ.get("VLANTOOL_PASSWORD", ""),
        "timeout": timeout,
    }
    plan = []
    if "stats" in want and plugin.key in STATS:
        plan.append(("stats", *STATS[plugin.key]))
    if "traffic" in want and plugin.key in IFACE_COUNTERS:
        plan.append(("traffic", *IFACE_COUNTERS[plugin.key]))
    if "sources" in want and plugin.key in TRAFFIC_SOURCES:
        plan.append(("sources", *TRAFFIC_SOURCES[plugin.key]))
    if "clients" in want and plugin.key in CLIENTS:
        plan.append(("clients", *CLIENTS[plugin.key]))
    if "sessions" in want and plugin.key in BILLING_SESSIONS:
        plan.append(("sessions", *BILLING_SESSIONS[plugin.key]))
    if not plan:
        return {}
    out: dict = {}
    with ConnectHandler(**params) as conn:
        for name, commands, parser in plan:
            try:
                text = "\n".join(conn.send_command(c) for c in commands)
                out[name] = parser(text)
            except Exception as exc:
                out.setdefault("errors", {})[name] = str(exc).splitlines()[0][:160]
    return out


# ------------------------------------------------ billing: active sessions
# Who is online right now on the hotspot and the PPPoE server (MikroTik).

def _dur_secs(s: str | None) -> int | None:
    if not s:
        return None
    total, num = 0, ""
    for ch in s:
        if ch.isdigit():
            num += ch
        elif ch in "wdhms" and num:
            total += int(num) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[ch]
            num = ""
    return total or None


def _mt_sessions(text: str) -> dict:
    out = {"hotspot": [], "pppoe": []}
    section = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("### "):
            section = s[4:]
            continue
        if section == "hs" and _kv(line, "user"):
            out["hotspot"].append({
                "user": _kv(line, "user"), "ip": _kv(line, "address"),
                "mac": (_kv(line, "mac-address") or "").upper() or None,
                "uptime": _kv(line, "uptime"),
                "in_bytes": _int(_kv(line, "bytes-in")), "out_bytes": _int(_kv(line, "bytes-out"))})
        elif section == "ppp" and _kv(line, "name"):
            out["pppoe"].append({
                "user": _kv(line, "name"), "ip": _kv(line, "address"),
                "service": _kv(line, "service"), "uptime": _kv(line, "uptime")})
    return out


def _int(v: str | None) -> int | None:
    return int(v) if v and v.isdigit() else None


BILLING_SESSIONS = {
    "mikrotik_routeros": ([':put "### hs"', "/ip hotspot active print terse",
                           ':put "### ppp"', "/ppp active print terse"], _mt_sessions),
}
