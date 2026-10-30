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
