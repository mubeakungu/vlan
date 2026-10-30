"""Management controller: reach every device over SSH (through the VPN if there is one)
for diagnostics, ad-hoc commands, log pulls, config backups and firmware upgrades.

This is central remote management of your own gear. It authenticates to each
device with your credentials; it does not intercept or relay traffic between
other parties.

    vlantool control network.yaml facts                 # model, version, uptime of each device
    vlantool control network.yaml diagnose              # health check across the whole network
    vlantool control network.yaml backup -o backups/    # save each device's config
    vlantool control network.yaml run "/system reboot" -d hap
    vlantool control network.yaml logs -d hap
    vlantool control network.yaml upgrade -d hap        # check for updates (add --apply to install)
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .model import Device, Network
from .vendors import get

# per-vendor commands. {} entry means the vendor has no non-interactive way (reported, not failed).
BACKUP_CMD = {
    "cisco_ios": "show running-config", "cisco_nxos": "show running-config", "arista_eos": "show running-config",
    "dell_os10": "show running-configuration", "cisco_smb": "show running-config", "dlink_dgs": "show running-config",
    "juniper_junos": "show configuration | display set", "aruba_aoscx": "show running-config",
    "hp_procurve": "show running-config", "huawei_vrp": "display current-configuration",
    "hp_comware": "display current-configuration", "mikrotik_routeros": "/export",
    "fortinet": "show full-configuration", "vyos": "show configuration commands",
    "ubiquiti_edgeos": "show configuration commands", "openwrt": "uci export",
    "ruckus_icx": "show running-config", "extreme_exos": "show configuration", "zyxel": "show running-config",
    "ubiquiti_edgeswitch": "show running-config", "netgear": "show running-config", "tplink_jetstream": "show running-config",
}
VERSION_CMD = {
    "cisco_ios": ["show version"], "cisco_nxos": ["show version"], "arista_eos": ["show version"],
    "dell_os10": ["show version"], "juniper_junos": ["show version"], "aruba_aoscx": ["show version"],
    "hp_procurve": ["show version"], "huawei_vrp": ["display version"], "hp_comware": ["display version"],
    "mikrotik_routeros": ["/system resource print", "/system routerboard print"],
    "fortinet": ["get system status"], "vyos": ["show version"], "ubiquiti_edgeos": ["show version"],
    "openwrt": ["ubus call system board", "cat /etc/openwrt_release"],
}
LOG_CMD = {
    "cisco_ios": "show logging", "cisco_nxos": "show logging last 200", "arista_eos": "show logging last 200",
    "juniper_junos": "show log messages | last 200", "aruba_aoscx": "show logging", "hp_procurve": "show logging",
    "huawei_vrp": "display logbuffer", "hp_comware": "display logbuffer", "mikrotik_routeros": "/log print",
    "fortinet": "execute log display", "vyos": "show log tail 200", "ubiquiti_edgeos": "show log tail 200",
    "openwrt": "logread | tail -n 200",
}


@dataclass
class Result:
    device: str
    ok: bool
    data: dict = field(default_factory=dict)
    output: str = ""
    error: str = ""


def _params(net: Network, d: Device, timeout: int = 20) -> dict:
    plugin = get(d.vendor)
    return {
        "device_type": plugin.netmiko_type, "host": d.host, "port": d.port,
        "username": d.username or os.environ.get("VLANTOOL_USERNAME"),
        "password": os.environ.get(f"VLANTOOL_PASSWORD_{d.name.upper().replace('-', '_')}",
                                   os.environ.get("VLANTOOL_PASSWORD", "")),
        "secret": os.environ.get("VLANTOOL_SECRET", ""), "timeout": timeout, "fast_cli": False,
    }


def _manageable(d: Device) -> tuple[bool, str]:
    plugin = get(d.vendor)
    if not d.host:
        return False, "no host set"
    if not plugin.netmiko_type:
        return False, f"{plugin.title} has no SSH management"
    return True, ""


def _connect(net: Network, d: Device):
    from netmiko import ConnectHandler
    conn = ConnectHandler(**_params(net, d))
    if _params(net, d)["secret"]:
        try:
            conn.enable()
        except Exception:
            pass
    return conn


# ---------------------------------------------------------------- operations

def facts(net: Network, d: Device) -> Result:
    ok, why = _manageable(d)
    if not ok:
        return Result(d.name, False, error=why)
    try:
        with _connect(net, d) as conn:
            text = "\n".join(conn.send_command(c) for c in VERSION_CMD.get(d.vendor, ["show version"]))
    except Exception as exc:
        return Result(d.name, False, error=str(exc).splitlines()[0][:200])
    return Result(d.name, True, data=_parse_facts(d.vendor, text), output=text)


def _parse_facts(vendor: str, text: str) -> dict:
    f = {}
    patterns = {
        "version": [r"Version:\s*([^\s]+)", r"Version ([^\s,]+)", r"version ([\w.]+)", r'"release":\s*"([^"]+)"',
                    r"DISTRIB_RELEASE='([^']+)'", r"Version:\s*(v[\d.]+)"],
        "model": [r"board-name:\s*(.+)", r"model:\s*(.+)", r"Hardware:\s*([^\n,]+)", r'"model":\s*"([^"]+)"',
                  r"Model:\s*([^\n]+)", r"cisco (\S+)"],
        "uptime": [r"uptime:\s*(.+)", r"uptime is (.+)", r"System booted.*\((.+?) ago\)", r"up\s+(.+?),"],
        "serial": [r"serial-number:\s*(\S+)", r"Serial Number:\s*(\S+)", r"System serial number\s*:\s*(\S+)"],
    }
    for key, pats in patterns.items():
        for pat in pats:
            m = re.search(pat, text, re.I)
            if m:
                f[key] = m.group(1).strip()
                break
    return f


def run(net: Network, d: Device, commands: list[str], config: bool = False) -> Result:
    ok, why = _manageable(d)
    if not ok:
        return Result(d.name, False, error=why)
    try:
        with _connect(net, d) as conn:
            if config:
                out = conn.send_config_set(commands)
            else:
                out = "\n".join(f"$ {c}\n{conn.send_command(c)}" for c in commands)
    except Exception as exc:
        return Result(d.name, False, error=str(exc).splitlines()[0][:200])
    return Result(d.name, True, output=out)


def logs(net: Network, d: Device) -> Result:
    cmd = LOG_CMD.get(d.vendor)
    if not cmd:
        return Result(d.name, False, error=f"no log command for {get(d.vendor).title}")
    return run(net, d, [cmd])


def backup(net: Network, d: Device, out_dir: Path | None = None) -> Result:
    cmd = BACKUP_CMD.get(d.vendor)
    if not cmd:
        return Result(d.name, False, error=f"no config export for {get(d.vendor).title}")
    r = run(net, d, [cmd])
    if not r.ok:
        return r
    text = r.output.split("\n", 1)[1] if r.output.startswith("$ ") else r.output
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = out_dir / f"{d.name}-{stamp}.cfg"
        path.write_text(text)
        r.data["path"] = str(path)
    r.output = text
    return r


def diagnose(net: Network, d: Device) -> Result:
    """Reachability + a few health signals, without logging in where we cannot."""
    from .monitor import checks
    if not d.host:
        return Result(d.name, False, error="no host set")
    latency = checks.ping(d.host)
    data = {"reachable": latency is not None, "latency_ms": latency}
    ok, why = _manageable(d)
    if ok and latency is not None and d.vendor in VERSION_CMD:
        try:
            with _connect(net, d) as conn:
                text = "\n".join(conn.send_command(c) for c in VERSION_CMD[d.vendor])
            data.update(_parse_facts(d.vendor, text))
            if d.vendor == "mikrotik_routeros":
                m = re.search(r"cpu-load:\s*(\d+)", text)
                if m:
                    data["cpu"] = m.group(1) + "%"
        except Exception as exc:
            data["ssh_error"] = str(exc).splitlines()[0][:120]
    return Result(d.name, latency is not None, data=data)


# ----------------------------------------------------------------- upgrades

def upgrade(net: Network, d: Device, apply: bool = False, out_dir: Path | None = None) -> Result:
    """Check for firmware updates; with apply=True, back up and install (MikroTik/OpenWrt)."""
    ok, why = _manageable(d)
    if not ok:
        return Result(d.name, False, error=why)
    k = d.vendor
    if k not in ("mikrotik_routeros", "openwrt"):
        return Result(d.name, False, error=f"automatic upgrade not supported for {get(d.vendor).title}; "
                                            "check the vendor's site and upgrade from its UI")
    try:
        b = backup(net, d, out_dir)
        note = f"backed up to {b.data.get('path')}" if b.ok and out_dir else ("backup ok" if b.ok else f"BACKUP FAILED: {b.error}")
        if not b.ok and apply:
            return Result(d.name, False, error=f"refusing to upgrade without a backup: {b.error}")
        with _connect(net, d) as conn:
            if k == "mikrotik_routeros":
                check = conn.send_command("/system package update check-for-updates", read_timeout=30)
                available = re.search(r"latest-version:\s*(\S+)", check)
                installed = re.search(r"installed-version:\s*(\S+)", check)
                status = f"installed {installed.group(1) if installed else '?'}, latest {available.group(1) if available else '?'}"
                if apply and available and installed and available.group(1) != installed.group(1):
                    conn.send_command("/system package update download", read_timeout=120)
                    out = conn.send_command_timing("/system reboot\ny")
                    return Result(d.name, True, output=f"{note}; downloading and rebooting to install ({status})\n{out}")
                return Result(d.name, True, output=f"{note}; {status}" + ("" if apply else " (run with --apply to install)"))
            else:  # openwrt
                board = conn.send_command("ubus call system board")
                if apply:
                    out = conn.send_command_timing("opkg update && opkg list-upgradable")
                    return Result(d.name, True, output=f"{note}; package list:\n{out}\n"
                                  "(firmware image upgrades need 'sysupgrade <image>'; do those by hand)")
                return Result(d.name, True, output=f"{note}; {board}\nRun 'opkg update && opkg list-upgradable' to see package updates")
    except Exception as exc:
        return Result(d.name, False, error=str(exc).splitlines()[0][:200])


# ------------------------------------------------------------------ runners

def _select(net: Network, names: list[str] | None) -> list[Device]:
    return [net.device(n) for n in names] if names else net.devices


def each(net: Network, fn, names: list[str] | None = None, workers: int = 10) -> list[Result]:
    devices = _select(net, names)
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(devices)))) as pool:
        return list(pool.map(lambda d: fn(net, d), devices))
