"""Send generated config to devices over SSH with Netmiko (optional dependency)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .model import Device, Network
from .vendors import get


@dataclass
class PushResult:
    device: str
    ok: bool
    output: str


def plan(net: Network, device: Device) -> list[str]:
    plugin = get(device.vendor)(net, device)
    return plugin.push_commands()


def push_device(net: Network, device: Device, *, username: str | None = None,
                password: str | None = None, secret: str | None = None,
                save: bool = True, timeout: int = 30) -> PushResult:
    plugin_cls = get(device.vendor)
    plugin = plugin_cls(net, device)
    if not plugin_cls.pushable or not plugin_cls.netmiko_type:
        return PushResult(device.name, False, f"{plugin_cls.title} cannot be pushed over SSH; apply the generated file by hand")
    if not device.host:
        return PushResult(device.name, False, "no 'host' set for this device")
    try:
        from netmiko import ConnectHandler
    except ImportError:
        return PushResult(device.name, False, "Netmiko is not installed: pip install netmiko")

    params = {
        "device_type": plugin_cls.netmiko_type,
        "host": device.host,
        "port": device.port,
        "username": username or device.username or os.environ.get("VLANTOOL_USERNAME"),
        "password": password or os.environ.get("VLANTOOL_PASSWORD"),
        "secret": secret or os.environ.get("VLANTOOL_SECRET", ""),
        "timeout": timeout,
    }
    if not params["username"] or params["password"] is None:
        return PushResult(device.name, False, "missing username/password (use flags, prompt, or VLANTOOL_USERNAME/VLANTOOL_PASSWORD)")

    commands = plugin.push_commands()
    log: list[str] = []
    try:
        with ConnectHandler(**params) as conn:
            if params["secret"]:
                conn.enable()
            log.append(conn.send_config_set(commands, enter_config_mode=plugin_cls.push_enter_config,
                                            exit_config_mode=not plugin_cls.commit, cmd_verify=False))
            if plugin_cls.commit:
                log.append(conn.commit())
                if save and plugin_cls.key != "juniper_junos":  # Junos commit already persists
                    log.append(conn.send_command_timing("save"))
                conn.exit_config_mode()
            elif save:
                try:
                    log.append(conn.save_config())
                except NotImplementedError:
                    log.append("(this driver has no save command; save the config manually)")
    except Exception as exc:  # report and keep going with the next device
        return PushResult(device.name, False, "\n".join(log + [f"ERROR: {exc}"]))
    return PushResult(device.name, True, "\n".join(log))
