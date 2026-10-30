"""Services layered on top of VLANs: router basics, point-to-point links, VPN, wireless.

Each service module exposes:
    render(plugin) -> list[str]           config lines for the device (empty if unused)
    files(plugin) -> dict[str, str]       optional extra files (e.g. WireGuard clients)
    validate(net, device) -> (errors, warnings)
A vendor without native support gets a manual step list instead of silence.
"""
from __future__ import annotations

from . import billing, filtering, links, router, security, vpn, wireless

SERVICES = [router, links, vpn, wireless, filtering, security, billing]


def render_services(plugin) -> list[str]:
    out: list[str] = []
    for svc in SERVICES:
        out += svc.render(plugin)
    return out


def postprocess(plugin, lines: list[str]) -> list[str]:
    """Let services adjust the finished config (e.g. attach IPS to every firewall policy)."""
    for svc in SERVICES:
        if hasattr(svc, "postprocess"):
            lines = svc.postprocess(plugin, lines)
    return lines


def service_files(plugin) -> dict[str, str]:
    files: dict[str, str] = {}
    for svc in SERVICES:
        if hasattr(svc, "files"):
            files.update(svc.files(plugin))
    return files


def validate_services(net, device) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    for svc in SERVICES:
        e, w = svc.validate(net, device)
        errors += e
        warnings += w
    return errors, warnings
