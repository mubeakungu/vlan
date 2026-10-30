"""Placeholder for devices that are only monitored (APs, extenders, servers, PtP radios...)."""
from __future__ import annotations

from .base import Vendor


class Generic(Vendor):
    key = "generic"
    title = "Generic device (monitoring only)"
    covers = "Access points, extenders, PtP radios, servers, cameras: anything with an IP to watch"
    netmiko_type = None
    pushable = False
    supports_switching = False
    comment = "#"

    def header(self) -> list[str]:
        return [f"# {self.dev.name}: {self.title}"]

    def render(self) -> list[str]:
        return []
