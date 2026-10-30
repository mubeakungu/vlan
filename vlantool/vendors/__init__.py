"""Vendor plugin registry.

To add a vendor, subclass vendors.base.Vendor, give it a unique `key`, and
list it in PLUGINS below (or call register()).
"""
from __future__ import annotations

from .aruba import ArubaAOSCX, ArubaOSSwitch
from .base import Vendor
from .cisco import AristaEOS, CiscoIOS, CiscoNXOS, CiscoSMB, DellOS10, DLinkDGS
from .comware import HPComware, HuaweiVRP
from .juniper import JuniperJunos
from .routers import EdgeOS, FortiGate, MikroTik, PfSense, VyOS
from .smallbiz import DLinkLegacy, ExtremeEXOS, FastPath, Netgear, RuckusICX, TPLinkJetStream, Zyxel
from .webgui import WebGUI

PLUGINS: list[type[Vendor]] = [
    CiscoIOS, CiscoNXOS, CiscoSMB, AristaEOS, DellOS10,
    JuniperJunos, ArubaAOSCX, ArubaOSSwitch, HPComware, HuaweiVRP,
    DLinkDGS, DLinkLegacy, TPLinkJetStream, FastPath, Netgear,
    ExtremeEXOS, RuckusICX, Zyxel,
    MikroTik, EdgeOS, VyOS, FortiGate, PfSense,
    WebGUI,
]

REGISTRY: dict[str, type[Vendor]] = {p.key: p for p in PLUGINS}

# friendly aliases people are likely to type
ALIASES = {
    "cisco": "cisco_ios", "ios": "cisco_ios", "iosxe": "cisco_ios", "nxos": "cisco_nxos",
    "arista": "arista_eos", "dell": "dell_os10", "juniper": "juniper_junos", "junos": "juniper_junos",
    "aruba": "aruba_aoscx", "aoscx": "aruba_aoscx", "procurve": "hp_procurve", "hp": "hp_procurve",
    "comware": "hp_comware", "h3c": "hp_comware", "huawei": "huawei_vrp",
    "tplink": "tplink_jetstream", "tp-link": "tplink_jetstream", "edgeswitch": "ubiquiti_edgeswitch",
    "ubiquiti": "ubiquiti_edgeswitch", "edgerouter": "ubiquiti_edgeos", "edgeos": "ubiquiti_edgeos",
    "unifi": "web_gui", "omada": "web_gui", "mikrotik": "mikrotik_routeros", "routeros": "mikrotik_routeros",
    "fortigate": "fortinet", "fortios": "fortinet", "opnsense": "pfsense", "extreme": "extreme_exos",
    "ruckus": "ruckus_icx", "brocade": "ruckus_icx", "cisco_sg": "cisco_smb", "cbs": "cisco_smb",
    "smart": "web_gui", "web": "web_gui",
}
for alias, key in ALIASES.items():
    REGISTRY.setdefault(alias, REGISTRY[key])


def register(plugin: type[Vendor]) -> None:
    PLUGINS.append(plugin)
    REGISTRY[plugin.key] = plugin


def get(key: str) -> type[Vendor]:
    try:
        return REGISTRY[key]
    except KeyError:
        raise KeyError(f"unknown vendor {key!r}; run 'vlantool vendors' for the list") from None
