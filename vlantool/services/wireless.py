"""Access points and extenders: SSIDs mapped to VLANs, repeater/extender mode, mesh.

    wireless:
      country: kenya              # MikroTik country name (OpenWrt: country_code: KE)
      mode: ap                    # ap (default), extender, or mesh
      ssids:
        - {ssid: Home,  passphrase: "long-passphrase", vlan: USERS, band: both}
        - {ssid: Guest, passphrase: "guest-pass-123",  vlan: GUEST, band: 2ghz}
      uplink:                     # extender mode: the network to repeat
        {ssid: MainWiFi, passphrase: "...", band: 5ghz}
      mesh: {id: home-mesh, passphrase: "...", band: 5ghz}   # mesh mode (OpenWrt 802.11s)

MikroTik: driver: wifi (hAP ax, newer) or wireless (hAP ac/ac lite legacy).
"""
from __future__ import annotations

import re

from ..model import parse_vlan_list
from .common import as_list, manual, mt_once

BANDS = ("2ghz", "5ghz")
SEC_OPENWRT = {"wpa2": "psk2", "wpa3": "sae", "wpa2/wpa3": "sae-mixed"}
SEC_MT_WIFI = {"wpa2": "wpa2-psk", "wpa3": "wpa3-psk", "wpa2/wpa3": "wpa2-psk,wpa3-psk"}


def cfg(p) -> dict | None:
    raw = p.dev.options.get("wireless")
    if not raw:
        return None
    c = dict(raw)
    c.setdefault("mode", "ap")
    ssids = []
    for s in as_list(c.get("ssids")):
        s = dict(s)
        band = str(s.get("band", "both")).lower()
        s["bands"] = list(BANDS) if band == "both" else [band]
        vid = parse_vlan_list(s.get("vlan"), p.net.vlans) if s.get("vlan") not in (None, "") else []
        s["vlan_id"] = vid[0] if vid else None
        s.setdefault("security", "wpa2/wpa3")
        s["slug"] = re.sub(r"[^a-z0-9]+", "", s["ssid"].lower())[:10] or "ssid"
        ssids.append(s)
    c["ssids"] = ssids
    return c


# ------------------------------------------------------------------ MikroTik

def mikrotik(p, c) -> list[str]:
    legacy = p.dev.options.get("wifi_driver", c.get("driver", "wifi")) == "wireless"
    radios = c.get("radios") or ({"2ghz": "wlan1", "5ghz": "wlan2"} if legacy else {"2ghz": "wifi2", "5ghz": "wifi1"})
    country = c.get("country", "etsi")
    br = p.dev.bridge
    out = []
    used: dict[str, int] = {}
    uplink_band = None
    if c["mode"] == "extender" and c.get("uplink"):
        u = c["uplink"]
        uplink_band = str(u.get("band", "5ghz")).lower()
        r = radios[uplink_band]
        mode = "station-bridge" if u.get("mikrotik") else "station-pseudobridge"
        if legacy:
            out += [f'/interface wireless security-profiles add name=sp-uplink mode=dynamic-keys authentication-types=wpa2-psk '
                    f'wpa2-pre-shared-key="{u["passphrase"]}"',
                    f"/interface wireless set [find default-name={r}] mode={mode} ssid={u['ssid']} security-profile=sp-uplink "
                    f"country={country} disabled=no"]
        else:
            out.append(f"/interface wifi set [find default-name={r}] configuration.mode={mode} configuration.ssid={u['ssid']} "
                       f'configuration.country={country} security.authentication-types=wpa2-psk,wpa3-psk '
                       f'security.passphrase="{u["passphrase"]}" disabled=no')
        out.append(mt_once(f"/interface bridge port find interface={r}", f"/interface bridge port add bridge={br} interface={r}"))
        used[r] = 1  # the uplink radio's master interface is taken; local SSIDs on it become virtual APs
    for s in c["ssids"]:
        for band in s["bands"]:
            r = radios[band]
            n = used.get(r, 0)
            used[r] = n + 1
            name = r if n == 0 else f"{r}-{s['slug']}"
            if legacy:
                sp = f"sp-{s['slug']}"
                out.append(mt_once(f"/interface wireless security-profiles find name={sp}",
                                   f"/interface wireless security-profiles add name={sp} mode=dynamic-keys "
                                   f'authentication-types=wpa2-psk wpa2-pre-shared-key="{s["passphrase"]}"'))
                if n == 0:
                    out.append(f"/interface wireless set [find default-name={r}] mode=ap-bridge ssid={s['ssid']} "
                               f"security-profile={sp} country={country} wps-mode=disabled disabled=no")
                else:
                    out.append(f"/interface wireless add master-interface={r} name={name} ssid={s['ssid']} "
                               f"security-profile={sp} wps-mode=disabled disabled=no")
            else:
                sec = (f"security.authentication-types={SEC_MT_WIFI.get(s['security'], 'wpa2-psk,wpa3-psk')} "
                       f'security.passphrase="{s["passphrase"]}"')
                hidden = " configuration.hide-ssid=yes" if s.get("hidden") else ""
                if n == 0:
                    out.append(f"/interface wifi set [find default-name={r}] configuration.mode=ap configuration.ssid={s['ssid']} "
                               f"configuration.country={country} {sec}{hidden} disabled=no")
                else:
                    out.append(f"/interface wifi add master-interface={r} name={name} configuration.mode=ap "
                               f"configuration.ssid={s['ssid']} {sec}{hidden} disabled=no")
            out.append(mt_once(f"/interface bridge port find interface={name}", f"/interface bridge port add bridge={br} interface={name}"))
            if s["vlan_id"]:
                out.append(f"/interface bridge port set [find interface={name}] pvid={s['vlan_id']} "
                           "frame-types=admit-only-untagged-and-priority-tagged")
    if c["mode"] == "mesh":
        out += manual(p, "Mesh", ["RouterOS has no 802.11s mesh; use CAPsMAN with wired backhaul, or extender mode "
                                  "(station-bridge) for wireless backhaul between MikroTik units"])
    return out


# ------------------------------------------------------------------- OpenWrt

def openwrt(p, c) -> list[str]:
    radios = c.get("radios") or {"2ghz": "radio0", "5ghz": "radio1"}
    cc = c.get("country_code", "KE")
    out = []
    for band, r in radios.items():
        out += [f"uci set wireless.{r}.disabled='0'", f"uci set wireless.{r}.country='{cc}'",
                f"uci set wireless.{r}.channel='{c.get('channel_' + band[0] + 'g', 'auto')}'",
                f"uci -q set wireless.default_{r}.disabled='1'"]
    for s in c["ssids"]:
        net = p.l3_name(p.vlan(s["vlan_id"])) if s["vlan_id"] else "lan"
        for band in s["bands"]:
            r = radios[band]
            sec = f"wireless.vt_{s['slug']}_{r}"
            out += [f"uci set {sec}=wifi-iface", f"uci set {sec}.device='{r}'", f"uci set {sec}.mode='ap'",
                    f"uci set {sec}.ssid='{s['ssid']}'", f"uci set {sec}.encryption='{SEC_OPENWRT.get(s['security'], 'sae-mixed')}'",
                    f"uci set {sec}.key='{s['passphrase']}'", f"uci set {sec}.network='{net}'"]
            if s.get("hidden"):
                out.append(f"uci set {sec}.hidden='1'")
    if c["mode"] == "extender" and c.get("uplink"):
        u = c["uplink"]
        r = radios[str(u.get("band", "5ghz")).lower()]
        sec = "wireless.vt_uplink"
        out += [f"uci set {sec}=wifi-iface", f"uci set {sec}.device='{r}'", f"uci set {sec}.mode='sta'",
                f"uci set {sec}.ssid='{u['ssid']}'", f"uci set {sec}.encryption='{SEC_OPENWRT.get(u.get('security', 'wpa2'), 'psk2')}'",
                f"uci set {sec}.key='{u['passphrase']}'"]
        if u.get("wds"):
            out += [f"uci set {sec}.wds='1'", f"uci set {sec}.network='lan'"]
        else:  # routed repeater: works with any upstream router
            out += [f"uci set {sec}.network='wwan'", "uci set network.wwan=interface", "uci set network.wwan.proto='dhcp'",
                    "uci add_list firewall.@zone[1].network='wwan'"]
    if c["mode"] == "mesh" and c.get("mesh"):
        m = c["mesh"]
        r = radios[str(m.get("band", "5ghz")).lower()]
        sec = "wireless.vt_mesh"
        out += [p.note("mesh needs the wpad-mesh-openssl package (opkg install wpad-mesh-openssl)"),
                f"uci set {sec}=wifi-iface", f"uci set {sec}.device='{r}'", f"uci set {sec}.mode='mesh'",
                f"uci set {sec}.mesh_id='{m['id']}'", f"uci set {sec}.encryption='sae'", f"uci set {sec}.key='{m['passphrase']}'",
                f"uci set {sec}.network='lan'", f"uci set {sec}.mesh_fwding='1'"]
    return out


def manual_steps(p, c) -> list[str]:
    steps = []
    for s in c["ssids"]:
        vlan = f"VLAN {s['vlan_id']} ({p.vlan(s['vlan_id']).name})" if s["vlan_id"] else "the default LAN (untagged)"
        steps.append(f"Create SSID '{s['ssid']}' on {' + '.join(s['bands'])}, {s['security'].upper()} passphrase "
                     f"'{s['passphrase']}', tagged as {vlan}")
    if any(s["vlan_id"] for s in c["ssids"]):
        steps.append("Make the switch port feeding this AP a trunk carrying those VLANs")
    if c["mode"] == "extender" and c.get("uplink"):
        u = c["uplink"]
        steps.append(f"Set repeater/extender mode: connect to '{u['ssid']}' with passphrase '{u['passphrase']}'")
    if c["mode"] == "mesh" and c.get("mesh"):
        steps.append(f"Enable mesh '{c['mesh']['id']}' (UniFi: Wireless Meshing; Omada: Mesh; Deco/EAP: pair from the app)")
    return manual(p, "Wi-Fi", steps)


def render(plugin) -> list[str]:
    c = cfg(plugin)
    if not c:
        return []
    out = [plugin.note("---- wireless ----")]
    if plugin.key == "mikrotik_routeros":
        return out + mikrotik(plugin, c)
    if plugin.key == "openwrt":
        return out + openwrt(plugin, c)
    return out + manual_steps(plugin, c)


def validate(net, device) -> tuple[list[str], list[str]]:
    raw = device.options.get("wireless")
    if not raw:
        return [], []
    errors, warnings = [], []
    where = f"device {device.name}: wireless"
    mode = raw.get("mode", "ap")
    if mode not in ("ap", "extender", "mesh"):
        errors.append(f"{where}: mode must be ap, extender or mesh")
    for s in as_list(raw.get("ssids")):
        if not s.get("ssid"):
            errors.append(f"{where}: every SSID needs 'ssid'")
        if len(str(s.get("passphrase", ""))) < 8:
            errors.append(f"{where}: SSID {s.get('ssid')} needs a passphrase of 8+ characters")
        if str(s.get("band", "both")).lower() not in ("both",) + BANDS:
            errors.append(f"{where}: SSID {s.get('ssid')} band must be both, 2ghz or 5ghz")
        if s.get("security", "wpa2/wpa3") not in SEC_OPENWRT:
            errors.append(f"{where}: SSID {s.get('ssid')} security must be wpa2, wpa3 or wpa2/wpa3")
        if s.get("vlan") not in (None, ""):
            try:
                vid = parse_vlan_list(s["vlan"], net.vlans)
            except ValueError as exc:
                errors.append(f"{where}: SSID {s.get('ssid')}: {exc}")
                continue
            if not vid or vid[0] not in net.vlans:
                errors.append(f"{where}: SSID {s.get('ssid')} uses undefined VLAN {s['vlan']}")
            elif vid[0] not in device.vlan_ids:
                errors.append(f"{where}: SSID {s.get('ssid')} VLAN {vid[0]} is not in this device's 'vlans'")
    if mode == "extender" and not (raw.get("uplink") or {}).get("ssid"):
        errors.append(f"{where}: extender mode needs 'uplink' with ssid and passphrase")
    if mode == "mesh" and not (raw.get("mesh") or {}).get("id"):
        errors.append(f"{where}: mesh mode needs 'mesh' with id and passphrase")
    return errors, warnings
