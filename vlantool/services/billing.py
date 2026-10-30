"""Billing / subscriber management: hotspot vouchers and PPPoE plans.

Turns a router into a prepaid internet seller: a captive-portal hotspot with
time/speed voucher codes, and/or a PPPoE server with per-plan speed limits and
subscriber accounts. Classic WISP / cyber-cafe setup. MikroTik generates full
config; other vendors get step-by-step notes. External billing software plugs
in through the optional RADIUS block.

    billing:
      radius: {server: 192.168.99.60, secret: s3cr3t}   # optional: hand auth to a billing server
      hotspot:
        interface: GUEST            # a VLAN (name or id) or a raw interface
        dns_name: login.hotspot     # captive-portal hostname (optional)
        plans:
          - {name: 1hour, rate: "5M/5M", session: 1h, shared: 1, price: 50}
          - {name: 1day,  rate: "10M/10M", session: 1d, price: 200}
        vouchers:
          - {plan: 1hour, count: 10}                 # 10 generated codes
          - {plan: 1day, user: vip, password: keepme}  # a named account
      pppoe:
        interface: ether1
        service: pppoe-isp
        pool: 10.6.0.2-10.6.0.254
        dns: [1.1.1.1, 8.8.8.8]
        plans:
          - {name: home-10m, rate: "10M/10M", price: 1500}
        subscribers:
          - {user: sub001, plan: home-10m}           # password generated if omitted
          - {user: sub002, plan: home-10m, password: given}

Rate is MikroTik rate-limit syntax (rx/tx, e.g. "10M/10M"). Session/quota use
MikroTik time/size syntax (1h, 30d, 2G). Generated voucher codes and passwords
are stored in <network>.secrets.json so they stay the same across regenerations,
and a printable list is written as an extra file by `generate -o`.
"""
from __future__ import annotations

from .common import as_list, manual


def iface_of(p, value: str) -> str:
    """Resolve a VLAN name/id to its routed-interface name, or pass a raw interface through."""
    if value is None:
        return value
    for v in p.net.vlans.values():
        if str(value) in (v.name, str(v.id)) and p.l3_name(v):
            return p.l3_name(v)
    return value


def cfg(p) -> dict | None:
    raw = p.dev.options.get("billing")
    if not raw:
        return None
    c = {"radius": raw.get("radius"), "hotspot": None, "pppoe": None}
    hs = raw.get("hotspot")
    if hs:
        hs = dict(hs)
        hs["plans"] = as_list(hs.get("plans"))
        hs["vouchers"] = as_list(hs.get("vouchers"))
        c["hotspot"] = hs
    pp = raw.get("pppoe")
    if pp:
        pp = dict(pp)
        pp["plans"] = as_list(pp.get("plans"))
        pp["subscribers"] = as_list(pp.get("subscribers") or pp.get("users"))
        pp["dns"] = as_list(pp.get("dns"))
        c["pppoe"] = pp
    return c if (c["hotspot"] or c["pppoe"]) else None


def accounts(p, c) -> dict:
    """Resolve every voucher/subscriber to concrete (user, password, plan, price) rows.

    Codes and generated passwords come from the secrets store so they are stable.
    """
    out = {"hotspot": [], "pppoe": []}
    hs = c.get("hotspot")
    if hs:
        prices = {pl["name"]: pl.get("price") for pl in hs["plans"]}
        for i, v in enumerate(hs["vouchers"]):
            plan = v.get("plan")
            if v.get("user"):
                pw = v.get("password") or p.net.secrets.voucher_code(f"{p.dev.name}/hs/{v['user']}")
                out["hotspot"].append({"user": v["user"], "password": pw, "plan": plan, "price": prices.get(plan)})
            else:
                for n in range(int(v.get("count", 1))):
                    code = p.net.secrets.voucher_code(f"{p.dev.name}/hs/{plan}/{i}/{n}")
                    out["hotspot"].append({"user": code, "password": code, "plan": plan, "price": prices.get(plan)})
    pp = c.get("pppoe")
    if pp:
        prices = {pl["name"]: pl.get("price") for pl in pp["plans"]}
        for s in pp["subscribers"]:
            pw = s.get("password") or p.net.secrets.voucher_code(f"{p.dev.name}/ppp/{s['user']}")
            out["pppoe"].append({"user": s["user"], "password": pw, "plan": s.get("plan"), "price": prices.get(s.get("plan"))})
    return out


# ------------------------------------------------------------------ MikroTik

def mikrotik(p, c) -> list[str]:
    out = [p.note("---- billing ----")]
    radius = c.get("radius")
    accts = accounts(p, c)
    hs = c.get("hotspot")
    if hs:
        iface = iface_of(p, hs.get("interface"))
        out.append(p.note(f"hotspot on {iface} (captive portal + vouchers)"))
        # one address pool for hotspot clients, derived from a VLAN subnet when possible
        vlan = next((v for v in p.routed if p.l3_name(v) == iface), None)
        gw = str(vlan.ip) if vlan else hs.get("gateway", "")
        if hs.get("pool"):
            pool_ranges = hs["pool"]
        elif vlan:
            net = vlan.interface.network
            pool_ranges = f"{net.network_address + 10}-{net.broadcast_address - 1}"
        else:
            pool_ranges = hs.get("network", "10.5.50.10-10.5.50.254")
        out.append(f"/ip pool add name=vt-hs-pool ranges={pool_ranges}")
        prof = ("/ip hotspot profile add name=vt-hsprof hotspot-address=" + gw
                + (f" dns-name={hs['dns_name']}" if hs.get("dns_name") else "")
                + " html-directory=hotspot login-by=http-chap,http-pap"
                + (" use-radius=yes" if radius else ""))
        out.append(prof)
        out.append(f"/ip hotspot add name=vt-hotspot interface={iface} address-pool=vt-hs-pool "
                   "profile=vt-hsprof disabled=no")
        for pl in hs["plans"]:
            line = f"/ip hotspot user profile add name={pl['name']}"
            if pl.get("rate"):
                line += f" rate-limit={pl['rate']}"
            if pl.get("session"):
                line += f" session-timeout={pl['session']}"
            if pl.get("shared"):
                line += f" shared-users={pl['shared']}"
            out.append(line + ' keepalive-timeout=2m status-autorefresh=1m')
        if radius:
            out.append(p.note("users come from RADIUS (billing server); no local hotspot users created"))
        else:
            for a in accts["hotspot"]:
                out.append(f'/ip hotspot user add name={a["user"]} password={a["password"]} '
                           f'profile={a["plan"]} comment="vlantool voucher"')
    pp = c.get("pppoe")
    if pp:
        iface = iface_of(p, pp.get("interface"))
        out.append(p.note(f"PPPoE server on {iface}"))
        if pp.get("pool"):
            out.append(f"/ip pool add name=vt-ppp-pool ranges={pp['pool']}")
        for pl in pp["plans"]:
            line = f"/ppp profile add name={pl['name']}"
            if pp.get("gateway"):
                line += f" local-address={pp['gateway']}"
            if pp.get("pool"):
                line += " remote-address=vt-ppp-pool"
            if pl.get("rate"):
                line += f" rate-limit={pl['rate']}"
            if pp["dns"]:
                line += f" dns-server={','.join(pp['dns'])}"
            out.append(line)
        default = pp["plans"][0]["name"] if pp["plans"] else "default"
        out.append(f"/interface pppoe-server server add service-name={pp.get('service', 'pppoe')} "
                   f"interface={iface} default-profile={default} one-session-per-host=yes disabled=no")
        if radius:
            out.append("/ppp aaa set use-radius=yes")
            out.append(p.note("subscribers come from RADIUS (billing server); no local secrets created"))
        else:
            for a in accts["pppoe"]:
                out.append(f'/ppp secret add name={a["user"]} password={a["password"]} '
                           f'profile={a["plan"]} service=pppoe')
    if radius:
        svc = ",".join(s for s, on in (("hotspot", hs), ("ppp", pp)) if on)
        out.append(f"/radius add service={svc} address={radius['server']} secret={radius['secret']}")
    return out


def render(plugin) -> list[str]:
    c = cfg(plugin)
    if not c:
        return []
    if plugin.key == "mikrotik_routeros":
        return mikrotik(plugin, c)
    # other vendors: concrete steps plus the resolved account list
    accts = accounts(plugin, c)
    steps = []
    if c.get("hotspot"):
        hs = c["hotspot"]
        steps.append(f"Set up a captive-portal hotspot on {hs.get('interface')} with these plans:")
        steps += [f"  plan {pl['name']}: speed {pl.get('rate', '-')}, session {pl.get('session', '-')}"
                  f"{', ' + str(pl['price']) if pl.get('price') else ''}" for pl in hs["plans"]]
        steps.append(f"Create {len(accts['hotspot'])} hotspot accounts/vouchers (see the voucher list file)")
    if c.get("pppoe"):
        pp = c["pppoe"]
        steps.append(f"Run a PPPoE server on {pp.get('interface')} with these plans:")
        steps += [f"  plan {pl['name']}: speed {pl.get('rate', '-')}" for pl in pp["plans"]]
        steps.append(f"Create {len(accts['pppoe'])} PPPoE subscriber accounts (see the voucher list file)")
    if c.get("radius"):
        steps.append(f"Point authentication at the RADIUS billing server {c['radius']['server']}")
    return manual(plugin, "Billing / hotspot", steps)


def files(plugin) -> dict[str, str]:
    """A printable list of generated vouchers and subscriber logins."""
    c = cfg(plugin)
    if not c:
        return {}
    accts = accounts(plugin, c)
    lines = [f"Vouchers and subscriber logins for {plugin.dev.name}", "=" * 48, ""]
    if accts["hotspot"]:
        lines.append("HOTSPOT VOUCHERS")
        lines.append(f"{'CODE':<14}{'PLAN':<12}{'PRICE':<8}")
        for a in accts["hotspot"]:
            lines.append(f"{a['user']:<14}{a['plan'] or '-':<12}{a['price'] if a['price'] is not None else '-':<8}")
        lines.append("")
    if accts["pppoe"]:
        lines.append("PPPoE SUBSCRIBERS")
        lines.append(f"{'USER':<16}{'PASSWORD':<14}{'PLAN':<12}{'PRICE':<8}")
        for a in accts["pppoe"]:
            lines.append(f"{a['user']:<16}{a['password']:<14}{a['plan'] or '-':<12}"
                         f"{a['price'] if a['price'] is not None else '-':<8}")
        lines.append("")
    if len(lines) <= 3:
        return {}
    return {f"{plugin.dev.name}-vouchers.txt": "\n".join(lines) + "\n"}


def validate(net, device) -> tuple[list[str], list[str]]:
    raw = device.options.get("billing")
    if not raw:
        return [], []
    errors, warnings = [], []
    where = f"device {device.name}: billing"
    for section in ("hotspot", "pppoe"):
        s = raw.get(section)
        if not s:
            continue
        if not s.get("interface"):
            errors.append(f"{where}: {section} needs an 'interface' (a VLAN name/id or a raw interface)")
        plan_names = {pl.get("name") for pl in as_list(s.get("plans"))}
        if not plan_names:
            errors.append(f"{where}: {section} needs at least one plan")
        for pl in as_list(s.get("plans")):
            if not pl.get("name"):
                errors.append(f"{where}: {section} plan needs a 'name'")
        rows = as_list(s.get("vouchers")) + as_list(s.get("subscribers") or s.get("users"))
        for r in rows:
            if r.get("plan") and r["plan"] not in plan_names:
                errors.append(f"{where}: {section} account references unknown plan {r['plan']!r}")
    if raw.get("radius") and not (raw["radius"].get("server") and raw["radius"].get("secret")):
        errors.append(f"{where}: radius needs 'server' and 'secret'")
    from ..vendors import REGISTRY
    plugin = REGISTRY.get(device.vendor)
    if plugin and plugin.key != "mikrotik_routeros":
        warnings.append(f"{where}: {plugin.title} gets manual steps for billing (MikroTik generates full config)")
    return errors, warnings
