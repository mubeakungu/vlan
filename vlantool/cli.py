"""Command line entry point: vlantool <command> ..."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import model
from .push import plan, push_device
from .validate import validate
from .vendors import PLUGINS, get


def _load_checked(path: str) -> model.Network:
    try:
        net = model.load(path)
    except (OSError, model.ModelError, ValueError) as exc:
        sys.exit(f"error: {exc}")
    errors, warnings = validate(net)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(f"{len(errors)} error(s); nothing generated")
    return net


def _select(net: model.Network, names: list[str] | None) -> list[model.Device]:
    if not names:
        return net.devices
    try:
        return [net.device(n) for n in names]
    except model.ModelError as exc:
        sys.exit(f"error: {exc}")


def cmd_vendors(args) -> None:
    for p in PLUGINS:
        push = "push" if p.pushable and p.netmiko_type else "file only"
        print(f"{p.key:<22} {p.title}  [{push}]")
        print(f"{'':<22} {p.covers}")


def cmd_validate(args) -> None:
    net = _load_checked(args.file)
    print(f"OK: {len(net.vlans)} VLANs, {len(net.devices)} devices")


def cmd_generate(args) -> None:
    net = _load_checked(args.file)
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    for dev in _select(net, args.device):
        plugin = get(dev.vendor)(net, dev)
        text = plugin.generate()
        if out_dir:
            ext = "xml" if plugin.key == "pfsense" else "txt"
            path = out_dir / f"{dev.name}.{ext}"
            path.write_text(text)
            print(f"wrote {path}")
            for name, content in plugin.extra_files().items():
                (out_dir / name).write_text(content)
                print(f"wrote {out_dir / name}")
        else:
            print(text)
            for name, content in plugin.extra_files().items():
                print(f"----- {name} -----\n{content}")
    if out_dir and not args.device:
        _write_edr(net, out_dir)


def _write_edr(net, out_dir) -> None:
    from .edr import files
    for rel, content in files(net).items():
        path = out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"wrote {path}")


def cmd_edr(args) -> None:
    from .edr import files
    net = _load_checked(args.file)
    if not files(net):
        sys.exit("no EDR setup: add security.wazuh.manager and an 'endpoints' list")
    if args.out:
        _write_edr(net, Path(args.out))
    else:
        for rel, content in files(net).items():
            print(f"===== {rel} =====\n{content}")


def cmd_push(args) -> None:
    net = _load_checked(args.file)
    devices = _select(net, args.device)
    for dev in devices:
        print(f"===== {dev.name} ({get(dev.vendor).title}) -> {dev.host or 'no host'}")
        print("\n".join(plan(net, dev)) or "(nothing to send)")
    if args.dry_run:
        print("\n(dry run: nothing was sent)")
        return
    if not args.yes:
        answer = input(f"\nSend these commands to {len(devices)} device(s)? Type 'yes' to continue: ")
        if answer.strip().lower() != "yes":
            sys.exit("aborted")
    password = args.password
    if password is None and not __import__("os").environ.get("VLANTOOL_PASSWORD"):
        password = getpass.getpass("SSH password: ")
    failed = 0
    for dev in devices:
        r = push_device(net, dev, username=args.username, password=password,
                        secret=args.secret, save=not args.no_save)
        print(f"\n----- {r.device}: {'OK' if r.ok else 'FAILED'}\n{r.output}")
        failed += not r.ok
    if failed:
        sys.exit(f"{failed} device(s) failed")


def cmd_gui(args) -> None:
    from .web.server import serve
    serve(args.file, host=args.host, port=args.port, monitor=args.monitor)


def cmd_monitor(args) -> None:
    net = _load_checked(args.file)
    if args.once:
        from .monitor.engine import Monitor
        mon = Monitor(net, ":memory:")
        mon.run_once()
        print(f"{'DEVICE':<22} {'HOST':<16} {'STATE':<9} {'PING':>8}  DETAILS")
        for s in mon.snapshot()["devices"]:
            ping = f"{s['latency_ms']} ms" if s["latency_ms"] is not None else "-"
            details = ", ".join(f"{k}={v}" for k, v in s["stats"].items())
            details += "".join(f" port {p} {'open' if ok else 'CLOSED'}" for p, ok in s["ports"].items())
            print(f"{s['device']:<22} {s['host'] or '-':<16} {s['state']:<9} {ping:>8}  {details}")
        return
    from .web.server import serve
    serve(args.file, host=args.host, port=args.port, monitor=True, db=args.db)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="vlantool", description="Define VLANs once, configure any switch, router or firewall.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("vendors", help="list supported vendors").set_defaults(func=cmd_vendors)

    p = sub.add_parser("validate", help="check a network file")
    p.add_argument("file")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("generate", help="print or write config for each device")
    p.add_argument("file")
    p.add_argument("-d", "--device", action="append", help="only this device (repeatable)")
    p.add_argument("-o", "--out", help="write one file per device into this folder")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("edr", help="Wazuh manager setup and EDR agent scripts for your endpoints")
    p.add_argument("file")
    p.add_argument("-o", "--out", help="write the scripts into this folder (default: print)")
    p.set_defaults(func=cmd_edr)

    p = sub.add_parser("push", help="send config to devices over SSH (needs netmiko)")
    p.add_argument("file")
    p.add_argument("-d", "--device", action="append", help="only this device (repeatable)")
    p.add_argument("-u", "--username")
    p.add_argument("-p", "--password", help="default: VLANTOOL_PASSWORD or prompt")
    p.add_argument("--secret", help="enable secret (Cisco-style devices)")
    p.add_argument("--dry-run", action="store_true", help="show what would be sent and stop")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--no-save", action="store_true", help="do not save running config after pushing")
    p.set_defaults(func=cmd_push)

    p = sub.add_parser("gui", help="open the web editor")
    p.add_argument("file", nargs="?", default="network.yaml")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--monitor", action="store_true", help="also monitor devices (see /monitor)")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("monitor", help="watch devices: ping, ports, uptime/CPU, alerts, dashboard")
    p.add_argument("file")
    p.add_argument("--once", action="store_true", help="check every device once, print a table, exit")
    p.add_argument("--db", help="history database (default: <file>.monitor.db)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_monitor)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
