"""Polling loop, history in SQLite, and alerts when a device goes down or up.

Configure in the network file:

    monitoring:
      interval: 30              # seconds between reachability rounds
      ssh_stats_every: 300      # seconds between SSH logins for stats/traffic/clients (0 = off)
      traffic: true             # collect per-interface throughput (default on)
      clients: true             # collect connected devices (DHCP/ARP/Wi-Fi) (default on)
      speedtest_every: 3600     # seconds between internet speed tests (0 = only on demand)
      speedtest: {download: "https://speed.cloudflare.com/__down?bytes={bytes}", bytes: 25000000}
      webhook: https://...      # optional: JSON POST on every alert (Slack, Discord, n8n...)
      telegram: {token: "123:ABC", chat_id: "456"}   # optional

    devices:
      - name: office-ap
        vendor: generic         # monitoring-only device
        host: 192.168.88.20
        monitor: {ports: [80, 443]}   # optional extra TCP checks
        # per-device: {ssh_stats: false} off logins, {interfaces: [ether1]} limit traffic to these

Throughput, byte totals and the connected-device list come from one SSH login
per round on routers that support it (MikroTik, Cisco, EdgeOS/VyOS, OpenWrt for
traffic; MikroTik and Cisco for clients). The speed test runs from the monitor
host and measures its internet path.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..model import Device, Network
from . import checks


@dataclass
class Status:
    device: str
    host: str | None
    vendor: str
    state: str = "unknown"          # up / down / degraded / unknown / no-host
    latency_ms: float | None = None
    ports: dict[str, bool] = field(default_factory=dict)
    stats: dict[str, str] = field(default_factory=dict)
    stats_error: str | None = None
    last_check: float | None = None
    last_change: float | None = None
    history: list[tuple[float, float | None]] = field(default_factory=list)
    traffic: dict[str, dict] = field(default_factory=dict)   # iface -> {rx_bps, tx_bps, rx_bytes, tx_bytes}
    clients: list[dict] = field(default_factory=list)         # connected devices seen by this box
    sessions: dict[str, list] = field(default_factory=dict)   # {hotspot: [...], pppoe: [...]} live billing sessions
    collect_error: str | None = None
    config_backed_up: float | None = None    # last successful config backup
    config_changed: float | None = None      # last time the running config changed (drift)
    config_sha: str | None = None
    config_error: str | None = None


class Monitor:
    def __init__(self, net: Network, db_path: str | Path = "vlantool-monitor.db"):
        self.net = net
        cfg = net.monitoring
        self.interval = float(cfg.get("interval", 30))
        self.stats_every = float(cfg.get("ssh_stats_every", 300))
        self.want_traffic = cfg.get("traffic", True)
        self.want_clients = cfg.get("clients", True)
        self.speedtest_every = float(cfg.get("speedtest_every", 0))
        self.speedtest_cfg = cfg.get("speedtest") or {}
        self.backup_every = float(cfg.get("backup_every", 0))     # config backup + drift detection (0 = off)
        self.reconcile = bool(cfg.get("reconcile", False))        # auto-push generated config on drift (opt-in)
        self.backup_keep = int(cfg.get("backup_keep", 10))
        self._last_backup: dict[str, float] = {}
        self.webhook = cfg.get("webhook")
        self.telegram = cfg.get("telegram") or {}
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS samples (ts REAL, device TEXT, state TEXT, latency REAL);
            CREATE TABLE IF NOT EXISTS events (ts REAL, device TEXT, state TEXT, message TEXT);
            CREATE TABLE IF NOT EXISTS traffic (ts REAL, device TEXT, iface TEXT, rx_bps REAL, tx_bps REAL);
            CREATE TABLE IF NOT EXISTS speedtest (ts REAL, down_mbps REAL, up_mbps REAL, ping_ms REAL);
            CREATE TABLE IF NOT EXISTS billing_samples (ts REAL, hotspot INTEGER, pppoe INTEGER);
            CREATE TABLE IF NOT EXISTS config_snaps (ts REAL, device TEXT, sha TEXT, text TEXT);
            CREATE INDEX IF NOT EXISTS config_dev_ts ON config_snaps (device, ts);
            CREATE INDEX IF NOT EXISTS samples_dev_ts ON samples (device, ts);
            CREATE INDEX IF NOT EXISTS traffic_dev_ts ON traffic (device, ts);
        """)
        self.status: dict[str, Status] = {}
        self.endpoints: dict[str, dict] = {}   # EDR agents from Wazuh, by name
        self.edr_error: str | None = None
        self.wazuh = None
        self._last_stats: dict[str, float] = {}
        self._traffic_prev: dict[str, dict[str, tuple[int, int, float]]] = {}
        self._last_speedtest = 0.0
        self._speedtest_running = False
        self._stop = threading.Event()
        self.reload(net)

    def reload(self, net: Network) -> None:
        self.net = net
        api = ((net.security or {}).get("wazuh") or {}).get("api")
        if api and api.get("url"):
            from .wazuh import WazuhAPI
            self.wazuh = WazuhAPI(api)
        with self.lock:
            old = self.status
            self.status = {}
            for d in net.devices:
                s = old.get(d.name) or Status(d.name, d.host, d.vendor)
                s.host, s.vendor = d.host, d.vendor
                if not d.host:
                    s.state = "no-host"
                self.status[d.name] = s

    # ------------------------------------------------------------- checking
    def check_device(self, d: Device) -> Status:
        s = self.status[d.name]
        if not d.host:
            return s
        latency = checks.ping(d.host)
        ports = {str(p): checks.tcp_check(d.host, int(p)) is not None
                 for p in (d.options.get("monitor") or {}).get("ports", [])}
        if latency is None:
            state = "down"
        elif ports and not all(ports.values()):
            state = "degraded"
        else:
            state = "up"

        now = time.time()
        mon_opts = d.options.get("monitor") or {}
        if state == "up" and self.stats_every and now - self._last_stats.get(d.name, 0) >= self.stats_every \
                and mon_opts.get("ssh_stats", True):
            self._last_stats[d.name] = now
            self._collect(d, s, now, mon_opts)

        with self.lock:
            previous = s.state
            s.latency_ms, s.ports, s.last_check = latency, ports, now
            s.history = (s.history + [(now, latency)])[-120:]
            if state != previous:
                s.state, s.last_change = state, now
                if previous not in ("unknown", "no-host") or state == "down":
                    self._alert(d, previous, state, ports)
            self.db.execute("INSERT INTO samples VALUES (?,?,?,?)", (now, d.name, state, latency))
            self.db.commit()
        return s

    def _collect(self, d: Device, s: Status, now: float, mon_opts: dict) -> None:
        """One SSH login per round: device stats, interface throughput, connected clients."""
        want = ["stats"]
        if self.want_traffic and mon_opts.get("traffic", True):
            want.append("traffic")
        if self.want_clients and mon_opts.get("clients", True):
            want.append("clients")
        if d.options.get("billing"):
            want.append("sessions")
        try:
            data = checks.ssh_collect(d, want=tuple(want))
        except Exception as exc:  # auth/connection failures must not stop monitoring
            s.stats_error = str(exc).splitlines()[0][:200]
            return
        errs = data.get("errors") or {}
        if "stats" in data:
            s.stats, s.stats_error = data["stats"], errs.get("stats")
        counters = data.get("traffic")
        if counters is not None:
            s.traffic = self._throughput(d.name, counters, now, mon_opts.get("interfaces"))
        clients = data.get("clients")
        if clients is not None:
            s.clients = sorted(clients, key=lambda c: (c.get("ip") or "", c.get("mac") or ""))
        sessions = data.get("sessions")
        if sessions is not None:
            s.sessions = sessions
        s.collect_error = errs.get("traffic") or errs.get("clients") or errs.get("sessions")

    def _throughput(self, name: str, counters: dict, now: float, only=None) -> dict:
        """Turn cumulative rx/tx byte counters into per-interface bit/s since the last round."""
        prev = self._traffic_prev.setdefault(name, {})
        out: dict[str, dict] = {}
        for iface, (rx, tx) in counters.items():
            if only and iface not in only:
                continue
            p = prev.get(iface)
            entry = {"rx_bytes": rx, "tx_bytes": tx, "rx_bps": None, "tx_bps": None}
            if p:
                dt = now - p[2]
                if dt > 0 and rx >= p[0] and tx >= p[1]:  # ignore counter resets (reboots)
                    entry["rx_bps"] = round((rx - p[0]) * 8 / dt)
                    entry["tx_bps"] = round((tx - p[1]) * 8 / dt)
                    with self.lock:
                        self.db.execute("INSERT INTO traffic VALUES (?,?,?,?,?)",
                                        (now, name, iface, entry["rx_bps"], entry["tx_bps"]))
            prev[iface] = (rx, tx, now)
            out[iface] = entry
        return out

    # ------------------------------------------------------------ speedtest
    def run_speedtest(self) -> dict:
        from . import speedtest
        self._speedtest_running = True
        try:
            r = speedtest.run(self.speedtest_cfg)
        finally:
            self._speedtest_running = False
        self._last_speedtest = time.time()
        if r.get("ok"):
            with self.lock:
                self.db.execute("INSERT INTO speedtest VALUES (?,?,?,?)",
                                (r["ts"], r["down_mbps"], r["up_mbps"], r["ping_ms"]))
                self.db.commit()
        return r

    def trigger_speedtest(self) -> None:
        """Kick off a speed test in the background (for the dashboard button)."""
        if not self._speedtest_running:
            threading.Thread(target=self.run_speedtest, daemon=True).start()

    def latest_speedtest(self) -> dict | None:
        with self.lock:
            row = self.db.execute(
                "SELECT ts, down_mbps, up_mbps, ping_ms FROM speedtest ORDER BY ts DESC LIMIT 1").fetchone()
        if not row:
            return None
        return {"ts": row[0], "down_mbps": row[1], "up_mbps": row[2], "ping_ms": row[3],
                "running": self._speedtest_running}

    def speedtest_history(self, limit: int = 30) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, down_mbps, up_mbps FROM speedtest ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": t, "down_mbps": d, "up_mbps": u} for t, d, u in reversed(rows)]

    # -------------------------------------------- config backup & drift
    def _backup_device(self, d: Device) -> None:
        """Pull the running config, store it, and alert if it changed since last time."""
        from .. import controller
        s = self.status.get(d.name)
        if s is None:
            return
        try:
            r = controller.backup(self.net, d)
        except Exception as exc:
            s.config_error = str(exc).splitlines()[0][:200]
            return
        if not r.ok:
            s.config_error = r.error
            return
        s.config_error = None
        text = r.output
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        now = time.time()
        with self.lock:
            prev = self.db.execute(
                "SELECT sha FROM config_snaps WHERE device=? ORDER BY ts DESC LIMIT 1", (d.name,)).fetchone()
            s.config_backed_up = now
            s.config_sha = sha
            if prev is None:
                self.db.execute("INSERT INTO config_snaps VALUES (?,?,?,?)", (now, d.name, sha, text))
            elif prev[0] != sha:
                self.db.execute("INSERT INTO config_snaps VALUES (?,?,?,?)", (now, d.name, sha, text))
                s.config_changed = now
                # keep only the most recent backup_keep snapshots per device
                self.db.execute(
                    "DELETE FROM config_snaps WHERE device=? AND ts NOT IN "
                    "(SELECT ts FROM config_snaps WHERE device=? ORDER BY ts DESC LIMIT ?)",
                    (d.name, d.name, self.backup_keep))
            self.db.commit()
        if prev is not None and prev[0] != sha:
            msg = f"{d.name} config CHANGED (drift detected)"
            with self.lock:
                self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (now, d.name, "drift", msg))
                self.db.commit()
            print(time.strftime("%H:%M:%S"), "ALERT", msg, flush=True)
            threading.Thread(target=self._notify, args=(msg,), daemon=True).start()
            if self.reconcile:
                self._reconcile(d)

    def _reconcile(self, d: Device) -> None:
        """Opt-in: push the generated config back to a drifted device."""
        from ..push import push_device
        from ..vendors import get as get_vendor
        if not (get_vendor(d.vendor).pushable and d.host):
            return
        try:
            r = push_device(self.net, d, save=True)
            ok = r.ok
        except Exception as exc:
            ok = False
            r = type("R", (), {"output": str(exc)[:200]})()
        msg = f"{d.name} auto-reconcile {'OK' if ok else 'FAILED'}: pushed generated config"
        with self.lock:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (time.time(), d.name, "reconcile", msg))
            self.db.commit()
        print(time.strftime("%H:%M:%S"), "RECONCILE", msg, flush=True)
        threading.Thread(target=self._notify, args=(msg,), daemon=True).start()

    def run_backups(self) -> None:
        from .. import controller
        now = time.time()
        due = [d for d in self.net.devices
               if controller._manageable(d)[0]
               and (d.options.get("monitor") or {}).get("backup", True)
               and now - self._last_backup.get(d.name, 0) >= self.backup_every]
        for d in due:
            self._last_backup[d.name] = now
        if due:
            with ThreadPoolExecutor(max_workers=min(8, len(due))) as pool:
                list(pool.map(self._backup_device, due))

    def config_diff(self, device: str) -> str:
        """Unified diff between the two most recent config snapshots of a device."""
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, text FROM config_snaps WHERE device=? ORDER BY ts DESC LIMIT 2", (device,)).fetchall()
        if len(rows) < 2:
            return ""
        (new_ts, new), (old_ts, old) = rows[0], rows[1]
        diff = difflib.unified_diff(
            old.splitlines(), new.splitlines(),
            fromfile=f"{device} @ {time.strftime('%Y-%m-%d %H:%M', time.localtime(old_ts))}",
            tofile=f"{device} @ {time.strftime('%Y-%m-%d %H:%M', time.localtime(new_ts))}", lineterm="")
        return "\n".join(diff)

    # ----------------------------------------------------------- trends
    def traffic_trend(self, limit: int = 60) -> list[dict]:
        """Network-wide throughput over time: bps summed across interfaces per round."""
        bucket = max(1, int(self.interval))
        with self.lock:
            rows = self.db.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, SUM(rx_bps), SUM(tx_bps) "
                "FROM traffic GROUP BY b ORDER BY b DESC LIMIT ?", (bucket, bucket, limit)).fetchall()
        return [{"ts": t, "rx_bps": rx or 0, "tx_bps": tx or 0} for t, rx, tx in reversed(rows)]

    def billing_trend(self, limit: int = 60) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, hotspot, pppoe FROM billing_samples ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": t, "hotspot": h, "pppoe": p} for t, h, p in reversed(rows)]

    def run_once(self) -> None:
        devices = [d for d in self.net.devices if d.host]
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(devices)))) as pool:
            list(pool.map(self.check_device, devices))
        self.check_endpoints()
        now = time.time()
        # record how many hotspot/PPPoE users are online, for the trend graph
        if any(d.options.get("billing") for d in self.net.devices):
            with self.lock:
                hs = sum(len((s.sessions or {}).get("hotspot") or []) for s in self.status.values())
                pp = sum(len((s.sessions or {}).get("pppoe") or []) for s in self.status.values())
                self.db.execute("INSERT INTO billing_samples VALUES (?,?,?)", (now, hs, pp))
                self.db.commit()
        if self.speedtest_every and not self._speedtest_running \
                and now - self._last_speedtest >= self.speedtest_every:
            self._last_speedtest = now
            threading.Thread(target=self.run_speedtest, daemon=True).start()
        if self.backup_every:
            self.run_backups()

    def check_endpoints(self) -> None:
        """EDR agent health from Wazuh; alert when an agent disconnects or reconnects."""
        expected = [e["name"] for e in self.net.endpoints if e.get("name")]
        if not self.wazuh:
            if expected:
                self.edr_error = "set security.wazuh.api to see agent status"
            return
        try:
            agents = {a["name"]: a for a in self.wazuh.agents()}
            self.edr_error = None
        except Exception as exc:
            self.edr_error = f"Wazuh API: {str(exc).splitlines()[0][:200]}"
            return
        for name in expected:
            agents.setdefault(name, {"name": name, "status": "not_enrolled", "ip": None, "os": "", "last_keepalive": None})
        with self.lock:
            for name, a in agents.items():
                old = (self.endpoints.get(name) or {}).get("status")
                if old and old != a["status"] and "active" in (old, a["status"]):
                    msg = f"endpoint {name} EDR agent is {a['status'].upper()}, was {old}"
                    self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (time.time(), name, a["status"], msg))
                    print(time.strftime("%H:%M:%S"), "ALERT", msg, flush=True)
                    threading.Thread(target=self._notify, args=(msg,), daemon=True).start()
            self.endpoints = agents

    def run_forever(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.run_once()
            except Exception as exc:
                print(f"monitor round failed: {exc}")
            self._stop.wait(max(1.0, self.interval - (time.monotonic() - started)))

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, daemon=True, name="vlantool-monitor")
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()

    # --------------------------------------------------------------- alerts
    def _alert(self, d: Device, old: str, new: str, ports: dict) -> None:
        detail = ""
        if new == "degraded":
            detail = " (closed ports: " + ", ".join(p for p, ok in ports.items() if not ok) + ")"
        msg = f"{d.name} ({d.host}) is {new.upper()}{detail}, was {old}"
        self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (time.time(), d.name, new, msg))
        print(time.strftime("%H:%M:%S"), "ALERT", msg, flush=True)
        threading.Thread(target=self._notify, args=(msg,), daemon=True).start()

    def _notify(self, msg: str) -> None:
        try:
            if self.webhook:
                body = json.dumps({"text": msg, "content": msg}).encode()
                req = urllib.request.Request(self.webhook, body, {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10).close()
            if self.telegram.get("token") and self.telegram.get("chat_id"):
                url = f"https://api.telegram.org/bot{self.telegram['token']}/sendMessage"
                data = urllib.parse.urlencode({"chat_id": self.telegram["chat_id"], "text": msg}).encode()
                urllib.request.urlopen(url, data, timeout=10).close()
        except Exception as exc:
            print(f"alert delivery failed: {exc}")

    # ---------------------------------------------------------------- views
    def snapshot(self) -> dict:
        with self.lock:
            devices = [asdict(s) for s in self.status.values()]
            rows = self.db.execute("SELECT ts, device, state, message FROM events ORDER BY ts DESC LIMIT 50").fetchall()
        counts: dict[str, int] = {}
        for d in devices:
            counts[d["state"]] = counts.get(d["state"], 0) + 1
        endpoints = sorted(self.endpoints.values(), key=lambda a: (a["status"] == "active", a["name"] or ""))
        # merge every router's connected-device view into one network-wide list, keyed by MAC
        merged: dict[str, dict] = {}
        for d in devices:
            for c in d.get("clients") or []:
                key = c.get("mac") or c.get("ip")
                if not key:
                    continue
                row = merged.setdefault(key, {})
                for k, v in c.items():
                    if v and not row.get(k):
                        row[k] = v
                row["seen_by"] = d["device"]
        clients = sorted(merged.values(), key=lambda c: (c.get("source") != "wifi", c.get("ip") or "~", c.get("mac") or ""))
        # live hotspot / PPPoE sessions across every billing router
        hotspot, pppoe = [], []
        for d in devices:
            for row in (d.get("sessions") or {}).get("hotspot") or []:
                hotspot.append({**row, "seen_by": d["device"]})
            for row in (d.get("sessions") or {}).get("pppoe") or []:
                pppoe.append({**row, "seen_by": d["device"]})
        billing = {"hotspot": hotspot, "pppoe": pppoe, "online": len(hotspot) + len(pppoe)}
        drift = {"enabled": bool(self.backup_every), "reconcile": self.reconcile,
                 "backed_up": sum(1 for d in devices if d.get("config_backed_up")),
                 "drifted": [d["device"] for d in devices if d.get("config_changed")],
                 "devices": [{"device": d["device"],
                              "backed_up": d.get("config_backed_up"),
                              "changed": d.get("config_changed"),
                              "error": d.get("config_error")}
                             for d in devices if d.get("config_backed_up") or d.get("config_error")]}
        return {"interval": self.interval, "devices": devices, "counts": counts,
                "endpoints": endpoints, "edr_error": self.edr_error,
                "clients": clients, "clients_total": len(clients), "billing": billing, "drift": drift,
                "trends": {"traffic": self.traffic_trend(), "billing": self.billing_trend(),
                           "speedtest": self.speedtest_history(60)},
                "speedtest": self.latest_speedtest(), "speedtest_history": self.speedtest_history(),
                "events": [{"ts": t, "device": dv, "state": st, "message": m} for t, dv, st, m in rows]}

    def uptime_percent(self, device: str, hours: float = 24) -> float | None:
        since = time.time() - hours * 3600
        with self.lock:
            total, up = self.db.execute(
                "SELECT COUNT(*), SUM(state != 'down') FROM samples WHERE device=? AND ts>=?",
                (device, since)).fetchone()
        return round(100 * (up or 0) / total, 2) if total else None
