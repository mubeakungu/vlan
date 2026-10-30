"""Polling loop, history in SQLite, and alerts when a device goes down or up.

Configure in the network file:

    monitoring:
      interval: 30              # seconds between rounds
      ssh_stats_every: 300      # seconds between uptime/CPU logins (0 = off)
      webhook: https://...      # optional: JSON POST on every alert (Slack, Discord, n8n...)
      telegram: {token: "123:ABC", chat_id: "456"}   # optional

    devices:
      - name: office-ap
        vendor: generic         # monitoring-only device
        host: 192.168.88.20
        monitor: {ports: [80, 443]}   # optional extra TCP checks
"""
from __future__ import annotations

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


class Monitor:
    def __init__(self, net: Network, db_path: str | Path = "vlantool-monitor.db"):
        self.net = net
        cfg = net.monitoring
        self.interval = float(cfg.get("interval", 30))
        self.stats_every = float(cfg.get("ssh_stats_every", 300))
        self.webhook = cfg.get("webhook")
        self.telegram = cfg.get("telegram") or {}
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS samples (ts REAL, device TEXT, state TEXT, latency REAL);
            CREATE TABLE IF NOT EXISTS events (ts REAL, device TEXT, state TEXT, message TEXT);
            CREATE INDEX IF NOT EXISTS samples_dev_ts ON samples (device, ts);
        """)
        self.status: dict[str, Status] = {}
        self.endpoints: dict[str, dict] = {}   # EDR agents from Wazuh, by name
        self.edr_error: str | None = None
        self.wazuh = None
        self._last_stats: dict[str, float] = {}
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
        if state == "up" and self.stats_every and now - self._last_stats.get(d.name, 0) >= self.stats_every \
                and checks.STATS.get(d.vendor) and (d.options.get("monitor") or {}).get("ssh_stats", True):
            self._last_stats[d.name] = now
            try:
                s.stats, s.stats_error = checks.ssh_stats(d), None
            except Exception as exc:  # auth failures etc. must not stop monitoring
                s.stats_error = str(exc).splitlines()[0][:200]

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

    def run_once(self) -> None:
        devices = [d for d in self.net.devices if d.host]
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(devices)))) as pool:
            list(pool.map(self.check_device, devices))
        self.check_endpoints()

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
        return {"interval": self.interval, "devices": devices, "counts": counts,
                "endpoints": endpoints, "edr_error": self.edr_error,
                "events": [{"ts": t, "device": dv, "state": st, "message": m} for t, dv, st, m in rows]}

    def uptime_percent(self, device: str, hours: float = 24) -> float | None:
        since = time.time() - hours * 3600
        with self.lock:
            total, up = self.db.execute(
                "SELECT COUNT(*), SUM(state != 'down') FROM samples WHERE device=? AND ts>=?",
                (device, since)).fetchone()
        return round(100 * (up or 0) / total, 2) if total else None
