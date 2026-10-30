"""Small local web editor (standard library only).

    vlantool gui network.yaml          -> http://127.0.0.1:8080

It edits the same network file the CLI uses. It binds to localhost by default
because the push endpoint can change your devices.
"""
from __future__ import annotations

import base64
import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from .. import model
from ..push import push_device
from ..validate import validate
from ..vendors import PLUGINS, get

STATIC = Path(__file__).with_name("index.html")
MONITOR_PAGE = Path(__file__).with_name("monitor.html")
EMPTY = {"vlans": [{"id": 10, "name": "USERS", "gateway": "192.168.10.1/24"}], "devices": []}


def build(data: dict, secrets_path: Path | None = None) -> dict:
    """Validate a network dict and render every device."""
    try:
        net = model.from_dict(data)
        if secrets_path:
            from ..secrets import Secrets
            net.secrets = Secrets.for_network(secrets_path)
    except (model.ModelError, ValueError, TypeError, KeyError) as exc:
        return {"errors": [str(exc)], "warnings": [], "configs": {}}
    errors, warnings = validate(net)
    configs = {}
    if not errors:
        for dev in net.devices:
            p = get(dev.vendor)
            plugin = p(net, dev)
            text = plugin.generate()
            for name, content in plugin.extra_files().items():
                text += f"\n# ===== {name} (WireGuard client file) =====\n{content}"
            configs[dev.name] = {"vendor": p.title, "text": text,
                                 "pushable": bool(p.pushable and p.netmiko_type and dev.host)}
        from ..edr import files as edr_files
        scripts = edr_files(net)
        if scripts:
            configs["endpoints (EDR)"] = {
                "vendor": "Wazuh EDR: manager setup and agent installers",
                "text": "\n".join(f"# ===== {name} =====\n{body}" for name, body in scripts.items()),
                "pushable": False}
    return {"errors": errors, "warnings": warnings, "configs": configs}


class Handler(BaseHTTPRequestHandler):
    path_file: Path
    monitor = None  # vlantool.monitor.engine.Monitor when monitoring is on
    auth = None     # "user:pass" from $VLANTOOL_AUTH guards every request when set

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _authed(self) -> bool:
        """When $VLANTOOL_AUTH is set, require matching HTTP basic auth.

        This is what makes a public deploy (e.g. Render) safe: the editor and
        push endpoints change config, so they must not be open to the world.
        """
        if not self.auth:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                if base64.b64decode(header[6:]).decode() == self.auth:
                    return True
            except (ValueError, UnicodeDecodeError):
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="vlantool"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, body: bytes, ctype: str = "application/json", code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(json.dumps(obj).encode(), code=code)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/healthz":          # unauthenticated: for platform health checks
            return self._json({"ok": True})
        if not self._authed():
            return
        if self.path in ("/", "/index.html"):
            self._send(STATIC.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/monitor":
            self._send(MONITOR_PAGE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            if self.monitor is None:
                return self._json({"running": False})
            snap = self.monitor.snapshot()
            for d in snap["devices"]:
                d["uptime_24h"] = self.monitor.uptime_percent(d["device"])
            self._json({"running": True, **snap})
        elif self.path == "/api/speedtest":
            if self.monitor is None:
                return self._json({"running": False})
            self._json({"latest": self.monitor.latest_speedtest(),
                        "history": self.monitor.speedtest_history()})
        elif self.path.startswith("/api/configdiff"):
            if self.monitor is None:
                return self._json({"error": "monitoring is not running"}, 409)
            from urllib.parse import parse_qs, urlparse
            device = (parse_qs(urlparse(self.path).query).get("device") or [""])[0]
            self._json({"device": device, "diff": self.monitor.config_diff(device)})
        elif self.path == "/api/vendors":
            self._json([{"key": p.key, "title": p.title, "covers": p.covers,
                         "pushable": bool(p.pushable and p.netmiko_type),
                         "switching": p.supports_switching, "policies": p.supports_policies,
                         "needs_parent": p.requires_parent} for p in PLUGINS])
        elif self.path == "/api/network":
            f = self.path_file
            data = yaml.safe_load(f.read_text()) if f.exists() else EMPTY
            self._json({"file": str(f), "data": data or EMPTY})
        else:
            self._send(b"not found", "text/plain", 404)

    def do_POST(self):
        if not self._authed():
            return
        # reject cross-site form posts: the browser page always sends JSON
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self._json({"error": "JSON only"}, 415)
        try:
            body = self._body()
        except json.JSONDecodeError:
            return self._json({"error": "bad JSON"}, 400)
        if self.path == "/api/speedtest":
            if self.monitor is None:
                return self._json({"error": "monitoring is not running"}, 409)
            self.monitor.trigger_speedtest()
            return self._json({"started": True})
        if self.path == "/api/generate":
            self._json(build(body.get("data") or {}, self.path_file))
        elif self.path == "/api/yaml":
            self._json({"yaml": yaml.safe_dump(body.get("data") or {}, sort_keys=False)})
        elif self.path == "/api/parse":
            try:
                self._json({"data": yaml.safe_load(body.get("yaml") or "") or {}})
            except yaml.YAMLError as exc:
                self._json({"error": str(exc)}, 400)
        elif self.path == "/api/save":
            data = body.get("data") or {}
            self.path_file.write_text(yaml.safe_dump(data, sort_keys=False))
            if self.monitor is not None:  # start watching newly added devices
                try:
                    self.monitor.reload(model.from_dict(data))
                except (model.ModelError, ValueError, TypeError, KeyError):
                    pass
            self._json({"saved": str(self.path_file)})
        elif self.path == "/api/push":
            result = build(body.get("data") or {}, self.path_file)
            if result["errors"]:
                return self._json({"results": [{"device": "-", "ok": False, "output": "\n".join(result["errors"])}]})
            net = model.from_dict(body["data"])
            from ..secrets import Secrets
            net.secrets = Secrets.for_network(self.path_file)
            validate(net)
            results = []
            for name in body.get("devices") or []:
                r = push_device(net, net.device(name), username=body.get("username") or None,
                                password=body.get("password"), secret=body.get("secret") or None,
                                save=body.get("save", True))
                results.append({"device": r.device, "ok": r.ok, "output": r.output})
            self._json({"results": results})
        else:
            self._json({"error": "not found"}, 404)


def serve(file: str, host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True,
          monitor: bool = False, db: str | None = None, backup_default: float = 0) -> None:
    Handler.path_file = Path(file)
    Handler.auth = os.environ.get("VLANTOOL_AUTH") or None
    page = ""
    if monitor:
        from ..monitor.engine import Monitor
        net = model.load(file)
        Handler.monitor = Monitor(net, db or Path(file).with_suffix(".monitor.db"))
        # `vlantool up` turns on config backup + drift detection even if the
        # network file didn't set monitoring.backup_every itself.
        if backup_default and not Handler.monitor.backup_every:
            Handler.monitor.backup_every = backup_default
        Handler.monitor.start()
        page = "monitor"
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/{page}"
    print(f"vlantool GUI editing {Handler.path_file} at {url}  (Ctrl+C to stop)", flush=True)
    # only pop a browser on a local run; a server deploy (0.0.0.0) is headless
    if open_browser and host in ("127.0.0.1", "localhost", "::1"):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
