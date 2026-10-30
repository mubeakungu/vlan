"""Small local web editor (standard library only).

    vlantool gui network.yaml          -> http://127.0.0.1:8080

It edits the same network file the CLI uses. It binds to localhost by default
because the push endpoint can change your devices.
"""
from __future__ import annotations

import json
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
    return {"errors": errors, "warnings": warnings, "configs": configs}


class Handler(BaseHTTPRequestHandler):
    path_file: Path
    monitor = None  # vlantool.monitor.engine.Monitor when monitoring is on

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

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
        # reject cross-site form posts: the browser page always sends JSON
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self._json({"error": "JSON only"}, 415)
        try:
            body = self._body()
        except json.JSONDecodeError:
            return self._json({"error": "bad JSON"}, 400)
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
          monitor: bool = False, db: str | None = None) -> None:
    Handler.path_file = Path(file)
    page = ""
    if monitor:
        from ..monitor.engine import Monitor
        net = model.load(file)
        Handler.monitor = Monitor(net, db or Path(file).with_suffix(".monitor.db"))
        Handler.monitor.start()
        page = "monitor"
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/{page}"
    print(f"vlantool GUI editing {Handler.path_file} at {url}  (Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
