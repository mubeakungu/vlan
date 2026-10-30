"""Read endpoint (EDR agent) health from the Wazuh manager API."""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request


class WazuhAPI:
    def __init__(self, cfg: dict):
        self.url = cfg["url"].rstrip("/")
        self.user = cfg.get("user", "wazuh-wui")
        self.password = cfg.get("password") or os.environ.get(cfg.get("password_env", "WAZUH_API_PASSWORD"), "")
        self.ctx = ssl.create_default_context()
        if not cfg.get("verify_tls", False):  # the manager ships with a self-signed certificate
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.token: str | None = None

    def _request(self, path: str, method: str = "GET", auth: str | None = None) -> dict:
        req = urllib.request.Request(self.url + path, method=method)
        req.add_header("Authorization", auth or f"Bearer {self.token}")
        with urllib.request.urlopen(req, context=self.ctx, timeout=10) as r:
            return json.load(r)

    def login(self) -> None:
        basic = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.token = self._request("/security/user/authenticate", "POST", f"Basic {basic}")["data"]["token"]

    def agents(self) -> list[dict]:
        """[{name, status, ip, os, last_keepalive, id}] for every agent except the manager itself."""
        if not self.token:
            self.login()
        path = "/agents?limit=1000&select=name,status,ip,os.name,os.version,lastKeepAlive,version"
        try:
            data = self._request(path)
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            self.login()  # token expired (15 min default)
            data = self._request(path)
        out = []
        for a in data["data"]["affected_items"]:
            if a.get("id") == "000":
                continue
            os_info = a.get("os") or {}
            out.append({"id": a.get("id"), "name": a.get("name"), "status": a.get("status"), "ip": a.get("ip"),
                        "os": " ".join(x for x in (os_info.get("name"), os_info.get("version")) if x),
                        "last_keepalive": a.get("lastKeepAlive"), "version": a.get("version")})
        return out
