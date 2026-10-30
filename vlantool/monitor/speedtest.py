"""Internet speed test run from the host that runs the monitor.

Downloads and uploads a chunk over HTTPS and measures throughput in Mbit/s.
It measures the monitor host's internet path, which for a box on the LAN is
effectively "our internet speed". Configure in the network file:

    monitoring:
      speedtest_every: 3600          # seconds between automatic runs (0 = only on demand)
      speedtest:
        download: https://speed.cloudflare.com/__down?bytes=25000000
        upload: https://speed.cloudflare.com/__up
        bytes: 25000000              # upload size and default download size
        timeout: 30
"""
from __future__ import annotations

import time
import urllib.request

# Cloudflare's speed endpoints are open and have no API key; override in config if blocked.
DEFAULT_DOWNLOAD = "https://speed.cloudflare.com/__down?bytes={bytes}"
DEFAULT_UPLOAD = "https://speed.cloudflare.com/__up"


def _download(url: str, timeout: float) -> tuple[int, float]:
    start = time.monotonic()
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": "vlantool-speedtest"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
    return total, time.monotonic() - start


def _upload(url: str, size: int, timeout: float) -> tuple[int, float]:
    payload = b"\x00" * size
    start = time.monotonic()
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/octet-stream",
                                          "User-Agent": "vlantool-speedtest"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()
    return size, time.monotonic() - start


def _mbps(byte_count: int, seconds: float) -> float:
    return round(byte_count * 8 / seconds / 1_000_000, 1) if seconds > 0 else 0.0


def run(cfg: dict | None = None) -> dict:
    """Run one speed test. Never raises: on failure returns ok=False with the error."""
    cfg = cfg or {}
    size = int(cfg.get("bytes", 25_000_000))
    timeout = float(cfg.get("timeout", 30))
    download = cfg.get("download") or DEFAULT_DOWNLOAD
    upload = cfg.get("upload", DEFAULT_UPLOAD)
    download = download.replace("{bytes}", str(size))
    result = {"ts": time.time(), "ok": False, "down_mbps": None, "up_mbps": None,
              "ping_ms": None, "error": None}
    if "cloudflare" in download:  # its __down supports a 1-byte request, a clean latency probe
        try:
            probe = download.split("?")[0] + "?bytes=1"
            probe_start = time.monotonic()
            _download(probe, min(timeout, 10))
            result["ping_ms"] = round((time.monotonic() - probe_start) * 1000, 1)
        except Exception:
            pass
    try:
        got, secs = _download(download, timeout)
        result["down_mbps"] = _mbps(got, secs)
    except Exception as exc:
        result["error"] = f"download: {str(exc).splitlines()[0][:160]}"
        return result
    if upload:
        try:
            sent, secs = _upload(upload, size, timeout)
            result["up_mbps"] = _mbps(sent, secs)
        except Exception as exc:
            result["error"] = f"upload: {str(exc).splitlines()[0][:160]}"
    result["ok"] = result["down_mbps"] is not None
    return result
