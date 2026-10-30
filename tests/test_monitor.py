"""Monitoring extras: interface throughput, connected devices, internet speed test."""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from vlantool import model
from vlantool.monitor import checks, speedtest
from vlantool.monitor.engine import Monitor


# ---- parsers ---------------------------------------------------------------
def test_mikrotik_counter_parser():
    out = checks._mt_counters("|ether1|1000|2000\n|wlan1|50|60\ngarbage\n|bad|x|y")
    assert out == {"ether1": (1000, 2000), "wlan1": (50, 60)}


def test_cisco_counter_parser():
    text = ("GigabitEthernet0/0 is up, line protocol is up\n"
            "  100 packets input, 64000 bytes\n  50 packets output, 32000 bytes\n")
    assert checks._cisco_counters(text) == {"GigabitEthernet0/0": (64000, 32000)}


def test_linux_counter_parser():
    text = ("Inter-|   Receive\n face |bytes    packets ...\n"
            "  eth0: 123456 10 0 0 0 0 0 0 7890 20 0 0 0 0 0 0\n")
    assert checks._linux_counters(text)["eth0"] == (123456, 7890)


def test_mikrotik_clients_parser_merges_sources():
    text = ('### leases\n'
            '0 D address=192.168.88.50 mac-address=08:00:27:AA:BB:CC server=dhcp-vlan10 status=bound host-name="laptop"\n'
            '### arp\n'
            '0 address=192.168.88.1 mac-address=AA:BB:CC:11:22:33 interface=bridge\n'
            '### wifi\n'
            '0 interface=wlan1 mac-address=08:00:27:AA:BB:CC signal-strength=-55\n')
    out = {c["mac"]: c for c in checks._mt_clients(text)}
    assert out["08:00:27:AA:BB:CC"]["ip"] == "192.168.88.50"      # from the lease
    assert out["08:00:27:AA:BB:CC"]["host"] == "laptop"
    assert out["08:00:27:AA:BB:CC"]["source"] == "wifi"           # also seen on Wi-Fi
    assert out["08:00:27:AA:BB:CC"]["signal"] == "-55"
    assert out["AA:BB:CC:11:22:33"]["source"] == "arp"


def test_cisco_clients_parser():
    out = {c["mac"]: c for c in checks._cisco_clients(
        "192.168.10.50  0063.3600.1234  86400  Automatic\n"
        "Internet  192.168.10.1   5   aabb.ccdd.eeff  ARPA  Vlan10\n")}
    assert out["00:63:36:00:12:34"]["ip"] == "192.168.10.50"
    assert out["AA:BB:CC:DD:EE:FF"]["iface"] == "Vlan10"


# ---- engine: throughput + clients in the snapshot --------------------------
def _net():
    data = {"vlans": [{"id": 10, "name": "USERS", "gateway": "192.168.88.1/24"}],
            "monitoring": {"ssh_stats_every": 0.01},
            "devices": [{"name": "hap", "vendor": "mikrotik_routeros", "host": "127.0.0.1",
                         "username": "admin", "routing": "all"}]}
    return model.from_dict(data)


def test_engine_computes_throughput_and_lists_clients(monkeypatch, tmp_path):
    rounds = {"n": 0}

    def fake_collect(d, want=(), timeout=15):
        rounds["n"] += 1
        base = rounds["n"] * 1_000_000
        return {"stats": {"version": "7.15"},
                "traffic": {"ether1": (base, base // 2)},
                "clients": [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.88.50",
                             "host": "laptop", "iface": "dhcp-vlan10", "source": "dhcp"}]}

    monkeypatch.setattr(checks, "ssh_collect", fake_collect)
    m = Monitor(_net(), tmp_path / "m.db")
    d = m.net.devices[0]
    m.check_device(d)                 # first round: only sets counters
    time.sleep(0.05)
    m._last_stats["hap"] = 0          # force the stats cadence to fire again
    m.check_device(d)                 # second round: bit/s from the delta
    snap = m.snapshot()
    t = snap["devices"][0]["traffic"]["ether1"]
    assert t["rx_bps"] and t["rx_bps"] > 0 and t["tx_bps"] > 0
    assert snap["clients_total"] == 1
    assert snap["clients"][0]["seen_by"] == "hap" and snap["clients"][0]["host"] == "laptop"


def test_throughput_ignores_counter_reset(tmp_path):
    m = Monitor(_net(), tmp_path / "m.db")
    now = time.time()
    m._throughput("r", {"e1": (1000, 1000)}, now)
    out = m._throughput("r", {"e1": (10, 10)}, now + 10)   # counter went backwards (reboot)
    assert out["e1"]["rx_bps"] is None                     # no bogus negative rate


# ---- speed test ------------------------------------------------------------
def test_speedtest_measures_down_and_up():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            n = 1_000_000
            if "bytes=" in self.path:
                try:
                    n = int(self.path.split("bytes=")[1])
                except ValueError:
                    pass
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            self.wfile.write(b"\x00" * n)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port
    r = speedtest.run({"download": f"http://127.0.0.1:{port}/d?bytes={{bytes}}",
                       "upload": f"http://127.0.0.1:{port}/u", "bytes": 1_000_000, "timeout": 10})
    srv.shutdown()
    assert r["ok"] and r["down_mbps"] > 0 and r["up_mbps"] > 0


def test_speedtest_handles_failure():
    r = speedtest.run({"download": "http://127.0.0.1:1/x", "upload": "", "timeout": 1})
    assert r["ok"] is False and r["error"]


def test_mikrotik_session_parser():
    text = ('### hs\n'
            '0 server=vt-hotspot user=VVJRHG8P address=192.168.20.15 mac-address=08:00:27:AA:BB:01 '
            'uptime=12m34s bytes-in=12400000 bytes-out=98700000\n'
            '### ppp\n'
            '0 name=sub001 service=pppoe address=10.80.0.10 uptime=1h2m3s\n')
    out = checks._mt_sessions(text)
    assert out["hotspot"][0]["user"] == "VVJRHG8P" and out["hotspot"][0]["out_bytes"] == 98700000
    assert out["pppoe"][0]["user"] == "sub001" and out["pppoe"][0]["service"] == "pppoe"
    assert checks._dur_secs("1h2m3s") == 3723


def test_engine_aggregates_hotspot_sessions(monkeypatch, tmp_path):
    def fake(d, want=(), timeout=15):
        assert "sessions" in want           # billing device asks for sessions
        return {"stats": {}, "sessions": {"hotspot": [{"user": "CODE1", "ip": "192.168.20.9", "uptime": "5m",
                                                        "in_bytes": 1000, "out_bytes": 2000}],
                                          "pppoe": [{"user": "sub001", "ip": "10.80.0.5", "service": "pppoe", "uptime": "1h"}]}}
    monkeypatch.setattr(checks, "ssh_collect", fake)
    data = {"vlans": [{"id": 20, "name": "GUEST", "gateway": "192.168.20.1/24"}],
            "monitoring": {"ssh_stats_every": 0.01},
            "devices": [{"name": "hap", "vendor": "mikrotik_routeros", "host": "127.0.0.1", "username": "admin",
                         "routing": "all",
                         "billing": {"hotspot": {"interface": "GUEST", "plans": [{"name": "1h"}],
                                                 "vouchers": [{"plan": "1h", "count": 1}]}}}]}
    m = Monitor(model.from_dict(data), tmp_path / "m.db")
    m.check_device(m.net.devices[0])
    b = m.snapshot()["billing"]
    assert b["online"] == 2 and b["hotspot"][0]["seen_by"] == "hap" and b["pppoe"][0]["user"] == "sub001"


def test_trends_persist_and_query(monkeypatch, tmp_path):
    seq = {"n": 0}

    def fake(d, want=(), timeout=15):
        seq["n"] += 1
        base = seq["n"] * 1_000_000
        hs = [{"user": f"u{i}", "ip": f"192.168.20.{10 + i}", "uptime": "5m", "in_bytes": 1, "out_bytes": 2}
              for i in range(seq["n"])]
        return {"stats": {}, "traffic": {"ether1": (base, base // 2)}, "sessions": {"hotspot": hs, "pppoe": []}}

    monkeypatch.setattr(checks, "ssh_collect", fake)
    data = {"vlans": [{"id": 20, "name": "GUEST", "gateway": "192.168.20.1/24"}],
            "monitoring": {"ssh_stats_every": 0.001, "interval": 1},
            "devices": [{"name": "hap", "vendor": "mikrotik_routeros", "host": "127.0.0.1", "username": "admin",
                         "routing": "all",
                         "billing": {"hotspot": {"interface": "GUEST", "plans": [{"name": "1h"}],
                                                 "vouchers": [{"plan": "1h", "count": 1}]}}}]}
    m = Monitor(model.from_dict(data), tmp_path / "m.db")
    for _ in range(3):
        m._last_stats["hap"] = 0
        m.run_once()
    trends = m.snapshot()["trends"]
    assert [p["hotspot"] for p in trends["billing"]] == [1, 2, 3]   # rising hotspot users over time
    assert trends["traffic"] and trends["traffic"][-1]["rx_bps"] > 0
