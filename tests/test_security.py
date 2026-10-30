import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from vlantool import model
from vlantool.edr import files as edr_files
from vlantool.monitor.engine import Monitor
from vlantool.validate import validate
from vlantool.vendors import get

EXAMPLE = "examples/full-network.yaml"


@pytest.fixture
def net(tmp_path):
    p = tmp_path / "net.yaml"
    p.write_text(open(EXAMPLE).read())
    n = model.load(p)
    assert validate(n)[0] == []
    return n


def gen(net, name):
    d = net.device(name)
    return get(d.vendor)(net, d).generate()


def test_fortigate_ips_sensor_first_and_on_every_policy(net):
    text = gen(net, "office2-fw")
    assert text.index('config ips sensor') < text.index("config firewall policy")
    policies = text.count('set srcintf')
    assert policies and text.count('set ips-sensor "vlantool-ips"') == policies
    assert "set action block" in text


def test_mikrotik_ips_lite_and_syslog(net):
    text = gen(net, "hap")
    assert "address-list=vt-bruteforce" in text and "psd=21,3s,3,1" in text
    assert "/system logging action add name=vlantool-siem target=remote remote=192.168.99.50" in text


def test_detect_mode_logs_instead_of_dropping():
    data = {"vlans": [], "devices": [{"name": "m", "vendor": "mikrotik_routeros", "security": {"ips": "detect"}}]}
    n = model.from_dict(data)
    text = get("mikrotik_routeros")(n, n.devices[0]).generate()
    assert "action=drop" not in text and "log-prefix=vlantool-ids" in text


def test_openwrt_snort():
    data = {"vlans": [{"id": 10, "name": "A", "gateway": "192.168.10.1/24"}],
            "devices": [{"name": "o", "vendor": "openwrt", "routing": [10], "parent_interface": "eth0",
                         "security": {"ips": "prevent"}, "router": {"wan": {"interface": "eth1"}}}]}
    n = model.from_dict(data)
    text = get("openwrt")(n, n.devices[0]).generate()
    assert "opkg update && opkg install snort3" in text
    assert "uci set snort.snort.mode='ips'" in text and "uci set snort.snort.interface='eth1'" in text


@pytest.mark.parametrize("vendor, needle", [
    ("cisco_ios", "logging host 10.9.9.9"), ("juniper_junos", "set system syslog host 10.9.9.9 any info"),
    ("fortinet", 'set server "10.9.9.9"'), ("vyos", "set system syslog host 10.9.9.9"),
    ("huawei_vrp", "info-center loghost 10.9.9.9"), ("openwrt", "log_ip='10.9.9.9'"),
    ("pfsense", "Send syslog"), ("cisco_nxos", "logging server 10.9.9.9"),
])
def test_syslog_every_vendor(vendor, needle):
    dev = {"name": "d", "vendor": vendor}
    if vendor in ("fortinet", "pfsense"):
        dev["parent_interface"] = "port1"
    n = model.from_dict({"vlans": [], "security": {"siem": "10.9.9.9"}, "devices": [dev]})
    assert needle in get(vendor)(n, n.devices[0]).generate()


@pytest.mark.parametrize("vendor", ["pfsense", "cisco_ios", "juniper_junos", "vyos"])
def test_ips_manual_steps(vendor):
    dev = {"name": "d", "vendor": vendor, "security": {"ips": "prevent"}}
    if vendor == "pfsense":
        dev["parent_interface"] = "igb1"
    n = model.from_dict({"vlans": [], "devices": [dev]})
    assert "do these steps by hand" in get(vendor)(n, n.devices[0]).generate()


def test_edr_scripts(net):
    f = edr_files(net)
    assert set(f) == {"edr/wazuh-manager-setup.sh", "edr/reception-pc.ps1", "edr/file-server.sh", "edr/design-mac.sh"}
    assert "WAZUH_MANAGER=`\"192.168.99.50`\"" in f["edr/reception-pc.ps1"]
    assert "apt-get install -y wazuh-agent=" in f["edr/file-server.sh"]
    assert "arm64.pkg" in f["edr/design-mac.sh"]
    assert "<allowed-ips>10.255.0.0/30</allowed-ips>" in f["edr/wazuh-manager-setup.sh"]


def test_edr_validation():
    n = model.from_dict({"vlans": [], "devices": [], "endpoints": [{"name": "pc", "os": "amiga"}]})
    errors, _ = validate(n)
    assert any("manager" in e for e in errors) and any("os must be" in e for e in errors)


def test_monitor_reads_wazuh_agents(tmp_path):
    state = {"status": "active"}

    class Fake(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            assert self.headers["Authorization"].startswith("Basic ")
            self._send({"data": {"token": "t0k"}})

        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer t0k"
            self._send({"data": {"affected_items": [
                {"id": "000", "name": "manager", "status": "active"},
                {"id": "001", "name": "reception-pc", "status": state["status"], "ip": "192.168.10.50",
                 "os": {"name": "Microsoft Windows 11 Pro", "version": "10.0.22631"}, "lastKeepAlive": "2026-10-30T07:00:00Z"},
            ]}})

    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    data = {"vlans": [], "devices": [],
            "security": {"wazuh": {"manager": "127.0.0.1", "api": {"url": f"http://127.0.0.1:{srv.server_port}", "password": "x"}}},
            "endpoints": [{"name": "reception-pc", "os": "windows"}, {"name": "file-server", "os": "ubuntu"}]}
    mon = Monitor(model.from_dict(data), tmp_path / "m.db")
    mon.run_once()
    snap = mon.snapshot()
    by = {a["name"]: a for a in snap["endpoints"]}
    assert by["reception-pc"]["status"] == "active" and "Windows 11" in by["reception-pc"]["os"]
    assert by["file-server"]["status"] == "not_enrolled"
    state["status"] = "disconnected"
    mon.run_once()
    assert any("reception-pc EDR agent is DISCONNECTED" in e["message"] for e in mon.snapshot()["events"])
    srv.shutdown()
