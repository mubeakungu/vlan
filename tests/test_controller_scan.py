import socket
import sys
import threading
import types
from pathlib import Path

import pytest

from vlantool import controller as ctl
from vlantool import model, scan
from vlantool.vendors import get


# ---- fake Netmiko ----------------------------------------------------------
class FakeConn:
    scripted: dict = {}
    seen_config: list = []

    def __init__(self, **kw):
        self.kw = kw
        FakeConn.last = kw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def enable(self):
        pass

    def disconnect(self):
        pass

    def send_command(self, cmd, **kw):
        return self.scripted.get(cmd, f"<output of {cmd}>")

    def send_command_timing(self, cmd, **kw):
        return self.scripted.get(cmd, f"<timed {cmd}>")

    def send_config_set(self, cmds, **kw):
        FakeConn.seen_config.append(list(cmds))
        return "configured " + "; ".join(cmds)


@pytest.fixture
def fake_netmiko(monkeypatch):
    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=FakeConn))
    FakeConn.scripted = {}
    FakeConn.seen_config = []
    return FakeConn


@pytest.fixture
def net():
    data = {"vlans": [{"id": 10, "name": "USERS", "gateway": "192.168.10.1/24"}],
            "devices": [{"name": "hap", "vendor": "mikrotik_routeros", "host": "127.0.0.1", "username": "admin",
                         "routing": "all"},
                        {"name": "sw", "vendor": "cisco_ios", "host": "127.0.0.1", "username": "admin"},
                        {"name": "ap", "vendor": "generic", "host": "127.0.0.1"}]}
    return model.from_dict(data)


def test_facts_parses_mikrotik(fake_netmiko, net):
    fake_netmiko.scripted = {"/system resource print": "uptime: 3d4h\n  cpu-load: 7\n  version: 7.15.3\n  board-name: hAP ac2",
                             "/system routerboard print": "  serial-number: ABC123"}
    r = ctl.facts(net, net.device("hap"))
    assert r.ok and r.data["version"] == "7.15.3" and r.data["model"] == "hAP ac2"
    assert r.data["uptime"] == "3d4h"


def test_facts_generic_not_manageable(net):
    r = ctl.facts(net, net.device("ap"))
    assert not r.ok and "no SSH" in r.error.lower() or "management" in r.error.lower()


def test_backup_writes_file(fake_netmiko, net, tmp_path):
    fake_netmiko.scripted = {"/export": "# config\n/ip address add ..."}
    r = ctl.backup(net, net.device("hap"), tmp_path)
    assert r.ok
    f = Path(r.data["path"])
    assert f.exists() and "/ip address add" in f.read_text() and f.suffix == ".cfg"


def test_run_requires_and_executes(fake_netmiko, net):
    r = ctl.run(net, net.device("sw"), ["show ip int brief"])
    assert r.ok and "show ip int brief" in r.output


def test_upgrade_checks_then_applies(fake_netmiko, net, tmp_path):
    fake_netmiko.scripted = {
        "/export": "# cfg",
        "/system package update check-for-updates": "installed-version: 7.15.1\n  latest-version: 7.15.3",
    }
    r = ctl.upgrade(net, net.device("hap"), apply=False, out_dir=tmp_path)
    assert r.ok and "7.15.3" in r.output and "--apply" in r.output
    r2 = ctl.upgrade(net, net.device("hap"), apply=True, out_dir=tmp_path)
    assert r2.ok and "reboot" in r2.output.lower()


def test_upgrade_unsupported(fake_netmiko, net):
    r = ctl.upgrade(net, net.device("sw"), apply=True)
    assert not r.ok and "not supported" in r.error


# ---- scanner ---------------------------------------------------------------
def test_config_audit_flags_weak_secrets():
    data = {"vlans": [{"id": 10, "name": "GUEST", "gateway": "192.168.10.1/24"}],
            "devices": [{"name": "r", "vendor": "mikrotik_routeros", "routing": "all",
                         "router": {"wan": {"interface": "e1"}, "firewall": False},
                         "wireless": {"ssids": [{"ssid": "Home", "passphrase": "1234", "vlan": "GUEST"}]},
                         "vpn": {"ipsec": [{"name": "t", "peer": "1.2.3.4", "psk": "short", "remote": ["10.0.0.0/8"]}]}}]}
    net = model.from_dict(data)
    rep = scan.run_scan(net, ports=False)
    titles = [f.title for f in rep.findings]
    assert any("firewall disabled" in t.lower() for t in titles)
    assert any("weak wi-fi" in t.lower() for t in titles)
    assert any("weak ipsec" in t.lower() for t in titles)
    assert any("guest vlan not isolated" in t.lower() for t in titles)


def test_port_scan_finds_open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    assert port in scan.scan_ports("127.0.0.1", [port, port + 1 if port + 1 < 65535 else port - 1])
    srv.close()


def test_telnet_flagged_critical():
    data = {"vlans": [], "devices": [{"name": "d", "vendor": "generic", "host": "203.0.113.9"}]}
    rep = scan.ScanReport()
    rep.open_ports  # noqa
    # inject a finding path directly via NOTABLE_PORTS logic
    from vlantool.scan import NOTABLE_PORTS
    assert NOTABLE_PORTS[23][1] == "critical"


def test_html_report_renders():
    data = {"vlans": [], "devices": [{"name": "d", "vendor": "mikrotik_routeros", "routing": "all",
             "vpn": {"ipsec": [{"name": "t", "peer": "1.2.3.4", "psk": "weak", "remote": ["10.0.0.0/8"]}]}}]}
    rep = scan.run_scan(model.from_dict(data), ports=False)
    html = scan.html_report(rep)
    assert "<table" in html and "Weak IPsec" in html


def test_cli_scan_exit_code(tmp_path, capsys):
    from vlantool.cli import main
    f = tmp_path / "n.yaml"
    f.write_text("vlans: []\ndevices:\n  - {name: d, vendor: mikrotik_routeros, routing: all, "
                 "vpn: {ipsec: [{name: t, peer: 1.2.3.4, psk: password, remote: [10.0.0.0/8]}]}}\n")
    with pytest.raises(SystemExit) as e:
        main(["scan", str(f), "--no-ports"])
    assert e.value.code == 1  # a high finding sets a non-zero exit
    assert "SECURITY SCAN" in capsys.readouterr().out
