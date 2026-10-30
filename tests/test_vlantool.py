import copy

import pytest

from vlantool import model
from vlantool.cli import main
from vlantool.validate import validate
from vlantool.vendors import PLUGINS, get

BASE = {
    "vlans": [
        {"id": 10, "name": "USERS", "gateway": "192.168.10.1/24", "dhcp_relay": "10.0.0.5"},
        {"id": 20, "name": "VOICE", "gateway": "192.168.20.1/24"},
        {"id": 99, "name": "MGMT", "gateway": "10.0.99.1/24"},
    ],
    "devices": [],
}


def net_for(vendor, **dev):
    data = copy.deepcopy(BASE)
    d = {"name": "dut", "vendor": vendor, "host": "10.0.0.1"}
    d.update(dev)
    data["devices"].append(d)
    net = model.from_dict(data)
    errors, _ = validate(net)
    assert errors == []
    return net


def render(vendor, **dev):
    net = net_for(vendor, **dev)
    return get(vendor)(net, net.devices[0]).generate()


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.key)
def test_every_vendor_renders_switching_and_routing(plugin):
    if plugin.requires_parent:
        dev = {"parent_interface": "port1", "routing": "all"}
    else:
        dev = {"routing": "all", "access": {"p1-2": 10}, "trunks": {"p24": {"allowed": "all", "native": 99}}}
    text = render(plugin.key, **dev)
    assert "dut" in text
    for needle in ("10", "USERS", "192.168.10.1"):
        assert needle in text, f"{plugin.key} lost {needle}"
    if plugin.supports_switching:
        assert "p1" in text and "p2" in text and "p24" in text


@pytest.mark.parametrize("plugin", [p for p in PLUGINS if not p.requires_parent], ids=lambda p: p.key)
def test_every_switch_renders_layer2_only(plugin):
    text = render(plugin.key, access={"p1": 20}, trunks={"p24": {"allowed": [10, 20]}})
    assert "192.168" not in text  # no routing asked for


def test_port_ranges():
    assert model.expand_ports("Gi1/0/1-3") == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3"]
    assert model.expand_ports("Gi1/0/1-Gi1/0/2,Gi1/0/9") == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/9"]
    assert model.expand_ports("1:1-1:3") == ["1:1", "1:2", "1:3"]
    assert model.expand_ports("ether2-3") == ["ether2", "ether3"]
    assert model.expand_ports("24") == ["24"]


def test_vlan_lists():
    assert model.compress_vlans([10, 11, 12, 20, 30, 31]) == "10-12,20,30-31"
    assert model.parse_vlan_list("10,20-22") == [10, 20, 21, 22]


def test_cisco_details():
    text = render("cisco_ios", routing=[10], access={"Gi1/0/1": "USERS"},
                  trunks={"Gi1/0/48": {"allowed": "10,20,99", "native": 99}})
    assert " switchport access vlan 10" in text
    assert " switchport trunk native vlan 99" in text
    assert " switchport trunk allowed vlan 10,20,99" in text
    assert "interface Vlan10\n description USERS\n ip address 192.168.10.1 255.255.255.0\n ip helper-address 10.0.0.5" in text
    assert "ip routing" in text


def test_router_on_a_stick():
    text = render("cisco_ios", parent_interface="Gi0/0", routing="all", vlans="all")
    assert "interface Gi0/0.20\n encapsulation dot1Q 20\n" in text


def test_mikrotik_enables_filtering_last():
    text = render("mikrotik_routeros", routing=[10], access={"ether2": 10}, trunks={"ether1": {"allowed": "all"}})
    lines = text.strip().splitlines()
    assert lines[-1] == "/interface bridge set bridge1 vlan-filtering=yes"
    assert "/interface bridge vlan add bridge=bridge1 vlan-ids=10 tagged=ether1,bridge1 untagged=ether2" in text


def test_fortigate_policy():
    text = render("fortinet", parent_interface="port2", routing="all",
                  policies=[{"from": "VOICE", "to": "USERS", "action": "deny"}])
    assert 'set srcintf "VOICE"' in text and "set action deny" in text
    assert 'set dhcp-relay-ip "10.0.0.5"' in text


@pytest.mark.parametrize("bad, msg", [
    ({"vlans": [{"id": 5000, "name": "X"}]}, "1-4094"),
    ({"vlans": [{"id": 10, "name": "A"}, {"id": 11, "name": "A"}]}, "already used"),
    ({"vlans": [{"id": 10, "name": "A", "gateway": "10.0.0.1/24"}, {"id": 11, "name": "B", "gateway": "10.0.0.2/25"}]}, "overlaps"),
    ({"vlans": [{"id": 10, "name": "has space"}]}, "name"),
    ({"vlans": [{"id": 10, "name": "A"}], "devices": [{"name": "s", "vendor": "nope"}]}, "unknown vendor"),
    ({"vlans": [{"id": 10, "name": "A"}], "devices": [{"name": "s", "vendor": "cisco_ios", "access": {"1": 30}}]}, "undefined VLAN"),
    ({"vlans": [{"id": 10, "name": "A", "gateway": "10.0.0.1/24"}], "devices": [{"name": "f", "vendor": "fortinet", "routing": "all"}]}, "parent_interface"),
    ({"vlans": [{"id": 10, "name": "A"}], "devices": [{"name": "s", "vendor": "cisco_ios", "access": {"1": 10}, "trunks": {"1": {}}}]}, "both access and trunk"),
])
def test_validation_errors(bad, msg):
    errors, _ = validate(model.from_dict(bad))
    assert any(msg in e for e in errors), errors


def test_cli_example(tmp_path, capsys):
    main(["generate", "examples/network.yaml", "-o", str(tmp_path)])
    files = sorted(p.name for p in tmp_path.iterdir())
    assert "core-sw1.txt" in files and "edge-fw.txt" in files
    main(["push", "examples/network.yaml", "-d", "core-sw1", "--dry-run"])
    assert "dry run" in capsys.readouterr().out


def test_web_build():
    from vlantool.web.server import build
    import yaml
    result = build(yaml.safe_load(open("examples/network.yaml")))
    assert result["errors"] == []
    assert result["configs"]["core-sw1"]["pushable"] is True
    assert result["configs"]["office-smart-switch"]["pushable"] is False
