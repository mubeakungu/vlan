import base64

import pytest
import yaml

from vlantool import model
from vlantool.secrets import Secrets, wg_private_key, wg_public_key, _x25519
from vlantool.validate import validate
from vlantool.vendors import get

EXAMPLE = "examples/full-network.yaml"


def load_example(tmp_path):
    p = tmp_path / "net.yaml"
    p.write_text(open(EXAMPLE).read())
    net = model.load(p)
    errors, _ = validate(net)
    assert errors == []
    return net, p


def gen(net, name):
    d = net.device(name)
    plugin = get(d.vendor)(net, d)
    return plugin.generate(), plugin.extra_files()


def test_full_example_generates_every_device(tmp_path):
    net, _ = load_example(tmp_path)
    for d in net.devices:
        text, _ = gen(net, d.name)
        assert d.name in text


def test_router_mikrotik(tmp_path):
    net, _ = load_example(tmp_path)
    text, _ = gen(net, "hap")
    assert "/ip dhcp-client add interface=ether1" in text
    assert 'action=masquerade comment="vlantool: masquerade"' in text
    assert "in-interface=vlan20-GUEST dst-address=192.168.0.0/16" in text
    assert "to-addresses=192.168.30.10 to-ports=443" in text
    assert "/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes" in text


def test_router_cisco_nat_and_dhcp():
    data = {"vlans": [{"id": 10, "name": "USERS", "gateway": "192.168.10.1/24"}],
            "devices": [{"name": "r1", "vendor": "cisco_ios", "parent_interface": "Gi0/1", "routing": "all",
                         "router": {"wan": {"interface": "Gi0/0"}, "dhcp_server": "all", "dns": ["1.1.1.1"],
                                    "port_forwards": [{"port": 80, "to": "192.168.10.5"}]}}]}
    net = model.from_dict(data)
    assert validate(net)[0] == []
    text = get("cisco_ios")(net, net.devices[0]).generate()
    assert "interface Gi0/0\n description WAN\n ip address dhcp\n ip nat outside" in text
    assert "interface Gi0/1.10\n ip nat inside" in text
    assert "ip nat inside source list VLANTOOL-NAT interface Gi0/0 overload" in text
    assert "ip dhcp pool USERS\n network 192.168.10.0 255.255.255.0\n default-router 192.168.10.1" in text
    assert "zone-pair security IN-OUT source INSIDE destination OUTSIDE" in text
    assert "ip nat inside source static tcp 192.168.10.5 80 interface Gi0/0 80" in text


@pytest.mark.parametrize("vendor", ["ubiquiti_edgeos", "vyos", "fortinet", "openwrt", "juniper_junos"])
def test_router_other_vendors(vendor):
    data = {"vlans": [{"id": 10, "name": "USERS", "gateway": "192.168.10.1/24"}],
            "devices": [{"name": "r1", "vendor": vendor, "parent_interface": "eth1", "routing": "all",
                         "router": {"wan": {"interface": "eth0", "mode": "static", "address": "203.0.113.2/30",
                                            "gateway": "203.0.113.1"},
                                    "dhcp_server": "all", "dns": ["1.1.1.1"], "isolate": [10],
                                    "static_routes": [{"to": "10.0.0.0/8", "via": "192.168.10.254"}]}}]}
    net = model.from_dict(data)
    assert validate(net)[0] == []
    text = get(vendor)(net, net.devices[0]).generate()
    assert "203.0.113" in text or "manual" in text or "by hand" in text
    assert "10.0.0.0" in text


def test_link_routes_both_sides(tmp_path):
    net, _ = load_example(tmp_path)
    hap, _ = gen(net, "hap")
    branch, _ = gen(net, "branch-router")
    assert "/ip route add dst-address=192.168.50.0/24 gateway=10.255.0.2" in hap
    assert "/interface bridge port remove [find interface=ether3]" in hap
    assert "set protocols static route 192.168.10.0/24 next-hop 10.255.0.1" in branch


def test_link_ospf_and_radio():
    data = {"vlans": [{"id": 10, "name": "A", "gateway": "192.168.10.1/24"}, {"id": 20, "name": "B", "gateway": "192.168.20.1/24"}],
            "devices": [{"name": "m1", "vendor": "mikrotik_routeros", "vlans": [10], "routing": [10]},
                        {"name": "m2", "vendor": "openwrt", "vlans": [20], "routing": [20]}],
            "links": [{"name": "air", "routing": "ospf",
                       "a": {"device": "m1", "interface": "wifi1", "address": "10.9.0.1/30"},
                       "b": {"device": "m2", "interface": "radio1", "address": "10.9.0.2/30"},
                       "wireless": {"ssid": "air", "passphrase": "12345678", "frequency": 5745, "width": 40}}]}
    net = model.from_dict(data)
    assert validate(net)[0] == []
    m1 = get("mikrotik_routeros")(net, net.devices[0]).generate()
    m2 = get("openwrt")(net, net.devices[1]).generate()
    assert "configuration.mode=ap" in m1 and "channel.frequency=5745" in m1
    assert "/routing ospf interface-template add area=backbone-vlantool networks=10.9.0.0/30" in m1
    assert "uci set wireless.ptp_air.mode='sta'" in m2 and "channel='149'" in m2


def test_x25519_rfc7748_vector():
    priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    pub = _x25519(priv, (9).to_bytes(32, "little"))
    assert pub.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    k = wg_private_key()
    assert len(base64.b64decode(k)) == 32 and len(base64.b64decode(wg_public_key(k))) == 32


def test_wireguard_keys_are_stable_and_clients_match(tmp_path):
    net, p = load_example(tmp_path)
    text1, files1 = gen(net, "hap")
    net2 = model.load(p)
    validate(net2)
    text2, files2 = gen(net2, "hap")
    assert text1 == text2 and files1 == files2  # keys persisted in net.secrets.json
    assert (tmp_path / "net.secrets.json").exists()
    phone = files1["hap-phone.conf"]
    priv = phone.split("PrivateKey = ")[1].split()[0]
    assert f'public-key="{wg_public_key(priv)}"' in text1  # router knows the phone's public key
    assert "Endpoint = myhome.ddns.net:51820" in phone and "AllowedIPs = 0.0.0.0/0" in phone


def test_ipsec_both_ends(tmp_path):
    net, _ = load_example(tmp_path)
    hap, _ = gen(net, "hap")
    fw, _ = gen(net, "office2-fw")
    assert "/ip ipsec policy add peer=vt-office2 tunnel=yes src-address=192.168.10.0/24 dst-address=10.60.0.0/24" in hap
    assert "ipsec-policy=in,ipsec" in hap
    assert "set remote-gw 203.0.113.10" in fw and "set dst-subnet 192.168.10.0 255.255.255.0" in fw


def test_wireless_mikrotik_and_openwrt(tmp_path):
    net, _ = load_example(tmp_path)
    hap, _ = gen(net, "hap")
    ap, _ = gen(net, "upstairs-ap")
    ext, _ = gen(net, "garden-extender")
    unifi, _ = gen(net, "lobby-unifi-ap")
    assert "/interface wifi add master-interface=wifi2 name=wifi2-guest" in hap
    assert "/interface bridge port set [find interface=wifi2-guest] pvid=20" in hap
    assert "uci set wireless.vt_guest_radio0.network='vlan20'" in ap
    assert "uci set network.vlan99.ipaddr='192.168.99.30'" in ap
    assert "uci set wireless.vt_uplink.mode='sta'" in ext
    assert "Create SSID 'Home'" in unifi


@pytest.mark.parametrize("bad, msg", [
    ({"router": {"wan": {"interface": "e1", "mode": "static"}}}, "static WAN needs"),
    ({"router": {"wan": {"interface": "e1", "mode": "pppoe"}}}, "PPPoE WAN needs"),
    ({"vpn": {"wireguard": {"address": "nope"}}}, "wireguard needs 'address'"),
    ({"vpn": {"ipsec": [{"name": "x", "peer": "1.2.3.4", "psk": "short", "remote": ["10.0.0.0/8"]}]}}, "8+ characters"),
    ({"wireless": {"ssids": [{"ssid": "x", "passphrase": "123"}]}}, "8+ characters"),
    ({"wireless": {"mode": "extender", "ssids": []}}, "needs 'uplink'"),
])
def test_service_validation(bad, msg):
    dev = {"name": "d", "vendor": "mikrotik_routeros"}
    dev.update(bad)
    errors, _ = validate(model.from_dict({"vlans": [{"id": 10, "name": "A"}], "devices": [dev]}))
    assert any(msg in e for e in errors), errors


def test_link_validation():
    data = {"vlans": [], "devices": [{"name": "a", "vendor": "vyos"}],
            "links": [{"name": "l", "a": {"device": "a", "interface": "eth1", "address": "10.0.0.1/30"},
                       "b": {"device": "ghost", "interface": "eth1", "address": "10.0.1.2/30"}}]}
    errors, _ = validate(model.from_dict(data))
    assert any("ghost" in e for e in errors) and any("same subnet" in e for e in errors)
