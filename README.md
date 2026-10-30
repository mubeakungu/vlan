# vlantool

Define your VLANs once, then get ready-to-paste (or push) config for every
switch, router and firewall in your network, whatever the brand.

```
network.yaml  ──►  vlantool  ──►  Cisco / Juniper / Aruba / D-Link / TP-Link / MikroTik / FortiGate / ... config
                              └─►  SSH push (Netmiko)  └─►  web editor
```

## Install

```bash
pip install .            # generate config only (needs PyYAML)
pip install ".[push]"    # also push over SSH (adds Netmiko)
```

Or run without installing: `python -m vlantool ...` from this folder.

## Quick start

```bash
vlantool vendors                                   # what is supported
vlantool validate examples/network.yaml            # check for mistakes
vlantool generate examples/network.yaml            # print every device's config
vlantool generate examples/network.yaml -o out/    # one file per device
vlantool push examples/network.yaml -d core-sw1 --dry-run
vlantool push examples/network.yaml -d core-sw1 -u admin   # asks for password, then confirmation
vlantool gui examples/network.yaml                 # web editor on http://127.0.0.1:8080
```

## The network file

```yaml
vlans:
  - id: 10
    name: USERS                 # letters, digits, _ . - (no spaces)
    gateway: 192.168.10.1/24    # optional; needed for any device that routes this VLAN
    dhcp_relay: 10.0.99.5       # optional; one IP or a list

devices:
  - name: core-sw1
    vendor: cisco_ios           # see `vlantool vendors`; aliases like cisco, tplink, mikrotik work
    host: 10.0.99.2             # only needed for push
    username: admin
    vlans: all                  # VLANs created on this device: all, or [10, 20]
    routing: [10, 20]           # VLANs this device routes (SVIs); omit for layer 2 only
    access:
      Gi1/0/1-12: USERS         # port or range -> VLAN (name or id)
    trunks:
      Gi1/0/48: {allowed: all, native: 99}

  - name: edge-fw               # routers/firewalls: router-on-a-stick subinterfaces
    vendor: fortinet
    parent_interface: port2
    routing: [30, 40]
    policies:                   # firewall vendors only (FortiGate, Juniper SRX, pfSense)
      - {from: GUEST, to: CAMERAS, action: deny}
```

Port ranges: `Gi1/0/1-12`, `Gi1/0/1-Gi1/0/12`, `ether2-5`, `1-8`, `1:1-1:8`,
and comma lists. Quote purely numeric ports in YAML (`"24":`).

Device-specific options: `dot1q_encapsulation: true` (old Catalyst 3560/3750
trunks), `port_type: tenGigabitEthernet` (TP-Link), `bridge: bridge1` and
`create_bridge: false` (MikroTik), `vdom: root` (FortiGate),
`opt_start: 3` (pfSense, first free optN), `relay_upstream: eth0` (VyOS).

## Supported vendors

| key | covers | push |
|---|---|---|
| `cisco_ios` | Catalyst 2960-9300, ISR routers | yes |
| `cisco_nxos` | Nexus | yes |
| `cisco_smb` | SG300/350/550, CBS250/350, Catalyst 1200/1300 | yes |
| `arista_eos` | Arista EOS | yes |
| `dell_os10` | Dell OS10 | yes |
| `juniper_junos` | EX/QFX switching, SRX zones+policies, MX | yes (commit) |
| `aruba_aoscx` | Aruba CX 6000-8000 | yes |
| `hp_procurve` | ArubaOS-Switch 2530/2930/3810, ProCurve | yes |
| `hp_comware` | HPE 1920/1950/5130, H3C | yes |
| `huawei_vrp` | Huawei S/CE switches, AR routers | yes |
| `dlink_dgs` | D-Link DGS-1250/1510/1520/3130 (new CLI) | yes |
| `dlink` | D-Link DES/DGS legacy `create vlan` CLI | yes |
| `tplink_jetstream` | TP-Link JetStream / Omada switches in standalone mode | yes |
| `ubiquiti_edgeswitch` | Ubiquiti EdgeSwitch | yes |
| `netgear` | Netgear M4xxx / GSM managed | yes |
| `extreme_exos` | Extreme EXOS | yes |
| `ruckus_icx` | Ruckus/Brocade ICX | yes |
| `zyxel` | Zyxel GS2210/XGS2220/XS3800 | yes |
| `mikrotik_routeros` | MikroTik CRS/CCR/hAP (RouterOS v7 bridge VLAN filtering) | yes |
| `ubiquiti_edgeos` | EdgeRouter | yes (commit) |
| `vyos` | VyOS | yes (commit) |
| `fortinet` | FortiGate | yes |
| `pfsense` | pfSense / OPNsense config.xml sections | file only |
| `web_gui` | Any switch with only a web page: TP-Link Easy Smart, Netgear Plus, UniFi, Omada, Zyxel GS1900... | manual steps |

Anything not listed that speaks 802.1Q can use `web_gui`, which prints a
port-by-VLAN table (U/T/PVID) to click through.

## Safety

* `validate` runs before every generate/push: VLAN ranges, duplicate names,
  overlapping subnets, ports in both access and trunk, missing parent interfaces.
* `push` always shows the exact commands first and asks you to type `yes`;
  `--dry-run` stops there.
* MikroTik output enables `vlan-filtering` as the last step so you don't lock
  yourself out mid-way. On any device, keep your management VLAN on the port
  you're connected through.
* Passwords are never stored: use the prompt, `-p`, or `VLANTOOL_PASSWORD`.
* The GUI listens on 127.0.0.1 only unless you pass `--host`.
* Huawei `save` asks for `y` when pasted by hand.
* Test on one device before pushing to many. Generated syntax follows each
  vendor's current documentation, but firmware versions differ.

## Adding a vendor

Create a class in `vlantool/vendors/` that subclasses `Vendor`, set `key`,
`title`, `covers`, `netmiko_type`, and implement `render()` returning a list of
config lines (helpers: `self.vlans`, `self.routed`, `self.dev.access`,
`self.trunks`, `untagged_ports(vid)`, `tagged_ports(vid)`). Add it to
`PLUGINS` in `vlantool/vendors/__init__.py`. The test suite renders every
plugin automatically.

## Tests

```bash
pip install ".[dev]" && pytest
```
