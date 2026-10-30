# vlantool

Describe your whole network once (VLANs, routers, VPNs, point-to-point links,
access points, extenders) and get ready-to-paste (or push) config for every
device, whatever the brand. Then watch it all from one monitoring dashboard.

| Module | What it does |
|---|---|
| VLANs | access/trunk ports, SVIs, router-on-a-stick, DHCP relay (24 platforms) |
| Router | WAN (DHCP/static/PPPoE), NAT, DNS, DHCP servers, firewall, guest isolation, DMZ, port forwards, static routes, NTP |
| Links | point-to-point links between devices, wired or wireless, static or OSPF routing |
| VPN | WireGuard server with ready-to-import phone/laptop files; IPsec IKEv2 site-to-site |
| Wireless | SSIDs mapped to VLANs, extender/repeater mode, mesh |
| Security | IPS on firewalls, syslog to a SIEM, Wazuh EDR agents for Windows/Linux/macOS |
| Filtering | block sites per device by MAC address, on a schedule |
| Billing | sell internet: captive-portal hotspot vouchers and PPPoE subscriber plans (speed/time limits), optional RADIUS |
| Control | manage every device over SSH/VPN: facts, diagnose, backup, run, logs, upgrade |
| Scan | security scan of your own network (config audit + port scan), report-only |
| Monitoring | ping, port checks, uptime/CPU over SSH, per-interface bandwidth & traffic, connected-device list, internet speed test, 24h history, down/up alerts (webhook, Telegram), dashboard |

See `examples/full-network.yaml` for every feature in one file.

```
network.yaml  ──►  vlantool  ──►  Cisco / Juniper / Aruba / MikroTik / FortiGate / Sophos / ... config
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
    policies:                   # firewall vendors only (FortiGate, Juniper SRX, pfSense, Sophos)
      - {from: GUEST, to: CAMERAS, action: deny}
```

Port ranges: `Gi1/0/1-12`, `Gi1/0/1-Gi1/0/12`, `ether2-5`, `1-8`, `1:1-1:8`,
and comma lists. Quote purely numeric ports in YAML (`"24":`).

Device-specific options: `dot1q_encapsulation: true` (old Catalyst 3560/3750
trunks), `port_type: tenGigabitEthernet` (TP-Link), `bridge: bridge1` and
`create_bridge: false`, `dhcp_server: [10, 20]` and `lan_list: false` (MikroTik), `vdom: root` (FortiGate),
`opt_start: 3` (pfSense, first free optN), `relay_upstream: eth0` (VyOS).

## Router, links, VPN and Wi-Fi

Add these sections to a device (or `links:` at the top level). Each module's
docstring in `vlantool/services/` lists every option.

```yaml
devices:
  - name: hap
    vendor: mikrotik_routeros
    routing: all
    router:
      wan: {interface: ether1, mode: dhcp}        # static: address + gateway; pppoe: user + password
      dns: [1.1.1.1, 8.8.8.8]
      dhcp_server: all
      isolate: [GUEST]                             # internet only
      port_forwards: [{proto: tcp, port: 8443, to: 192.168.30.10, to_port: 443}]
    vpn:
      wireguard:
        address: 10.100.0.1/24
        endpoint: myhome.ddns.net                  # what phones dial
        peers: [{name: phone}, {name: laptop}]     # keys generated, .conf files written
      ipsec:
        - {name: office2, peer: 198.51.100.7, psk: long-secret, remote: [10.60.0.0/24]}
    wireless:
      country: kenya
      ssids:
        - {ssid: Home,  passphrase: "...", vlan: USERS, band: both}
        - {ssid: Guest, passphrase: "...", vlan: GUEST, band: 2ghz}

links:
  - name: tower
    a: {device: hap, interface: ether3, address: 10.255.0.1/30}
    b: {device: branch, interface: eth1, address: 10.255.0.2/30}
    routing: static                               # or ospf
    wireless: {ssid: ptp, passphrase: "...", frequency: 5745, width: 40}   # radio link (optional)
```

Generated config per module:

| | Router | Links | WireGuard | IPsec | Wi-Fi |
|---|---|---|---|---|---|
| MikroTik | yes | yes (+OSPF, radio) | yes | yes | yes (wifi + legacy wireless) |
| OpenWrt | yes | yes (radio) | yes | steps | yes (AP, extender, 802.11s mesh) |
| Cisco IOS | yes (zone firewall) | yes (+OSPF) | n/a | yes | steps |
| EdgeRouter | yes | yes (+OSPF) | yes | yes | n/a |
| VyOS | yes | yes (+OSPF) | yes | yes | n/a |
| FortiGate | yes | yes | n/a | yes | steps |
| Sophos Firewall (SFOS) | steps (Web Admin) | steps | steps | steps | steps |
| Juniper | steps | yes (+OSPF) | steps | steps | n/a |
| Everything else (UniFi, Omada, airMAX, TP-Link...) | numbered manual steps in the output |

WireGuard private keys are created once and stored in `<network>.secrets.json`
next to your file, so regenerating never breaks working tunnels. Keep that file
private. `vlantool generate file.yaml -o out/` writes `<device>-<peer>.conf`
for each phone/laptop; import it into the WireGuard app.

Devices you only want to watch (APs, radios, cameras, servers) use
`vendor: generic`.

## Monitoring

```bash
vlantool monitor network.yaml            # dashboard at http://127.0.0.1:8080/monitor
vlantool monitor network.yaml --once     # one round, printed as a table
vlantool gui network.yaml --monitor      # editor and dashboard together
```

```yaml
monitoring:
  interval: 30                 # seconds between checks
  ssh_stats_every: 300         # SSH login for stats/bandwidth/clients (MikroTik, Cisco, Junos, EdgeOS, VyOS...); 0 = off
  traffic: true                # per-interface throughput + byte totals (default on)
  clients: true                # connected devices: DHCP leases + ARP + Wi-Fi (default on)
  speedtest_every: 3600        # internet speed test every N seconds (0 = only the dashboard button)
  speedtest: {bytes: 25000000} # size per run; override download/upload URLs if Cloudflare is blocked
  backup_every: 900            # back up each device's running config every N seconds for drift detection (0 = off)
  reconcile: false             # on drift, auto-push the generated config back (opt-in; default: alert only)
  backup_keep: 10              # config snapshots kept per device
  webhook: https://...         # JSON POST on every alert (Slack, Discord, n8n, ...)
  telegram: {token: "123:ABC", chat_id: "456"}
devices:
  - name: lobby-ap
    vendor: generic
    host: 192.168.99.31
    monitor: {ports: [80, 443]}   # also check these TCP ports
```

SSH stats use `VLANTOOL_USERNAME`/`VLANTOOL_PASSWORD` (or the device's
`username`). History is kept in `<network>.monitor.db` (SQLite).

The dashboard shows each device's **bandwidth** (Mbps in/out per interface) and
traffic totals, a network-wide **connected-devices** table (IP, MAC, hostname,
VLAN, and whether it's wired or Wi-Fi), and an **internet speed test** with a
"Run test" button plus scheduled runs. Bandwidth and byte counters come from
MikroTik, Cisco, EdgeOS/VyOS and OpenWrt; the client list from MikroTik and
Cisco (other vendors show reachability and uptime only).

With `backup_every` set, the monitor also pulls each device's running config on
a schedule, stores a snapshot, and compares it to the last one. When a config
changes out-of-band it raises a **drift** alert (webhook/Telegram) and the
dashboard's **Config & drift** section shows which devices are in sync vs
changed, the last-backup time, and a unified diff of what changed. Set
`reconcile: true` to have the monitor automatically push the generated config
back to a drifted device (opt-in, since that changes live gear unattended).

## Automating the whole lifecycle: `vlantool up`

```bash
vlantool up network.yaml                 # validate -> push every device -> watch, with drift detection on
vlantool up network.yaml --yes           # don't prompt before pushing
vlantool up network.yaml --no-push       # just bring up monitoring (no config push)
```

`vlantool up` is the one-command path: it validates the file, shows and pushes
the config to every SSH-reachable device (after a confirmation, or `--yes`),
then launches the dashboard with config backup + drift detection turned on
(`--backup-every`, default 900s). From then on it keeps the network matching
the file and flags anything that drifts.

## Deploying on Render (or any host)

A [`render.yaml`](render.yaml) Blueprint is included. In Render:
**New + → Blueprint → pick this repo**. It builds `pip install ".[push]"` and
starts the editor + dashboard as one web service. Then open the service URL:
`/` is the config editor, `/monitor` is the dashboard.

Set these in the Render dashboard before you expose it:

| Env var | What it does |
|---------|--------------|
| `VLANTOOL_AUTH` | `user:pass` — HTTP login guarding the whole site. **Set this.** Without it the editor and the Push-over-SSH endpoint are open to anyone with the URL. |
| `NETWORK_FILE` | which network file to open (default `examples/full-network.yaml`) |
| `VLANTOOL_USERNAME` / `VLANTOOL_PASSWORD` | SSH credentials for push / live monitoring (optional) |

To run the server anywhere else, bind a public interface and set auth:

```bash
VLANTOOL_AUTH=admin:secret vlantool gui network.yaml --monitor --host 0.0.0.0 --port 8080
```

Two things to know about a cloud deploy:

- **Reachability.** A cloud service can only push to and monitor devices it can
  actually reach over the network — devices with public IPs or reachable through
  a VPN/tunnel. It can't touch a home/office LAN behind NAT. The editor
  (generate + download config) works regardless.
- **Persistence.** The container filesystem is ephemeral, so edits saved from
  the editor and the monitoring history (`<network>.monitor.db`) reset on each
  deploy unless you attach a persistent disk. Keep the network file in git as
  the source of truth.

A `/healthz` endpoint (unauthenticated) is provided for platform health checks.

## Security: IPS, log forwarding and EDR

```yaml
security:
  siem: 192.168.99.50                 # every device sends syslog here
  wazuh:
    manager: 192.168.99.50
    active_response: true             # auto-block brute-force attackers on endpoints
    api: {url: "https://192.168.99.50:55000", user: wazuh-wui, password_env: WAZUH_API_PASSWORD}

endpoints:                            # PCs and servers that get the Wazuh EDR agent
  - {name: reception-pc, os: windows}
  - {name: file-server,  os: ubuntu}
  - {name: design-mac,   os: macos, arch: arm64}

devices:
  - name: office2-fw
    vendor: fortinet
    security: {ips: prevent}          # or detect (alert only)
```

| | IPS |
|---|---|
| FortiGate | IPS sensor (medium/high/critical) attached to every firewall policy |
| OpenWrt | Snort 3 inline (prevent) or passive (detect) |
| MikroTik | no signature IPS in RouterOS: brute-force and port-scan banning, plus `sensor:` to stream WAN traffic to a Suricata box |
| Sophos Firewall (SFOS) | steps: IPS policy with drop (prevent) / log (detect), attached to the firewall rule |
| pfSense/OPNsense, Cisco, Juniper SRX, VyOS, EdgeOS | numbered steps (Suricata, UTD Snort, IDP) |

Syslog forwarding is generated for every vendor with a CLI.

EDR uses [Wazuh](https://wazuh.com) (free, open source): malware and rootkit
detection, file integrity monitoring, vulnerability detection and automatic
blocking.

```bash
vlantool edr network.yaml -o out/
#   out/edr/wazuh-manager-setup.sh   run once on a Linux server
#   out/edr/reception-pc.ps1         run on each PC (PowerShell as Administrator)
#   out/edr/file-server.sh           sudo bash on Linux / macOS
```

With `security.wazuh.api` set, `vlantool monitor` shows every endpoint's agent
(active, disconnected, not enrolled) and alerts when one drops off.

## DMZ (public-facing servers)

Put servers that must be reachable from the internet on their own VLAN and mark
it a DMZ. It can reach the internet and be reached from the WAN through your
port-forwards, but it is blocked from the rest of your LAN, so a compromised
server there can't pivot into your internal network.

```yaml
vlans:
  - {id: 70, name: DMZ, gateway: 192.168.70.1/24}

devices:
  - name: edge
    vendor: mikrotik_routeros
    routing: all
    router:
      wan: {interface: ether1, mode: dhcp}
      dmz: [DMZ]                 # one or more VLANs
      dhcp_server: [DMZ]
      port_forwards:
        - {name: web, proto: tcp, port: 443, to: 192.168.70.10}
```

Generated for MikroTik, Cisco, EdgeRouter, VyOS, FortiGate and OpenWrt (others
get manual steps). The scanner warns if a VLAN named like a DMZ isn't actually
walled off.

## Content filtering by device

Block sites for a specific device by its MAC address, optionally on a schedule:

```yaml
devices:
  - name: hap
    vendor: mikrotik_routeros
    routing: all
    filtering:
      - name: kids-tablet
        mac: AA:BB:CC:DD:EE:01
        vlan: USERS                 # the VLAN it's on (used to pin a static IP), or give 'ip:'
        block: [facebook.com, tiktok.com]
        categories: [adult, gambling]           # built-in lists: adult, gambling, social, streaming, ads
        schedule: {days: [mon,tue,wed,thu,fri], from: "22:00", to: "06:30"}
```

The device is pinned to a static IP by its MAC, and traffic from it to those
domains is dropped. Generated for **MikroTik** (layer7 on the TLS hostname),
**FortiGate** (web filter with a MAC address object), **OpenWrt** (dnsmasq
nftset) and **Sophos Firewall** (URL group + web policy per MAC/IP host); other
vendors get manual steps. For airtight HTTPS filtering, also
point those clients at a filtering DNS resolver.

## Billing: hotspot vouchers and PPPoE plans

Turn a router into a prepaid internet seller: a captive-portal hotspot with
time/speed voucher codes, and/or a PPPoE server with per-plan speed limits and
subscriber accounts. MikroTik generates the full config; other vendors get
step-by-step notes. Hand authentication to external billing software with the
optional `radius` block.

```yaml
devices:
  - name: hap
    vendor: mikrotik_routeros
    routing: all
    billing:
      hotspot:
        interface: GUEST                 # a VLAN (name/id) or a raw interface
        dns_name: login.hotspot
        plans:
          - {name: 1hour, rate: "5M/5M",   session: 1h, shared: 1, price: 50}
          - {name: 1day,  rate: "10M/10M", session: 1d, price: 200}
        vouchers:
          - {plan: 1hour, count: 10}      # 10 printable one-hour codes
          - {plan: 1day,  user: vip, password: keepme}
      pppoe:
        interface: ether3
        pool: 10.80.0.2-10.80.0.254
        gateway: 10.80.0.1
        plans:
          - {name: home-10m, rate: "10M/10M", price: 1500}
        subscribers:
          - {user: sub001, plan: home-10m}   # password generated if omitted
      radius: {server: 192.168.99.60, secret: s3cr3t}   # optional
```

Generated voucher codes and passwords are stored in `<network>.secrets.json`,
so they stay the same every time you regenerate. `vlantool generate -o out/`
also writes `out/<device>-vouchers.txt`, a printable list of every code, plan
and price to hand out or tape to the wall.

## Managing the live network

Once the network is up, manage every device from one place over SSH (run it
across your WireGuard VPN to reach sites remotely):

```bash
vlantool control network.yaml facts                  # model, firmware, uptime of each device
vlantool control network.yaml diagnose               # reachability + health across the network
vlantool control network.yaml backup -o backups/     # save every device's running config
vlantool control network.yaml logs -d hap            # pull recent logs from one device
vlantool control network.yaml run "/system reboot" -d hap
vlantool control network.yaml upgrade -d hap         # check for firmware updates
vlantool control network.yaml upgrade -d hap --apply # back up first, then install (MikroTik/OpenWrt)
```

Credentials come from `VLANTOOL_USERNAME`/`VLANTOOL_PASSWORD`, or
`VLANTOOL_PASSWORD_<DEVICE>` per device, or each device's `username`. This is
central management of your own gear: it logs in as you, and never relays or
intercepts other devices' traffic.

## Security scanning

Scan your own network for weaknesses. It only probes the hosts named in your
file, and by default changes nothing:

```bash
vlantool scan network.yaml                   # config audit + live port scan
vlantool scan network.yaml -o report.html    # also write an HTML report
vlantool scan network.yaml --check-passwords # also test devices for default/weak SSH passwords
```

It flags weak Wi-Fi passphrases and VPN keys, reused secrets, disabled
firewalls, un-isolated guest VLANs, exposed management ports (Telnet, FTP,
plain HTTP, WinBox on the internet) and, with `--check-passwords`, devices
still on their factory login. The exit code is non-zero when anything high or
critical is found, so you can run it in a scheduled job.

## Trying it on a MikroTik hAP

`examples/mikrotik-hap.yaml` is written for a hAP on its default config
(ether1 internet, ether2-5 in `bridge`, LAN 192.168.88.0/24). It puts ether4
in VLAN 10 and ether5 in VLAN 20, each with its own gateway and DHCP server,
and leaves ether2/ether3 untouched so you keep management access.

```bash
pip install ".[push]"
/system backup save name=before-vlan       # on the hAP first (Terminal in WinBox/WebFig)
vlantool push examples/mikrotik-hap.yaml --dry-run
vlantool push examples/mikrotik-hap.yaml -u admin
```

Run it from a PC plugged into ether2 or ether3. Undo with
`/system backup load name=before-vlan`.

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
| `sophos` | Sophos XG/XGS Firewall (SFOS v18-v21) | Web Admin / XML API steps |
| `openwrt` | OpenWrt 21.02+ routers and APs (uci, DSA) | yes |
| `generic` | monitoring-only devices (APs, radios, servers, cameras) | n/a |
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
