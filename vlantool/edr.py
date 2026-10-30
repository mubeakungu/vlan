"""EDR with Wazuh: manager setup plus agent install scripts for every endpoint.

    security:
      siem: 192.168.99.50              # where network devices send syslog (usually the manager)
      wazuh:
        manager: 192.168.99.50
        version: 4.14.7                # agent version to install
        group: default
        active_response: true          # auto-block IPs that brute-force endpoints
        api: {url: https://192.168.99.50:55000, user: wazuh-wui, password_env: WAZUH_API_PASSWORD}

    endpoints:
      - {name: reception-pc, os: windows}
      - {name: file-server,  os: ubuntu, host: 192.168.10.20}
      - {name: design-mac,   os: macos, arch: arm64}
"""
from __future__ import annotations

from .model import Network

DEFAULT_VERSION = "4.14.7"
OS_FAMILY = {
    "windows": "windows", "win": "windows",
    "ubuntu": "deb", "debian": "deb", "mint": "deb", "kali": "deb", "raspbian": "deb",
    "rhel": "rpm", "centos": "rpm", "rocky": "rpm", "alma": "rpm", "almalinux": "rpm", "fedora": "rpm", "amazon": "rpm",
    "macos": "macos", "mac": "macos", "osx": "macos",
}


def wazuh(net: Network) -> dict | None:
    w = dict((net.security or {}).get("wazuh") or {})
    if not w and not net.endpoints:
        return None
    w.setdefault("manager", (net.security or {}).get("siem"))
    w.setdefault("version", DEFAULT_VERSION)
    w.setdefault("group", "default")
    w.setdefault("active_response", True)
    return w


def private_ranges(net: Network) -> str:
    nets = {v.network for v in net.vlans.values() if v.gateway}
    for link in net.links:  # routers may log from their link address
        for side in ("a", "b"):
            addr = (link.get(side) or {}).get("address")
            if addr:
                import ipaddress
                nets.add(str(ipaddress.ip_interface(addr).network))
    nets = sorted(nets)
    return "\n".join(f"    <allowed-ips>{n}</allowed-ips>" for n in nets) or "    <allowed-ips>192.168.0.0/16</allowed-ips>"


def manager_script(net: Network, w: dict) -> str:
    major = ".".join(w["version"].split(".")[:2])
    ar = ""
    if w["active_response"]:
        ar = """  <!-- block IPs that brute-force SSH (Linux/macOS) or Windows logons for 10 minutes -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5763</rules_id>
    <timeout>600</timeout>
  </active-response>
  <active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>60204</rules_id>
    <timeout>600</timeout>
  </active-response>
"""
    return f"""#!/usr/bin/env bash
# Wazuh manager (EDR + SIEM) for {len(net.endpoints)} endpoint(s) and {len(net.devices)} network device(s).
# Run on a Linux server (Ubuntu 22.04/24.04, 4 CPU, 8 GB RAM, 50 GB disk) at {w['manager']}.
set -euo pipefail

# 1. All-in-one install: indexer, manager and dashboard. Prints the admin password at the end: save it.
curl -sO https://packages.wazuh.com/{major}/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# 2. Accept syslog from routers, switches and firewalls (set up by vlantool's security section)
#    and turn on active response. Added as a separate <ossec_config> block, which Wazuh merges.
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'XML'

<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
{private_ranges(net)}
  </remote>
{ar}</ossec_config>
XML

sudo systemctl restart wazuh-manager
echo "Dashboard: https://{w['manager']}  (user admin, password printed above)"
"""


def agent_script(ep: dict, w: dict) -> tuple[str, str]:
    """(filename, script) for one endpoint."""
    name, version, mgr, group = ep["name"], w["version"], w["manager"], ep.get("group", w["group"])
    family = OS_FAMILY.get(str(ep.get("os", "windows")).lower(), "deb")
    if family == "windows":
        return f"{name}.ps1", f"""# Wazuh EDR agent for {name}. Run in PowerShell as Administrator.
$ErrorActionPreference = "Stop"
$msi = "$env:TEMP\\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-{version}-1.msi" -OutFile $msi
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=`"{mgr}`" WAZUH_AGENT_NAME=`"{name}`" WAZUH_AGENT_GROUP=`"{group}`""
NET START WazuhSvc
Write-Host "Wazuh agent installed; {name} will appear in the dashboard within a minute."
"""
    if family == "macos":
        arch = "arm64" if str(ep.get("arch", "")).lower() in ("arm64", "m1", "m2", "m3", "m4", "apple") else "intel64"
        return f"{name}.sh", f"""#!/usr/bin/env bash
# Wazuh EDR agent for {name} (macOS {arch}). Run with: sudo bash {name}.sh
set -euo pipefail
curl -so /tmp/wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-{version}-1.{arch}.pkg
echo "WAZUH_MANAGER='{mgr}' && WAZUH_AGENT_NAME='{name}' && WAZUH_AGENT_GROUP='{group}'" > /tmp/wazuh_envs
installer -pkg /tmp/wazuh-agent.pkg -target /
/Library/Ossec/bin/wazuh-control start
"""
    if family == "rpm":
        return f"{name}.sh", f"""#!/usr/bin/env bash
# Wazuh EDR agent for {name} (RHEL/Rocky/Alma/Fedora). Run with: sudo bash {name}.sh
set -euo pipefail
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
WAZUH_MANAGER="{mgr}" WAZUH_AGENT_NAME="{name}" WAZUH_AGENT_GROUP="{group}" yum install -y wazuh-agent-{version}
systemctl daemon-reload && systemctl enable --now wazuh-agent
"""
    return f"{name}.sh", f"""#!/usr/bin/env bash
# Wazuh EDR agent for {name} (Debian/Ubuntu). Run with: sudo bash {name}.sh
set -euo pipefail
apt-get install -y gnupg apt-transport-https curl
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER="{mgr}" WAZUH_AGENT_NAME="{name}" WAZUH_AGENT_GROUP="{group}" apt-get install -y wazuh-agent={version}-1
systemctl daemon-reload && systemctl enable --now wazuh-agent
"""


def files(net: Network) -> dict[str, str]:
    """All EDR files, keyed by relative path."""
    w = wazuh(net)
    if not w or not w.get("manager"):
        return {}
    out = {"edr/wazuh-manager-setup.sh": manager_script(net, w)}
    for ep in net.endpoints:
        fname, script = agent_script(ep, w)
        out[f"edr/{fname}"] = script
    return out


def validate(net: Network) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    w = (net.security or {}).get("wazuh")
    if net.endpoints and not ((w or {}).get("manager") or (net.security or {}).get("siem")):
        errors.append("endpoints need security.wazuh.manager (or security.siem): the Wazuh manager's IP")
    names = set()
    for ep in net.endpoints:
        if not ep.get("name"):
            errors.append(f"endpoint needs a 'name': {ep}")
            continue
        if ep["name"] in names:
            errors.append(f"endpoint {ep['name']} listed twice")
        names.add(ep["name"])
        if str(ep.get("os", "windows")).lower() not in OS_FAMILY:
            errors.append(f"endpoint {ep['name']}: os must be one of {', '.join(sorted(set(OS_FAMILY)))}")
    return errors, warnings
