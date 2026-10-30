"""Switches with no usable CLI: produce a click-by-click membership sheet."""
from __future__ import annotations

from .base import Vendor


class WebGUI(Vendor):
    key = "web_gui"
    title = "Web-managed / smart switch (manual steps)"
    covers = ("TP-Link Easy Smart (TL-SG105E/108E/116E), Netgear Plus (GS105E/GS308E), "
              "D-Link Smart (DGS-1100/1210 web), UniFi & Omada controller-managed switches, "
              "Zyxel GS1200/GS1900, Cisco CBS110, any other 802.1Q switch with a web page")
    netmiko_type = None
    pushable = False
    comment = "#"

    def render(self) -> list[str]:
        ports = list(self.dev.access) + [t.port for t in self.trunks]
        vlans = self.vlans
        out = [
            "",
            "Step 1. Open the switch web page and enable '802.1Q VLAN' mode",
            "        (TP-Link: VLAN > 802.1Q VLAN; Netgear: VLAN > Advanced 802.1Q;",
            "         UniFi: Settings > Networks + Port Manager; Omada: LAN > Networks + Profiles).",
            "",
            "Step 2. Create these VLANs:",
        ]
        out += [f"        VLAN {v.id:<5} {v.name}" for v in vlans]
        out += ["", "Step 3. Set each port's membership (U = untagged, T = tagged, - = not a member):", ""]
        width = max([len(p) for p in ports] + [4])
        out.append("        " + "Port".ljust(width) + " | " + " | ".join(f"{v.id:>4}" for v in vlans) + " | PVID")
        out.append("        " + "-" * (width + 7 * len(vlans) + 9))
        for p in ports:
            cells = []
            for v in vlans:
                if p in self.untagged_ports(v.id):
                    cells.append("   U")
                elif p in self.tagged_ports(v.id):
                    cells.append("   T")
                else:
                    cells.append("   -")
            pvid = self.dev.access.get(p) or next((t.native for t in self.trunks if t.port == p), None) or 1
            out.append("        " + p.ljust(width) + " | " + " | ".join(cells) + f" | {pvid}")
        out += [
            "",
            "Step 4. Set the PVID of every port to the value in the PVID column.",
            "Step 5. Remove access ports from VLAN 1 if the switch keeps them there by default.",
            "Step 6. Save / apply. Keep one port in your management VLAN so you do not lose access.",
        ]
        if self.routed:
            out += ["", "Routing: this switch type usually cannot route; put these gateways on your router/firewall:"]
            out += [f"        VLAN {v.id} {v.name}: {v.gateway}" for v in self.routed]
        return out

    def generate(self) -> str:
        return "\n".join(self.header() + self.render()) + "\n"
