"""Generated secrets (WireGuard keys) kept next to the network file.

network.yaml -> network.secrets.json. Keys are created once and reused, so
regenerating config never changes a working tunnel. Keep this file private.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

# ----------------------------------------------------------- X25519 (RFC 7748)
_P = 2 ** 255 - 19
_A24 = 121665


def _x25519(k: bytes, u: bytes) -> bytes:
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(kb, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def wg_public_key(private_b64: str) -> str:
    return base64.b64encode(_x25519(base64.b64decode(private_b64), (9).to_bytes(32, "little"))).decode()


def wg_private_key() -> str:
    k = bytearray(os.urandom(32))
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    return base64.b64encode(bytes(k)).decode()


# -------------------------------------------------------------------- store

class Secrets:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self.data: dict[str, str] = {}
        if self.path and self.path.exists():
            self.data = json.loads(self.path.read_text())

    @classmethod
    def for_network(cls, network_file: str | Path) -> "Secrets":
        p = Path(network_file)
        return cls(p.with_name(p.stem + ".secrets.json"))

    @property
    def persistent(self) -> bool:
        return self.path is not None

    def wg_key(self, ident: str) -> str:
        """Private key for ident, created on first use."""
        if ident not in self.data:
            self.data[ident] = wg_private_key()
            self._save()
        return self.data[ident]

    def _save(self) -> None:
        if not self.path:
            return
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
