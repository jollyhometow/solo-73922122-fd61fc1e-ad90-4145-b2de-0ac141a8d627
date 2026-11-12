"""Startup configuration.

Everything the backup feature may talk to is fixed at process start time via
environment variables -- the browser UI cannot introduce arbitrary servers,
zone names or keys.

BACKUP_TARGETS is a newline- or comma-separated list of entries:

    id|label|host|port|zone|key_name|key_secret_b64

The shared demo key can also be supplied through BACKUP_TSIG_KEY_NAME /
BACKUP_TSIG_KEY_SECRET (base64) so entries may omit the last two fields.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

import dns.name
import dns.tsig

DEFAULT_ZONE = "backup.test."
DEFAULT_KEY_NAME = "backup-key.backup.test."
# 32-byte demo secret (base64).  Overridable for real deployments.
DEFAULT_KEY_SECRET_B64 = "ZGVtby10c2lnLXNlY3JldC0zMmJ5dGVzLWxvbmchISE="


@dataclass(frozen=True)
class Target:
    target_id: str
    label: str
    host: str
    port: int
    zone: str
    key_name: str
    key_secret_b64: str

    def build_key(self) -> dns.tsig.Key:
        secret = base64.b64decode(self.key_secret_b64)
        return dns.tsig.Key(
            dns.name.from_text(self.key_name),
            secret,
            dns.tsig.HMAC_SHA256,
        )


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _default_targets() -> list[Target]:
    key_name = _env("BACKUP_TSIG_KEY_NAME", DEFAULT_KEY_NAME)
    secret = _env("BACKUP_TSIG_KEY_SECRET", DEFAULT_KEY_SECRET_B64)
    zone = _env("BACKUP_ZONE", DEFAULT_ZONE)
    host = _env("BACKUP_SERVER_HOST", "auth-dns")
    # id, label, port, scenario description
    ports = [
        ("multi", "多报文完整传输（正常）", 5301),
        ("badsig", "末报文签名损坏", 5302),
        ("truncated", "传输中断流", 5303),
        ("stale", "旧版本延迟完成", 5304),
        ("timeout", "服务器超时不响应", 5305),
    ]
    return [
        Target(
            target_id=tid,
            label=label,
            host=host,
            port=port,
            zone=zone,
            key_name=key_name,
            key_secret_b64=secret,
        )
        for tid, label, port in ports
    ]


def load_targets() -> list[Target]:
    raw = os.environ.get("BACKUP_TARGETS", "").strip()
    if not raw:
        return _default_targets()
    targets: list[Target] = []
    entries = [e.strip() for chunk in raw.splitlines() for e in chunk.split(",")]
    for entry in entries:
        if not entry:
            continue
        parts = [p.strip() for p in entry.split("|")]
        if len(parts) not in (5, 7):
            raise ValueError(
                "BACKUP_TARGETS 条目格式应为 id|label|host|port|zone"
                "[|key_name|key_secret_b64]"
            )
        target_id, label, host, port_text, zone = parts[:5]
        key_name = parts[5] if len(parts) == 7 else _env(
            "BACKUP_TSIG_KEY_NAME", DEFAULT_KEY_NAME
        )
        secret = parts[6] if len(parts) == 7 else _env(
            "BACKUP_TSIG_KEY_SECRET", DEFAULT_KEY_SECRET_B64
        )
        targets.append(
            Target(
                target_id=target_id,
                label=label,
                host=host,
                port=int(port_text),
                zone=zone if zone.endswith(".") else zone + ".",
                key_name=key_name,
                key_secret_b64=secret,
            )
        )
    return targets


def db_url() -> str:
    return os.environ.get("BACKUP_DB", "/data/backup.db")


def files_dir() -> str:
    return os.environ.get("BACKUP_FILES_DIR", "/data/zones")
