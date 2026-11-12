"""Shared pytest fixtures: ephemeral ports for the demo authoritative source."""

from __future__ import annotations

import socket
import time

import pytest

from app.auth_server import make_key, serve
from app.config import DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64

ZONE = "backup.test."
SERIAL = 2026111201
STALE_SERIAL = 2026111100


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def tsig_key():
    return make_key(DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64)


@pytest.fixture(scope="session")
def scenario_ports():
    names = ["multi", "badsig", "truncated", "stale", "timeout"]
    return {name: _free_port() for name in names}


@pytest.fixture(scope="session")
def auth_servers(scenario_ports, tsig_key):
    servers = serve(
        "127.0.0.1",
        scenario_ports,
        ZONE,
        tsig_key,
        SERIAL,
        STALE_SERIAL,
        delay=1.0,
    )
    time.sleep(0.3)
    yield scenario_ports
    for server in servers:
        server.shutdown()
