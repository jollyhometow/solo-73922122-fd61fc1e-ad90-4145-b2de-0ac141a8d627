"""End-to-end AXFR client tests against the local authoritative source."""

import socket
import time

import pytest

from app import axfr_client
from app.axfr_client import MAX_RECORDS, TransferError

from .conftest import SERIAL, STALE_SERIAL, ZONE


def test_multi_message_success(auth_servers, tsig_key):
    data = axfr_client.axfr(
        "127.0.0.1", auth_servers["multi"], ZONE, tsig_key
    )
    assert data.serial == SERIAL
    assert data.message_count >= 3  # genuinely multi-message
    assert data.record_count == 66
    # only SOA/NS/A records are present
    assert {rr[2] for rr in data.rrs} <= {"SOA", "NS", "A"}
    # leading and trailing SOA are identical
    soas = [rr for rr in data.rrs if rr[2] == "SOA"]
    assert len(soas) == 2 and soas[0] == soas[-1]
    # all names rendered absolute
    assert all(rr[0].endswith(".") for rr in data.rrs)


def test_bad_final_signature_fails_and_reports_message(auth_servers, tsig_key):
    with pytest.raises(TransferError) as excinfo:
        axfr_client.axfr("127.0.0.1", auth_servers["badsig"], ZONE, tsig_key)
    message = str(excinfo.value)
    assert "TSIG" in message and "验签失败" in message


def test_truncated_stream_fails(auth_servers, tsig_key):
    with pytest.raises(TransferError) as excinfo:
        axfr_client.axfr("127.0.0.1", auth_servers["truncated"], ZONE, tsig_key)
    assert "断流" in str(excinfo.value)


def test_timeout_enforces_five_second_budget(auth_servers, tsig_key):
    start = time.monotonic()
    with pytest.raises(TransferError) as excinfo:
        axfr_client.axfr(
            "127.0.0.1", auth_servers["timeout"], ZONE, tsig_key, timeout=5.0
        )
    elapsed = time.monotonic() - start
    assert "超时" in str(excinfo.value)
    assert 4.9 <= elapsed <= 5.6


def test_stale_transfer_completes_but_carries_old_serial(auth_servers, tsig_key):
    data = axfr_client.axfr(
        "127.0.0.1", auth_servers["stale"], ZONE, tsig_key
    )
    assert data.serial == STALE_SERIAL
    assert data.message_count >= 3


def test_connection_refused_is_transfer_error(tsig_key):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_port = sock.getsockname()[1]
    with pytest.raises(TransferError) as excinfo:
        axfr_client.axfr("127.0.0.1", unused_port, ZONE, tsig_key, timeout=2)
    assert "无法连接" in str(excinfo.value)


def test_wrong_key_fails_signature(auth_servers):
    from app.auth_server import make_key

    wrong = make_key("backup-key.backup.test.", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    with pytest.raises(TransferError):
        axfr_client.axfr("127.0.0.1", auth_servers["multi"], ZONE, wrong)


def test_record_limit_is_enforced(auth_servers, tsig_key, monkeypatch):
    monkeypatch.setattr(axfr_client, "MAX_RECORDS", 10)
    with pytest.raises(TransferError) as excinfo:
        axfr_client.axfr("127.0.0.1", auth_servers["multi"], ZONE, tsig_key)
    assert "上限 10 条" in str(excinfo.value)


def test_default_limit_is_one_thousand():
    assert MAX_RECORDS == 1000
