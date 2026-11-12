"""Protocol guards: unsupported record types and concurrent backup safety."""

import threading

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import pytest
import socketserver

from app import axfr_client
from app.axfr_client import TransferError
from app.config import DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64
from app.auth_server import make_key

from .conftest import ZONE


class _TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def test_unsupported_record_type_is_rejected(tsig_key):
    """An AAAA record in the zone must abort the whole transfer."""

    class AaaaHandler(socketserver.BaseRequestHandler):
        def handle(self):
            length = int.from_bytes(self._read(2), "big")
            request_wire = self._read(length)
            request = dns.message.from_wire(
                request_wire, keyring=tsig_key, request_mac=b""
            )
            origin = dns.name.from_text(ZONE)
            messages = []

            def make():
                msg = dns.message.make_response(request)
                msg.flags = dns.flags.QR
                msg.question = list(request.question)
                msg.origin = origin
                return msg

            first = make()
            first.answer.append(
                dns.rrset.from_text(
                    ZONE, 3600, "IN", "SOA",
                    f"ns1.{ZONE} admin.{ZONE} 1 7200 3600 1209600 3600",
                )
            )
            first.answer.append(
                dns.rrset.from_text(
                    f"v6.{ZONE}", 300, "IN", "AAAA", "2001:db8::1"
                )
            )
            last = make()
            last.answer.append(
                dns.rrset.from_text(
                    ZONE, 3600, "IN", "SOA",
                    f"ns1.{ZONE} admin.{ZONE} 1 7200 3600 1209600 3600",
                )
            )
            messages = [first, last]

            ctx, mac = None, request.mac or b""
            for index, msg in enumerate(messages):
                multi = index > 0
                msg.use_tsig(tsig_key, tsig_key.name, algorithm=tsig_key.algorithm)
                msg.request_mac = mac
                wire = msg.to_wire(multi=multi, tsig_ctx=ctx, origin=origin)
                if multi:
                    ctx = msg.tsig_ctx
                else:
                    ctx = dns.tsig._maybe_start_digest(
                        tsig_key, msg.tsig[0].mac, True
                    )
                mac = msg.tsig[0].mac
                self.request.sendall(len(wire).to_bytes(2, "big") + wire)

        def _read(self, n):
            chunks = []
            while n:
                chunk = self.request.recv(n)
                if not chunk:
                    raise ConnectionError
                chunks.append(chunk)
                n -= len(chunk)
            return b"".join(chunks)

    server = _TcpServer(("127.0.0.1", 0), AaaaHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            axfr_client.axfr("127.0.0.1", port, ZONE, tsig_key)
        except TransferError as exc:
            assert "AAAA" in str(exc) and "不支持" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("AAAA record must abort transfer")
    finally:
        server.shutdown()


def test_first_message_without_tsig_is_rejected(tsig_key):
    """A server that answers without any TSIG must be refused."""

    class UnsignedHandler(socketserver.BaseRequestHandler):
        def handle(self):
            length = int.from_bytes(self._read(2), "big")
            self._read(length)
            origin = dns.name.from_text(ZONE)
            msg = dns.message.Message()
            msg.set_rcode(0)
            msg.answer.append(
                dns.rrset.from_text(
                    ZONE, 3600, "IN", "SOA",
                    f"ns1.{ZONE} admin.{ZONE} 1 7200 3600 1209600 3600",
                )
            )
            wire = msg.to_wire(origin=origin)
            self.request.sendall(len(wire).to_bytes(2, "big") + wire)

        def _read(self, n):
            chunks = []
            while n:
                chunk = self.request.recv(n)
                if not chunk:
                    raise ConnectionError
                chunks.append(chunk)
                n -= len(chunk)
            return b"".join(chunks)

    server = _TcpServer(("127.0.0.1", 0), UnsignedHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(TransferError) as excinfo:
            axfr_client.axfr("127.0.0.1", port, ZONE, tsig_key)
        assert "TSIG" in str(excinfo.value)
    finally:
        server.shutdown()


def test_concurrent_backups_never_corrupt_stored_version(
    auth_servers, tsig_key, tmp_path
    ):
    """Many parallel transfers against the shared DB leave one coherent row."""
    from app.service import BackupService, JobRegistry
    from app.storage import Storage

    storage = Storage(tmp_path / "backup.db", tmp_path / "zones")
    service = BackupService(storage, JobRegistry())
    from app.config import Target

    target = Target(
        target_id="multi",
        label="multi",
        host="127.0.0.1",
        port=auth_servers["multi"],
        zone=ZONE,
        key_name=DEFAULT_KEY_NAME,
        key_secret_b64=DEFAULT_KEY_SECRET_B64,
    )

    jobs = []
    lock = threading.Lock()

    def worker():
        job = service.run_backup(target)
        with lock:
            jobs.append(job)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(j.state == "success" for j in jobs)
    zone = storage.get_zone(ZONE)
    # exactly one row, one file, and the file matches the row's record count
    assert zone is not None
    content = storage.read_zone_file(zone)
    data_lines = [ln for ln in content.splitlines() if "\tIN\t" in ln]
    assert len(data_lines) == zone.record_count
