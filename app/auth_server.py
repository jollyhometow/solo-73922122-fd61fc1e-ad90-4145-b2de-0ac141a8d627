"""Local authoritative DNS source for demos and integration tests.

A tiny TCP-only DNS server that answers TSIG-signed AXFR requests.  Every
listening port corresponds to one failure scenario:

* 5301 multi      -- a healthy zone split across several TCP messages, all
                     correctly TSIG-signed (RFC 8945 multi-message MAC chain);
* 5302 badsig     -- identical traffic but the HMAC of the final message is
                     corrupted after signing;
* 5303 truncated  -- the server closes the TCP connection after the first
                     message so the closing SOA never arrives;
* 5304 stale      -- a complete, correctly signed transfer of an *older*
                     serial, with an artificial delay before it completes;
* 5305 timeout    -- accepts the connection and request but never replies,
                     exercising the client's 5 second overall deadline.

Signing uses dns.tsig directly so the happy path interoperates with
dnspython's RFC 8945 validation (and vice versa for the request check).
"""

from __future__ import annotations

import argparse
import base64
import socket
import socketserver
import threading
import time

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig

SCENARIOS = ("multi", "badsig", "truncated", "stale", "timeout")
DEFAULT_SCENARIO_PORTS = {
    "multi": 5301,
    "badsig": 5302,
    "truncated": 5303,
    "stale": 5304,
    "timeout": 5305,
}


def build_zone(origin_text: str, serial: int) -> list[tuple[str, int, str, str]]:
    """Return a zone large enough to force multiple AXFR messages."""
    origin = dns.name.from_text(origin_text)
    rrs: list[tuple[str, int, str, str]] = [
        (origin_text, 3600, "SOA",
         f"ns1.{origin_text} admin.{origin_text} {serial} 7200 3600 1209600 3600"),
        (origin_text, 3600, "NS", f"ns1.{origin_text}"),
        (origin_text, 3600, "NS", f"ns2.{origin_text}"),
        ("ns1." + origin_text, 3600, "A", "10.0.0.11"),
        ("ns2." + origin_text, 3600, "A", "10.0.0.12"),
    ]
    # 60 A records -> with message size limits the transfer spans 3+ messages.
    for i in range(1, 61):
        rrs.append(
            (f"host{i:02d}.{origin_text}", 300, "A", f"10.1.{i // 256}.{i % 256}")
        )
    rrs.append(
        (origin_text, 3600, "SOA",
         f"ns1.{origin_text} admin.{origin_text} {serial} 7200 3600 1209600 3600")
    )
    return rrs


def _make_rrset(origin: dns.name.Name, name_text: str, ttl: int,
                rdtype_text: str, rdata_text: str):
    rdtype = dns.rdatatype.from_text(rdtype_text)
    rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, rdata_text, origin=origin)
    rrset = dns.rrset.from_rdata(
        dns.name.from_text(name_text, origin), ttl, rdata
    )
    return rrset


def build_axfr_wires(
    origin_text: str,
    serial: int,
    query: dns.message.Message,
    key: dns.tsig.Key,
    *,
    max_wire_size: int = 600,
) -> list[bytes]:
    """Build the signed wire bytes of the AXFR response sequence.

    The bytes are returned directly so callers never re-render (and thus
    never re-sign) a message: the TSIG MAC in the cached bytes is the exact
    digest the client is expected to verify.
    """
    origin = dns.name.from_text(origin_text)
    rrs = build_zone(origin_text, serial)
    query_mac = query.mac or b""

    messages: list[dns.message.Message] = []

    def new_message() -> dns.message.Message:
        msg = dns.message.make_response(query)
        msg.flags = dns.flags.QR
        msg.question = list(query.question)
        msg.origin = origin
        return msg

    current = new_message()
    for name_text, ttl, rdtype_text, rdata_text in rrs:
        rrset = _make_rrset(origin, name_text, ttl, rdtype_text, rdata_text)
        current.answer.append(rrset)
        wire_estimate = len(current.to_wire(origin=origin))
        if wire_estimate > max_wire_size and rdtype_text != "SOA":
            # Roll the last rrset into a fresh message.
            current.answer.pop()
            messages.append(current)
            current = new_message()
            current.answer.append(rrset)
    messages.append(current)

    # Sign first message against request MAC; later ones continue the
    # RFC 8945 5.3.1 digest chain.  to_wire() only writes tsig_ctx back onto
    # the message when multi=True, so the ongoing context is kept explicitly.
    wires: list[bytes] = []
    request_mac = query_mac
    tsig_ctx = None
    for index, msg in enumerate(messages):
        multi = index > 0
        msg.use_tsig(key, key.name, algorithm=key.algorithm)
        msg.request_mac = request_mac
        wire = msg.to_wire(multi=multi, tsig_ctx=tsig_ctx, origin=origin)
        if multi:
            tsig_ctx = msg.tsig_ctx
        else:
            # dns.tsig.sign() also returns the post-MAC context for the
            # continuation message; capture it via a fresh digest start.
            tsig_ctx = dns.tsig._maybe_start_digest(
                key, msg.tsig[0].mac, True
            )
        request_mac = msg.tsig[0].mac
        wires.append(wire)
    return wires


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class AxfrHandler(socketserver.BaseRequestHandler):
    server: "ScenarioServer"

    def _read_exact(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining:
            chunk = self.request.recv(remaining)
            if not chunk:
                raise ConnectionError("client closed connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def handle(self) -> None:
        try:
            length_raw = self._read_exact(2)
            (length,) = int.from_bytes(length_raw, "big"),
            request_wire = self._read_exact(length)
            request = dns.message.from_wire(
                request_wire, keyring=self.server.key, request_mac=b""
            )
        except Exception:
            # Unsigned or badly signed queries are refused.
            self._send_refusal()
            return

        if not request.had_tsig:
            self._send_refusal()
            return
        question = request.question[0]
        if question.rdtype != dns.rdatatype.AXFR:
            self._send_refusal()
            return

        scenario = self.server.scenario
        if scenario == "timeout":
            # Hold the connection open without sending anything; the client's
            # 5 second deadline must fire.
            time.sleep(15)
            return

        serial = self.server.stale_serial if scenario == "stale" else self.server.serial
        wires = build_axfr_wires(
            self.server.zone, serial, request, self.server.key
        )

        if scenario == "stale":
            time.sleep(self.server.delay)

        if scenario == "truncated":
            # Only the first message, then a hard close: no closing SOA and
            # no final TSIG.
            self._write_wire(wires[0])
            self.request.shutdown(socket.SHUT_RDWR)
            return

        for index, wire in enumerate(wires):
            if scenario == "badsig" and index == len(wires) - 1:
                wire = self._corrupt_final_mac(wire)
            self._write_wire(wire)

    def _write_wire(self, wire: bytes) -> None:
        self.request.sendall(len(wire).to_bytes(2, "big") + wire)

    def _send_refusal(self) -> None:
        try:
            # Refuse without TSIG; client treats this as a transfer failure.
            err = dns.message.Message()
            err.set_rcode(dns.rcode.REFUSED)
            wire = err.to_wire()
            self.request.sendall(len(wire).to_bytes(2, "big") + wire)
        except OSError:
            pass

    @staticmethod
    def _corrupt_final_mac(wire: bytes) -> bytes:
        """Flip a byte inside the final message's TSIG MAC field."""
        parsed = dns.message.from_wire(wire, keyring=False)
        tsig_rrset = parsed.tsig
        if tsig_rrset is None:
            return wire
        rdata = tsig_rrset[0]
        mac = rdata.mac
        # Locate the MAC bytes in the wire and flip the first MAC octet.
        marker = mac
        pos = wire.find(marker)
        if pos < 0:
            return wire
        corrupted = bytearray(wire)
        corrupted[pos] ^= 0xFF
        return bytes(corrupted)


class ScenarioServer(_ThreadingTCPServer):
    def __init__(
        self,
        server_address,
        handler_cls,
        *,
        scenario: str,
        zone: str,
        key: dns.tsig.Key,
        serial: int,
        stale_serial: int,
        delay: float,
    ):
        super().__init__(server_address, handler_cls)
        self.scenario = scenario
        self.zone = zone
        self.key = key
        self.serial = serial
        self.stale_serial = stale_serial
        self.delay = delay


def make_key(key_name: str, secret_b64: str) -> dns.tsig.Key:
    return dns.tsig.Key(
        dns.name.from_text(key_name),
        base64.b64decode(secret_b64),
        dns.tsig.HMAC_SHA256,
    )


def serve(
    host: str,
    ports: dict[str, int],
    zone: str,
    key: dns.tsig.Key,
    serial: int,
    stale_serial: int,
    delay: float,
) -> list[ScenarioServer]:
    servers: list[ScenarioServer] = []
    threads: list[threading.Thread] = []
    for scenario, port in ports.items():
        server = ScenarioServer(
            (host, port),
            AxfrHandler,
            scenario=scenario,
            zone=zone,
            key=key,
            serial=serial,
            stale_serial=stale_serial,
            delay=delay,
        )
        thread = threading.Thread(
            target=server.serve_forever, name=f"dns-{scenario}", daemon=True
        )
        thread.start()
        servers.append(server)
        threads.append(thread)
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo authoritative AXFR source")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port-base",
        type=int,
        default=5300,
        help="scenario ports are base+1..+5 (default: 5300 -> 5301..5305)",
    )
    parser.add_argument("--zone", default="backup.test.")
    parser.add_argument("--key-name", default="backup-key.backup.test.")
    parser.add_argument(
        "--key-secret",
        default="ZGVtby10c2lnLXNlY3JldC0zMmJ5dGVzLWxvbmchISE=",
        help="base64 HMAC-SHA256 secret",
    )
    parser.add_argument("--serial", type=int, default=2026111201)
    parser.add_argument("--stale-serial", type=int, default=2026111100)
    parser.add_argument("--delay", type=float, default=2.5)
    args = parser.parse_args()

    key = make_key(args.key_name, args.key_secret)
    ports = {
        scenario: args.port_base + index
        for index, scenario in enumerate(SCENARIOS, start=1)
    }
    servers = serve(
        args.host, ports, args.zone, key,
        args.serial, args.stale_serial, args.delay,
    )
    print(
        "authoritative DNS listening on "
        + ", ".join(f"{args.host}:{p} ({s})" for s, p in ports.items()),
        flush=True,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
