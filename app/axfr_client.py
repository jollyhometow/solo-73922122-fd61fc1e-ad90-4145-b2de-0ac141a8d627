"""Authenticated AXFR client.

The transfer runs over TCP (RFC 5936) with a single 5 second wall-clock
deadline that covers every socket operation.  TSIG verification is performed
message-by-message with dnspython's RFC 8945 machinery, chaining the HMAC
context across the multi-message transfer:

* the first response must carry a TSIG whose MAC verifies against the
  request MAC (RFC 8945 5.3.1);
* intermediate messages may be unsigned -- the running digest context
  still covers their wire bytes;
* the final message must carry a TSIG and its MAC must verify;
* the leading and trailing SOA records must be identical, and the final
  message must be the one carrying the closing SOA.

Nothing is returned to the caller unless the whole transfer is complete and
authenticated, so a verification failure, truncated stream or timeout can
never leave behind a partial, unauthenticated zone copy.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

import dns.exception
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tsig

ALLOWED_RDTYPES = {
    dns.rdatatype.SOA,
    dns.rdatatype.NS,
    dns.rdatatype.A,
}
MAX_RECORDS = 1000
TRANSFER_TIMEOUT = 5.0


class TransferError(Exception):
    """A transfer failed.  The message is suitable for the UI failure panel."""


@dataclass(frozen=True)
class ZoneData:
    origin: str
    rrs: list[tuple[str, int, str, str]]  # (name, ttl, rdtype text, rdata text)
    serial: int
    message_count: int

    @property
    def record_count(self) -> int:
        return len(self.rrs)


def _abs_name(name: dns.name.Name, origin: dns.name.Name) -> str:
    """Return the absolute text of a name possibly relativized to *origin*."""
    if name.is_absolute():
        return name.to_text()
    if name == dns.name.empty:
        return origin.to_text()
    return dns.name.Name(list(name) + list(origin)).to_text()


def _abs_rdata_text(rdata, origin: dns.name.Name) -> str:
    """Render rdata with any relative DNS names absolutized against origin."""
    text = rdata.to_text()
    if rdata.rdtype == dns.rdatatype.SOA:
        # SOA text: "mname rname serial refresh retry expire minimum"
        parts = text.split()
        names = [
            dns.name.from_text(p, origin).to_text() for p in parts[:2]
        ]
        return " ".join(names + parts[2:])
    if rdata.rdtype == dns.rdatatype.NS:
        return dns.name.from_text(text, origin).to_text()
    return text


def _read_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise TransferError("传输超时：超过 5 秒总时限")
        sock.settimeout(timeout)
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise TransferError("传输超时：超过 5 秒总时限") from exc
        except OSError as exc:
            raise TransferError(f"连接中断：{exc}") from exc
        if not chunk:
            raise TransferError("断流：服务器在传输完成前关闭了 TCP 连接")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_message(sock: socket.socket, deadline: float) -> bytes:
    length_wire = _read_exact(sock, 2, deadline)
    (length,) = int.from_bytes(length_wire, "big"),
    if length == 0:
        raise TransferError("断流：收到长度为 0 的 DNS 报文")
    if length > 65535:  # pragma: no cover - impossible from 2-byte field
        raise TransferError("报文长度超出 DNS 消息上限")
    return _read_exact(sock, length, deadline)


def axfr(
    server: str,
    port: int,
    zone_name: str,
    key: dns.tsig.Key,
    *,
    timeout: float = TRANSFER_TIMEOUT,
) -> ZoneData:
    """Run a TSIG-authenticated AXFR and return the validated zone contents."""
    origin = dns.name.from_text(zone_name)
    # Passing the dns.tsig.Key directly pins both the key name and the
    # HMAC-SHA256 algorithm; a downgrade to another algorithm raises
    # dns.tsig.BadAlgorithm during from_wire().
    keyring = key

    query = dns.message.make_query(
        origin, dns.rdatatype.AXFR, dns.rdataclass.IN
    )
    query.use_tsig(keyring, key.name, algorithm=key.algorithm)
    request_wire = query.to_wire()
    request_mac = query.mac or b""

    deadline = time.monotonic() + timeout
    sock: socket.socket | None = None
    try:
        try:
            # Bound even the connect phase by the remaining overall budget.
            sock = socket.create_connection(
                (server, port), timeout=max(0.05, deadline - time.monotonic())
            )
        except socket.timeout as exc:
            raise TransferError("传输超时：超过 5 秒总时限") from exc
        except OSError as exc:
            raise TransferError(f"无法连接权威服务器 {server}:{port}：{exc}") from exc

        try:
            sock.sendall(len(request_wire).to_bytes(2, "big") + request_wire)
        except OSError as exc:
            raise TransferError(f"发送 AXFR 请求失败：{exc}") from exc

        records: list[tuple[str, int, str, str]] = []
        first_soa_rrset = None
        final_soa_seen = False
        tsig_ctx = None
        message_index = 0
        total_messages = 0

        while not final_soa_seen:
            wire = _read_message(sock, deadline)
            message_index += 1
            # An AXFR is always a multi-message sequence (RFC 8945 5.3.1):
            # every response is parsed in multi mode so the ongoing HMAC
            # context is retained, including after the first message.
            try:
                message = dns.message.from_wire(
                    wire,
                    keyring=keyring,
                    request_mac=request_mac,
                    xfr=True,
                    origin=origin,
                    tsig_ctx=tsig_ctx,
                    multi=True,
                    one_rr_per_rrset=True,
                )
            except dns.tsig.BadSignature as exc:
                raise TransferError(
                    f"TSIG 验签失败（第 {message_index} 个报文 HMAC-SHA256 签名不匹配）"
                ) from exc
            except dns.tsig.BadTime as exc:
                raise TransferError(
                    f"TSIG 验签失败（第 {message_index} 个报文时间戳超出 fudge 窗口）"
                ) from exc
            except dns.tsig.BadKey as exc:
                raise TransferError("TSIG 验签失败：密钥名不匹配") from exc
            except dns.tsig.BadAlgorithm as exc:
                raise TransferError("TSIG 验签失败：算法不是 HMAC-SHA256") from exc
            except dns.exception.FormError as exc:
                raise TransferError(
                    f"TSIG 验签失败（第 {message_index} 个报文缺少或带有非法 TSIG：{exc}）"
                ) from exc

            # The ongoing context must keep chaining even for unsigned
            # intermediate messages; from_wire already updated it in that case.
            tsig_ctx = message.tsig_ctx
            total_messages = message_index

            # RFC 8945 5.3.1: the first message of a signed transfer MUST be
            # signed itself. Intermediate messages may be unsigned.
            if message_index == 1 and not message.had_tsig:
                raise TransferError("首报文缺少 TSIG 签名，拒绝未认证的区域数据")

            if message.rcode() != 0:
                raise TransferError(
                    f"服务器返回错误 RCODE={message.rcode()}，传输被拒绝"
                )

            for rrset in message.answer:
                rdtype = rrset.rdtype
                if rdtype not in ALLOWED_RDTYPES:
                    raise TransferError(
                        f"区域包含不支持的记录类型 {dns.rdatatype.to_text(rdtype)}，"
                        "仅允许 SOA、NS、A"
                    )
                # In xfr mode names are relativized to the origin, so the
                # apex owner is represented by the empty relative name.
                if rdtype == dns.rdatatype.SOA and rrset.name != dns.name.empty:
                    raise TransferError("SOA 记录的属主不是区域起点")
                for rdata in rrset:
                    records.append(
                        (
                            _abs_name(rrset.name, origin),
                            rrset.ttl,
                            dns.rdatatype.to_text(rdtype),
                            _abs_rdata_text(rdata, origin),
                        )
                    )
                    if len(records) > MAX_RECORDS:
                        raise TransferError(
                            f"记录数超过上限 {MAX_RECORDS} 条，放弃本次传输"
                        )
                if rdtype == dns.rdatatype.SOA and rrset.name == dns.name.empty:
                    if first_soa_rrset is None:
                        first_soa_rrset = rrset
                    else:
                        if rrset != first_soa_rrset:
                            raise TransferError(
                                "首尾 SOA 记录不一致，区域传输不完整"
                            )
                        final_soa_seen = True
                        break

        # RFC 8945 5.3.1: the last message of a signed transfer MUST be signed.
        if not message.had_tsig:
            raise TransferError("末报文缺少 TSIG 签名，传输不完整")
        # A valid MAC on the final message proves the whole chain.
        if message.tsig is None:
            raise TransferError("末报文验签未通过，传输不完整")

        if first_soa_rrset is None or len(records) < 2:
            raise TransferError("区域内容为空或缺少 SOA，传输不完整")

        serial = int(first_soa_rrset[0].serial)
        return ZoneData(
            origin=origin.to_text(),
            rrs=records,
            serial=serial,
            message_count=total_messages,
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover - best effort cleanup
                pass
