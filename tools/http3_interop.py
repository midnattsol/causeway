#!/usr/bin/env python3
"""External HTTP/3 interoperability checks using aioquic.

Run the Causeway HTTP/3 example first, then execute this script in an
environment containing aioquic. It validates Retry, NEW_TOKEN, TLS resumption,
accepted and replay-rejected 0-RTT, HTTP/3 server push, and WebTransport
draft-16 bidirectional streams.
"""

import argparse
import asyncio
import copy
import ssl
from dataclasses import dataclass, field

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import (
    DataReceived,
    HeadersReceived,
    PushPromiseReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived, StreamReset


@dataclass
class Response:
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Draft16H3Connection(H3Connection):
    """aioquic framing with draft-ietf-webtrans-http3-16 SETTINGS."""

    def __init__(self, quic):
        super().__init__(quic, enable_webtransport=True)

    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings.pop(Setting.ENABLE_WEBTRANSPORT, None)
        settings[0x2C7CF000] = 1
        settings[0x2B64] = 4
        settings[0x2B65] = 4
        settings[0x2B61] = 1024
        return settings


class Http3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        serialize_transport_parameters = self._quic._serialize_transport_parameters
        self._quic._serialize_transport_parameters = lambda: (
            serialize_transport_parameters() + encode_uint_var(0x1D) + encode_uint_var(0)
        )
        self.http = None
        self.handshake = asyncio.get_running_loop().create_future()
        self.responses: dict[int, Response] = {}
        self.waiters: dict[int, asyncio.Future[Response]] = {}
        self.push_promises: dict[int, PushPromiseReceived] = {}
        self.pushes: dict[int, Response] = {}
        self.finished_pushes: set[int] = set()
        self.push_waiter = asyncio.get_running_loop().create_future()
        self.header_waiters: dict[int, asyncio.Future[list[tuple[bytes, bytes]]]] = {}
        self.webtransport_waiter = None
        self.webtransport_stream_id = None
        self.webtransport_data = bytearray()

    async def get(self, authority: str, path: str) -> Response:
        if self.http is None:
            self.http = H3Connection(self._quic)
        stream_id = self._quic.get_next_available_stream_id()
        waiter = asyncio.get_running_loop().create_future()
        self.waiters[stream_id] = waiter
        self.responses[stream_id] = Response()
        self.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode("ascii")),
                (b":path", path.encode("ascii")),
                (b"user-agent", b"causeway-aioquic-interop"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(waiter, timeout=10)

    async def first_push(self) -> tuple[PushPromiseReceived, Response]:
        push_id = await asyncio.wait_for(self.push_waiter, timeout=10)
        return self.push_promises[push_id], self.pushes[push_id]

    def complete_push(self, push_id: int) -> None:
        if (
            push_id in self.push_promises
            and push_id in self.finished_pushes
            and not self.push_waiter.done()
        ):
            self.push_waiter.set_result(push_id)

    async def webtransport_echo(self, authority: str) -> bytes:
        if self.http is None:
            self.http = Draft16H3Connection(self._quic)
        session_id = self._quic.get_next_available_stream_id()
        headers_waiter = asyncio.get_running_loop().create_future()
        self.header_waiters[session_id] = headers_waiter
        self.responses[session_id] = Response()
        self.http.send_headers(
            stream_id=session_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", authority.encode("ascii")),
                (b":path", b"/webtransport"),
                (b":protocol", b"webtransport-h3"),
            ],
            end_stream=False,
        )
        self.transmit()
        headers = await asyncio.wait_for(headers_waiter, timeout=10)
        require(dict(headers).get(b":status") == b"200", "WebTransport CONNECT failed")

        stream_id = self.http.create_webtransport_stream(session_id, is_unidirectional=False)
        self.webtransport_stream_id = stream_id
        self.webtransport_waiter = asyncio.get_running_loop().create_future()
        self._quic.send_stream_data(stream_id, b"ping", end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self.webtransport_waiter, timeout=10)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted) and not self.handshake.done():
            self.handshake.set_result(event)
        elif isinstance(event, ConnectionTerminated):
            error = RuntimeError(
                f"connection terminated: code={event.error_code} reason={event.reason_phrase!r}"
            )
            if not self.handshake.done():
                self.handshake.set_exception(error)
            for waiter in self.waiters.values():
                if not waiter.done():
                    waiter.set_exception(error)
            for waiter in self.header_waiters.values():
                if not waiter.done():
                    waiter.set_exception(error)
            if self.webtransport_waiter is not None and not self.webtransport_waiter.done():
                self.webtransport_waiter.set_exception(error)
            if not self.push_waiter.done():
                self.push_waiter.set_exception(error)

        elif isinstance(event, StreamReset):
            error = RuntimeError(
                f"stream reset: stream={event.stream_id} code={event.error_code}"
            )
            waiter = self.waiters.get(event.stream_id)
            if waiter is not None and not waiter.done():
                waiter.set_exception(error)
            header_waiter = self.header_waiters.get(event.stream_id)
            if header_waiter is not None and not header_waiter.done():
                header_waiter.set_exception(error)
            if (
                event.stream_id == self.webtransport_stream_id
                and self.webtransport_waiter is not None
                and not self.webtransport_waiter.done()
            ):
                self.webtransport_waiter.set_exception(error)

        if isinstance(event, StreamDataReceived) and event.stream_id == self.webtransport_stream_id:
            self.webtransport_data.extend(event.data)
            if event.end_stream and not self.webtransport_waiter.done():
                self.webtransport_waiter.set_result(bytes(self.webtransport_data))
            return

        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, PushPromiseReceived):
                self.push_promises[http_event.push_id] = http_event
                self.pushes.setdefault(http_event.push_id, Response())
                self.complete_push(http_event.push_id)
                continue
            if isinstance(http_event, WebTransportStreamDataReceived):
                self.webtransport_data.extend(http_event.data)
                if (
                    http_event.stream_ended
                    and self.webtransport_waiter is not None
                    and not self.webtransport_waiter.done()
                ):
                    self.webtransport_waiter.set_result(bytes(self.webtransport_data))
                continue
            if not isinstance(http_event, (HeadersReceived, DataReceived)):
                continue

            if http_event.push_id is None:
                response = self.responses.setdefault(http_event.stream_id, Response())
            else:
                response = self.pushes.setdefault(http_event.push_id, Response())
            if isinstance(http_event, HeadersReceived):
                response.headers.extend(http_event.headers)
                header_waiter = self.header_waiters.get(http_event.stream_id)
                if header_waiter is not None and not header_waiter.done():
                    header_waiter.set_result(http_event.headers)
            else:
                response.body.extend(http_event.data)

            if not http_event.stream_ended:
                continue
            if http_event.push_id is not None:
                self.finished_pushes.add(http_event.push_id)
                self.complete_push(http_event.push_id)
            else:
                waiter = self.waiters.get(http_event.stream_id)
                if waiter is not None and not waiter.done():
                    waiter.set_result(response)


def configuration(ticket=None, token: bytes = b"") -> QuicConfiguration:
    value = QuicConfiguration(
        alpn_protocols=["h3"],
        is_client=True,
        server_name="localhost",
        session_ticket=ticket,
        token=token,
        max_datagram_frame_size=1200,
    )
    value.verify_mode = ssl.CERT_NONE
    return value


async def wait_for_value(values: list, name: str):
    for _ in range(1000):
        if values:
            return values[-1]
        await asyncio.sleep(0.01)
    raise AssertionError(f"server did not issue {name}")


async def run(host: str, port: int) -> None:
    authority = f"{host}:{port}"
    tickets = []
    tokens = []

    async with connect(
        host,
        port,
        configuration=configuration(),
        create_protocol=Http3Client,
        session_ticket_handler=tickets.append,
        token_handler=tokens.append,
    ) as protocol:
        response = await protocol.get(authority, "/")
        handshake = await protocol.handshake
        promise, pushed = await protocol.first_push()
        require(not handshake.session_resumed and not handshake.early_data_accepted, "first handshake unexpectedly resumed")
        require(protocol._quic._retry_count == 1, "first handshake did not use Retry")
        require(b"hello from Causeway" in response.body, "unexpected root response")
        require(dict(promise.headers).get(b":path") == b"/assets/app.css", "unexpected push path")
        require(b"font-family" in pushed.body, "unexpected pushed response")
        ticket = await wait_for_value(tickets, "session ticket")
        token = await wait_for_value(tokens, "NEW_TOKEN")
        require(ticket.max_early_data_size is not None, "ticket does not permit early data")

    resumed_tickets = []
    resumed_tokens = []
    resumption_ticket = copy.copy(ticket)
    resumption_ticket.max_early_data_size = None
    async with connect(
        host,
        port,
        configuration=configuration(resumption_ticket, token),
        create_protocol=Http3Client,
        session_ticket_handler=resumed_tickets.append,
        token_handler=resumed_tokens.append,
    ) as protocol:
        response = await protocol.get(authority, "/early")
        handshake = await protocol.handshake
        require(handshake.session_resumed, "second handshake did not resume")
        require(not handshake.early_data_accepted, "1-RTT control connection unexpectedly sent early data")
        require(protocol._quic._retry_count == 0, "resumed handshake unexpectedly used Retry")
        require(response.body == b"hello from 1-RTT\n", "unexpected resumed response")
        early_ticket = await wait_for_value(resumed_tickets, "resumed session ticket")
        early_token = resumed_tokens[-1] if resumed_tokens else token

    async with connect(
        host,
        port,
        configuration=configuration(early_ticket, early_token),
        create_protocol=Http3Client,
        wait_connected=False,
    ) as protocol:
        response = await protocol.get(authority, "/early")
        handshake = await protocol.handshake
        require(handshake.session_resumed and handshake.early_data_accepted, "early data was not accepted")
        require(response.body == b"hello from 0-RTT\n", "unexpected early response")

    async with connect(
        host,
        port,
        configuration=configuration(early_ticket, early_token),
        create_protocol=Http3Client,
        wait_connected=False,
    ) as protocol:
        response = await protocol.get(authority, "/early")
        handshake = await protocol.handshake
        require(handshake.session_resumed and not handshake.early_data_accepted, "replayed early data was not rejected")
        require(response.body == b"hello from 1-RTT\n", "unexpected replay fallback response")

    async with connect(
        host,
        port,
        configuration=configuration(token=early_token),
        create_protocol=Http3Client,
    ) as protocol:
        echoed = await protocol.webtransport_echo(authority)
        require(protocol._quic._retry_count == 0, "token-authenticated handshake unexpectedly used Retry")
        require(echoed == b"pong", "unexpected WebTransport echo")

    print(
        "HTTP/3 interop: Retry, NEW_TOKEN, push, resumption, 0-RTT, "
        "replay fallback, WebTransport draft-16 passed"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    asyncio.run(run(args.host, args.port))


if __name__ == "__main__":
    main()
