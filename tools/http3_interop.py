#!/usr/bin/env python3
"""External HTTP/3 interoperability checks using aioquic.

Run the Causeway HTTP/3 example first, then execute this script in an
environment containing aioquic. It validates Retry, NEW_TOKEN, TLS resumption,
accepted and replay-rejected 0-RTT, and HTTP/3 server push.
"""

import argparse
import asyncio
import copy
import ssl
from dataclasses import dataclass, field

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived, PushPromiseReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


@dataclass
class Response:
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)


class Http3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.handshake = asyncio.get_running_loop().create_future()
        self.responses: dict[int, Response] = {}
        self.waiters: dict[int, asyncio.Future[Response]] = {}
        self.push_promises: dict[int, PushPromiseReceived] = {}
        self.pushes: dict[int, Response] = {}
        self.push_waiter = asyncio.get_running_loop().create_future()

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
            if not self.push_waiter.done():
                if self.push_promises:
                    self.push_waiter.set_exception(error)
                else:
                    self.push_waiter.cancel()

        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, PushPromiseReceived):
                self.push_promises[http_event.push_id] = http_event
                self.pushes.setdefault(http_event.push_id, Response())
                continue
            if not isinstance(http_event, (HeadersReceived, DataReceived)):
                continue

            if http_event.push_id is None:
                response = self.responses.setdefault(http_event.stream_id, Response())
            else:
                response = self.pushes.setdefault(http_event.push_id, Response())
            if isinstance(http_event, HeadersReceived):
                response.headers.extend(http_event.headers)
            else:
                response.body.extend(http_event.data)

            if not http_event.stream_ended:
                continue
            if http_event.push_id is not None:
                if not self.push_waiter.done():
                    self.push_waiter.set_result(http_event.push_id)
            else:
                waiter = self.waiters[http_event.stream_id]
                if not waiter.done():
                    waiter.set_result(response)


def configuration(ticket=None, token: bytes = b"") -> QuicConfiguration:
    value = QuicConfiguration(
        alpn_protocols=["h3"],
        is_client=True,
        server_name="localhost",
        session_ticket=ticket,
        token=token,
    )
    value.verify_mode = ssl.CERT_NONE
    return value


async def wait_for_value(values: list, name: str):
    for _ in range(100):
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
        assert not handshake.session_resumed and not handshake.early_data_accepted
        assert protocol._quic._retry_count == 1
        assert b"hello from Causeway" in response.body
        assert dict(promise.headers)[b":path"] == b"/assets/app.css"
        assert b"font-family" in pushed.body
        ticket = await wait_for_value(tickets, "session ticket")
        token = await wait_for_value(tokens, "NEW_TOKEN")
        assert ticket.max_early_data_size is not None

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
        assert handshake.session_resumed, "second handshake did not resume"
        assert not handshake.early_data_accepted, "1-RTT control connection unexpectedly sent early data"
        assert protocol._quic._retry_count == 0
        assert response.body == b"hello from 1-RTT\n"
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
        assert handshake.session_resumed and handshake.early_data_accepted
        assert response.body == b"hello from 0-RTT\n"

    async with connect(
        host,
        port,
        configuration=configuration(early_ticket, early_token),
        create_protocol=Http3Client,
        wait_connected=False,
    ) as protocol:
        response = await protocol.get(authority, "/early")
        handshake = await protocol.handshake
        assert handshake.session_resumed and not handshake.early_data_accepted
        assert response.body == b"hello from 1-RTT\n"

    print("HTTP/3 interop: Retry, NEW_TOKEN, push, resumption, 0-RTT, replay fallback passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    asyncio.run(run(args.host, args.port))


if __name__ == "__main__":
    main()
