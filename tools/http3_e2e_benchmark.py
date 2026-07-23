#!/usr/bin/env python3
"""Loopback end-to-end benchmarks for the Causeway HTTP/3 example."""

import argparse
import asyncio
import copy
import math
import statistics
import time

from aioquic.asyncio.client import connect

from http3_interop import Http3Client, configuration, wait_for_value


def report(name: str, samples: list[int]) -> None:
    ordered = sorted(samples)
    p95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
    print(
        f"{name:<34} median={statistics.median(ordered) / 1_000:.0f} us "
        f"p95={p95 / 1_000:.0f} us n={len(ordered)}"
    )


async def exchange(host, port, config, *, early=False, collect_ticket=False):
    authority = f"{host}:{port}"
    tickets = []
    tokens = []
    started = time.perf_counter_ns()
    async with connect(
        host,
        port,
        configuration=config,
        create_protocol=Http3Client,
        session_ticket_handler=tickets.append,
        token_handler=tokens.append,
        wait_connected=not early,
    ) as protocol:
        response = await protocol.get(authority, "/early")
        handshake = await protocol.handshake
        elapsed = time.perf_counter_ns() - started
        assert response.body in (b"hello from 0-RTT\n", b"hello from 1-RTT\n")
        ticket = await wait_for_value(tickets, "benchmark session ticket") if collect_ticket else None
        token = tokens[-1] if tokens else config.token
        return elapsed, handshake, ticket, token


async def run(host: str, port: int, iterations: int, concurrency: int) -> None:
    full_samples = []
    for _ in range(iterations):
        elapsed, handshake, _, _ = await exchange(host, port, configuration())
        assert not handshake.session_resumed
        full_samples.append(elapsed)

    _, _, seed_ticket, seed_token = await exchange(
        host, port, configuration(), collect_ticket=True
    )
    resumed_samples = []
    early_tickets = []
    for _ in range(iterations):
        resumption_ticket = copy.copy(seed_ticket)
        resumption_ticket.max_early_data_size = None
        elapsed, handshake, ticket, seed_token = await exchange(
            host,
            port,
            configuration(resumption_ticket, seed_token),
            collect_ticket=True,
        )
        assert handshake.session_resumed and not handshake.early_data_accepted
        resumed_samples.append(elapsed)
        early_tickets.append(ticket)

    zero_rtt_samples = []
    for ticket in early_tickets:
        elapsed, handshake, _, seed_token = await exchange(
            host, port, configuration(ticket, seed_token), early=True
        )
        assert handshake.session_resumed and handshake.early_data_accepted
        zero_rtt_samples.append(elapsed)

    authority = f"{host}:{port}"
    async with connect(
        host,
        port,
        configuration=configuration(token=seed_token),
        create_protocol=Http3Client,
    ) as protocol:
        started = time.perf_counter_ns()
        responses = await asyncio.gather(
            *(protocol.get(authority, "/early") for _ in range(concurrency))
        )
        concurrent_elapsed = time.perf_counter_ns() - started
        assert all(response.body == b"hello from 1-RTT\n" for response in responses)

    report("full handshake + Retry + GET", full_samples)
    report("resumed handshake + GET", resumed_samples)
    report("0-RTT handshake + GET", zero_rtt_samples)
    print(
        f"{concurrency} concurrent HTTP/3 GETs".ljust(35)
        + f"total={concurrent_elapsed / 1_000:.0f} us "
        + f"per-request={concurrent_elapsed / concurrency / 1_000:.0f} us"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()
    if args.iterations <= 0 or args.concurrency <= 0:
        parser.error("iterations and concurrency must be positive")
    asyncio.run(run(args.host, args.port, args.iterations, args.concurrency))


if __name__ == "__main__":
    main()
