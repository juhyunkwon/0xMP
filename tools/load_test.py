"""5. Performance test: concurrent clients, throughput, p95/p99 latency.

Usage:
    python tools/load_test.py --clients 10 --messages 50
    python tools/load_test.py --clients 50 --messages 100 --port-db bench.db

Starts a throwaway server (or reuses --db), has every client authenticate
and send its share of messages to one conversation, and reports wall time,
messages/sec and send-round-trip latency percentiles. Local loopback
numbers are a development baseline, not a production SLO (spec ch. 12).
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.client import OxmpClient  # noqa: E402
from server.testing import running_server  # noqa: E402


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((pct / 100) * (len(ordered) - 1))))
    return ordered[idx]


async def worker(url, creds, conv, count, latencies):
    client = OxmpClient(url, creds)
    await client.connect()
    try:
        for i in range(count):
            start = time.perf_counter()
            await client.send_text(conv, f"load-{i}")
            latencies.append((time.perf_counter() - start) * 1000)
    finally:
        await client.close()


async def main_async(args) -> None:
    async with running_server(args.db) as env:
        # Every load client uses Alice's account pool via extra accounts is
        # unnecessary here: create one sender per client slot from Bob's
        # credential set is wrong, so provision extra accounts directly.
        from server.provision import create_account
        creds = [create_account(env.store, env.tokens, f"load-{i}")
                 for i in range(args.clients)]
        conv = uuid.uuid4().bytes
        for c in creds:
            env.store.add_member(conv, c.user_id)
        latencies: list[float] = []
        start = time.perf_counter()
        await asyncio.gather(*[
            worker(env.url, c, conv, args.messages, latencies) for c in creds])
        elapsed = time.perf_counter() - start
    total = args.clients * args.messages
    print(f"clients={args.clients} messages/client={args.messages} total={total}")
    print(f"elapsed={elapsed:.2f}s throughput={total / elapsed:.1f} msg/s")
    print(f"latency ms: mean={statistics.mean(latencies):.2f} "
          f"p50={percentile(latencies, 50):.2f} "
          f"p95={percentile(latencies, 95):.2f} "
          f"p99={percentile(latencies, 99):.2f} max={max(latencies):.2f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, default=10)
    parser.add_argument("--messages", type=int, default=50)
    parser.add_argument("--db", default=None, help="reuse this DB file instead of a temp one")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
