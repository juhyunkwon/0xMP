"""3. Staged load test: concurrent connections 10 -> 100 -> 500 -> 1000.

Each stage starts a fresh throwaway server, provisions that many accounts,
connects all clients (connection ramp), then has every client send a fixed
number of messages to its own conversation (fan-out is measured separately
by tools/load_test.py, so this isolates connection/send scaling).

Reports per stage: connected/attempted, send errors and error rate,
elapsed, throughput (msg/s), latency mean/p50/p95/p99/max, and the harness
process CPU% and RSS (server and clients share one process here, so treat
CPU/RSS as a combined local baseline, not server-only production figures).

Usage:
    python tools/staged_load.py
    python tools/staged_load.py --stages 10,100 --messages 5
Results are preserved as JSON + CSV under reports/ (--out-dir).
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import datetime
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.client import OxmpClient  # noqa: E402
from server.provision import create_account  # noqa: E402
from server.testing import running_server  # noqa: E402


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round((p / 100) * (len(ordered) - 1))))]


async def run_stage(count: int, messages: int, connect_batch: int) -> dict:
    proc = psutil.Process()
    proc.cpu_percent()  # prime the CPU sampler
    rss_before = proc.memory_info().rss
    latencies: list[float] = []
    errors: list[str] = []
    clients: list[OxmpClient] = []

    async with running_server() as env:
        started = time.perf_counter()
        creds = [create_account(env.store, env.tokens, f"stage-{i}")
                 for i in range(count)]
        provision_s = time.perf_counter() - started

        semaphore = asyncio.Semaphore(connect_batch)

        async def connect_one(cred):
            async with semaphore:
                client = OxmpClient(env.url, cred)
                try:
                    await asyncio.wait_for(client.connect(), timeout=60)
                    return client
                except Exception as exc:  # noqa: BLE001 - counted as error rate
                    errors.append(f"connect: {type(exc).__name__}: {exc}")
                    return None

        started = time.perf_counter()
        connected = await asyncio.gather(*[connect_one(c) for c in creds])
        clients = [c for c in connected if c is not None]
        connect_s = time.perf_counter() - started
        rss_connected = proc.memory_info().rss

        conversations = {c.creds.device_id: uuid.uuid4().bytes for c in clients}

        async def send_all(client: OxmpClient):
            conv = conversations[client.creds.device_id]
            for i in range(messages):
                begin = time.perf_counter()
                try:
                    await client.send_text(conv, f"staged-{i}")
                    latencies.append((time.perf_counter() - begin) * 1000)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"send: {type(exc).__name__}: {exc}")

        started = time.perf_counter()
        await asyncio.gather(*[send_all(c) for c in clients])
        send_s = time.perf_counter() - started
        rss_after = proc.memory_info().rss
        cpu_percent = proc.cpu_percent()

        for client in clients:
            try:
                await client.close()
            except Exception:  # noqa: BLE001,S110
                pass

    sent = len(latencies)
    attempted = count * messages
    return {
        "connections_target": count,
        "connections_ok": len(clients),
        "provision_s": round(provision_s, 2),
        "connect_s": round(connect_s, 2),
        "send_s": round(send_s, 2),
        "messages_attempted": attempted,
        "messages_sent": sent,
        "throughput_msg_s": round(sent / send_s, 1) if send_s else 0,
        "latency_ms_mean": round(statistics.mean(latencies), 2) if latencies else 0,
        "latency_ms_p50": round(pct(latencies, 50), 2),
        "latency_ms_p95": round(pct(latencies, 95), 2),
        "latency_ms_p99": round(pct(latencies, 99), 2),
        "latency_ms_max": round(max(latencies), 2) if latencies else 0,
        "errors": len(errors),
        "error_rate": round(len(errors) / max(attempted, 1), 4),
        "error_samples": errors[:5],
        "cpu_percent_harness": cpu_percent,
        "rss_mb_start": round(rss_before / 1e6, 1),
        "rss_mb_connected": round(rss_connected / 1e6, 1),
        "rss_mb_after_send": round(rss_after / 1e6, 1),
        "rss_mb_per_1000_conn": round((rss_connected - rss_before) / 1e6
                                      / max(len(clients), 1) * 1000, 1),
    }


async def amain(args) -> list[dict]:
    stages = [int(x) for x in args.stages.split(",") if x.strip()]
    results = []
    for count in stages:
        print(f"--- stage: {count} connections x {args.messages} messages ---",
              flush=True)
        result = await run_stage(count, args.messages, args.connect_batch)
        results.append(result)
        print(f"connected {result['connections_ok']}/{count}  "
              f"throughput {result['throughput_msg_s']} msg/s  "
              f"p95 {result['latency_ms_p95']} ms  p99 {result['latency_ms_p99']} ms  "
              f"errors {result['errors']} ({result['error_rate']:.2%})  "
              f"RSS {result['rss_mb_connected']}->{result['rss_mb_after_send']} MB  "
              f"CPU {result['cpu_percent_harness']}%", flush=True)
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stages", default="10,100,500,1000")
    parser.add_argument("--messages", type=int, default=3)
    parser.add_argument("--connect-batch", type=int, default=100)
    parser.add_argument("--out-dir", default="reports")
    args = parser.parse_args()

    results = asyncio.run(amain(args))
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"generated_at": datetime.datetime.now().isoformat(),
               "tool": "tools/staged_load.py", "stages": results}
    (out_dir / f"staged_load_{stamp}.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    with (out_dir / f"staged_load_{stamp}.csv").open(
            "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=[k for k in results[0] if k != "error_samples"])
        writer.writeheader()
        for row in results:
            writer.writerow({k: v for k, v in row.items() if k != "error_samples"})
    print(f"preserved: {out_dir}/staged_load_{stamp}.json (+ .csv)")


if __name__ == "__main__":
    main()
