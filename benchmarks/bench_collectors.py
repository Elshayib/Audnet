#!/usr/bin/env python3
"""Benchmark: sync (ThreadPool) vs async (asyncio) collection throughput.

This script simulates collection of N devices using both the sync and async
collectors, measuring wall-clock time and memory usage. Since we can't connect
to real devices, it uses mocked SSH responses.

Run with: uv run python benchmarks/bench_collectors.py

Results are printed to stdout and written to benchmarks/results.json.
"""

import asyncio
import json
import time
import tracemalloc
from pathlib import Path
from unittest.mock import patch, MagicMock

from pydantic import SecretStr

from net_audit.collector import collect_all as sync_collect_all
from net_audit.collector_async import collect_all_async
from net_audit.models import Device

# Simulated device counts to benchmark
DEVICE_COUNTS = [4, 8, 16, 32]

# Mock SSH response (3 commands per device)
MOCK_OUTPUTS = [
    "Interface  IP-Address  Status  Protocol\nGi0/0      10.0.0.1    up      up",
    "Cisco IOS Software, Version 15.2",
    "hostname test-device\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0",
]

BENCHMARK_DIR = Path(__file__).parent
RESULTS_FILE = BENCHMARK_DIR / "results.json"


def make_devices(count: int) -> list[Device]:
    """Create N mock devices."""
    return [
        Device(
            name=f"device-{i:04d}",
            host=f"10.0.0.{i % 256}",
            username="admin",
            password=SecretStr("mock-password"),
            device_type="cisco_ios",
        )
        for i in range(count)
    ]


def mock_send_command(cmd: str) -> str:
    """Return mock output based on command index."""
    idx = min(len(MOCK_OUTPUTS) - 1, hash(cmd) % len(MOCK_OUTPUTS))
    return MOCK_OUTPUTS[idx]


def run_sync_benchmark(devices: list[Device]) -> dict:
    """Run sync collector benchmark. Returns timing + memory stats."""
    mock_conn = MagicMock()
    mock_conn.send_command = mock_send_command
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)

    tracemalloc.start()
    start = time.perf_counter()

    with patch("net_audit.collector.ConnectHandler", return_value=mock_conn):
        results = sync_collect_all(devices, max_workers=min(len(devices), 8))

    elapsed = time.perf_counter() - start
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "collector": "sync (ThreadPool)",
        "devices": len(devices),
        "elapsed_s": round(elapsed, 4),
        "peak_mem_kb": round(peak_mem / 1024, 1),
        "results_count": len(results),
    }


async def run_async_benchmark(devices: list[Device]) -> dict:
    """Run async collector benchmark. Returns timing + memory stats."""
    tracemalloc.start()
    start = time.perf_counter()

    with patch("net_audit.collector_async.asyncssh") as mock_ssh:
        mock_conn = MagicMock()
        mock_conn.run = MagicMock(return_value=MagicMock(stdout=MOCK_OUTPUTS[0]))
        mock_conn.__aenter__ = MagicMock(return_value=mock_conn)
        mock_conn.__aexit__ = MagicMock(return_value=False)
        mock_ssh.connect = MagicMock(return_value=mock_conn)
        # Make async context manager work
        mock_cm = MagicMock()
        mock_cm.__aenter__ = MagicMock(return_value=mock_conn)
        mock_cm.__aexit__ = MagicMock(return_value=False)
        mock_ssh.connect.return_value = mock_cm

        results = await collect_all_async(devices, max_workers=min(len(devices), 50))

    elapsed = time.perf_counter() - start
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "collector": "async (asyncio)",
        "devices": len(devices),
        "elapsed_s": round(elapsed, 4),
        "peak_mem_kb": round(peak_mem / 1024, 1),
        "results_count": len(results),
    }


def main() -> None:
    """Run all benchmarks and print results."""
    all_results: list[dict] = []

    print("=" * 64)
    print("Collector Benchmark: Sync (ThreadPool) vs Async (asyncio)")
    print("=" * 64)

    for count in DEVICE_COUNTS:
        devices = make_devices(count)
        print(f"\n--- {count} devices ---")

        # Sync benchmark
        sync_result = run_sync_benchmark(devices)
        all_results.append(sync_result)
        print(
            f"  Sync  ({count:>3}d): {sync_result['elapsed_s']:.4f}s  "
            f"peak_mem={sync_result['peak_mem_kb']:.0f}KB  "
            f"results={sync_result['results_count']}"
        )

        # Async benchmark
        async_result = asyncio.run(run_async_benchmark(devices))
        all_results.append(async_result)
        print(
            f"  Async ({count:>3}d): {async_result['elapsed_s']:.4f}s  "
            f"peak_mem={async_result['peak_mem_kb']:.0f}KB  "
            f"results={async_result['results_count']}"
        )

        # Speedup
        speedup = sync_result["elapsed_s"] / max(async_result["elapsed_s"], 0.0001)
        print(f"  Speedup: {speedup:.2f}x")

    # Write results
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(json.dumps(all_results, indent=2))
    print(f"\nResults written to {RESULTS_FILE}")

    # Summary
    print("\n" + "=" * 64)
    print("Summary")
    print("=" * 64)
    print(f"{'Devices':>8} | {'Sync (s)':>10} | {'Async (s)':>10} | {'Speedup':>8}")
    print("-" * 48)
    for i in range(0, len(all_results), 2):
        sync_r = all_results[i]
        async_r = all_results[i + 1]
        speedup = sync_r["elapsed_s"] / max(async_r["elapsed_s"], 0.0001)
        print(
            f"{sync_r['devices']:>8} | "
            f"{sync_r['elapsed_s']:>10.4f} | "
            f"{async_r['elapsed_s']:>10.4f} | "
            f"{speedup:>7.2f}x"
        )


if __name__ == "__main__":
    main()
