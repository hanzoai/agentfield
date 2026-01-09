#!/usr/bin/env python
"""
Memory benchmark for Python SDK components.
Compares memory usage before/after optimizations.
"""

import gc
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Dict, Any, List

# Add SDK to path
sys.path.insert(0, "/home/user/agentfield/sdk/python")

from agentfield.async_config import AsyncConfig
from agentfield.execution_state import ExecutionState, ExecutionStatus
from agentfield.result_cache import ResultCache


@dataclass
class BenchmarkResult:
    name: str
    peak_memory_mb: float
    current_memory_mb: float
    objects_created: int
    duration_seconds: float


def benchmark_execution_state_memory() -> BenchmarkResult:
    """Test ExecutionState memory with input_data clearing."""
    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    states: List[ExecutionState] = []

    # Create 1000 execution states with large input data
    for i in range(1000):
        state = ExecutionState(
            execution_id=f"exec_{i:06d}",
            target=f"test-agent.reasoner_{i}",
            input_data={
                "large_payload": "x" * 10000,  # ~10KB per execution
                "nested": {"data": list(range(1000))},
            }
        )
        states.append(state)

    # Mark half as completed (should clear input_data)
    for i in range(500):
        states[i].set_result({"output": f"result_{i}"})

    # Mark some as failed (should clear input_data)
    for i in range(500, 700):
        states[i].set_error("Test error")

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="ExecutionState memory",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        objects_created=1000,
        duration_seconds=duration
    )


def benchmark_result_cache_memory() -> BenchmarkResult:
    """Test ResultCache memory with new defaults."""
    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    config = AsyncConfig()
    cache = ResultCache(config)

    # Add many entries to trigger LRU eviction
    for i in range(10000):
        cache.set(f"key_{i}", {"data": "x" * 1000})  # ~1KB per entry

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="ResultCache memory",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        objects_created=10000,
        duration_seconds=duration
    )


def benchmark_async_config() -> BenchmarkResult:
    """Test AsyncConfig defaults."""
    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    config = AsyncConfig()

    # Verify new optimized defaults
    results = {
        "result_cache_ttl": config.result_cache_ttl,
        "result_cache_max_size": config.result_cache_max_size,
        "cleanup_interval": config.cleanup_interval,
        "max_completed_executions": config.max_completed_executions,
        "completed_execution_retention_seconds": config.completed_execution_retention_seconds,
    }

    print("\n  Optimized AsyncConfig defaults:")
    for key, value in results.items():
        print(f"    {key}: {value}")

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="AsyncConfig verification",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        objects_created=1,
        duration_seconds=duration
    )


def run_memory_comparison():
    """Run memory benchmark and compare with expected baselines."""
    print("=" * 60)
    print("AgentField Python SDK Memory Benchmark")
    print("=" * 60)

    benchmarks = [
        benchmark_async_config,
        benchmark_execution_state_memory,
        benchmark_result_cache_memory,
    ]

    results = []
    for benchmark_fn in benchmarks:
        gc.collect()
        result = benchmark_fn()
        results.append(result)

        print(f"\n{result.name}:")
        print(f"  Peak memory:    {result.peak_memory_mb:.2f} MB")
        print(f"  Current memory: {result.current_memory_mb:.2f} MB")
        print(f"  Objects:        {result.objects_created}")
        print(f"  Duration:       {result.duration_seconds:.3f}s")

    # Summary
    print("\n" + "=" * 60)
    print("Memory Optimization Summary")
    print("=" * 60)

    # Check ExecutionState memory (should be reduced due to input_data clearing)
    exec_state_result = results[1]
    # With 1000 states at ~10KB each = ~40MB peak baseline
    # After clearing 700 states' input_data, current should be much lower than peak
    memory_reduction_pct = (1 - exec_state_result.current_memory_mb / exec_state_result.peak_memory_mb) * 100
    print(f"\nExecutionState: {exec_state_result.current_memory_mb:.2f} MB (peak: {exec_state_result.peak_memory_mb:.2f} MB)")
    print(f"  Memory reduction: {memory_reduction_pct:.1f}%")
    if memory_reduction_pct > 50:
        print("  ✅ Memory reduced due to input_data clearing after completion")
    else:
        print("  ⚠️  Memory reduction lower than expected")

    # Check ResultCache memory (should be bounded by max_size)
    cache_result = results[2]
    config = AsyncConfig()
    # With max 5000 entries at ~1KB = ~5MB max
    expected_max = (config.result_cache_max_size * 1.5) / 1024  # ~7.5 MB
    print(f"\nResultCache: {cache_result.current_memory_mb:.2f} MB")
    if cache_result.current_memory_mb < expected_max:
        print(f"  ✅ Memory bounded by max_size ({config.result_cache_max_size} entries)")
    else:
        print("  ⚠️  Memory higher than expected")

    print("\n" + "=" * 60)
    print("Benchmark Complete")
    print("=" * 60)

    return results


if __name__ == "__main__":
    run_memory_comparison()
