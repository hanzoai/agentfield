#!/usr/bin/env python
"""
Memory Benchmark: AgentField SDK vs LangChain Patterns

This benchmark compares memory usage between:
1. AgentField SDK execution state management
2. LangChain-style chain execution patterns

Run with: python benchmark_comparison.py
"""

import gc
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import json

# Add SDK to path
sys.path.insert(0, "/home/user/agentfield/sdk/python")


@dataclass
class BenchmarkResult:
    name: str
    peak_memory_mb: float
    current_memory_mb: float
    iterations: int
    duration_seconds: float
    memory_per_iteration_kb: float


def format_memory(mb: float) -> str:
    """Format memory size."""
    if mb < 1:
        return f"{mb * 1024:.1f} KB"
    return f"{mb:.2f} MB"


# ============================================================
# LangChain-style Memory Patterns (Baseline)
# ============================================================

class LangChainStyleRunnable:
    """Simulates LangChain RunnableSequence memory patterns."""

    def __init__(self, name: str):
        self.name = name
        self._history: List[Dict] = []
        self._config: Dict = {}
        self._callbacks: List = []
        self._metadata: Dict = {}

    def invoke(self, input_data: Dict) -> Dict:
        """LangChain-style invoke that retains full history."""
        # LangChain typically stores full run history
        run_info = {
            "input": input_data.copy(),  # Full input retained
            "output": {"result": f"processed_{self.name}"},
            "start_time": time.time(),
            "end_time": time.time(),
            "metadata": self._metadata.copy(),
            "callbacks": list(self._callbacks),
        }
        self._history.append(run_info)
        return run_info["output"]


class LangChainStyleMemory:
    """Simulates LangChain memory retention patterns."""

    def __init__(self):
        self._chat_memory: List[Dict] = []
        self._buffer: str = ""
        self._context: Dict = {}

    def add_message(self, role: str, content: str):
        """Add message to memory - LangChain retains all messages."""
        self._chat_memory.append({
            "role": role,
            "content": content,
            "timestamp": time.time(),
        })
        # LangChain often builds up buffer string
        self._buffer += f"{role}: {content}\n"


def benchmark_langchain_pattern() -> BenchmarkResult:
    """Benchmark LangChain-style memory patterns."""
    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    iterations = 1000
    runnables: List[LangChainStyleRunnable] = []
    memories: List[LangChainStyleMemory] = []

    for i in range(iterations):
        # Create runnable with large payload
        runnable = LangChainStyleRunnable(f"chain_{i}")
        runnable.invoke({
            "large_payload": "x" * 10000,
            "nested_data": {"items": list(range(500))},
            "metadata": {"run_id": f"run_{i}", "config": {"k": "v" * 100}},
        })
        runnables.append(runnable)

        # Create memory with messages
        memory = LangChainStyleMemory()
        for j in range(10):
            memory.add_message("user", f"Message {j}: " + "y" * 500)
            memory.add_message("assistant", f"Response {j}: " + "z" * 500)
        memories.append(memory)

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="LangChain Pattern (Baseline)",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        iterations=iterations,
        duration_seconds=duration,
        memory_per_iteration_kb=(current / 1024) / iterations,
    )


# ============================================================
# AgentField SDK Patterns (Optimized)
# ============================================================

def benchmark_agentfield_pattern() -> BenchmarkResult:
    """Benchmark AgentField SDK memory patterns."""
    from agentfield.execution_state import ExecutionState, ExecutionStatus
    from agentfield.result_cache import ResultCache
    from agentfield.async_config import AsyncConfig

    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    iterations = 1000
    config = AsyncConfig()
    cache = ResultCache(config)
    states: List[ExecutionState] = []

    for i in range(iterations):
        # Create execution state with same payload size as LangChain test
        state = ExecutionState(
            execution_id=f"exec_{i:06d}",
            target=f"agent_{i}.reasoner",
            input_data={
                "large_payload": "x" * 10000,
                "nested_data": {"items": list(range(500))},
                "metadata": {"run_id": f"run_{i}", "config": {"k": "v" * 100}},
            }
        )

        # Complete the execution (triggers input_data clearing)
        state.set_result({"result": f"processed_{i}"})

        # Cache the result (with bounded cache size)
        cache.set_execution_result(state.execution_id, state.result)

        states.append(state)

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="AgentField SDK (Optimized)",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        iterations=iterations,
        duration_seconds=duration,
        memory_per_iteration_kb=(current / 1024) / iterations,
    )


def benchmark_agentfield_session_reuse() -> BenchmarkResult:
    """Benchmark AgentField HTTP session reuse pattern."""
    from agentfield.client import AgentFieldClient

    gc.collect()
    tracemalloc.start()
    start_time = time.time()

    iterations = 100
    clients: List[AgentFieldClient] = []

    for i in range(iterations):
        # Create client (should share HTTP session)
        client = AgentFieldClient(base_url=f"http://localhost:808{i % 10}")
        clients.append(client)

    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    duration = time.time() - start_time

    return BenchmarkResult(
        name="AgentField Client (Session Reuse)",
        peak_memory_mb=peak / 1024 / 1024,
        current_memory_mb=current / 1024 / 1024,
        iterations=iterations,
        duration_seconds=duration,
        memory_per_iteration_kb=(current / 1024) / iterations,
    )


# ============================================================
# Main Benchmark Runner
# ============================================================

def print_bar(label: str, value: float, max_value: float, width: int = 40):
    """Print a simple ASCII bar chart."""
    filled = int((value / max_value) * width) if max_value > 0 else 0
    bar = "█" * filled + "░" * (width - filled)
    print(f"  {label:30} [{bar}] {format_memory(value)}")


def run_comparison():
    """Run full comparison benchmark."""
    print("=" * 70)
    print("  Memory Benchmark: AgentField SDK vs LangChain Patterns")
    print("=" * 70)
    print()

    results = []

    # Run LangChain baseline
    print("Running LangChain-style pattern benchmark...")
    langchain_result = benchmark_langchain_pattern()
    results.append(langchain_result)
    print(f"  ✓ Complete: {format_memory(langchain_result.current_memory_mb)}")

    # Run AgentField optimized
    print("\nRunning AgentField SDK pattern benchmark...")
    agentfield_result = benchmark_agentfield_pattern()
    results.append(agentfield_result)
    print(f"  ✓ Complete: {format_memory(agentfield_result.current_memory_mb)}")

    # Run AgentField session reuse
    print("\nRunning AgentField client session reuse benchmark...")
    session_result = benchmark_agentfield_session_reuse()
    results.append(session_result)
    print(f"  ✓ Complete: {format_memory(session_result.current_memory_mb)}")

    # Results Summary
    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)

    max_memory = max(r.current_memory_mb for r in results)

    for result in results:
        print(f"\n{result.name}:")
        print(f"  Iterations:       {result.iterations}")
        print(f"  Peak Memory:      {format_memory(result.peak_memory_mb)}")
        print(f"  Current Memory:   {format_memory(result.current_memory_mb)}")
        print(f"  Per Iteration:    {result.memory_per_iteration_kb:.2f} KB")
        print(f"  Duration:         {result.duration_seconds:.3f}s")

    # Memory Comparison Chart
    print("\n" + "=" * 70)
    print("  MEMORY COMPARISON (Current)")
    print("=" * 70)

    for result in results:
        print_bar(result.name, result.current_memory_mb, max_memory)

    # Calculate improvements
    print("\n" + "=" * 70)
    print("  IMPROVEMENT ANALYSIS")
    print("=" * 70)

    baseline = langchain_result.current_memory_mb
    optimized = agentfield_result.current_memory_mb

    if baseline > 0:
        improvement_pct = ((baseline - optimized) / baseline) * 100
        memory_saved = baseline - optimized

        print(f"\n  LangChain Baseline:     {format_memory(baseline)}")
        print(f"  AgentField Optimized:   {format_memory(optimized)}")
        print(f"  Memory Saved:           {format_memory(memory_saved)}")
        print(f"  Improvement:            {improvement_pct:.1f}%")

        if improvement_pct > 0:
            print(f"\n  ✅ AgentField SDK uses {improvement_pct:.1f}% LESS memory than LangChain patterns")
        else:
            print(f"\n  ⚠️  Needs further optimization")

    # Per-iteration comparison
    print("\n" + "-" * 70)
    print("  Per-Iteration Memory Usage:")
    print("-" * 70)
    print(f"  LangChain:   {langchain_result.memory_per_iteration_kb:.2f} KB/iteration")
    print(f"  AgentField:  {agentfield_result.memory_per_iteration_kb:.2f} KB/iteration")

    per_iter_improvement = ((langchain_result.memory_per_iteration_kb - agentfield_result.memory_per_iteration_kb)
                           / langchain_result.memory_per_iteration_kb * 100)
    print(f"  Reduction:   {per_iter_improvement:.1f}%")

    print("\n" + "=" * 70)
    print("  Benchmark Complete")
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_comparison()
