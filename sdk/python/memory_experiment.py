#!/usr/bin/env python3
"""
Memory profiling experiment for AgentField SDK vs LangChain.

Run with: python memory_experiment.py
"""

import sys
import gc
import tracemalloc


def measure_import(module_name: str, description: str) -> dict:
    """Measure memory impact of importing a module."""
    # Force garbage collection and reset
    gc.collect()
    gc.collect()
    gc.collect()

    tracemalloc.start()

    try:
        __import__(module_name)
        current, peak = tracemalloc.get_traced_memory()
        return {
            "module": module_name,
            "description": description,
            "current_mb": current / 1024 / 1024,
            "peak_mb": peak / 1024 / 1024,
            "success": True,
        }
    except ImportError as e:
        return {
            "module": module_name,
            "description": description,
            "error": str(e),
            "success": False,
        }
    finally:
        tracemalloc.stop()


def run_isolated_measurement(module_name: str) -> float:
    """
    Run measurement in a subprocess for isolation.
    This gives more accurate results since modules aren't cached.
    """
    import subprocess
    import json

    code = f'''
import gc
import tracemalloc
import json

gc.collect()
tracemalloc.start()

import {module_name}

current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

print(json.dumps({{"current_mb": current / 1024 / 1024, "peak_mb": peak / 1024 / 1024}}))
'''

    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            return data["peak_mb"]
        else:
            print(f"  Error importing {module_name}: {result.stderr[:200]}")
            return -1
    except Exception as e:
        print(f"  Exception measuring {module_name}: {e}")
        return -1


def main():
    print("=" * 70)
    print("AgentField SDK Memory Profiling Experiment")
    print("=" * 70)
    print()

    # Tests to run (in isolated subprocesses for accuracy)
    tests = [
        # Baseline
        ("json", "Python stdlib baseline"),

        # Individual heavy dependencies
        ("pydantic", "Pydantic (validation)"),
        ("fastapi", "FastAPI (web framework)"),
        ("aiohttp", "aiohttp (async HTTP)"),
        ("uvicorn", "Uvicorn (ASGI server)"),

        # LLM libraries
        ("litellm", "LiteLLM (multi-provider LLM)"),
        ("openai", "OpenAI SDK"),

        # The SDK
        ("agentfield", "AgentField SDK (full)"),

        # LangChain for comparison
        ("langchain_core", "LangChain Core"),
        ("langchain", "LangChain (full)"),
    ]

    print("Running isolated memory measurements...")
    print("(Each import runs in a fresh Python process)\n")

    results = []

    for module, description in tests:
        print(f"Measuring: {module}...", end=" ", flush=True)
        peak_mb = run_isolated_measurement(module)
        if peak_mb >= 0:
            print(f"{peak_mb:.1f} MB")
            results.append((module, description, peak_mb))
        else:
            print("FAILED (not installed?)")
            results.append((module, description, None))

    print()
    print("=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print()
    print(f"{'Module':<25} {'Description':<30} {'Peak Memory':>12}")
    print("-" * 70)

    for module, description, peak_mb in results:
        if peak_mb is not None:
            print(f"{module:<25} {description:<30} {peak_mb:>10.1f} MB")
        else:
            print(f"{module:<25} {description:<30} {'N/A':>12}")

    print()

    # Calculate specific comparisons
    agentfield_mem = next((m for mod, _, m in results if mod == "agentfield" and m), None)
    langchain_mem = next((m for mod, _, m in results if mod == "langchain_core" and m), None)
    litellm_mem = next((m for mod, _, m in results if mod == "litellm" and m), None)
    fastapi_mem = next((m for mod, _, m in results if mod == "fastapi" and m), None)

    print("=" * 70)
    print("ANALYSIS")
    print("=" * 70)
    print()

    if agentfield_mem and langchain_mem:
        ratio = agentfield_mem / langchain_mem
        diff = agentfield_mem - langchain_mem
        print(f"AgentField vs LangChain Core: {ratio:.1f}x more memory ({diff:.1f} MB difference)")

    if litellm_mem and agentfield_mem:
        pct = (litellm_mem / agentfield_mem) * 100
        print(f"LiteLLM accounts for: ~{pct:.0f}% of AgentField memory ({litellm_mem:.1f} MB)")

    if fastapi_mem and agentfield_mem:
        pct = (fastapi_mem / agentfield_mem) * 100
        print(f"FastAPI accounts for: ~{pct:.0f}% of AgentField memory ({fastapi_mem:.1f} MB)")

    print()
    print("=" * 70)
    print("COMPONENT BREAKDOWN TEST")
    print("=" * 70)
    print()
    print("Testing import chain step by step...")
    print()

    # Step-by-step import chain
    chain_tests = [
        "agentfield.types",
        "agentfield.logger",
        "agentfield.async_config",
        "agentfield.execution_context",
        "agentfield.client",
        "agentfield.agent_ai",  # This imports litellm
        "agentfield.agent",     # This imports everything
        "agentfield",           # Full package
    ]

    for module in chain_tests:
        print(f"  {module}...", end=" ", flush=True)
        peak_mb = run_isolated_measurement(module)
        if peak_mb >= 0:
            print(f"{peak_mb:.1f} MB")
        else:
            print("FAILED")

    print()
    print("=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)
    print("""
Based on the measurements above, key optimization targets are likely:

1. If LiteLLM is >30MB: Make it a lazy import in agent_ai.py
2. If FastAPI is >10MB: Consider composition instead of inheritance
3. If agentfield.agent_ai alone is heavy: It's importing LiteLLM eagerly

To test lazy LiteLLM import hypothesis, compare:
  - agentfield.client (before agent_ai import)
  - agentfield.agent_ai (after litellm import)

The difference shows LiteLLM's true impact.
""")


if __name__ == "__main__":
    main()
