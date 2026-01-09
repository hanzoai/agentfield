#!/usr/bin/env python3
"""
Detailed memory debugging for AgentField SDK.

This script provides line-by-line memory profiling and object tracking.

Install dependencies:
    pip install memory_profiler objgraph pympler

Run with:
    python memory_debug.py

Or for line-by-line profiling:
    python -m memory_profiler memory_debug.py
"""

import gc
import sys
import tracemalloc


def snapshot_top_allocations(snapshot, limit=20):
    """Display top memory allocations from a tracemalloc snapshot."""
    top_stats = snapshot.statistics('lineno')

    print(f"\nTop {limit} memory allocations:")
    print("-" * 80)

    for idx, stat in enumerate(top_stats[:limit], 1):
        print(f"{idx:2}. {stat.size / 1024:.1f} KB - {stat.traceback}")


def compare_snapshots(before, after, limit=15):
    """Compare two snapshots and show what grew."""
    top_stats = after.compare_to(before, 'lineno')

    print(f"\nTop {limit} memory growth between snapshots:")
    print("-" * 80)

    for idx, stat in enumerate(top_stats[:limit], 1):
        if stat.size_diff > 0:
            print(f"{idx:2}. +{stat.size_diff / 1024:.1f} KB - {stat.traceback}")


def analyze_with_tracemalloc():
    """Use tracemalloc to identify memory hotspots."""
    print("=" * 80)
    print("TRACEMALLOC ANALYSIS")
    print("=" * 80)

    gc.collect()
    tracemalloc.start(25)  # 25 frames of traceback

    # Snapshot before imports
    snapshot1 = tracemalloc.take_snapshot()

    print("\n[1] Importing agentfield.types...")
    import agentfield.types
    snapshot2 = tracemalloc.take_snapshot()
    compare_snapshots(snapshot1, snapshot2, 5)

    print("\n[2] Importing agentfield.client...")
    import agentfield.client
    snapshot3 = tracemalloc.take_snapshot()
    compare_snapshots(snapshot2, snapshot3, 5)

    print("\n[3] Importing agentfield.agent_ai (triggers LiteLLM)...")
    import agentfield.agent_ai
    snapshot4 = tracemalloc.take_snapshot()
    compare_snapshots(snapshot3, snapshot4, 10)

    print("\n[4] Importing agentfield (full SDK)...")
    import agentfield
    snapshot5 = tracemalloc.take_snapshot()
    compare_snapshots(snapshot4, snapshot5, 5)

    # Final summary
    current, peak = tracemalloc.get_traced_memory()
    print("\n" + "=" * 80)
    print(f"TOTAL: Current={current/1024/1024:.1f} MB, Peak={peak/1024/1024:.1f} MB")
    print("=" * 80)

    # Show top allocations in final state
    snapshot_top_allocations(snapshot5, 20)

    tracemalloc.stop()


def analyze_with_objgraph():
    """Use objgraph to find memory leaks and large objects."""
    try:
        import objgraph
    except ImportError:
        print("objgraph not installed. Run: pip install objgraph")
        return

    print("\n" + "=" * 80)
    print("OBJGRAPH ANALYSIS (Object counts)")
    print("=" * 80)

    gc.collect()

    print("\nBefore importing agentfield:")
    before = objgraph.typestats()

    import agentfield

    gc.collect()

    print("\nAfter importing agentfield:")
    print("\nMost common types:")
    objgraph.show_most_common_types(limit=20)

    print("\nGrowth in object counts:")
    objgraph.show_growth(limit=20)


def analyze_with_pympler():
    """Use pympler for detailed memory analysis."""
    try:
        from pympler import asizeof, tracker, summary, muppy
    except ImportError:
        print("pympler not installed. Run: pip install pympler")
        return

    print("\n" + "=" * 80)
    print("PYMPLER ANALYSIS (Deep size calculation)")
    print("=" * 80)

    gc.collect()

    # Track memory before
    tr = tracker.SummaryTracker()

    print("\nImporting agentfield...")
    import agentfield

    gc.collect()

    print("\nMemory summary after import:")
    tr.print_diff()

    # Size of key objects
    print("\n" + "-" * 80)
    print("Size of key SDK components:")
    print("-" * 80)

    try:
        from agentfield import Agent
        from agentfield.async_config import AsyncConfig

        config = AsyncConfig()
        print(f"AsyncConfig instance: {asizeof.asizeof(config) / 1024:.1f} KB")

        # Don't instantiate Agent as it starts background tasks
        print(f"Agent class object: {asizeof.asizeof(Agent) / 1024:.1f} KB")

    except Exception as e:
        print(f"Error measuring components: {e}")


def analyze_sys_modules():
    """Analyze what modules are loaded after importing agentfield."""
    print("\n" + "=" * 80)
    print("LOADED MODULES ANALYSIS")
    print("=" * 80)

    before_modules = set(sys.modules.keys())

    import agentfield

    after_modules = set(sys.modules.keys())
    new_modules = after_modules - before_modules

    print(f"\nModules loaded by 'import agentfield': {len(new_modules)}")
    print("-" * 80)

    # Group by package
    packages = {}
    for mod in sorted(new_modules):
        pkg = mod.split('.')[0]
        if pkg not in packages:
            packages[pkg] = []
        packages[pkg].append(mod)

    # Sort by count
    for pkg, mods in sorted(packages.items(), key=lambda x: -len(x[1])):
        print(f"{pkg}: {len(mods)} modules")
        if len(mods) <= 5:
            for m in mods:
                print(f"  - {m}")

    print(f"\nTotal new modules: {len(new_modules)}")

    # Identify heavy hitters
    print("\n" + "-" * 80)
    print("Likely heavy packages (by module count):")
    print("-" * 80)
    heavy = [(pkg, len(mods)) for pkg, mods in packages.items() if len(mods) > 10]
    for pkg, count in sorted(heavy, key=lambda x: -x[1]):
        print(f"  {pkg}: {count} modules")


def quick_memory_check():
    """Quick memory measurement using resource module."""
    try:
        import resource

        def get_mem_mb():
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

        print("=" * 80)
        print("QUICK MEMORY CHECK (RSS)")
        print("=" * 80)

        gc.collect()
        before = get_mem_mb()
        print(f"Before import: {before:.1f} MB")

        import agentfield

        gc.collect()
        after = get_mem_mb()
        print(f"After import:  {after:.1f} MB")
        print(f"Difference:    {after - before:.1f} MB")

    except ImportError:
        print("resource module not available (Windows?)")

        # Fallback to psutil
        try:
            import psutil
            process = psutil.Process()

            gc.collect()
            before = process.memory_info().rss / 1024 / 1024
            print(f"Before import: {before:.1f} MB")

            import agentfield

            gc.collect()
            after = process.memory_info().rss / 1024 / 1024
            print(f"After import:  {after:.1f} MB")
            print(f"Difference:    {after - before:.1f} MB")

        except ImportError:
            print("Neither resource nor psutil available")


def main():
    print("AgentField SDK Memory Debugging")
    print("================================\n")

    # Run all analyses
    quick_memory_check()
    analyze_sys_modules()
    analyze_with_tracemalloc()

    # These require optional dependencies
    print("\n" + "=" * 80)
    print("OPTIONAL ANALYSES (require extra packages)")
    print("=" * 80)

    analyze_with_objgraph()
    analyze_with_pympler()

    print("\n" + "=" * 80)
    print("DEBUGGING COMPLETE")
    print("=" * 80)
    print("""
Next steps:
1. Look at the tracemalloc output to see which files allocate the most
2. Check 'LOADED MODULES' to see which packages pull in the most submodules
3. If litellm shows high in both, that confirms it as the main culprit

To profile a specific function with line-by-line memory:
    from memory_profiler import profile

    @profile
    def my_function():
        import agentfield
        agent = agentfield.Agent(...)

    my_function()
""")


if __name__ == "__main__":
    main()
