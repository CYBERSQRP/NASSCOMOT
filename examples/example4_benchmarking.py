#!/usr/bin/env python3
"""
Example 4: Performance Benchmarking

Demonstrates performance benchmarking of PQC algorithms.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module8_hil_demo import PQCBenchmark


def main():
    """Run performance benchmarks."""
    print("=" * 60)
    print("Example: PQC Performance Benchmarking")
    print("=" * 60)

    # Initialize benchmark
    benchmark = PQCBenchmark(platform="Development Machine")

    # Run all benchmarks
    results = benchmark.run_all_benchmarks()

    print("\n" + "=" * 60)
    print("Benchmark Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
