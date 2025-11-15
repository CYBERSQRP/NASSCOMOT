"""PQC Performance Benchmarking"""

import time
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from modules.module1_pqc_layer import MLKEM768, MLDSA65

class PQCBenchmark:
    """Benchmark PQC operations on target hardware."""
    
    def __init__(self, platform: str = "NVIDIA Orin"):
        self.platform = platform
        self.kem = MLKEM768()
        self.dsa = MLDSA65()
    
    def benchmark_keygen(self, iterations: int = 100) -> dict:
        """Benchmark key generation."""
        start = time.perf_counter()
        for _ in range(iterations):
            self.kem.generate_keypair()
        elapsed = (time.perf_counter() - start) / iterations
        
        return {
            "operation": "ML-KEM-768 KeyGen",
            "avg_time_us": elapsed * 1e6,
            "iterations": iterations,
            "platform": self.platform
        }
    
    def benchmark_sign_verify(self, iterations: int = 100) -> dict:
        """Benchmark signing and verification."""
        keypair = self.dsa.generate_keypair()
        message = b"Test message for benchmarking"
        
        # Benchmark signing
        start = time.perf_counter()
        for _ in range(iterations):
            sig = self.dsa.sign(keypair.secret_key, message)
        sign_time = (time.perf_counter() - start) / iterations
        
        # Benchmark verification
        sig = self.dsa.sign(keypair.secret_key, message)
        start = time.perf_counter()
        for _ in range(iterations):
            self.dsa.verify(keypair.public_key, message, sig)
        verify_time = (time.perf_counter() - start) / iterations
        
        return {
            "sign_time_us": sign_time * 1e6,
            "verify_time_us": verify_time * 1e6,
            "iterations": iterations,
            "platform": self.platform
        }
    
    def run_all_benchmarks(self) -> dict:
        """Run all benchmarks."""
        print(f"Running benchmarks on {self.platform}...")
        
        results = {
            "platform": self.platform,
            "keygen": self.benchmark_keygen(),
            "sign_verify": self.benchmark_sign_verify()
        }
        
        print("\n=== Benchmark Results ===")
        print(f"ML-KEM-768 KeyGen: {results['keygen']['avg_time_us']:.2f} μs")
        print(f"ML-DSA-65 Sign: {results['sign_verify']['sign_time_us']:.2f} μs")
        print(f"ML-DSA-65 Verify: {results['sign_verify']['verify_time_us']:.2f} μs")
        
        return results
