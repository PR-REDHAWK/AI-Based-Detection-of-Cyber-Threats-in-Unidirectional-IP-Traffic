import time
import os
import psutil
import numpy as np
from simulator.traffic_generator import TrafficGenerator
from flows.flow_manager import FlowManager
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine

def run_throughput_benchmark(flow_counts: list = [500, 1000, 2000, 5000]):
    print("==================================================================")
    print("        OracleShield Passive Engine Throughput & Latency Benchmark ")
    print("==================================================================")

    generator = TrafficGenerator()
    pipeline = FeaturePipeline()
    process = psutil.Process(os.getpid())

    for target_count in flow_counts:
        flow_manager = FlowManager(window_seconds=1.0)
        risk_engine = RiskEngine()

        latencies = []
        alerts_raised = 0
        total_packets = 0
        total_bytes = 0

        # Generate synthetic benchmark traffic
        packets = []
        for i in range(target_count):
            if i % 5 == 0:
                packets.extend(generator.generate_syn_flood(timestamp=time.time(), duration_seconds=0.1, rate=200))
            elif i % 7 == 0:
                packets.extend(generator.generate_c2_beacon(timestamp=time.time(), count=4, interval=0.1))
            else:
                packets.extend(generator.generate_benign_flow(timestamp=time.time()))

        t_start = time.time()
        for pkt in packets:
            t0 = time.perf_counter()
            emitted_flows = flow_manager.process_packet(pkt)
            total_packets += 1
            total_bytes += pkt.length

            for flow in emitted_flows:
                feats = pipeline.extract_features(flow)
                alert = risk_engine.analyze(flow, feats)
                if alert:
                    alerts_raised += 1

            t_end = time.perf_counter()
            latencies.append((t_end - t0) * 1000.0)  # Convert to ms

        t_total = max(time.time() - t_start, 0.001)

        flows_per_sec = len(packets) / t_total
        pkts_per_sec = total_packets / t_total
        p50 = np.percentile(latencies, 50)
        p95 = np.percentile(latencies, 95)
        p99 = np.percentile(latencies, 99)

        cpu_usage = process.cpu_percent(interval=0.1)
        mem_mb = process.memory_info().rss / (1024 * 1024)

        print(f"Target Flows: {target_count:5d} | Throughput: {flows_per_sec:7.1f} flows/s ({pkts_per_sec:7.1f} pkts/s)")
        print(f"  Latency (ms):  Mean: {np.mean(latencies):.3f} | P50: {p50:.3f} | P95: {p95:.3f} | P99: {p99:.3f}")
        print(f"  System Usage:  CPU: {cpu_usage:.1f}% | Memory: {mem_mb:.1f} MB | Alerts Raised: {alerts_raised}")
        print("------------------------------------------------------------------")

if __name__ == "__main__":
    run_throughput_benchmark()
