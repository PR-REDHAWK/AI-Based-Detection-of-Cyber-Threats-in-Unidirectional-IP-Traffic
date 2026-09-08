import argparse
import time
import asyncio
import logging
from ingest.pcap_reader import PCAPReader
from flows.flow_manager import FlowManager
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine
from backend.api.alerts import in_memory_alerts
from backend.api.flows import in_memory_flows
from backend.api.statistics import stats_cache

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("OracleShieldReplay")

def main():
    parser = argparse.ArgumentParser(description="OracleShield Passive PCAP Replay Tool")
    parser.add_argument("--pcap", type=str, required=True, help="Path to PCAP file")
    parser.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier (e.g. 1.0, 5.0, 10.0)")
    args = parser.parse_args()

    reader = PCAPReader(args.pcap)
    flow_manager = FlowManager(window_seconds=5.0)
    pipeline = FeaturePipeline()
    risk_engine = RiskEngine()

    logger.info(f"Starting PCAP replay for file: {args.pcap} at {args.speed}x speed...")
    pkt_count = 0

    for pkt in reader.read_packets(speed_multiplier=args.speed):
        pkt_count += 1
        t0 = time.time()
        emitted_flows = flow_manager.process_packet(pkt)
        latency = (time.time() - t0) * 1000.0

        stats_cache["packets_processed"] += 1
        stats_cache["bytes_processed"] += pkt.length
        stats_cache["avg_latency_ms"] = round(latency, 2)

        for flow in emitted_flows:
            stats_cache["flows_processed"] += 1
            feats = pipeline.extract_features(flow)
            alert = risk_engine.analyze(flow, feats)

            if alert:
                logger.warning(f"🚨 ALERT DETECTED [{alert.severity}]: {alert.threat_class} ({alert.confidence*100:.0f}%) {alert.src_ip} -> {alert.dst_ip}")
                in_memory_alerts.insert(0, alert.model_dump())

    logger.info(f"Replay complete. Processed {pkt_count} packets.")

if __name__ == "__main__":
    main()
