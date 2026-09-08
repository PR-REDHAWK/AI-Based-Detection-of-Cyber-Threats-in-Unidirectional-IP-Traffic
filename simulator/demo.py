import time
import asyncio
import logging
from typing import List

from ingest.models import PacketMetadata
from flows.flow_manager import FlowManager
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine
from simulator.traffic_generator import TrafficGenerator
from backend.api.alerts import in_memory_alerts
from backend.api.flows import in_memory_flows
from backend.api.statistics import stats_cache
from backend.websocket import ws_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("OracleShieldDemo")

class LiveDemoRunner:
    """
    Live Demo Runner that executes real-time streaming traffic generation,
    flow aggregation, feature extraction, threat detection, and WebSocket broadcasting.
    """

    def __init__(self):
        self.flow_manager = FlowManager(window_seconds=2.0)
        self.feature_pipeline = FeaturePipeline()
        self.risk_engine = RiskEngine()
        self.generator = TrafficGenerator()

    async def run_simulation(self):
        logger.info("Starting OracleShield Live Demo Simulation...")
        start_time = time.time()
        pkt_clock = start_time

        # Simulation scenario sequence
        scenarios = [
            ("BENIGN", lambda t: self.generator.generate_benign_flow(t)),
            ("SYN_FLOOD", lambda t: self.generator.generate_syn_flood(t, duration_seconds=3.0, rate=50.0)),
            ("BENIGN", lambda t: self.generator.generate_benign_flow(t)),
            ("PORT_SCAN", lambda t: self.generator.generate_port_scan(t, port_count=20)),
            ("BENIGN", lambda t: self.generator.generate_benign_flow(t)),
            ("C2_BEACON", lambda t: self.generator.generate_c2_beacon(t, count=8, interval=1.5)),
            ("BENIGN", lambda t: self.generator.generate_benign_flow(t))
        ]

        scenario_idx = 0

        while True:
            name, gen_func = scenarios[scenario_idx % len(scenarios)]
            logger.info(f"Emitting scenario phase: {name}")

            packets: List[PacketMetadata] = gen_func(pkt_clock)
            for pkt in packets:
                pkt_clock += 0.02
                t0 = time.time()

                # Process packet through flow manager
                emitted_flows = self.flow_manager.process_packet(pkt)
                latency = (time.time() - t0) * 1000.0

                stats_cache["packets_processed"] += 1
                stats_cache["bytes_processed"] += pkt.length
                stats_cache["avg_latency_ms"] = round(latency, 2)

                # Process emitted/windowed flows
                for flow in emitted_flows:
                    stats_cache["flows_processed"] += 1

                    # Update in-memory flow cache
                    in_memory_flows.insert(0, {
                        "flow_id": flow.flow_id,
                        "initiator_ip": flow.initiator_ip,
                        "responder_ip": flow.responder_ip,
                        "initiator_port": flow.initiator_port,
                        "responder_port": flow.responder_port,
                        "protocol": flow.protocol,
                        "total_packets": flow.total_packets,
                        "total_bytes": flow.total_bytes,
                        "duration": flow.duration,
                        "first_seen": flow.first_seen,
                        "last_seen": flow.last_seen
                    })
                    if len(in_memory_flows) > 200:
                        in_memory_flows.pop()

                    # Feature extraction
                    feats = self.feature_pipeline.extract_features(flow)

                    # Threat Analysis
                    alert = self.risk_engine.analyze(flow, feats)
                    if alert:
                        logger.warning(f"🚨 THREAT DETECTED: [{alert.severity}] {alert.threat_class} ({alert.confidence*100:.0f}%) from {alert.src_ip} -> {alert.dst_ip}")
                        alert_dict = alert.model_dump()
                        in_memory_alerts.insert(0, alert_dict)
                        if len(in_memory_alerts) > 100:
                            in_memory_alerts.pop()

                        # Broadcast via WebSocket
                        await ws_manager.broadcast_alert(alert_dict)

                await asyncio.sleep(0.01)

            scenario_idx += 1
            await asyncio.sleep(1.0)

if __name__ == "__main__":
    runner = LiveDemoRunner()
    asyncio.run(runner.run_simulation())
