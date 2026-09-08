import time
from fastapi import APIRouter
from backend.api.alerts import in_memory_alerts
from backend.api.flows import in_memory_flows

router = APIRouter(prefix="/api/statistics", tags=["Statistics"])

stats_cache = {
    "start_time": time.time(),
    "flows_processed": 0,
    "packets_processed": 0,
    "bytes_processed": 0,
    "avg_latency_ms": 1.2
}

@router.get("")
async def get_statistics():
    """Retrieve real-time system metrics, throughput, latency, and threat severity distribution."""
    uptime = max(1.0, time.time() - stats_cache["start_time"])
    
    crit_count = sum(1 for a in in_memory_alerts if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in in_memory_alerts if a.get("severity") == "HIGH")
    med_count = sum(1 for a in in_memory_alerts if a.get("severity") == "MEDIUM")
    low_count = sum(1 for a in in_memory_alerts if a.get("severity") == "LOW")

    # Threat distribution
    threat_dist = {}
    for a in in_memory_alerts:
        tc = a.get("threat_class", "UNKNOWN")
        threat_dist[tc] = threat_dist.get(tc, 0) + 1

    return {
        "status": "MONITORING",
        "ingest_mode": "PASSIVE_READ_ONLY",
        "active_response": False,
        "uptime_seconds": round(uptime, 1),
        "flows_per_sec": round(stats_cache["flows_processed"] / uptime, 1),
        "packets_per_sec": round(stats_cache["packets_processed"] / uptime, 1),
        "total_flows": stats_cache["flows_processed"],
        "total_packets": stats_cache["packets_processed"],
        "total_alerts": len(in_memory_alerts),
        "avg_latency_ms": stats_cache["avg_latency_ms"],
        "severity_counts": {
            "CRITICAL": crit_count,
            "HIGH": high_count,
            "MEDIUM": med_count,
            "LOW": low_count
        },
        "threat_distribution": threat_dist
    }
