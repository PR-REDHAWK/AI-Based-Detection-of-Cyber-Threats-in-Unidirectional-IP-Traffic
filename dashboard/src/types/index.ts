export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Alert {
  alert_id: string;
  timestamp: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  threat_class: string;
  severity: Severity;
  confidence: number;
  evidence: Record<string, any>;
  contributing_features?: Record<string, number>;
  model_version: string;
  correlated_alerts_count?: number;
}

export interface Statistics {
  status: string;
  ingest_mode: string;
  active_response: boolean;
  uptime_seconds: number;
  flows_per_sec: number;
  packets_per_sec: number;
  total_flows: number;
  total_packets: number;
  total_alerts: number;
  avg_latency_ms: number;
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  threat_distribution: Record<string, number>;
}
