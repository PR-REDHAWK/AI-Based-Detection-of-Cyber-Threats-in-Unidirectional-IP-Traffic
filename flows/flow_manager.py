import time
from typing import Dict, List, Optional, Generator
from ingest.models import PacketMetadata
from flows.flow_key import CanonicalFlowKey, Flow

class FlowManager:
    """
    Incremental Flow Manager maintaining active bidirectional flows,
    performing active/idle timeouts, and emitting closed or windowed flows.
    """

    def __init__(self,
                 active_timeout_seconds: float = 60.0,
                 idle_timeout_seconds: float = 15.0,
                 window_seconds: float = 5.0):
        self.active_timeout = active_timeout_seconds
        self.idle_timeout = idle_timeout_seconds
        self.window_seconds = window_seconds

        self.active_flows: Dict[CanonicalFlowKey, Flow] = {}
        self.last_window_timestamp: Optional[float] = None
        self.processed_packet_count = 0
        self.processed_byte_count = 0

    def process_packet(self, pkt: PacketMetadata) -> List[Flow]:
        """
        Processes a single packet incrementally.
        Returns a list of expired/windowed flows ready for feature extraction & detection.
        """
        self.processed_packet_count += 1
        self.processed_byte_count += pkt.length

        if self.last_window_timestamp is None:
            self.last_window_timestamp = pkt.timestamp

        key = CanonicalFlowKey.from_packet(pkt)
        flows_to_emit: List[Flow] = []

        if key in self.active_flows:
            flow = self.active_flows[key]
            # Check if idle timeout exceeded prior to this packet
            if (pkt.timestamp - flow.last_seen) > self.idle_timeout:
                flows_to_emit.append(flow)
                # Re-initialize new flow for this key
                self.active_flows[key] = Flow(key, pkt)
            else:
                flow.add_packet(pkt)
                # Check active timeout
                if flow.duration > self.active_timeout:
                    flows_to_emit.append(flow)
                    del self.active_flows[key]
        else:
            self.active_flows[key] = Flow(key, pkt)

        # Check sliding window expiration
        if (pkt.timestamp - self.last_window_timestamp) >= self.window_seconds:
            # Emit active flows for windowed evaluation
            window_flows = self._flush_window_flows(pkt.timestamp)
            flows_to_emit.extend(window_flows)
            self.last_window_timestamp = pkt.timestamp

        return flows_to_emit

    def _flush_window_flows(self, current_timestamp: float) -> List[Flow]:
        """Collect active flows that have seen traffic within current window."""
        windowed: List[Flow] = []
        for key, flow in list(self.active_flows.items()):
            if (current_timestamp - flow.last_seen) <= self.window_seconds:
                windowed.append(flow)
        return windowed

    def flush_expired(self, current_timestamp: float) -> List[Flow]:
        """Force flush flows exceeding idle timeout."""
        expired: List[Flow] = []
        for key, flow in list(self.active_flows.items()):
            if (current_timestamp - flow.last_seen) > self.idle_timeout:
                expired.append(flow)
                del self.active_flows[key]
        return expired

    def get_stats(self) -> dict:
        return {
            "active_flows_count": len(self.active_flows),
            "processed_packets": self.processed_packet_count,
            "processed_bytes": self.processed_byte_count
        }
