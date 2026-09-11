import os

from backend.core.schemas import Thresholds


def thresholds_from_env() -> Thresholds:
    values = {
        key: os.environ[key.upper()] for key in Thresholds.model_fields if key.upper() in os.environ
    }
    return Thresholds(**values)


class RuleEngine:
    def __init__(self, thresholds: Thresholds | None = None):
        self.thresholds = thresholds or thresholds_from_env()

    def detect(self, features: dict) -> str | None:
        t = self.thresholds
        # Count SYNs across source ports, including randomized 5-tuples.
        syn_rate = max(
            features.get("source_syn_rate", 0), features["pkt_rate"] * features["syn_ratio"]
        )
        source_packets = max(features.get("source_pkt_rate", 0), features["pkt_rate"])
        ratio = syn_rate / source_packets if source_packets else 0
        if syn_rate >= t.syn_pps_threshold and ratio >= t.syn_ratio_threshold:
            return "SYN_FLOOD"
        if (
            features["port_entropy"] >= t.port_entropy_threshold
            and features.get("port_cnt", 0) >= t.port_cnt_threshold
        ):
            return "PORT_SCAN"
        if features["pkt_rate"] >= t.baseline_pps * t.spike_threshold_multiplier:
            return "TRAFFIC_SPIKE"
        if features["byte_rate"] >= t.large_flow_threshold:
            return "LARGE_FLOW"
        return None
