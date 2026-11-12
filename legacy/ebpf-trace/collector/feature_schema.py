"""Ordered, shared feature contracts. No labels, addresses or future traffic."""

LEGACY_FEATURES = [
    "pkt_rate", "byte_rate", "syn_ratio", "port_entropy", "flow_duration", "avg_pkt_size",
]
SOURCE_FEATURES = LEGACY_FEATURES + ["source_pkt_rate", "source_syn_rate", "port_cnt"]
CONTEXT_FEATURES = SOURCE_FEATURES + [
    "destination_pkt_rate", "destination_byte_rate", "destination_syn_rate",
    "destination_source_count", "service_pkt_rate", "service_byte_rate", "service_syn_rate",
    "service_source_count", "reverse_pkt_rate", "reverse_byte_rate",
    "bidirectional_pkt_rate", "bidirectional_byte_rate", "reverse_packet_fraction",
    "bidirectional_syn_ratio", "source_pkt_rate_10s", "destination_pkt_rate_10s",
]
FEATURE_SCHEMA_VERSION = 2
CONTEXT_SECONDS = 10
