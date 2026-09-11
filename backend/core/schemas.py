from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class FlowInfo(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal[6, 17]


class Features(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra="forbid")
    pkt_rate: float = Field(ge=0)
    byte_rate: float = Field(ge=0)  # bytes/s; convert to bits/s only for display
    syn_ratio: float = Field(ge=0, le=1)
    port_entropy: float = Field(ge=0, le=16)
    flow_duration: float = Field(ge=0)
    avg_pkt_size: float = Field(ge=0)
    port_cnt: int = Field(default=1, ge=0, le=65536)
    source_pkt_rate: float = Field(default=0, ge=0)
    source_syn_rate: float = Field(default=0, ge=0)


class FlowMessage(BaseModel):
    type: Literal["flow_features"]
    message_id: UUID
    timestamp: int = Field(ge=0)
    flow: FlowInfo
    features: Features


class Thresholds(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra="forbid")
    syn_ratio_threshold: float = Field(default=0.8, ge=0, le=1)
    syn_pps_threshold: float = Field(default=1000, gt=0)
    port_entropy_threshold: float = Field(default=3.5, ge=0, le=16)
    port_cnt_threshold: int = Field(default=20, ge=2, le=65536)
    spike_threshold_multiplier: float = Field(default=10, gt=1)
    baseline_pps: float = Field(default=1000, gt=0)
    large_flow_threshold: float = Field(default=12_500_000, gt=0)
    anomaly_threshold: float = Field(default=-0.1, ge=-1, lt=0)


class EventQuery(BaseModel):
    severity: Severity | None = None
    attack_type: (
        Literal["SYN_FLOOD", "PORT_SCAN", "ANOMALY", "TRAFFIC_SPIKE", "LARGE_FLOW"] | None
    ) = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)

    @field_validator("start_time", "end_time")
    @classmethod
    def utc_time(cls, value):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
