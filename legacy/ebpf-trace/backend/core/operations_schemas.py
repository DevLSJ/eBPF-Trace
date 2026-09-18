from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Login(Input):
    username: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=256)


class Mutation(Input):
    version: int = Field(ge=1)
    reason: str = Field(default="", max_length=2000)


class Transition(Mutation):
    status: Literal[
        "investigating",
        "contained",
        "recovering",
        "resolved",
        "false_positive",
        "duplicate",
        "accepted_risk",
    ]


class Assignment(Mutation):
    operator_id: UUID
    reason: str = Field(min_length=3, max_length=2000)


class Note(Input):
    reason: str = Field(min_length=1, max_length=2000)


class AssetInput(Input):
    name: str = Field(min_length=1, max_length=120)
    address: IPvAnyAddress
    service_port: int = Field(ge=1, le=65535)
    protocol: Literal[6, 17] = 6
    environment: Literal["production", "lab", "simulation"] = "lab"
    criticality: Literal["standard", "critical"] = "standard"
    owner_id: UUID | None = None
    protected_cidrs: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("protected_cidrs")
    @classmethod
    def networks(cls, values):
        import ipaddress

        return [str(ipaddress.ip_network(v, strict=False)) for v in values]


class PointInput(Input):
    asset_id: UUID
    name: str = Field(min_length=1, max_length=120)
    mode: Literal["lab", "nftables"] = "lab"


class PreviewInput(Mutation):
    request_id: UUID
    point_id: UUID
    action: Literal["block_source", "rate_limit"] = "block_source"
    source_ip: IPv4Address
    ttl_seconds: int = Field(ge=30, le=900)
    rate_pps: int = Field(default=100, ge=10, le=100000)
    reason: str = Field(min_length=3, max_length=2000)


class Approval(Input):
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=3, max_length=2000)


class Heartbeat(Input):
    capabilities: list[Literal["block_source", "rate_limit"]] = Field(max_length=2)
    mode: Literal["lab", "nftables"]
    healthy: bool
    success_rate: float = Field(ge=0, le=1)
    latency_ms: float = Field(ge=0, le=300000)
    ingress_pps: float = Field(ge=0, le=1e12)
    policy_hits: int = Field(ge=0)
    normal_sessions: int = Field(ge=0)


class AgentReport(Input):
    sequence: int = Field(ge=1)
    status: Literal["applied", "failed", "released", "release_failed"]
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_handle: str = Field(default="", max_length=120)
    detail: str = Field(default="", max_length=240)


class KillSwitch(Input):
    enabled: bool
    reason: str = Field(min_length=3, max_length=2000)


class ModelStage(Input):
    stage: Literal["offline", "shadow", "advisory", "production"]
    reason: str = Field(min_length=3, max_length=2000)
