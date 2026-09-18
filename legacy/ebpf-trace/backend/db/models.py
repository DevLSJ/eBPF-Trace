from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class DetectionEvent(Base):
    __tablename__ = "detection_events"
    __table_args__ = (
        CheckConstraint("src_port BETWEEN 0 AND 65535"),
        CheckConstraint("dst_port BETWEEN 0 AND 65535"),
        CheckConstraint("severity IN ('critical','high','medium','low')"),
        CheckConstraint("protocol IN (6,17)"),
    )
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    message_id: Mapped[str] = mapped_column(String(36), unique=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45).with_variant(INET, "postgresql"), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45).with_variant(INET, "postgresql"))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)
    attack_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(8), index=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    pkt_rate: Mapped[float] = mapped_column(Float)
    byte_rate: Mapped[float] = mapped_column(Float)
    syn_ratio: Mapped[float] = mapped_column(Float)
    port_entropy: Mapped[float] = mapped_column(Float)
    flow_duration: Mapped[float] = mapped_column(Float)
    raw_features: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    is_confirmed: Mapped[bool | None] = mapped_column(Boolean)
    note: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16), default="live", server_default="live", index=True)
    scenario_run_id: Mapped[str | None] = mapped_column(ForeignKey("scenario_runs.id"), index=True)
    expected_label: Mapped[str | None] = mapped_column(String(32))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    thresholds: Mapped[dict] = mapped_column(JSON)
    detection_mode: Mapped[str] = mapped_column(String(16))


class ScenarioSample(Base):
    __tablename__ = "scenario_samples"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("scenario_runs.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    step: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(32))
    expected_label: Mapped[str] = mapped_column(String(32))
    detected_label: Mapped[str] = mapped_column(String(32))
    features: Mapped[dict] = mapped_column(JSON)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("detection_events.id"))


class SystemMetric(Base):
    __tablename__ = "system_metrics"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    ebpf_cpu_delta: Mapped[float | None] = mapped_column(Float)
    pkt_total: Mapped[int] = mapped_column(BigInteger, default=0)
    event_total: Mapped[int] = mapped_column(BigInteger, default=0)


class RuntimeConfig(Base):
    __tablename__ = "runtime_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    thresholds: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class Operator(Base):
    __tablename__ = "operators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_test_account: Mapped[bool] = mapped_column(Boolean, default=False)
    slack_user_id: Mapped[str | None] = mapped_column(String(40), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OperatorSession(Base):
    __tablename__ = "operator_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id"), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(45))
    service_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer, default=6)
    environment: Mapped[str] = mapped_column(String(16), default="lab")
    criticality: Mapped[str] = mapped_column(String(16), default="standard")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id"))
    protected_cidrs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("address", "service_port", "protocol", "environment"),)


class EnforcementPoint(Base):
    __tablename__ = "enforcement_points"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    mode: Mapped[str] = mapped_column(String(16), default="lab")
    token_hash: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    health: Mapped[dict] = mapped_column(JSON, default=dict)


class CorrelationKey(Base):
    __tablename__ = "correlation_keys"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    touched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    active_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(240))
    attack_type: Mapped[str] = mapped_column(String(32))
    priority: Mapped[str] = mapped_column(String(2), index=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)
    scenario_run_id: Mapped[str | None] = mapped_column(ForeignKey("scenario_runs.id"))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    asset_name: Mapped[str] = mapped_column(String(120))
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovering_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("detection_events.id"), primary_key=True, unique=True)


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id"))
    actor_name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(60))
    detail: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(180), unique=True)
    kind: Mapped[str] = mapped_column(String(24))
    channel: Mapped[str] = mapped_column(String(16))
    destination: Mapped[str] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(24), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_id: Mapped[str | None] = mapped_column(String(120))
    last_error: Mapped[str | None] = mapped_column(String(240))


class ActionRequest(Base):
    __tablename__ = "action_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    requester_id: Mapped[str] = mapped_column(ForeignKey("operators.id"))
    approver_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id"))
    point_id: Mapped[str] = mapped_column(ForeignKey("enforcement_points.id"))
    status: Mapped[str] = mapped_column(String(24), default="preview", index=True)
    incident_version: Mapped[int] = mapped_column(Integer)
    policy: Mapped[dict] = mapped_column(JSON)
    policy_hash: Mapped[str] = mapped_column(String(64))
    preview: Mapped[dict] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActionRun(Base):
    __tablename__ = "action_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), unique=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    point_id: Mapped[str] = mapped_column(ForeignKey("enforcement_points.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    policy: Mapped[dict] = mapped_column(JSON)
    policy_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    command_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_result: Mapped[dict] = mapped_column(JSON, default=dict)
    last_error: Mapped[str | None] = mapped_column(String(240))
    last_report_seq: Mapped[int] = mapped_column(Integer, default=0)


class ServiceObservation(Base):
    __tablename__ = "service_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    point_id: Mapped[str] = mapped_column(ForeignKey("enforcement_points.id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    healthy: Mapped[bool] = mapped_column(Boolean)
    success_rate: Mapped[float] = mapped_column(Float)
    latency_ms: Mapped[float] = mapped_column(Float)
    ingress_pps: Mapped[float] = mapped_column(Float)
    policy_hits: Mapped[int] = mapped_column(BigInteger)
    normal_sessions: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(16))


class OpsControl(Base):
    __tablename__ = "ops_control"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kill_switch: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelDeployment(Base):
    __tablename__ = "model_deployments"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    stage: Mapped[str] = mapped_column(String(16), default="offline")
    artifact_hash: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ShadowPrediction(Base):
    __tablename__ = "shadow_predictions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    model_id: Mapped[str] = mapped_column(ForeignKey("model_deployments.id"), index=True)
    message_id: Mapped[str] = mapped_column(String(36))
    source: Mapped[str] = mapped_column(String(16), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[str] = mapped_column(String(24))
    score: Mapped[float | None] = mapped_column(Float)
    predicted_attack: Mapped[bool | None] = mapped_column(Boolean)
    rule_attack: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[float] = mapped_column(Float)
    feature_schema_version: Mapped[int] = mapped_column(Integer)
    __table_args__ = (UniqueConstraint("model_id", "message_id"),)
