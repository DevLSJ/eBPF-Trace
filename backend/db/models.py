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
