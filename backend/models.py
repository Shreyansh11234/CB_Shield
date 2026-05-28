"""
models.py
---------
SQLAlchemy ORM models — one table for system-stat snapshots,
one for threat alerts.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class SystemLog(Base):
    """One row per monitoring tick (every ~2 seconds)."""
    __tablename__ = "system_logs"

    id                 = Column(Integer, primary_key=True, index=True)
    timestamp          = Column(DateTime(timezone=True), default=_now_utc)
    cpu_percent        = Column(Float,   nullable=False)
    memory_percent     = Column(Float,   nullable=False)
    active_connections = Column(Integer, nullable=False, default=0)
    process_count      = Column(Integer, nullable=False, default=0)
    risk_score         = Column(Integer, nullable=False, default=0)


class Alert(Base):
    """Persisted threat alert emitted by the AI engine or threat-intel module."""
    __tablename__ = "alerts"

    id          = Column(Integer, primary_key=True, index=True)
    timestamp   = Column(DateTime(timezone=True), default=_now_utc)
    risk_level  = Column(String,  nullable=False)   # "Low" | "Medium" | "High"
    description = Column(String,  nullable=False)
    source      = Column(String,  nullable=False)   # "AI" | "ThreatIntel" | "System"
