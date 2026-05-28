"""
schemas.py
----------
Pydantic v2 schemas used for API request / response validation.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertCreate(BaseModel):
    risk_level:  str
    description: str
    source:      str


class AlertOut(AlertCreate):
    id:        int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)  # Pydantic v2 replacement for orm_mode


# ── Live payload broadcasted over WebSocket ───────────────────────────────────

class ProcessInfo(BaseModel):
    pid:            int
    name:           str
    cpu_percent:    float
    memory_percent: float


class ConnectionInfo(BaseModel):
    laddr:  str
    raddr:  str
    status: str
    pid:    Optional[int] = None


class AIAnalysis(BaseModel):
    is_anomaly: bool
    risk_score: int           # 0-100


class LivePayload(BaseModel):
    cpu_percent:     float
    memory_percent:  float
    process_count:   int
    processes:       list[ProcessInfo]
    connections:     list[ConnectionInfo]
    ai_status:       str       # "Training (N/30)" | "Active"
    ai_analysis:     Optional[AIAnalysis] = None
    alerts:          list[dict] = []


# ── Action responses ──────────────────────────────────────────────────────────

class ActionResult(BaseModel):
    status:  str    # "success" | "error"
    message: str
