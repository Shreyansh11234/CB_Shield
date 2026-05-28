"""
monitor.py
----------
Background coroutine that:
  1. Collects system stats via psutil every TICK_SECONDS seconds.
  2. Feeds them into the AI detector for training / inference.
  3. Runs spike detection — alerts when CPU, memory, or risk score jump suddenly.
  4. Optionally runs threat-intel checks on one connection per tick.
  5. Calls the caller-supplied broadcast() coroutine with a LivePayload dict.
"""

import asyncio
import logging
import random
import time

import psutil

from ai_engine import detector, MAX_SAMPLES
from threat_intel import check_ip, is_public_ip

logger = logging.getLogger("sentinel.monitor")

TICK_SECONDS   = 2      # how often to poll
TOP_PROCS      = 15     # max processes to send to the UI
MAX_CONNS      = 20     # max connections to send to the UI

# ── Spike detection thresholds ─────────────────────────────────────────────────
CPU_SPIKE_THRESHOLD   = 15.0   # alert if CPU jumps by ≥15 % in one tick
MEM_SPIKE_THRESHOLD   = 10.0   # alert if RAM jumps by ≥10 % in one tick
RISK_SPIKE_THRESHOLD  = 8      # alert if risk score jumps by ≥8 points in one tick
CONN_SPIKE_THRESHOLD  = 10     # alert if connection count jumps by ≥10 in one tick

# Previous-tick state (module-level so it persists across ticks)
_prev = {
    "cpu":         None,   # float | None
    "mem":         None,   # float | None
    "risk":        None,   # int   | None
    "connections": None,   # int   | None
}


# ── helpers ────────────────────────────────────────────────────────────────────

def _get_processes() -> tuple[int, list[dict]]:
    """Return (total_count, top-N process list)."""
    procs: list[dict] = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            procs.append({
                "pid":            info["pid"],
                "name":           info["name"] or "?",
                "cpu_percent":    round(info["cpu_percent"] or 0.0, 2),
                "memory_percent": round(info["memory_percent"] or 0.0, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    total = len(procs)
    top   = sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:TOP_PROCS]
    return total, top


def _get_connections() -> list[dict]:
    """Return established TCP/UDP connections."""
    conns: list[dict] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "ESTABLISHED":
                continue
            conns.append({
                "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid":    c.pid,
            })
    except psutil.AccessDenied:
        logger.warning("Access denied reading net_connections — try running as Administrator for full data.")
    return conns[:MAX_CONNS]


def _threat_check_one(connections: list[dict]) -> dict | None:
    """Pick a random public remote IP from the connection list and check it."""
    public = [c for c in connections if c["raddr"] and is_public_ip(c["raddr"].split(":")[0])]
    if not public:
        return None
    conn = random.choice(public)
    ip   = conn["raddr"].split(":")[0]
    result = check_ip(ip)
    if result["malicious"]:
        return {
            "risk_level":  "High",
            "description": result["detail"],
            "source":      "ThreatIntel",
            "timestamp":   time.time(),
        }
    return None


def _check_spikes(cpu: float, mem: float, risk_score: int, conn_count: int) -> list[dict]:
    """
    Compare current values against the previous tick.
    Returns a list of spike-alert dicts (may be empty).
    """
    spike_alerts: list[dict] = []
    now = time.time()

    # — CPU spike —
    if _prev["cpu"] is not None:
        delta = cpu - _prev["cpu"]
        if delta >= CPU_SPIKE_THRESHOLD:
            level = "High" if delta >= 30 else "Medium"
            spike_alerts.append({
                "risk_level":  level,
                "description": (
                    f"CPU spike detected: {_prev['cpu']}% → {cpu}% "
                    f"(+{delta:.1f}% in {TICK_SECONDS}s)"
                ),
                "source":    "SpikeDetector",
                "timestamp": now,
            })
            logger.warning("CPU spike: %.1f → %.1f (+%.1f)", _prev["cpu"], cpu, delta)

    # — Memory spike —
    if _prev["mem"] is not None:
        delta = mem - _prev["mem"]
        if delta >= MEM_SPIKE_THRESHOLD:
            level = "High" if delta >= 20 else "Medium"
            spike_alerts.append({
                "risk_level":  level,
                "description": (
                    f"Memory spike detected: {_prev['mem']}% → {mem}% "
                    f"(+{delta:.1f}% in {TICK_SECONDS}s)"
                ),
                "source":    "SpikeDetector",
                "timestamp": now,
            })
            logger.warning("MEM spike: %.1f → %.1f (+%.1f)", _prev["mem"], mem, delta)

    # — Risk score spike —
    if _prev["risk"] is not None:
        delta = risk_score - _prev["risk"]
        if delta >= RISK_SPIKE_THRESHOLD:
            level = "High" if delta >= 20 else "Medium"
            spike_alerts.append({
                "risk_level":  level,
                "description": (
                    f"Risk score surged: {_prev['risk']} → {risk_score} "
                    f"(+{delta} points in {TICK_SECONDS}s)"
                ),
                "source":    "SpikeDetector",
                "timestamp": now,
            })
            logger.warning("RISK spike: %d → %d (+%d)", _prev["risk"], risk_score, delta)

    # — Connection count spike —
    if _prev["connections"] is not None:
        delta = conn_count - _prev["connections"]
        if delta >= CONN_SPIKE_THRESHOLD:
            level = "High" if delta >= 20 else "Medium"
            spike_alerts.append({
                "risk_level":  level,
                "description": (
                    f"Connection surge: {_prev['connections']} → {conn_count} "
                    f"(+{delta} new connections in {TICK_SECONDS}s)"
                ),
                "source":    "SpikeDetector",
                "timestamp": now,
            })
            logger.warning("CONN spike: %d → %d (+%d)", _prev["connections"], conn_count, delta)

    # Update previous values for next tick
    _prev["cpu"]         = cpu
    _prev["mem"]         = mem
    _prev["risk"]        = risk_score
    _prev["connections"] = conn_count

    return spike_alerts


# ── main coroutine ─────────────────────────────────────────────────────────────

async def run_monitor(broadcast):
    """
    Endless loop — call once as an asyncio background task.
    `broadcast` is an async callable that accepts a plain dict.
    """
    # Prime the CPU counter (first call always returns 0.0)
    psutil.cpu_percent(interval=None)
    await asyncio.sleep(1)

    logger.info("Monitor started.")

    while True:
        try:
            await _tick(broadcast)
        except Exception:
            logger.exception("Unhandled error in monitor tick — continuing.")
        await asyncio.sleep(TICK_SECONDS)


async def _tick(broadcast):
    cpu    = round(psutil.cpu_percent(interval=None), 1)
    mem    = round(psutil.virtual_memory().percent, 1)
    total, procs = _get_processes()
    conns  = _get_connections()

    # ── AI ──────────────────────────────────────────────────────────────────
    alerts: list[dict] = []
    risk_score = 0

    if not detector.is_trained:
        detector.ingest(cpu, mem, len(conns))
        ai_status = f"Training ({detector.training_progress}/{MAX_SAMPLES})"
        ai_analysis = None
    else:
        ai_result   = detector.predict(cpu, mem, len(conns))
        ai_status   = "Active"
        ai_analysis = ai_result
        risk_score  = ai_result["risk_score"]

        if ai_result["is_anomaly"]:
            level = "High" if risk_score > 80 else "Medium"
            alerts.append({
                "risk_level":  level,
                "description": (
                    f"Anomalous system behaviour detected — "
                    f"CPU {cpu}% | RAM {mem}% | Connections {len(conns)}"
                ),
                "source":    "AI",
                "timestamp": time.time(),
            })

    # ── Spike detection ─────────────────────────────────────────────────────
    spike_alerts = _check_spikes(cpu, mem, risk_score, len(conns))
    alerts.extend(spike_alerts)

    # ── Threat Intel (one connection per tick, async-friendly) ───────────────
    threat_alert = await asyncio.to_thread(_threat_check_one, conns)
    if threat_alert:
        alerts.append(threat_alert)

    # ── Build payload ────────────────────────────────────────────────────────
    payload = {
        "cpu_percent":    cpu,
        "memory_percent": mem,
        "process_count":  total,
        "processes":      procs,
        "connections":    conns,
        "ai_status":      ai_status,
        "ai_analysis":    ai_analysis,
        "alerts":         alerts,
    }

    await broadcast(payload)
