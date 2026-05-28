"""
main.py
-------
FastAPI application entry-point for Sentinel AI.

Endpoints
---------
GET  /                        → health check
GET  /api/alerts              → last N alerts from DB
WS   /ws                      → live data stream (JSON every 2 s)
POST /api/action/kill_process → (simulated) process termination
POST /api/action/block_ip     → (simulated) firewall block
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import engine, Base, SessionLocal
import models
from monitor import run_monitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("sentinel.main")


# ── WebSocket connection manager ───────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)
        logger.info("WS client connected. Total: %d", len(self._clients))

    def disconnect(self, ws: WebSocket):
        self._clients.remove(ws)
        logger.info("WS client disconnected. Total: %d", len(self._clients))

    async def broadcast(self, payload: dict):
        """Send payload to all connected clients; drop dead connections."""
        dead: list[WebSocket] = []
        text = json.dumps(payload, default=str)
        for ws in self._clients:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._clients:
                self._clients.remove(ws)


manager = ConnectionManager()


# ── Lifespan (replaces deprecated @app.on_event) ──────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created / verified.")
    task = asyncio.create_task(run_monitor(manager.broadcast))
    logger.info("Background monitor task started.")
    yield
    # Shutdown
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("Monitor task stopped. Bye!")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Sentinel AI", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def health():
    return {"status": "ok", "service": "Sentinel AI"}


@app.get("/api/alerts", tags=["Alerts"])
async def get_alerts(limit: int = Query(default=50, le=200)):
    """Return recent alerts from the SQLite database."""
    db: Session = SessionLocal()
    try:
        rows = (
            db.query(models.Alert)
            .order_by(models.Alert.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id":          r.id,
                "timestamp":   r.timestamp.isoformat(),
                "risk_level":  r.risk_level,
                "description": r.description,
                "source":      r.source,
            }
            for r in rows
        ]
    finally:
        db.close()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep the socket alive; ignore any client messages
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as exc:
        logger.warning("WS error: %s", exc)
        manager.disconnect(ws)


@app.post("/api/action/kill_process", tags=["Actions"])
async def kill_process(pid: int = Query(..., description="Process ID to terminate")):
    """
    Terminate a running process by PID.
    Currently SIMULATED — uncomment p.terminate() to enable real termination
    (requires the backend to run with sufficient OS privileges).
    """
    try:
        p = psutil.Process(pid)
        name = p.name()
        # ── Un-comment the next two lines to enable real termination ──────────
        # p.terminate()
        # p.wait(timeout=3)
        return {"status": "success", "message": f"[SIMULATED] Terminated '{name}' (PID {pid})"}
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"No process with PID {pid}")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail="Access denied — re-run backend as Administrator")


@app.post("/api/action/block_ip", tags=["Actions"])
async def block_ip(ip: str = Query(..., description="Remote IP address to block")):
    """
    Block an IP address via Windows Firewall (netsh).
    Currently SIMULATED — uncomment the subprocess call to enable real blocking.
    """
    # ── Un-comment the block below to enable real firewall rules ──────────────
    # import subprocess, shlex
    # cmd = f'netsh advfirewall firewall add rule name="SentinelBlock_{ip}" dir=out action=block remoteip={ip}'
    # subprocess.run(shlex.split(cmd), check=True, capture_output=True)
    return {"status": "success", "message": f"[SIMULATED] Firewall rule added for {ip}"}


# ── Dev runner ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
