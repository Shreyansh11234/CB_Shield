# Sentinel AI — Setup & Run Instructions

## Prerequisites
- **Python 3.10+** (a `venv` is already created in `backend/venv/`)
- **Node.js 18+** with npm

---

## 1. Backend (FastAPI + Python)

```bash
cd backend

# Activate virtual environment
.\venv\Scripts\activate        # Windows
# source venv/bin/activate     # Linux/macOS

# Install dependencies (already done if you followed the build)
pip install -r requirements.txt

# Start the server
python main.py
```

The backend runs at **http://localhost:8000**.
- Swagger docs: http://localhost:8000/docs
- Health check:  http://localhost:8000/

---

## 2. Frontend (React + Vite)

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

The dashboard opens at **http://localhost:5173**.

---

## How It Works

1. **System Monitor** — `psutil` polls CPU, RAM, processes, and network connections every 2 seconds.
2. **AI Engine** — An Isolation Forest model auto-trains on the first 30 readings (~60 seconds), then flags anomalies in real-time.
3. **Threat Intel** — Simulates VirusTotal-style IP reputation checks on active connections. Randomly flags ~3% of public IPs for demo.
4. **WebSocket** — The backend streams a JSON payload to the React frontend every 2 seconds.
5. **Actions** — "Kill Process" and "Block IP" buttons are **simulated** by default. Uncomment the real commands in `main.py` to enable them (requires Administrator).

---

## Project Structure

```
CB_shield/
├── backend/
│   ├── main.py            # FastAPI app + WebSocket + action endpoints
│   ├── monitor.py         # psutil system monitoring loop
│   ├── ai_engine.py       # Isolation Forest anomaly detector
│   ├── threat_intel.py    # Simulated VirusTotal IP checker
│   ├── database.py        # SQLAlchemy engine + session
│   ├── models.py          # ORM models (SystemLog, Alert)
│   ├── schemas.py         # Pydantic v2 schemas
│   ├── requirements.txt   # Python dependencies
│   └── venv/              # Virtual environment
├── frontend/
│   ├── src/
│   │   ├── App.jsx        # Main dashboard component
│   │   ├── App.css        # Dashboard styles
│   │   ├── index.css      # Base reset + design tokens
│   │   └── main.jsx       # React entry point
│   ├── package.json
│   └── vite.config.js
└── README.md              # ← this file
```
