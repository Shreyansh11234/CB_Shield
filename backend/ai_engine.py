"""
ai_engine.py
------------
Anomaly detection using scikit-learn's Isolation Forest.

Strategy
--------
* The detector auto-trains itself during the first `MAX_SAMPLES` ticks.
* After training it scores every tick; an outlier (-1 prediction) generates
  an alert with a risk score mapped to [50, 100].
* A rough risk score is also produced for normal readings so the gauge is
  always non-zero and meaningful.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

MAX_SAMPLES = 30   # collect ~60 seconds of data before training


class AnomalyDetector:
    def __init__(self) -> None:
        # contamination=0.05 → model expects ≤5 % of points to be outliers
        self._model      = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        self.is_trained  = False
        self._buffer:    list[list[float]] = []

    # ── public API ──────────────────────────────────────────────────────────

    def ingest(self, cpu: float, memory: float, connections: int) -> None:
        """Add a data point; trains the model once enough data is collected."""
        if self.is_trained:
            return  # already trained — nothing to buffer
        self._buffer.append([cpu, memory, float(connections)])
        if len(self._buffer) >= MAX_SAMPLES:
            self._train()

    @property
    def training_progress(self) -> int:
        """How many samples have been collected so far."""
        return len(self._buffer)

    def predict(self, cpu: float, memory: float, connections: int) -> dict:
        """
        Returns:
            {
                "is_anomaly": bool,
                "risk_score": int  # 0-100
            }
        """
        if not self.is_trained:
            return {"is_anomaly": False, "risk_score": 0}

        X = np.array([[cpu, memory, float(connections)]])
        label    = self._model.predict(X)[0]          # +1 normal, -1 anomaly
        raw      = self._model.decision_function(X)[0] # lower = more anomalous

        is_anomaly = label == -1

        if is_anomaly:
            # raw is typically negative; clamp risk into [50, 100]
            risk_score = int(min(100, max(50, 50 - raw * 80)))
        else:
            # raw is typically positive; map into [0, 45] for a live "health" feel
            risk_score = int(max(0, min(45, (0.5 - raw) * 50)))

        return {"is_anomaly": is_anomaly, "risk_score": risk_score}

    # ── private ─────────────────────────────────────────────────────────────

    def _train(self) -> None:
        print(f"[AI] Training on {len(self._buffer)} samples…", flush=True)
        X = np.array(self._buffer)
        self._model.fit(X)
        self.is_trained = True
        print("[AI] Training complete — anomaly detection is now active.", flush=True)


# Module-level singleton shared by monitor + main
detector = AnomalyDetector()
