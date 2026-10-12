"""Deliverable: trace recorder (Person 2).

Saves/loads Trace objects as JSON under data/results/runs/, so Person 3's
GET /runs/{id} endpoint (and the dashboard) can read a trace straight off
disk by run_id.
"""
from __future__ import annotations

import config
from contract import Trace

RUNS_DIR = config.DATA_DIR / "results" / "runs"


def record(trace: Trace) -> str:
    """Writes the trace to disk, returns its run_id."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = RUNS_DIR / f"{trace.run_id}.json"
    path.write_text(trace.model_dump_json(indent=2), encoding="utf-8")
    return trace.run_id


def load(run_id: str) -> Trace:
    path = RUNS_DIR / f"{run_id}.json"
    return Trace.model_validate_json(path.read_text(encoding="utf-8"))


def list_runs() -> list:
    if not RUNS_DIR.exists():
        return []
    return sorted(p.stem for p in RUNS_DIR.glob("*.json"))
