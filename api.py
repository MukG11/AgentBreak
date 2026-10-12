"""Person 3: FastAPI backend for the dashboard.

    uvicorn api:app --reload --port 8000

Contract endpoints (CONTRACT.md):  POST /runs, GET /runs/{id}, GET /summary, POST /replay/{id}
Plan v2 endpoints:                 GET /audit, GET /regression
Extras for the dashboard:          GET /runs (list), GET /attacks, GET /defenses, GET /benign, GET /health

The demo plays from cached results: POST /replay/{id} returns the recorded run for the requested defense when
one exists, and only re-executes (needs the LLM) when none exists or ?live=true is passed. Live runs get ids
starting with "live-" and never overwrite the cached batch runs.
"""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config
import p3_common
from audit import audit_permissions, regression_report
from batch_runner import compute_extras
from benign_tasks import BENIGN_TASKS, BENIGN_ATTACK_ID
from contract import AttackPayload, BatchResults, Defense, RunRequest, Trace
from defenses import DEFENSE_INFO
from p3_common import (
    attack_run_id, execute_run, is_safe_id, list_trace_files, load_attack, load_attack_library, load_trace,
    save_attack, save_trace,
)

app = FastAPI(title="AgentBreak API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["X-AgentBreak-Source", "X-AgentBreak-Fallback-Reason"])

LIVE_TIMEOUT_S = float(os.getenv("AGENTBREAK_LIVE_TIMEOUT", "45"))   # "Replay live" falls back to the cache after this
_pool = ThreadPoolExecutor(max_workers=2)


class ReplayRequest(BaseModel):
    defense: Optional[Defense] = None      # default: the defense the original run used


def _require_safe(value: str, what: str) -> None:
    if not is_safe_id(value):
        raise HTTPException(400, f"invalid {what}: use letters, digits, '-', '_' and '.' only")


def _execute_and_save(attack: AttackPayload, defense: Defense, run_index: int) -> Trace:
    trace = execute_run(attack, defense, run_index)
    save_trace(trace)
    return trace


def _run_live(attack: AttackPayload, defense: Defense, run_index: int) -> Trace:
    try:
        return _execute_and_save(attack, defense, run_index)
    except Exception as e:                               # LLM down, rate limit exhausted, ...
        raise HTTPException(502, f"run failed: {type(e).__name__}: {e}")


def _load_results() -> BatchResults:
    if not config.RESULTS_FILE.exists():
        raise HTTPException(404, "no batch results yet: run `python batch_runner.py`")
    return BatchResults.model_validate_json(config.RESULTS_FILE.read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict:
    p3_common.get_detect()
    return {
        "ok": True,
        "detector": "fallback" if p3_common.USING_FALLBACK_DETECTOR else "detectors.py",
        "model": config.MODEL,
        "has_batch_results": config.RESULTS_FILE.exists(),
        "saved_runs": len(list_trace_files()),
    }


@app.post("/runs", response_model=Trace)
def start_run(req: RunRequest) -> Trace:
    """Start an attack run now (calls the LLM). Saved so GET /runs/{id} and replay work."""
    _require_safe(req.attack.attack_id, "attack_id")
    save_attack(req.attack)
    return _run_live(req.attack, req.defense, req.run_index)


@app.get("/runs/{run_id}", response_model=Trace)
def get_run(run_id: str) -> Trace:
    _require_safe(run_id, "run id")
    trace = load_trace(run_id)
    if trace is None:
        raise HTTPException(404, f"no run {run_id!r}")
    return trace


@app.get("/runs")
def list_runs(attack_id: Optional[str] = None, defense: Optional[Defense] = None,
              include_benign: bool = False) -> list[dict]:
    """Lightweight list (no steps) so the dashboard can pick runs to show."""
    rows = []
    for path in list_trace_files():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if raw.get("attack_id") == BENIGN_ATTACK_ID and not include_benign:
            continue
        if attack_id and raw.get("attack_id") != attack_id:
            continue
        if defense and raw.get("defense") != defense:
            continue
        out = raw.get("outcome", {})
        rows.append({"run_id": raw.get("run_id"), "attack_id": raw.get("attack_id"), "defense": raw.get("defense"),
                     "run_index": raw.get("run_index", 0), "success": out.get("success"),
                     "violation": out.get("violation"), "severity": out.get("severity", 0)})
    return rows


@app.get("/summary")
def get_summary() -> dict:
    """BatchResults.summary plus findings, per-attack ASR and benign pass rates (see batch_runner.compute_extras)."""
    return compute_extras(_load_results(), load_attack_library())


@app.get("/audit")
def get_audit() -> dict:
    """Permission audit table: tool, intended scope, observed use, verdict (plan v2 section 9)."""
    results = _load_results()
    rows = audit_permissions(results.traces)
    return {"generated_at": results.generated_at,
            "basis": f"{rows[0].runs_checked if rows else 0} undefended runs; by_defense shows what remains with each defense",
            "rows": [r.model_dump() for r in rows]}


@app.get("/regression")
def get_regression() -> dict:
    """Utility retention plus new_vuln flags per defense (plan v2 section 10). An empty list is a good result."""
    results = _load_results()
    report = regression_report([t for t in results.traces if t.attack_id != BENIGN_ATTACK_ID], results.summary)
    return {"generated_at": results.generated_at, **report}


@app.post("/replay/{run_id}", response_model=Trace)
def replay(run_id: str, response: Response, body: Optional[ReplayRequest] = None, live: bool = Query(False)) -> Trace:
    """Replay a saved attack, optionally with a different defense.

    Default: return the RECORDED run for that defense (instant, reproducible). With ?live=true: run it for real,
    and fall back to the recorded run if the live run fails or takes longer than AGENTBREAK_LIVE_TIMEOUT seconds.
    The header X-AgentBreak-Source says which one you got: cache, live or cache-fallback.
    """
    _require_safe(run_id, "run id")
    original = load_trace(run_id)
    if original is None:
        raise HTTPException(404, f"no run {run_id!r}")
    if original.attack_id == BENIGN_ATTACK_ID:
        raise HTTPException(400, "benign runs cannot be replayed (they are not attacks)")
    attack = load_attack(original.attack_id)
    if attack is None:
        raise HTTPException(404, f"attack {original.attack_id!r} is not in the attack library")

    defense: Defense = (body.defense if body and body.defense else None) or original.defense
    cached = load_trace(attack_run_id(attack.attack_id, defense, original.run_index))
    if not live and cached is not None:
        response.headers["X-AgentBreak-Source"] = "cache"
        return cached
    try:
        trace = _pool.submit(_execute_and_save, attack, defense, original.run_index).result(timeout=LIVE_TIMEOUT_S)
    except (Exception, FutureTimeout) as e:
        if cached is None:
            raise HTTPException(502, f"run failed: {type(e).__name__}: {e}")
        response.headers["X-AgentBreak-Source"] = "cache-fallback"
        response.headers["X-AgentBreak-Fallback-Reason"] = type(e).__name__
        return cached
    response.headers["X-AgentBreak-Source"] = "live"
    return trace


@app.get("/attacks")
def list_attacks() -> list[AttackPayload]:
    return list(load_attack_library().values())


@app.get("/defenses")
def list_defenses() -> dict:
    return DEFENSE_INFO


@app.get("/benign")
def list_benign() -> list[dict]:
    return [{"task_id": t.task_id, "prompt": t.prompt, "allowed_tools": sorted(t.allowed_tools),
             "expected": t.expected} for t in BENIGN_TASKS]
