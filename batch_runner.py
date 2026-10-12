"""Person 3: batch runner. Every attack x every defense x N runs, plus the benign suite per defense.

    python batch_runner.py --estimate          # how many runs / LLM calls, nothing is executed
    python batch_runner.py --runs 1 --defenses none all --max-attacks 1    # tiny smoke test first
    python batch_runner.py                     # the full batch (resumable: finished runs are skipped)
    python batch_runner.py --redetect          # re-decide success on saved traces (no LLM calls)

Each finished run is written to data/results/runs/<run_id>.json immediately, so a crash or a rate-limit
stop loses nothing. The final aggregate goes to data/results/batch_results.json (shape: BatchResults).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config
from audit import audit_permissions, new_vuln_keys, regression_report, seeded_vs_found
from benign_tasks import BENIGN_TASKS, benign_run_id, evaluate, run_benign
from contract import AttackPayload, BatchResults, BenignResult, Defense, DefenseSummary, Outcome, Trace
from p3_common import (
    SEED_ATTACKS_FILE, _atomic_write, _read_attack_list, attack_run_id, execute_run, get_detect, load_trace,
    results_dir, run_detect, runs_dir, save_attack, save_trace, winning_attacks_file,
)
import p3_common

DEFENSE_ORDER: list[Defense] = ["none", "D1", "D2", "D3", "all"]


# ============================================================================= choosing attacks
def failed_attacks_file() -> Path:
    return results_dir() / "failed_attacks.json"


def load_attacks(path: Optional[Path] = None, with_seeds: bool = False,
                 with_failed: bool = False) -> tuple[list[AttackPayload], str]:
    """Phase A winners (Person 2's winning_attacks.json) if present, otherwise our seeded ones (clearly reported).
    with_failed adds payloads that FAILED at baseline (failed_attacks.json); only those can reveal a new_vuln."""
    if path:
        return _read_attack_list(path), f"attacks from {path}"
    winners = _read_attack_list(winning_attacks_file())
    seeds = _read_attack_list(SEED_ATTACKS_FILE)
    if winners and with_seeds:
        ids = {a.attack_id for a in winners}
        attacks, source = winners + [s for s in seeds if s.attack_id not in ids], "attacker winners + seeded attacks"
    elif winners:
        attacks, source = winners, "attacker winners (winning_attacks.json)"
    else:
        attacks = seeds
        source = "SEEDED attacks only (winning_attacks.json not found, so nothing was discovered by the attacker)"
    if with_failed:
        have = {a.attack_id for a in attacks}
        extra = [a for a in _read_attack_list(failed_attacks_file()) if a.attack_id not in have]
        attacks, source = attacks + extra, f"{source} + {len(extra)} baseline-failed attacks"
    return attacks, source


# ============================================================================= aggregation
def compute_summary(attack_traces: list[Trace], benign: list[BenignResult],
                    defenses: list[Defense]) -> list[DefenseSummary]:
    """ASR per defense and utility retention (benign pass rate with the defense / pass rate with none)."""
    def pass_rate(defense: str) -> Optional[float]:
        rs = [r for r in benign if r.defense == defense]
        return sum(r.passed for r in rs) / len(rs) if rs else None

    base = pass_rate("none")
    out: list[DefenseSummary] = []
    for d in defenses:
        ts = [t for t in attack_traces if t.defense == d]
        asr = sum(t.outcome.success for t in ts) / len(ts) if ts else 0.0
        rate = pass_rate(d)
        if rate is None or not base:
            retention = 0.0          # no benign data (or a failing baseline): reported as 0, warned about in main()
        else:
            retention = min(1.0, rate / base)
        out.append(DefenseSummary(defense=d, asr=round(asr, 4), runs=len(ts), utility_retention=round(retention, 4)))
    return out


def compute_extras(results: BatchResults, library: dict[str, AttackPayload]) -> dict:
    """Everything the dashboard needs beyond BatchResults.summary: findings, per-attack ASR, benign pass rates."""
    attack_traces = results.traces
    defenses = [s.defense for s in results.summary] or DEFENSE_ORDER

    per_attack: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
    for t in attack_traces:
        per_attack[t.attack_id][t.defense].append(t.outcome.success)

    attack_rows, findings = [], []
    for attack_id, by_def in per_attack.items():
        asr = {d: round(sum(v) / len(v), 4) for d, v in by_def.items() if v}
        meta = library.get(attack_id)
        row = {"attack_id": attack_id, "strategy": meta.strategy if meta else None,
               "vector": meta.vector if meta else None,
               "discovered_by": meta.discovered_by if meta else None, "asr": asr}
        attack_rows.append(row)
        base = asr.get("none", 0.0)
        if base > 0:
            wins = [t for t in attack_traces if t.attack_id == attack_id and t.defense == "none" and t.outcome.success]
            violations = Counter(t.outcome.violation for t in wins if t.outcome.violation)
            findings.append({
                **{k: row[k] for k in ("attack_id", "strategy", "vector", "discovered_by")},
                "violation": violations.most_common(1)[0][0] if violations else None,
                "severity": max(t.outcome.severity for t in wins),
                "success_rate_without_defense": base,
                "reduced_by": [d for d in defenses if d != "none" and asr.get(d, base) < base],
                "fully_blocked_by": [d for d in defenses if d != "none" and d in asr and asr[d] == 0.0],
            })

    attempts: dict[str, int] = {}
    for f in findings:
        meta = library.get(f["attack_id"])
        if meta and meta.discovered_by == "attacker" and meta.strategy:
            attempts[meta.strategy] = min(attempts.get(meta.strategy, meta.attempt), meta.attempt)

    # Share of runs per defense that ended in each kind of violation (shows e.g. D3 driving canary leaks to 0).
    by_violation: dict[str, dict[str, float]] = {}
    for d in defenses:
        ts = [t for t in attack_traces if t.defense == d]
        counts = Counter(t.outcome.violation for t in ts if t.outcome.success and t.outcome.violation)
        by_violation[d] = {v: round(counts.get(v, 0) / len(ts), 4) if ts else 0.0
                           for v in ("canary_leak", "unauthorized_tool", "memory_poison")}

    benign_rows = []
    for task in BENIGN_TASKS:
        rates = {}
        for d in defenses:
            rs = [r for r in results.benign if r.task_id == task.task_id and r.defense == d]
            if rs:
                rates[d] = round(sum(r.passed for r in rs) / len(rs), 4)
        benign_rows.append({"task_id": task.task_id, "prompt": task.prompt, "pass_rate": rates})

    return {
        "generated_at": results.generated_at,
        "model": results.model,
        "runs_per_attack": results.runs_per_attack,
        "summary": [s.model_dump() for s in results.summary],
        "seeded_vs_found": seeded_vs_found(attack_traces, library),
        "regression": regression_report(attack_traces, results.summary),
        "audit": [r.model_dump() for r in audit_permissions(results.traces)],
        "findings": {
            "count": len(findings),
            "max_severity": max((f["severity"] for f in findings), default=0),
            "by_violation": dict(Counter(f["violation"] for f in findings if f["violation"])),
            "items": findings,
        },
        "per_attack": attack_rows,
        "violation_rate_by_defense": by_violation,
        "attempts_to_first_success": attempts,
        "benign": benign_rows,
    }


def _fingerprint(t: Trace) -> str:
    raw = json.dumps([(s.type, s.content, s.tool, s.args) for s in t.steps], sort_keys=True, default=str)
    return hashlib.sha1(raw.encode()).hexdigest()


def identical_run_groups(attack_traces: list[Trace]) -> tuple[int, int]:
    """(groups where every repeat produced the same trace, total groups with repeats)."""
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for t in attack_traces:
        groups[(t.attack_id, t.defense)].append(_fingerprint(t))
    repeated = [v for v in groups.values() if len(v) > 1]
    return sum(1 for v in repeated if len(set(v)) == 1), len(repeated)


# ============================================================================= planning and running
def plan_counts(attacks: list[AttackPayload], defenses: list[Defense], runs: int, benign: bool) -> dict:
    attack_runs = len(attacks) * len(defenses) * runs
    benign_runs = len(BENIGN_TASKS) * len(defenses) * runs if benign else 0
    two_task = sum(1 for a in attacks if a.follow_up_task)
    calls_upper = (
        (len(attacks) + two_task) * len(defenses) * runs * config.MAX_AGENT_STEPS
        + benign_runs * config.MAX_AGENT_STEPS
    )
    done = sum(
        1 for a in attacks for d in defenses for i in range(runs)
        if (runs_dir() / f"{attack_run_id(a.attack_id, d, i)}.json").exists()
    ) + (sum(
        1 for t in BENIGN_TASKS for d in defenses for i in range(runs)
        if (runs_dir() / f"{benign_run_id(t.task_id, d, i)}.json").exists()
    ) if benign else 0)
    return {"attack_runs": attack_runs, "benign_runs": benign_runs, "total_runs": attack_runs + benign_runs,
            "already_cached": done, "llm_calls_upper_bound": calls_upper}


def run_batch(attacks: list[AttackPayload], defenses: list[Defense], runs: int, benign: bool,
              delay: float, fresh: bool, only_benign: bool) -> list[str]:
    """Execute every missing run and save each trace as it finishes. Returns error messages."""
    jobs: list[tuple] = []
    if not only_benign:
        for a in attacks:
            save_attack(a)
            for d in defenses:
                for i in range(runs):
                    jobs.append(("attack", a, d, i, attack_run_id(a.attack_id, d, i)))
    if benign:
        for t in BENIGN_TASKS:
            for d in defenses:
                for i in range(runs):
                    jobs.append(("benign", t, d, i, benign_run_id(t.task_id, d, i)))

    errors: list[str] = []
    for n, (kind, item, d, i, run_id) in enumerate(jobs, 1):
        path = runs_dir() / f"{run_id}.json"
        if path.exists() and not fresh:
            continue
        label = f"[{n}/{len(jobs)}] {run_id}"
        try:
            if kind == "attack":
                trace = execute_run(item, d, i, run_id=run_id)
                result = f"attack {'SUCCEEDED' if trace.outcome.success else 'failed'} ({trace.outcome.violation})"
            else:
                trace, res = run_benign(item, d, i)
                result = f"benign {'pass' if res.passed else 'FAIL'}: {res.detail}"
            save_trace(trace)
            print(f"{label}: {result}", flush=True)
        except Exception as e:                      # rate limit after retries, bad model output, ...
            msg = f"{run_id}: {type(e).__name__}: {e}"
            errors.append(msg)
            print(f"{label}: ERROR {msg}", file=sys.stderr, flush=True)
        if delay:
            time.sleep(delay)
    return errors


def assemble(attacks: list[AttackPayload], defenses: list[Defense], runs: int, benign: bool,
             redetect: bool) -> BatchResults:
    """Build BatchResults from the trace files on disk (so a resumed or partial batch still aggregates)."""
    attack_traces: list[Trace] = []
    for a in attacks:
        for d in defenses:
            for i in range(runs):
                t = load_trace(attack_run_id(a.attack_id, d, i))
                if t is None:
                    continue
                if redetect:
                    t.outcome = run_detect(t)
                    save_trace(t)
                attack_traces.append(t)

    benign_results: list[BenignResult] = []
    benign_traces: list[Trace] = []
    if benign:
        for task in BENIGN_TASKS:
            for d in defenses:
                for i in range(runs):
                    t = load_trace(benign_run_id(task.task_id, d, i))
                    if t is not None:
                        benign_traces.append(t)
                        benign_results.append(evaluate(task, t))

    if "new_vuln" in Outcome.model_fields:               # plan v2 contract field
        flagged = new_vuln_keys(attack_traces)
        for t in attack_traces:
            t.outcome.new_vuln = (t.attack_id, t.defense) in flagged

    return BatchResults(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        model=config.MODEL,
        runs_per_attack=runs,
        traces=attack_traces + benign_traces,
        benign=benign_results,
        summary=compute_summary(attack_traces, benign_results, defenses),
    )


def score_utility(defense: Defense, runs: int = 1) -> float:
    """Plan v2 interface: utility retention for one defense = benign pass rate with it / pass rate with none.
    Uses cached benign runs and executes only the missing ones (needs the LLM for those)."""
    rates: dict[str, float] = {}
    for d in ("none", defense):
        results: list[BenignResult] = []
        for task in BENIGN_TASKS:
            for i in range(runs):
                t = load_trace(benign_run_id(task.task_id, d, i))
                if t is None:
                    t, _ = run_benign(task, d, i)
                    save_trace(t)
                results.append(evaluate(task, t))
        rates[d] = sum(r.passed for r in results) / len(results)
    if not rates["none"]:
        return 0.0
    return round(min(1.0, rates[defense] / rates["none"]), 4)


# ============================================================================= CLI
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="AgentBreak batch runner (Person 3)")
    p.add_argument("--attacks", type=Path, help="JSON file of AttackPayloads (default: winning_attacks.json, else seeds)")
    p.add_argument("--with-seeds", action="store_true", help="also include the seeded attacks next to the attacker's winners")
    p.add_argument("--with-failed", action="store_true",
                   help="also run payloads that failed at baseline (failed_attacks.json) so new_vuln can be detected")
    p.add_argument("--defenses", nargs="+", default=DEFENSE_ORDER, choices=DEFENSE_ORDER)
    p.add_argument("--runs", type=int, default=config.RUNS_PER_ATTACK, help="repeats per attack/task/defense")
    p.add_argument("--max-attacks", type=int, help="only the first N attacks (smoke tests)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds to sleep between runs (rate limits)")
    p.add_argument("--no-benign", action="store_true", help="skip the benign suite")
    p.add_argument("--only-benign", action="store_true", help="run only the benign suite")
    p.add_argument("--fresh", action="store_true", help="ignore cached runs and redo everything")
    p.add_argument("--redetect", action="store_true", help="re-decide success on saved traces, no LLM calls")
    p.add_argument("--estimate", action="store_true", help="print the size of the batch and exit")
    p.add_argument("--no-write", action="store_true", help="do not write batch_results.json")
    args = p.parse_args(argv)

    attacks, source = load_attacks(args.attacks, args.with_seeds, args.with_failed)
    if args.max_attacks:
        attacks = attacks[: args.max_attacks]
    defenses: list[Defense] = list(args.defenses)
    benign = not args.no_benign
    print(f"Attacks: {len(attacks)} ({source})")

    counts = plan_counts(attacks, defenses, args.runs, benign)
    print(f"Plan: {counts['attack_runs']} attack runs + {counts['benign_runs']} benign runs = {counts['total_runs']} "
          f"({counts['already_cached']} already cached). LLM calls, upper bound: {counts['llm_calls_upper_bound']}.")
    if args.estimate:
        return 0

    if not (args.redetect):
        errors = run_batch(attacks, defenses, args.runs, benign, args.delay, args.fresh, args.only_benign)
    else:
        errors = []
    get_detect()
    if p3_common.USING_FALLBACK_DETECTOR:
        print("WARNING: detectors.py (Person 2) not found. Success was decided by Person 3's fallback detector, "
              "which implements the same three rules from CONTRACT.md. Run --redetect once Person 2 delivers.")

    results = assemble(attacks, defenses, args.runs, benign, args.redetect)
    same, repeated = identical_run_groups([t for t in results.traces if t.attack_id != "benign"])
    if repeated and same == repeated and args.runs > 1:
        print(f"WARNING: all {repeated} repeated groups produced identical traces. With temperature 0 and a "
              "cache keyed on the full prompt, repeating a run adds no information, so the 5-run rates are really "
              "1 run. Either accept that (replays are reproducible) or have Person 1 add run_index to the cache "
              "key and use a small temperature for batch repeats.")

    if not args.no_write:
        _atomic_write(config.RESULTS_FILE, results.model_dump_json(indent=2))
        analysis = compute_extras(results, p3_common.load_attack_library())
        analysis_path = config.RESULTS_FILE.with_name("analysis.json")
        _atomic_write(analysis_path, json.dumps(analysis, indent=2))
        print(f"Wrote {config.RESULTS_FILE}\nWrote {analysis_path} (summary, audit table, regression flags, seeded vs found)")
    print("\ndefense   ASR     runs  utility")
    for s in results.summary:
        print(f"{s.defense:<8} {s.asr:>6.1%} {s.runs:>5}  {s.utility_retention:>6.1%}")
    if benign and not results.benign:
        print("WARNING: no benign results, utility retention is reported as 0.")
    reg = regression_report([t for t in results.traces if t.attack_id != "benign"], results.summary)
    print(f"\nRegression: {reg['message']}")
    if errors:
        print(f"\n{len(errors)} run(s) failed and were skipped; re-run the same command to retry only those.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
