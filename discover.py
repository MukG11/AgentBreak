"""Phase A (discovery): run Person 2's adaptive attacker once against the undefended OfficeBot.

    python discover.py                 # all 3 strategies, up to config.MAX_ATTACK_ATTEMPTS tries each
    python discover.py --defense none

What it writes
  data/results/winning_attacks.json   the payloads that worked (batch_runner.py replays these in Phase B)
  data/results/runs/<run_id>.json     every trace, so the dashboard can show how the attacker adapted

This file only wires attacker.py (Person 2) to recorder.py (Person 2). It was added during the merge because
attacker.py has no command-line entry point. Cost: every attempt is one or two OfficeBot tasks (about 15 to 35
seconds each), so a full run with all retries can take 10 to 20 minutes. Results are saved after EACH strategy,
so an API error late in the run does not lose the earlier winners.
"""
from __future__ import annotations

import argparse
import time

import attacker
import recorder

STRATEGIES = ("instruction_override", "authority_impersonation", "memory_poisoning")


def _run_strategy(strategy: str, defense: str) -> dict:
    if strategy == "memory_poisoning":
        attack, traces = attacker.run_memory_poisoning_attack(defense)
        success = bool(traces) and traces[-1].outcome.success
    else:
        attack, trace = attacker.run_single_shot_attack(strategy, defense)
        traces, success = [trace], trace.outcome.success
    return {"strategy": strategy, "attack": attack, "traces": traces, "success": success}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--defense", default="none", choices=["none", "D1", "D2", "D3", "all"],
                    help="discovery is normally against the undefended agent")
    args = ap.parse_args(argv)

    results: list[dict] = []
    print(f"Phase A: attacker vs OfficeBot (defense={args.defense}), up to "
          f"{attacker.config.MAX_ATTACK_ATTEMPTS} attempts per strategy")
    for strategy in STRATEGIES:
        t0 = time.time()
        try:
            res = _run_strategy(strategy, args.defense)
        except Exception as e:      # keep earlier winners if the API fails part-way through
            print(f"  {strategy:<24} ERROR {type(e).__name__}: {str(e)[:150]}")
            continue
        for t in res["traces"]:
            recorder.record(t)
        results.append(res)
        attacker.save_winning_attacks(results)
        last = res["traces"][-1].outcome if res["traces"] else None
        verdict = f"WON  ({last.violation}, severity {last.severity})" if res["success"] else "failed"
        print(f"  {strategy:<24} {verdict}  after {res['attack'].attempt} attempt(s)  [{time.time() - t0:.0f}s]")

    wins = sum(1 for r in results if r["success"])
    print(f"\n{wins} of {len(STRATEGIES)} strategies found a working attack. "
          f"Saved to data/results/winning_attacks.json")
    print("Next: python batch_runner.py --estimate   then   python batch_runner.py --delay 2")
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
