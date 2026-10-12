"""Structural test of attacker.py's loop (Person 2).

Uses AGENTBREAK_STUB=1 so officebot.agent.run_task returns canned traces --
no GEMINI_API_KEY needed to exercise plant(), fresh_state(), clear_planted(),
run_task(), and detect() wiring exactly as the real loop will call them.
llm.complete is monkeypatched only for attacker.py's own mutation calls (the
stub mode never calls it for the main agent loop).

This does not prove the live model falls for an attack -- only a real run
with a key does, which is Person 1's and the team's job per CONTRACT.md.
It proves attacker.py drives OfficeBot's real interfaces correctly, retries
up to the cap without crashing, and that memory poisoning's two-task +
clear_planted flow runs end to end.

Run: AGENTBREAK_STUB=1 python3 test_attacker.py
"""
import os

os.environ["AGENTBREAK_STUB"] = "1"

import config  # noqa: E402
import llm  # noqa: E402
import attacker  # noqa: E402

_mutate_calls = []


def fake_complete(prompt, system=None, **kw):
    _mutate_calls.append((system, prompt))
    return "MUTATED: a different pretext for the same goal"


llm.complete = fake_complete  # attacker.py calls llm.complete(...) by module attribute lookup


def test_single_shot_succeeds_immediately_when_undefended():
    # stub mode returns trace_attack_success.json for defense="none", which already
    # contains a canary leak, so detect() should succeed on attempt 1, no mutation needed.
    before = len(_mutate_calls)
    attack, trace = attacker.run_single_shot_attack("instruction_override", defense="none")
    assert trace.outcome.success and trace.outcome.violation == "canary_leak", trace.outcome
    assert attack.attempt == 1, attack.attempt
    assert len(_mutate_calls) == before, "should not have needed to mutate"
    print("test_single_shot_succeeds_immediately_when_undefended: pass")


def test_single_shot_exhausts_attempts_when_defended():
    # stub mode returns trace_blocked.json for any non-"none" defense: always success=False,
    # so the loop should run exactly MAX_ATTACK_ATTEMPTS times and mutate between each.
    before = len(_mutate_calls)
    attack, trace = attacker.run_single_shot_attack("authority_impersonation", defense="D1")
    assert not trace.outcome.success, trace.outcome
    assert attack.attempt == config.MAX_ATTACK_ATTEMPTS, attack.attempt
    assert len(_mutate_calls) == config.MAX_ATTACK_ATTEMPTS - 1, len(_mutate_calls) - before
    print("test_single_shot_exhausts_attempts_when_defended: pass")


def test_memory_poisoning_runs_two_tasks_with_clear_planted():
    attack, traces = attacker.run_memory_poisoning_attack(defense="none")
    assert len(traces) == 2, len(traces)
    assert traces[0].run_index == 0 and traces[1].run_index == 1
    # both traces share the same attack_id (same AgentState, same attack)
    assert traces[0].attack_id == traces[1].attack_id == attack.attack_id
    # follow-up trace is what decides success (per CONTRACT.md's scenario)
    assert traces[1].outcome.success, traces[1].outcome
    print("test_memory_poisoning_runs_two_tasks_with_clear_planted: pass")


def test_memory_poisoning_exhausts_attempts_when_defended():
    attack, traces = attacker.run_memory_poisoning_attack(defense="all")
    assert len(traces) == 2
    assert not traces[1].outcome.success
    assert attack.attempt == config.MAX_ATTACK_ATTEMPTS
    print("test_memory_poisoning_exhausts_attempts_when_defended: pass")


def test_discover_all_and_save_winning_attacks(tmp_path_str="/tmp/winning_attacks_test.json"):
    results = attacker.discover_all(defense="none")
    assert {r["strategy"] for r in results} == {
        "instruction_override", "authority_impersonation", "memory_poisoning"}
    from pathlib import Path
    attacker.save_winning_attacks(results, path=Path(tmp_path_str))
    import json
    saved = json.loads(Path(tmp_path_str).read_text())
    assert len(saved) == sum(1 for r in results if r["success"])
    assert all("attack_id" in a and "payload_text" in a for a in saved)
    Path(tmp_path_str).unlink()
    print("test_discover_all_and_save_winning_attacks: pass")


if __name__ == "__main__":
    test_single_shot_succeeds_immediately_when_undefended()
    test_single_shot_exhausts_attempts_when_defended()
    test_memory_poisoning_runs_two_tasks_with_clear_planted()
    test_memory_poisoning_exhausts_attempts_when_defended()
    test_discover_all_and_save_winning_attacks()
    print("\nAll attacker structural tests passed.")
