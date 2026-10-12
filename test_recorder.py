"""Test recorder.py round-trips a Trace through disk correctly.

Run: python3 test_recorder.py
"""
import shutil

from contract import Outcome, Step, Trace
import recorder


def test_record_and_load_round_trip():
    if recorder.RUNS_DIR.exists():
        shutil.rmtree(recorder.RUNS_DIR)

    trace = Trace(
        run_id="rr-test-001", attack_id="a1", defense="none", run_index=0,
        steps=[Step(i=0, type="input", content="Summarize my inbox"),
              Step(i=1, type="tool_call", tool="read_inbox", args={})],
        outcome=Outcome(success=False, violation=None, severity=0, detail="no violation detected"),
    )
    run_id = recorder.record(trace)
    assert run_id == "rr-test-001"

    loaded = recorder.load(run_id)
    assert loaded.run_id == trace.run_id
    assert loaded.steps[1].tool == "read_inbox"
    assert loaded.outcome.success is False
    print("test_record_and_load_round_trip: pass")


def test_list_runs():
    runs = recorder.list_runs()
    assert "rr-test-001" in runs, runs
    print("test_list_runs: pass")

    shutil.rmtree(recorder.RUNS_DIR)


if __name__ == "__main__":
    test_record_and_load_round_trip()
    test_list_runs()
    print("\nAll recorder tests passed.")
