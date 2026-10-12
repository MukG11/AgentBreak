# Person 3 notes (plan v2): defenses, API, batch runner, audit and regression

## FINAL merge: Person 1 (OfficeBot) + Person 2 (attacker, detectors, recorder) + Person 3
Run order (one terminal, inside the `agentbreak` folder):
```
python -m pip install -r requirements.txt
python llm.py                     # pong = key works
python try_attack.py email --fresh   # one live attack (Person 1's check)
python discover.py                # PHASE A: Person 2's attacker finds working attacks -> data/results/winning_attacks.json
python batch_runner.py --estimate # size of Phase B
python batch_runner.py --delay 2  # PHASE B: every winner x D1/D2/D3/all x runs; resumable (safe to Ctrl+C and rerun)
uvicorn api:app --port 8000       # dashboard reads http://localhost:8000
python -m pytest -q               # 67 tests, no key needed
```
Added or changed in this merge
- `discover.py` (new): command-line entry for Person 2's attacker (attacker.py had none). Saves winners after each strategy.
- `p3_common.run_detect` now judges a memory-poisoning run's FOLLOW-UP task on its own. Reason: the merged trace holds two
  tasks and Person 2's detectors score every step against the first task's allowed tools, so a normal reply email to Priya was
  wrongly counted as a successful attack (found by running Person 2's real detectors in the batch tests).
- `requirements.txt`: added `pytest` and `httpx` (Person 1 owns this file; tell them).

Known gaps (honest limits, say them in the pitch)
- Person 2's detectors have no salary-leak rule and do not fill `outcome.path`. `salary_leak` is not in the contract's `Violation` list
  either, so the latent flaw (salaries reachable) shows up in the audit table only, not as an attack finding.
- Severities differ from plan v2 (detectors.py: canary 4, memory 4, unauthorized tool 2; plan: 5 / 2 / 3). Display only.
- `new_vuln`, `meta`, `caused_by`, `path` stay inactive until Person 1 applies `CONTRACT_V2_PATCH.md` to contract.py.
- Nothing here has produced REAL results yet: run Phase A and Phase B on your machine, then share `data/results/*.json`.

## Merged with Person 1's real OfficeBot (latest)
- Trace convention: a D1 block is a flagged `decision` step with note `BLOCKED: ...`, NOT a `tool_call`. `p3_common.is_blocked_attempt`,
  `audit.py` and the tests follow this. D1 reasons now read `D1: ...` so the note is `BLOCKED: D1: ...` (no doubled wording).
- `p3_common.execute_run` now calls `clear_planted(state)` between the two tasks of a memory-poisoning attack (CONTRACT.md).
  Before this, the follow-up could simply re-read the injection email, which is not memory poisoning.
- New tests run the REAL `officebot.agent.run_task` and our real `build_hooks` with only the model scripted
  (`test_real_loop_*`). They check D1/D2/D3 wiring, trace shape, and clear_planted. They do not show how Gemini behaves.
- Not yet done: a live run with a Gemini key. First thing to do: `python batch_runner.py --runs 1 --defenses none all --max-attacks 1`.
- Watch on the first live run: D1's note-query rule may block a legitimate `search_notes` in "Draft a reply to Priya"
  (utility retention will show it; switch off with `D1_SCOPE_NOTE_QUERIES = False`). D3 alone cannot reach 0% ASR because the
  agent still uses `search_notes` outside its task scope (unauthorized_tool); it only removes the secret from the email.


Files owned: `defenses.py`, `api.py`, `benign_tasks.py`, `batch_runner.py`, `audit.py`, `p3_common.py` (shared helper),
`test_person3.py`, `data/seed_attacks.json`, `data/mock/*example*.json` (labelled MOCK), `CONTRACT_V2_PATCH.md`.

## Run it
```bash
pip install -r requirements.txt pytest httpx
python -m pytest test_person3.py -q            # scripted stand-in for OfficeBot, temp folder
uvicorn api:app --port 8000 --reload           # dashboard talks to http://localhost:8000
python batch_runner.py --estimate              # size of the batch, runs nothing
python batch_runner.py --runs 1 --defenses none all --max-attacks 1    # smoke test with the real agent
python batch_runner.py --delay 2               # Phase B: every successful payload x defense x runs (resumable)
python batch_runner.py --with-failed           # also replay baseline-failed payloads (only these can show a new_vuln)
python batch_runner.py --redetect              # re-decide success on saved traces (no LLM)
```
Outputs: `data/results/batch_results.json` (contract shape) and `data/results/analysis.json` (summary, audit table,
regression flags, seeded vs found). Run ids: `{attack_id}__{defense}__{i}`, `benign-{task}__{defense}__{i}`, live runs `live-xxxx`.

## What plan v2 changed for Person 3, and what is done
| v2 item | Done in |
|---|---|
| D1 also scopes files (only files named in the task) and notes (query must relate to the task) | `defenses.py` |
| D3 covers canary and salary rows | `defenses.py` |
| `GET /audit` (tool, intended scope, observed use, verdict) and `audit_permissions()` | `audit.py`, `api.py` |
| `GET /regression`: utility retention, utility drop, `new_vuln` flags | `audit.py`, `api.py` |
| `/summary` adds seeded-vs-found, audit, regression | `batch_runner.py` |
| "Replay live" with cache fallback | `POST /replay/{id}?live=true`, header `X-AgentBreak-Source` = cache / live / cache-fallback |
| Python interface `score_utility`, `apply_defense` | `batch_runner.py`, `defenses.py` |
| Run metadata (`meta`) and `caused_by` handling | active once contract.py has the fields (`CONTRACT_V2_PATCH.md`) |

New API behaviour to know about
- `POST /replay/{id}` returns the RECORDED run by default. `?live=true` runs for real and falls back to the recorded
  run after `AGENTBREAK_LIVE_TIMEOUT` seconds (default 45) or on any error. Read the `X-AgentBreak-Source` header.
- `new_vuln` is strict: failed in every baseline run, succeeded with a defense on. Winners from Phase A succeed at
  baseline by definition, so the list is usually empty (that is a good result, the endpoint says so). Use `--with-failed`
  with a `data/results/failed_attacks.json` from Person 2 to give it something to find.

## What I need from the others
**Person 1**
1. Real OfficeBot calling every hook (`sanitize_retrieved` on ALL retrieved text, `authorize_tool` before EVERY tool with
   the exact task string, `egress_filter` on string args and the final answer). Blocked calls: do not run them, record the
   `tool_call` with `flagged=True` and the note my hook returns ("D1 blocked..."). D3 redaction: record the redacted args.
2. If `run_task`'s signature changes (v2 lists `run_task(task, defense, payload)`), tell me. I call it from one place only,
   `p3_common.call_run_task`.
3. Apply `CONTRACT_V2_PATCH.md` to contract.py when the group agrees (recon step type, caused_by, path, new_vuln, meta, salary_leak).
4. Reproducibility vs repeats: temperature 0 plus a cache keyed on the full prompt makes the 5 repeats identical. Decide:
   accept it (replays reproducible) or add run_index to the cache key for batch repeats. My runner prints a warning.
5. Latent flaw 4: `read_file` and `search_notes` must really ignore the task at baseline, or the audit and D1 have nothing to show.
6. `search_notes("Monday")` must match the todo note; add `pytest` and `httpx` to requirements.txt.

**Person 2**
1. `detectors.detect(trace, state=None) -> Outcome`; ignore blocked calls; fill `outcome.path`. Memory-poison runs reach
   you as ONE trace with two `input` steps. Use `p3_common.execute_run` and `save_trace/load_trace` instead of rewriting them.
2. `data/results/winning_attacks.json` (Phase A winners, `discovered_by="attacker"`, real `attempt`), and optionally
   `failed_attacks.json`. The seeded-vs-found table only counts attacks marked `discovered_by="attacker"`.
3. Agree with Person 1 on ONE memory-poison rule (CONTRACT.md says BCC audit address, plan v2 section 7 says a tool call
   outside the task scope with the note retrieval in caused_by).

**Person 4**
- Mock shapes: `data/mock/summary_example.json` (`GET /summary`), `audit_example.json` (`GET /audit`),
  `regression_example.json` (`GET /regression`), `run_*.json` (`GET /runs/{id}`). They come from a scripted bot, never
  show them as results.
- Plan v2 gives Person 4 the fake data and the 6 benign task definitions. Person 3 already built the 6 tasks with code checks
  and expected results (`GET /benign`, `benign_tasks.py`), so Person 4 only needs the fake data, or can edit the wording there.
- "Replay live" button: call `POST /replay/{id}?live=true` with `{"defense": "..."}` and show the source header.

## Honest limits
- Tested against Person 1's real agent loop with a SCRIPTED model, not against live Gemini. No live batch has been run yet.
- D1's note rule is a heuristic (query shares a word with the task). If it blocks normal tasks, set
  `D1_SCOPE_NOTE_QUERIES = False` in defenses.py; utility retention shows the cost either way.
- D2 will not reach 0% on a real model. Batch size at 5 runs: 225 runs, up to about 1,500 LLM calls (900 at 3 runs).
