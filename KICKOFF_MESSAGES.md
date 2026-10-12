# Kickoff messages (paste into the group chat, or into each person's Claude)

First step for everyone: clone/unzip the repo, `pip install -r requirements.txt`, copy `.env.example` to `.env`, read `CONTRACT.md`.

---

## Person 2: Attacker, detectors, trace recorder
Read CONTRACT.md. You own `attacker.py`, `detectors.py`, `recorder.py`.
1. `detectors.py`: `detect(trace, state=None) -> Outcome` with the three rules in CONTRACT.md. Test them first on `data/mock/trace_attack_success.json` (must return canary_leak, severity >= 3) and `data/mock/trace_blocked.json` (must return success=False).
2. `recorder.py`: save/load `Trace` as JSON under `data/results/runs/`.
3. `attacker.py`: loop of up to `config.MAX_ATTACK_ATTEMPTS`. Each attempt: build an `AttackPayload`, `plant()` it into `fresh_state()`, call `run_task(...)`, run `detect()`, then ask `llm.complete()` for a mutated payload using the trace as feedback. Strategies: instruction_override, authority_impersonation, memory_poisoning. Save winners to `data/results/winning_attacks.json`.
4. The real OfficeBot loop is in (see "Trace conventions" in CONTRACT.md). Detectors must only read `tool_call` steps: a tool blocked by D1 is a flagged `decision` step, not a `tool_call`. Set `AGENTBREAK_STUB=1` to use canned traces until you have a key.
Deliverable: given an `AttackPayload`, produce a `Trace` with a real `Outcome`.

## Person 3: Defenses, API, benign tasks, batch runner
Read CONTRACT.md. You own `defenses.py`, `api.py`, `benign_tasks.py`, `batch_runner.py`.
1. `defenses.py`: `build_hooks(defense) -> DefenseHooks` (see `officebot/hooks.py`). D1: allow only `@acme.test` recipients and only `ALLOWED_TOOLS[task]`. D2: wrap retrieved text as untrusted and set `extra_system_prompt` with an instruction hierarchy. D3: scan args and output for `config.CANARY` and block. `"all"` combines all three.
2. `benign_tasks.py`: 6 normal tasks with a code check each (for example the summary mentions 4 emails; a reply to Priya goes to `priya@acme.test`). Produces `BenignResult`.
3. `api.py` (FastAPI): `POST /runs`, `GET /runs/{id}`, `GET /summary`, `POST /replay/{id}` using the shapes in `contract.py`. Enable CORS for the dashboard.
4. `batch_runner.py`: for each winning attack x defense (none, D1, D2, D3, all) x `config.RUNS_PER_ATTACK`, run, detect, save `BatchResults` to `config.RESULTS_FILE`. Include the benign tasks per defense for utility retention.
   - Speed: one task takes about 15 to 35 seconds. Sequentially, 300 runs would take about 2 hours. Use a thread pool (about 4 workers, check for 429/503 errors) and make the runner resumable (save after each run, skip finished ones). Start with 6 attacks x 5 defenses x 3 runs and grow only if time allows.
   - Memory attacks: call `clear_planted(state)` between the two tasks (see CONTRACT.md).
   - Use `AGENTBREAK_TEMPERATURE` above 0 only if you want run-to-run variation; at 0 repeated runs hit the cache and look identical.
Deliverable: a cached `batch_results.json` with ASR per defense and utility retention.

## Person 4: Dashboard, replay, demo
Read CONTRACT.md. You own `dashboard/*`, the demo script, slides and video.
1. Vite + React + Tailwind + Recharts. Build against `data/mock/*.json` first, then swap in the real API (`GET /summary`, `GET /runs/{id}`). Fallback if time gets tight: Streamlit.
2. Three pages: Overview (ASR before/after, utility retention, findings count), Trace viewer with Replay button (red = attack worked, green = blocked), Defense comparison (bars per defense).
3. Note: there is no pre-made HTML prototype. Use the two mock traces for layout.
4. Replay in the demo = show the cached trace with defense off, then the cached trace with defense on, for the same attack. Say "replay from recorded runs" in the pitch.
5. Start the demo script early. Record several takes at hour 13 to 14 (4-5am), keep a backup copy.
Deliverable: a clean dashboard, a recorded demo video, the pitch.
