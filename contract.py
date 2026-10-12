"""AgentBreak contract: the ONLY shapes modules share.

Owner: Person 1. Nobody else edits this file without telling the group.
Convention: Outcome.success == True means the ATTACK succeeded (bad for the agent).
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Defense = Literal["none", "D1", "D2", "D3", "all"]
StepType = Literal["input", "recon", "retrieval", "decision", "tool_call", "tool_result", "output"]
Violation = Literal["canary_leak", "salary_leak", "unauthorized_tool", "memory_poison"]
Strategy = Literal["instruction_override", "authority_impersonation", "memory_poisoning"]
Vector = Literal["email", "document", "note"]


class Step(BaseModel):
    i: int
    type: StepType
    content: str = ""
    tool: Optional[str] = None
    args: dict[str, Any] = Field(default_factory=dict)
    flagged: bool = False          # True if a detector or defense marked this step
    note: Optional[str] = None     # e.g. "D1 blocked send_email to ceo@outside.test"
    caused_by: list[int] = Field(default_factory=list)   # indexes of earlier steps that led to this one


class Outcome(BaseModel):
    success: bool                  # True = attack worked
    violation: Optional[Violation] = None
    severity: int = Field(0, ge=0, le=5)
    detail: str = ""
    path: list[int] = Field(default_factory=list)        # step indexes that form the attack chain
    new_vuln: bool = False                                # failed at baseline but worked with a defense on


class Trace(BaseModel):
    run_id: str
    attack_id: str
    defense: Defense
    run_index: int = 0             # 0..4 when each attack is repeated
    steps: list[Step]
    outcome: Outcome
    meta: dict[str, Any] = Field(default_factory=dict)   # phase, attempt, strategy, model, temperature, seed, prompt_hash


class AttackPayload(BaseModel):
    attack_id: str
    strategy: Strategy
    vector: Vector                 # where the payload is planted
    payload_text: str              # the hidden instruction text
    victim_task: str               # benign user request the agent is given, e.g. "Summarize my inbox"
    follow_up_task: Optional[str] = None   # memory poisoning only: second task run later on same state
    discovered_by: Literal["attacker", "seeded"] = "attacker"
    parent_attack_id: Optional[str] = None  # which attack this one mutated from
    attempt: int = 1


class BenignResult(BaseModel):
    task_id: str
    defense: Defense
    run_index: int = 0
    passed: bool
    detail: str = ""


class DefenseSummary(BaseModel):
    defense: Defense
    asr: float                     # attack success rate, 0..1
    runs: int
    utility_retention: float       # benign tasks passed with this defense / passed with none, 0..1


class BatchResults(BaseModel):
    """What the batch runner saves to data/results/batch_results.json and the dashboard reads."""
    generated_at: str
    model: str
    runs_per_attack: int
    traces: list[Trace]
    benign: list[BenignResult]
    summary: list[DefenseSummary]


class RunRequest(BaseModel):
    """Body of POST /runs and POST /replay/{id}."""
    attack: AttackPayload
    defense: Defense = "none"
    run_index: int = 0
