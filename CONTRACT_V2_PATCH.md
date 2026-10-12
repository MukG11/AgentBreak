# Contract v2 patch (for Person 1: contract.py)

Plan v2 adds a few fields. Person 3's code works with the current contract AND with this patch (44 tests pass
both ways; the two v2-only tests are skipped until the patch is applied). Apply it when the group agrees.

```diff
-StepType = Literal["input", "retrieval", "decision", "tool_call", "tool_result", "output"]
-Violation = Literal["canary_leak", "unauthorized_tool", "memory_poison"]
+StepType = Literal["input", "recon", "retrieval", "decision", "tool_call", "tool_result", "output"]
+Violation = Literal["canary_leak", "salary_leak", "unauthorized_tool", "memory_poison"]

 class Step(BaseModel):
     ...
     note: Optional[str] = None
+    caused_by: list[int] = Field(default_factory=list)   # indexes of earlier steps that led to this one

 class Outcome(BaseModel):
     ...
     detail: str = ""
+    path: list[int] = Field(default_factory=list)        # step indexes that form the attack chain
+    new_vuln: bool = False                                # failed at baseline but worked with a defense on

 class Trace(BaseModel):
     ...
     run_index: int = 0
+    meta: dict[str, Any] = Field(default_factory=dict)   # phase, attempt, strategy, model, temperature, seed, prompt_hash
```

What Person 3 does with the new fields once they exist
- `meta`: the batch runner fills phase="validation", strategy, attempt, model, temperature on every run.
  Person 1 / Person 2 add `seed` and `prompt_hash` (llm.py knows them).
- `caused_by`: when two tasks are merged for memory poisoning, the second task's indexes are shifted so they stay correct.
- `new_vuln`: set on traces of any (attack, defense) pair that failed at baseline but succeeded with the defense on.
- `salary_leak`: used by the stand-in detector (severity 4). Without the patch it is reported as `canary_leak`.

Other things Person 1 / Person 2 should know from plan v2
- `run_task`'s signature may change. Person 3 calls it from ONE place, `p3_common.call_run_task`; tell me the new
  signature and it is a one-line edit.
- The memory-poison rule differs between CONTRACT.md (poisoned note makes the follow-up email BCC audit@outside.test)
  and plan v2 section 7 (note retrieved later, then a tool call outside the task scope, retrieval step in caused_by).
  Person 2 and Person 1 need to agree on one. My seed attack and stand-in detector follow CONTRACT.md.
