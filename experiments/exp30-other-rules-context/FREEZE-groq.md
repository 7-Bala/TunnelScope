# EXP-30, groq arm — prompt freeze (2026-09-27, before any EXP-30 run)

frozen prompt: P3

P3 is fixed by PREREG.md (no variants, nothing tuned on any set): P0 plus `generate_plan(other_rules=True)`
(`tunnelscope/remediate/generate.py`: `other_active_rules`, `SYSTEM_PROMPT_OTHER_RULES`). The dev run is the
PREREG's no-harm gate, not a selection step.
