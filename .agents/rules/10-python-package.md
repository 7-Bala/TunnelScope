# Python package rules (apply when editing tunnelscope/** or tests/**)

- Use `.venv/bin/python`. Match the style of the file you are editing: same naming, same comment density.
- A **Finding** (`evidence/record.py`) has a status. `UNKNOWN` and `NOT_OBSERVABLE` findings must NOT
  carry a value (the constructor raises). `OBSERVED`/`INFERRED`/`MEASURED` need evidence pointers.
- New finding -> add a plain name in `report/labels.py`, a test in `tests/`, and if it is new
  behaviour on existing captures, an entry in `build/findings-allow.txt` with a `# reason`.
- New rule in `tunnelscope/rules/*.yaml` -> it needs a matching entry in `explain/explain.py` `GLOSSARY`
  (a test enforces this) and a test that FAILs on a capture that should fail and PASSes on one that should pass.
- Rules judge, they do not guess: if a value cannot be judged, the verdict is UNKNOWN, never PASS or FAIL.
- Only `ingest/tshark.py` runs tshark. Do not add `subprocess` calls elsewhere.
- Every model file is plain numpy arrays (`.npz`, loaded with `allow_pickle=False`). Never use pickle.
- Do not touch `tunnelscope/leakage/attacker.py`, `mixed.py`, `mode_model.py` thresholds (`TAU`,
  `MIN_CONSISTENCY`, `MIN_PURITY`) or the training data builders without an experiment behind it.
- Tests: add new tests in a new function. Existing assertions stay.
