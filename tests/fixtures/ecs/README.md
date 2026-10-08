# Elastic Common Schema reference (vendored, unmodified)

`ecs_flat.yml` is `generated/ecs/ecs_flat.yml` from https://github.com/elastic/ecs at tag **v9.5.0**,
downloaded 2026-10-02 (1,265,633 bytes, SHA-256 `70557ba53e2bda966688f8255193d36f2dcfa5bce2fb4a1a460bcccfd328ed5c`).
`LICENSE.txt` is the repository's Apache License 2.0 (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`).

Used only by `tests/test_siem_ecs.py` and `experiments/exp46-siem-export/analyze.py` to check that every
non-`tunnelscope.*` field TunnelScope exports exists in ECS with the right type and allowed values. Not shipped in the
wheel, not read at run time.
