# Backlog: what is left, and who should do it

## Antigravity can do (tasks written)
| # | Task | Risk | File |
|---|---|---|---|
| 01 | README refresh (canary) | low | `tasks/01-readme-refresh.md` |
| 02 | "How these numbers were measured" panel | low | `tasks/02-how-measured-panel.md` |
| 03 | Traffic dataset datasheet + generator | low | `tasks/03-traffic-datasheet.md` |
| 04 | Third-party validation in CI, non-blocking | low | `tasks/04-ci-external-validation.md` |
| 05 | EXP-17 network conditions (run + analyse) | medium (Docker) | `tasks/05-exp17-network-conditions.md` |

## Needs you (accounts, decisions, recording)
- **Fetch ISCXVPN2016** (form at unb.ca/cic/datasets/vpn.html, or Kaggle). The VPN pcaps only (about 6 files).
  Then a task "run our classifier on it as an out-of-domain benchmark" can be written.
- **Permission** from `naman9271` to use `ipsec-pcap-lab` (it has no licence file). Do not use it without.
- **Name**: another team publicly uses "TunnelScope" for this same problem statement. Decide whether to rename.
- **Dataset licence and citation** (datasheet says `TBD (owner decision)`).
- **Record the demo video** from `build/sih/DEMO-SCRIPT.md`; re-upload the deck; submit on the portal (T-046).
- Real AWS tunnel (follow-up C2) needs your AWS account.

## Needs Claude (judgement, not typing)
- **IKEv1 suite extraction** (IKEv1 is currently version-only). Parsing semantics are subtle.
- **Deck update** (numbers are stale: now 175 tests, more captures) and the story reframe.
- Interpreting EXP-17 results and any decision-log entry it triggers.
- Any change to a threshold, a rule's severity, the risk formula, or the models.
- Second client per traffic type (Firefox, another mail client): needs a pre-registration first.
- Zeek front-end for live monitoring (design decision).

## Known reproducibility gaps (found while writing this handoff)
- `testbed/scripts/run_exp15_traffic.sh` assumes the IP aliases (10.10.1.21x) and swanctl configs were loaded by hand;
  `run_exp17.sh` does this itself. Port that setup into `run_exp15_traffic.sh`.
- Two real Chromium sessions in EXP-16 are flagged "mixed" by the detector (measured false-flag rate 8.3%).
