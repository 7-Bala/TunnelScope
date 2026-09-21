# Task 02: a "How these numbers were measured" panel on the Traffic tab

Purpose: judges will ask what the accuracy score means. Put the answer next to the number.

- Branch: `task/measured-panel`
- You may edit: `fleet-dashboard/src/components/dashboard/TunnelAI.tsx` (only the `AttackerPane` function), `TODO.md`
- Run checks as: `ALLOW="fleet-dashboard/src/components/dashboard/TunnelAI.tsx" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/20-dashboard.md` first.

Goal: at the bottom of the "Traffic & exposure" tab (the `AttackerPane` component in
`fleet-dashboard/src/components/dashboard/TunnelAI.tsx`) add a collapsed-by-default panel titled
"How these numbers were measured". Create branch `task/measured-panel` from `main`.

Use the existing `Collapsible`, `CollapsibleTrigger`, `CollapsibleContent` from
`@/components/ui/collapsible` (see how `FleetRegister.tsx` imports and uses them; copy that pattern).
Use the `ChevronDown` icon from `lucide-react` as `FleetRegister.tsx` does. Do not add packages.

The panel body is EXACTLY this list. Use these words. Do not rewrite, shorten or "improve" them,
because each number was checked against a results file:

1. "What is scored: the model looks at 2-second slices of the tunnel's packet sizes, timing and direction and guesses the traffic type. It never sees the content, which is encrypted."
2. "The accuracy score is macro-F1, averaged over the 8 traffic types so a rare type counts as much as a common one. 1.0 is perfect; guessing at random scores about 0.12."
3. "How it was tested: every setup was recorded several times. The model is trained without one repetition and scored on that one, so it is never scored on data it trained on."
4. "Result on runs it had not seen: 0.986, from 1,964 two-second windows across 216 sessions (synthetic traffic shapes, real applications, and a second IPsec implementation)."
5. "Different VPN software: trained on strongSwan traffic, it scored 1.000 on Libreswan traffic."
6. "The warning that matters: a model trained only on synthetic traffic scored 0.461 on real applications. A model is only as good as how closely its training traffic resembles yours."
7. "Mixed traffic: a second check flags tunnels carrying several kinds of traffic at once. It catches 92.9% of mixed sessions and wrongly flags 8.3% of single-type sessions."
8. "Lab only: one lab network, no internet delay or packet loss, our own servers. Read these scores as evidence that the method works, not as accuracy in the field."

After the list add a small muted line: "Sources: experiments/exp15-traffic-classes-suites-ah and experiments/exp16-real-apps-cross-impl (RESULT.md)."

Style rules: use the same text sizes and muted colours the rest of `AttackerPane` uses
(`text-[12.5px] leading-relaxed text-muted-foreground`). No blur. No emoji. The trigger button needs
`aria-label` text "How these numbers were measured". The panel must fit at 375 px width with no
horizontal scrolling.

Verify in this order and paste the output of each:
  1. `cd fleet-dashboard && npx tsc -b && npm run lint && npm run build`
  2. `ALLOW="fleet-dashboard/src/components/dashboard/TunnelAI.tsx" build/check_all.sh --fast`
  3. In a terminal: `./start.sh -d --no-browser`, then open http://127.0.0.1:8765 in the browser tool.
     Press any key to skip the intro. Drop this file onto the page:
     `testbed/captures/exp15/traffic/exp15-tun-messaging-rep4.pcap` (if it does not exist use
     `testbed/captures/cloud/c-w.pcap`). Open the tunnel row, click the tab "Traffic & exposure",
     scroll down. Confirm: the panel exists, starts collapsed, expands on click, shows all 8 items.
     Take a screenshot expanded. Then set the browser width to 375 px and take another.
     Report the browser console error count (must be 0).
  4. `./start.sh stop`

Add one line to the bottom of `TODO.md`. Commit: `T-088: how-measured panel on the Traffic tab`, with no Co-Authored-By line.

REPORT: the check table, both screenshots, console error count, the diff (`git diff main --stat`).

## DONE WHEN
- `RESULT: PASS`; only the one .tsx file and TODO.md changed.
- The 8 items match the wording above character for character (the reviewer diffs them).
- Panel is collapsed by default and accessible; 0 console errors; no horizontal scroll at 375 px.
