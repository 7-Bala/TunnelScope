# Dashboard rules (apply when editing fleet-dashboard/**)

- Stack: React 19, TypeScript, Tailwind, shadcn-style components. Check with
  `cd fleet-dashboard && npx tsc -b && npm run lint && npm run build`. Lint warnings that existed
  before your change are fine; new lint ERRORS are not.
- The types in `src/lib/api.ts` mirror `tunnelscope/api/server.py` (`analysis_json`). Change one, change both.
- Style: dark, black/violet. Cards use the `glass` class. **Never add blur (`backdrop-filter`).**
- Do NOT edit `src/components/intro/` or `src/components/tunnel/`. They were tuned by measurement and are fragile.
- Copy text: use the exact wording the task gives you. Do not rewrite or "improve" claims; they were
  checked against results files.
- Layout must work at 375 px wide with no horizontal scrolling.
- Every interactive element needs an accessible name. No emoji in the UI.
- No new npm packages. Use what is already in `package.json`.
- Show what the engine sends; never compute a security verdict in the browser.
