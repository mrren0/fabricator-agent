# Fabricator Agent AI Notes

Before every task, read the Thunder operational context:

1. `C:\Users\reno\RiderProjects\thunder\AGENTS.md`
2. `C:\Users\reno\RiderProjects\thunder\imported-docs\CURRENT.md`
3. `C:\Users\reno\RiderProjects\thunder\imported-docs\AI_CONTEXT.md`
4. `C:\Users\reno\RiderProjects\thunder\imported-docs\fabricator\agent-context\AGENTS.md`

Local aliases:

- `f-a` = `C:\Users\reno\RiderProjects\fabricator-agent`
- `f` = `C:\Users\reno\RiderProjects\fabricator`
- `c-s` = `C:\Users\reno\RiderProjects\control-services`
- `thunder` = `C:\Users\reno\RiderProjects\thunder`

Rules:

- This repo is for remote/runtime behavior: instruction polling, local node/container
  commands, self-update, telemetry, and agent-side execution.
- If a backend or UI feature depends on work inside a live container, implement the
  durable agent path here instead of leaving a manual SSH-only fix.
- Verify live command assumptions through `thunder` before coding.
- If API contracts or UI behavior are involved, inspect `f` too.
- Before edits, pull when the worktree is clean. If the worktree is dirty, inspect it
  first and do not overwrite user changes.
- After changes, run targeted checks, commit the intended files, and push to `main`.
  Do not push unrelated dirty files.

