# Agent Instructions (content-control)

This repo uses **repo-first memory** + **deterministic context packs** to keep AI-driven development consistent across time and agents.

## Mandatory workflow
1) Read: `.ai/README.md` and `.ai/memory/runbooks/RUNBOOK-0001-codex-cli-workflow/body.md`
2) Require a `Task ID` (a `.ai/memory/tasks/TASK-.../meta.json` item). If missing, ask the user to provide the requirements doc path and create a new TASK.
   - Default requirements path (if user has none): `docs/requirements.md` (create it and ask the user to paste requirements).
3) Build + verify the context pack for that task:
   - `python .ai/tools/memctl.py build-pack --commit HEAD --task-id TASK-... --out context_pack.json`
   - `python .ai/tools/memctl.py validate-pack --pack context_pack.json --task-id TASK-...`
4) Only make decisions based on files inside the pack. If you need more context, output a list of repo paths to add to `pack.include_paths`, then wait.
5) After changing `.ai/**` / workflows / memory, run:
   - `python .ai/tools/memctl.py validate --commit HEAD`
   - `python .ai/tools/memctl.py check-stale --commit HEAD`

## PR discipline (when the PR is AI-driven)
- PR body must contain `Task ID: TASK-...`
- Add PR label `ai` to enable the gate; `ai-exempt` bypasses it (see `.ai/config.json`).

## Deliverables for each task
- Implement changes, run relevant tests/commands, and provide a PR-ready summary.
- If applicable, write one `.ai/evidence/runs/<run_id>.agent_report.json` that records `context.pack_id` and `context.repo_commit`.
