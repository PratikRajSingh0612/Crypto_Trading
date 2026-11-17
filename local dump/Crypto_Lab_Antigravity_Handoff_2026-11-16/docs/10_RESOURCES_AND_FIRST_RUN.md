# 10. Local resources and first execution

## Hardware reported by the user

Windows 11 Pro; Ryzen 7 3800X (8 cores / 16 threads); 16 GB system RAM; NVIDIA RTX 3060 with approximately 12 GB dedicated VRAM. DxDiag shared graphics memory is system RAM, not additional dedicated VRAM.

Some older host reports referenced approximately 31.46 GB RAM. The screenshots later described a 16 GB machine. Do not assume they are the same physical host or hard-code readiness thresholds without local observation.

Google-hosted Antigravity inference does not require loading a large local model. The application, editor, browser and Windows test subprocesses still consume local CPU/RAM. Do not run a local LLM alongside the critical verifier. Avoid reviewer swarms.

## Initial read-only sequence

- Confirm root and worktrees with read-only Git commands and existing local source.
- Inspect current task plan, its amendments and relevant source/tests.
- Inventory active owned processes and any paused verification.
- Reconcile local/remote HEAD, accepted branch history and unknown private evidence.
- Extract exact stage/task headings with the optional collector or by reading files.
- Write a takeover checkpoint outside the product's active candidate.

Do not begin by cloning over the existing tree, downloading engines, editing policy, resetting to snapshot SHA or running every historical suite.

## Antigravity installation/customization

This package does not install Antigravity or change account settings. Use its existing supported installation and workspace selection. Prefer Google models currently available in that account; no hard-coded speculative model IDs or prices are required for this handoff.

Current official documentation recognizes root AGENTS.md/GEMINI.md and `.agents/rules/*.md`. Rule Markdown needs a recognized `trigger` such as `always_on`. The supplied templates use this form and remain short. Verify discovery in the installed version. Product rules are cumulative, so resolve conflicts deliberately.

Workflow documentation now marks older workflows deprecated; this package uses ordinary explicit prompts and supported rules instead of relying on a deprecated slash command or unverified orchestrator API. It contains no installer or automatic permission bypass.

## Progress reporting

The first report should contain actual subject, source/plan identities, retired-writer state, missing evidence, selected task and whether implementation really began. It should not contain a new generic promise of full autonomy or a speculative completion date.

Official documentation references, accessed 16 November 2026:
- https://antigravity.google/docs/rules/
- https://antigravity.google/docs/ide/workflows/

Only the small rule-discovery/format guidance is derived from these pages. Their current behavior must still be checked against the installed client.
