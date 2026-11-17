# 08 - Sources, assumptions and limits

## Repository sources inspected

Repository: https://github.com/PratikRajSingh0612/Crypto_Trading
Pinned reference for preparation: e9fdfc3914310fe3ef68cf759583205725c236e7

- AGENTS.md at that commit: core runtime/launcher, acquisition, offline,
  GitNexus and safety constraints.
- docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md: architecture,
  permanent scope, Project 1 exclusions, section 32 future project boundaries.
- docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md: just-in-time
  planning, sequential core stages, Stage 9/10 and acceptance requirements.
- User-provided completion/diagnostic reports in this conversation: the
  current Stage 8 branch/main discrepancy and interrupted-writer investigation.
- User-provided Claude Code skill inventory: routing candidates, not audited
  local skill behavior or a claim that each skill is connected/authorized.

The older uploaded architecture and roadmap copies contain historical status
headers. They are not evidence of current completion. Actual local Git and
matching verifier reports must control the next action.

## Official guidance consulted on 2026-10-31

- https://code.claude.com/docs/en/best-practices
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/sub-agents
- https://code.claude.com/docs/en/permissions
- https://github.com/obra/superpowers

These support the general approach of explicit verification, bounded context,
selective skills and isolated workers. Exact local versions may differ. This
package does not assume an undocumented CLI flag, slash-command namespace,
permission mode or persistent background executor.

## Deliberate new operating-policy proposals

The following are this package's proposed delegation, adopted when the user
pastes START_CLAUDE.txt; they are not quotations from the old repository plan:
- one standing full-product mandate instead of stopping after each routine task;
- delegated acceptance of within-boundary just-in-time plans after independent review;
- a default two-auxiliary-worker budget and one writer per worktree;
- concise progress records and evidence-based stall escalation;
- detailed proposed acceptance guidance for future Projects 2-13;
- reusable resume/task/human-gate prompts without installing another plugin.

Current specific correction constraints and existing explicit permission gates
are preserved. This package supplies no future engine compatibility result,
tax-law interpretation, acquisition approval, verified UI framework choice,
fixed completion date or guarantee of successful unattended operation.

## Current runtime observation

The user's diagnostics identify separate uv-trampoline and SQLite-holder
processes and reproduce mapped-SHM sensitivity in controlled first-opener
conditions. The upstream candidate patch discussed in the conversation is:
https://github.com/sqlite/sqlite/commit/5ee733befea57e6a12943273fe98b4f3d722b8f6

The package does not certify a fixed release or claim that an upstream patch
is installed. The historical failure's exact mapping/Win32 state was not
captured. The first assignment fixes test ownership while retaining that limit.

## What was not done by generating this package

No repository edit, push, merge, Windows test, skill invocation in the user's
Claude installation, dependency acquisition, UI generation or product build.
No new SKILL.md, plugin manifest, CLAUDE.md, hook, permissions file or executable
PowerShell wrapper is bundled. Markdown/text files and hashes only.
