# Guarded GitNexus Development Tooling

This directory records the optional Project 1 Stage 2 developer-tool decision.
It is outside the Python package and Hatch build inputs. GitNexus is never a
product, runtime, build, test, adapter, trading-engine, or acceptance
dependency.

## Outcome authority

- `supply-chain.json` records the exact reviewed package identity and official
  source identifiers.
- `outcome.json` records the single Stage 2 outcome and non-sensitive reason
  evidence.

When `outcome.json` says `DISABLED_WITH_EVIDENCE`, this directory contains only
`README.md`, `supply-chain.json`, and `outcome.json`. There is no package
manifest, pnpm lock, script, installation, MCP entry, or local index.

When `outcome.json` says `ENABLED`, use only the committed project-local
wrappers and exact lock. GitNexus output remains advisory. Never use a launcher
discovered through PATH or a user-profile package shim.

## Manual source, reference, and diff fallback

Run from the repository root:

```powershell
rg --files src tests scripts docs AGENTS.md README.md pyproject.toml
rg -n "crypto_lab|class |def |import |from " src tests
git log -20 --oneline --decorate
$stage2BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit)) {
    throw "Unable to determine the review base"
}
git diff --name-status "$stage2BaseCommit..HEAD"
git diff "$stage2BaseCommit..HEAD"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Read the approved specification and ADR before an architectural change. Trace
imports and references with `rg`, inspect the complete base-to-HEAD diff, run
focused tests, and finish with the complete offline verifier. This fallback
satisfies the roadmap's advisory-tool gate when GitNexus is disabled or
temporarily unhealthy.

## Removal boundary

The local graph is disposable. Removing an enabled integration means disabling
or removing the project MCP entry, stopping its project-local process, removing
the ignored `.gitnexus/` index and project-local `node_modules`, and then
removing enabled-only package/config/wrapper files in a reviewed change. The
ordinary Python project must continue to verify before and after removal.
