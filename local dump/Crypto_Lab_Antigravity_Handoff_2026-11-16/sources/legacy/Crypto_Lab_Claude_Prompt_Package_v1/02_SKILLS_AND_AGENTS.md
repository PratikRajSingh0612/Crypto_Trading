# 02 - Use the installed skills selectively

## Selection rule

The user supplied the installed skill names. Their exact local versions, descriptions and side effects have not been audited by this package. Read the relevant installed entrypoint before using it. Resolve the actual namespace from local discovery; do not invent a slash command, API, capability or parameter. A listed skill is not permission to use external services.

Use skills as work instructions and subagents as bounded workers. Do not load the entire inventory or run every reviewer on every change.

## Default process route

| Situation | Use |
|---|---|
| Start or resume | using-superpowers, then repository instructions and delivery state |
| New material design | brainstorming; use supplied scope, do not reopen settled choices |
| Next milestone plan | writing-plans, just in time |
| Implementation | subagent-driven-development OR executing-plans, not duplicate controllers |
| Small production change | test-driven-development within the active plan |
| Unexpected failure | systematic-debugging before changing behavior |
| Independent bounded work | dispatching-parallel-agents, only when dependencies permit |
| Verification/acceptance | verification-before-completion |
| Review | requesting-code-review and receiving-code-review |
| Worktree and landing | using-git-worktrees and finishing-a-development-branch, constrained by the non-destructive Git policy |

Brainstorming is not another discovery interview for an already approved task. Read its specification first. Plans should identify real interfaces, owners, risks and executable acceptance checks; do not generate thousands of lines of speculative code fences for future projects.

A skill suggestion to merge, delete a worktree, run online tooling or install a dependency cannot override this package's gates. Preserve existing worktrees; choose finishing options consistent with that constraint.

## Code quality and review

Use the local code-review skill or an independent reviewer role for correctness and maintainability. Use security-review for new trust boundaries, subprocess paths, file import/export, parsing, network boundaries, migrations and local UI bridges. Use simplify only when green and limited to the active change; it is not authorization for repository-wide cleanup.

CodeRabbit skills (coderabbit:code-review, coderabbit:coderabbit-review, coderabbit:autofix) are OPTIONAL. First read their actual instructions. Do not configure accounts, post reviews, upload source/evidence or auto-apply remote changes without a separately authorized service scope. Public GitHub status does not authorize all third-party data transfers. Prefer the existing local review path when sufficient.

SonarQube skills (sonar-integrate, sonar-analyze, sonar-coverage, sonar-duplication, sonar-dependency-risks, sonar-fix-issue, sonar-list-issues, sonar-list-projects, sonar-quality-gate) are CONDITIONAL, not prerequisites. Do not start servers, install scanners, provision Docker/cloud or replace existing gates to use them. Existing approved access may be used within its permission scope; otherwise continue with local tools and document the optional tool as unused.

## Design/front-end route, only when the UI milestone activates

Choose one lead workflow: design / frontend-design:frontend-design / superdesign as appropriate. Add design-system, ui-styling, ui-ux-pro-max and web-design-guidelines selectively. Use dataviz for quantitative views and writing-guidelines for user-facing copy. brand, banner-design, slides and styleseed are optional presentation aids, not required product dependencies.

Known visual preference: premium analytical UI, navy-to-burgundy header, light background, rounded white cards, restrained pastel health states and a compact insights area. Treat this as a design preference, not evidence that a reference image is currently available. Use real application data; clearly label fixtures. Provide an updated mockup or actual rendered screenshot for each substantive UI iteration using the available visual tools; never invent a screenshot or claim pixel verification without viewing it.

React guidance from vercel-react-best-practices, vercel-composition-patterns, vercel:react-best-practices and similar purely code-oriented skills may be useful ONLY if the approved local UI actually uses that stack. Do not select a web framework merely to use an installed skill. Native-local alternatives remain valid.

Chrome DevTools skills (chrome-devtools, chrome-devtools-cli, a11y-debugging, cookie-debugging, debug-optimize-lcp, memory-leak-debugging, troubleshooting) apply only to an approved local UI in a dedicated test profile. Do not attach to the user's personal browser session, inspect personal cookies, visit logged-in accounts or expose a public debug endpoint. No browser automation is needed for the current backend correction.

## Explicitly unused/disabled

ALL GitNexus skills are disabled for this repository, including gitnexus-cli, guide, exploring, debugging, impact-analysis, refactoring, plan, work, review, lfg, pdg-query and taint-analysis. No invocation, setup, index or reactivation. Use manual source/reference/diff analysis. Disabled optional tooling never blocks implementation.

Vercel deployment/cloud/service skills are not used: deploy-to-vercel, vercel-cli-with-tokens, and vercel deployment, env, storage, auth, AI gateway, hosted-agent, server, marketplace, sandbox, queue, firewall, integration and related cloud operations. A skill namespace being installed does not make deployment part of the product.

Do not use claude-api or Vercel AI skills to substitute a cloud model for Project 13's LOCAL LLM requirement. Local model/runtime selection and weight acquisition are separate reviewed decisions.

Do not use init to overwrite instructions. Do not use writing-skills or skill-creator:skill-creator to build another orchestration plugin for this assignment. This package intentionally uses existing skills without installing new ones.

run may be used to demonstrate the actual accepted CLI or local UI once it exists, through the repository's approved execution route. It does not replace verify.ps1. Do not use loop to schedule indefinite retries or concurrent verification. update-config, keybindings-help, fewer-permission-prompts, workflow-authoring and run-ide3-session are not a reason to alter settings. Any proposed permission simplification must be narrow, inspectable and separately approved; never disable prompts globally or use a bypass flag.

## Worker budget and isolation

Default: one controller, one implementing worker and one fresh read-only reviewer, not all necessarily concurrent. At most two auxiliary workers. Only one writer per worktree. The reviewer examines the final diff in a stable snapshot; do not edit underneath the review.

The controller owns integration, commits and publication. Pass each worker its exact root/base, task, allowed writes, consuming contracts, verification expectations and forbidden areas. Do not assume a subagent inherited the conversation, AGENTS.md or skill bodies; provide explicit pointers and require acknowledgment of relevant constraints.

Read-only parallel research is allowed when useful. Do not run independent engine acquisition/builds, live-process fixtures or full verifiers concurrently on this host. Do not create parallel writable stage branches without a justified integration design; never force/cherry-pick unreviewed output into accepted main.

One fresh final reviewer suffices unless an existing binding plan requires more. Reverify changed material with that reviewer after fixes; do not restart a swarm for every comment. Self-review alone is not independent review. If the skill cannot spawn a reviewer, report the limitation rather than fabricating a verdict.
