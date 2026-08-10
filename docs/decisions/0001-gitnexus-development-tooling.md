# ADR 0001: GitNexus for Local Development Context

Status: Approved

Date: 2026-08-10

## Context

Project 1 will grow into a multi-module, engine-neutral research, backtesting, and paper-trading application. Developers need a convenient way to explore symbols, call paths, and cross-module impact without making a derived code graph authoritative or coupling the application to a particular developer tool.

GitNexus can provide local repository context to Codex through the Model Context Protocol (MCP). Its value is architectural discovery and change-impact assistance. Its index and findings are derived, advisory developer aids, not product state or verification evidence.

## Decision

Use a manually configured, project-scoped GitNexus MCP connection for Codex after the initial Project 1 source and module scaffold exists. The connection will be read-only, limited to this repository, exactly version-pinned, optional for Codex operation, and removable without changing the application.

GitNexus is development tooling only. It is not:

- a runtime dependency of `crypto_lab`;
- a trading engine;
- an adapter;
- the system of record;
- a test oracle;
- a build requirement for end users;
- part of the packaged personal application; or
- permitted to access exchange credentials or runtime trading data.

The normative Project 1 design specification, reviewed source, generated schemas, migrations, ordinary verification tools, and test results remain authoritative within their respective roles. GitNexus does not enter the runtime dependency graph, adapter protocol, evidence model, or seven-engine integration matrix.

## Selected integration

The selected integration is a manually configured, project-scoped GitNexus MCP connection for Codex. Initial adoption deliberately excludes:

- the full GitNexus Codex plugin;
- `gitnexus setup`;
- GitNexus-generated `AGENTS.md` files;
- GitNexus-generated skills;
- GitNexus hooks;
- GitNexus wiki generation;
- the GitNexus web UI and serve mode;
- GitNexus publish;
- repository groups;
- raw Cypher;
- rename tools; and
- embeddings.

This narrow surface avoids silent edits to project instructions, avoids duplicate or conflicting skills and hooks, keeps Superpowers and the project's future `AGENTS.md` authoritative, restricts GitNexus to read-only architectural context, and keeps the integration removable and nonessential to product operation.

## Installation and pinning policy

Installation is deferred until a separate, explicitly approved task after the initial Project 1 source and module scaffold exists. That task must:

1. verify the locally available Node.js runtime and npm or pnpm package manager before attempting installation;
2. verify the then-current stable GitNexus release and the license attached to that exact release;
3. select and pin one exact GitNexus version;
4. avoid `gitnexus@latest` in every persistent MCP command;
5. record the selected version and package integrity in development-tooling documentation or a dedicated tool manifest;
6. obtain explicit user approval before any network access or package download; and
7. demonstrate that, after installation and indexing, normal graph queries operate locally.

The pinned executable and its dependency tree are a reviewed supply-chain boundary. Updating the pin is a new installation decision, not an automatic background action.

## Project index policy

A later implementation task will add a committed `.gitnexusrc` whose semantics are equivalent to:

```json
{
  "analyze": {
    "defaultBranch": "main",
    "indexOnly": true,
    "embeddings": false
  }
}
```

This ADR does not create that file. The later task must also:

- add `.gitnexus/` to `.gitignore`;
- keep `runtime/`, `data/`, `artifacts/`, `logs/`, `runtimes/`, virtual environments, credentials, `.env` files, databases, and generated market data outside the indexed source graph through `.gitignore` and any explicit `.gitnexusignore` rules found necessary after tool verification;
- treat the GitNexus index as disposable derived data;
- never commit the `.gitnexus/` index; and
- never use GitNexus as the authoritative architecture specification.

Deleting and rebuilding the local index must be safe. No canonical project record, experiment evidence, test result, or runtime data may depend on it.

## MCP policy

A later implementation task will add a project-scoped `.codex/config.toml` entry. This ADR does not create that file. The eventual entry must:

- run an exact pinned GitNexus installation;
- set `GITNEXUS_MCP_READ_ONLY=1`;
- restrict `GITNEXUS_MCP_ALLOWED_REPOS` to this repository only;
- set this repository as `GITNEXUS_MCP_DEFAULT_REPO`;
- set `GITNEXUS_MCP_DEFAULT_MAX_TOKENS` initially to the bounded value `8000`;
- mark the MCP server non-required so Codex remains usable when GitNexus is absent;
- use an MCP startup timeout appropriate for a local indexed repository; and
- expose only `list_repos`, `query`, `context`, `impact`, `trace`, `detect_changes`, and `check` initially.

Mutation, rename, raw-Cypher, repository-group, publishing, and server tools remain excluded. The allowlisted tool surface may be narrowed further if verification shows that a listed tool mutates repository or index state beyond an explicitly requested refresh.

The final Windows command and any absolute executable path will be selected only after environment verification. The configuration must not assume that a global npm executable is visible to the Codex desktop sandbox.

## Development workflow

Before a cross-module or architectural change:

1. Run `gitnexus status`.
2. Refresh the index when it is stale.
3. Use `context` or `query` to locate relevant symbols and flows.
4. Use `impact` before changing public interfaces or shared domain models.
5. Compare graph findings with the normative design specification.

After implementation:

1. Run focused tests.
2. Run the full relevant test suite.
3. Run formatting, linting, static typing, schema generation, migration checks, and the package build.
4. Refresh the GitNexus index.
5. Run `detect_changes` and impact analysis.
6. Review unexpected graph effects.
7. Review the Git diff.
8. Commit only after normal verification succeeds.

GitNexus findings are advisory. A clean graph check cannot replace tests, type checking, schema checks, migration checks, security review, or human diff review. A GitNexus result cannot authorize a design deviation or establish that a runtime behavior is correct.

## Security and privacy

- Indexing remains local.
- No GitNexus web UI, public publishing, or wiki LLM connection is enabled.
- The MCP repository allowlist is mandatory.
- Read-only MCP mode is mandatory.
- GitNexus does not receive exchange API keys, tax documents, personal records, runtime databases, paper-wallet state, or market-data caches.
- Ignored sensitive or runtime paths must be excluded before the first project index is accepted.
- A compromised developer executable still runs with the local user's permissions; GitNexus is not an operating-system sandbox.
- Install and update commands require review because npm packages and native dependencies are a supply-chain boundary.

Read-only MCP mode constrains exposed tool behavior; it does not replace operating-system permissions, source review, package-integrity verification, path exclusions, or credential hygiene.

## License

As reviewed on 2026-08-10, GitNexus uses the PolyForm Noncommercial License 1.0.0. The current personal, noncommercial research and hobby use is permitted. Any anticipated commercial use, distribution, consulting use, or monetization requires a fresh legal and license review before continued use.

The license must be rechecked for the exact pinned version selected at installation time. This decision does not grant rights beyond the license applicable to that version.

## Consequences

The project gains optional local architectural discovery and change-impact assistance without introducing a product dependency. Developers must maintain a small, reviewed tooling configuration and refresh disposable graph data when source changes. Codex may continue without GitNexus, and ordinary development and verification workflows remain complete without it.

The deliberately narrow initial integration forgoes plugin conveniences, generated guidance, hosted views, embeddings, and mutation-oriented tools in exchange for a smaller trust surface and clearer authority boundaries.

## Rollback

GitNexus can be removed by:

1. disabling or removing the project-scoped MCP entry;
2. removing its generated local index;
3. removing the GitNexus installation; and
4. removing its developer-tooling configuration after confirming that no other developer workflow depends on it.

Removing GitNexus must not affect application source, canonical data, experiments, tests, or runtime operation. If removal does affect any of those assets, the integration has violated this ADR and must be corrected before relying on it further.
