# Project 2 integration-readiness brief

**Status.** Readiness brief for the later combined integration of the preserved
Project 2 (P2) stack with the published Stage 9 core. Produced as Task 1 of
`docs/superpowers/plans/2026-11-11-project-2-integration-readiness-preparation-plan.md`
(revision 3, committed at `bced68ffa737da8123219bc9e319d862335f902a`). This brief
records source-grounded facts and requirements; it records no runtime acceptance of
any combined tree.

**This task creates and tests no combined tree.** Its full gate
(`offline_data/scripts/verify-offline.ps1` followed by `scripts/verify.ps1`, plan
section 4) validates this documentation subject on the preserved P2 core baseline
`079395bec70f1deda406d0ca14b2d4bf79aaf063`. No evidence in this brief shows that the
P2 sub-project runs against the Stage 9 core; sections 3 and 4 state what evidence a
later reviewed route must produce before any such claim is made.

## 0. Inspected commits, worktree, method and limits

### 0.1 Inspected commits

Resolved with `git rev-parse 3a47d4c9 4d70f673 970c1fb5 19d4db1e ae529fd7 079395be
874fb51b bced68ff 9e07ce23` and described with `git show -s --format=%H%x20%ci%x20%s
3a47d4c9 4d70f673 970c1fb5 19d4db1e ae529fd7 079395be 874fb51b bced68ff` (eight of the
nine; `%ci` is the committer date; observed values below).

| Role | Commit | Committer date (observed) | Subject (observed) |
|---|---|---|---|
| Common core baseline | `079395bec70f1deda406d0ca14b2d4bf79aaf063` | 2026-10-31 13:34:38 +0530 | test: terminate and await the sqlite writer before recovery |
| Published slice 1 | `3a47d4c9ecdcd6967a670246144ea7ee6c999ed4` | 2026-11-10 16:00:39 +0530 | feat(offline-data): emit dataset descriptor and partition metadata with the core identity hash |
| Published slice 2 | `4d70f673a004b47883388fa45a0d93c8daa9167a` | 2026-11-10 23:12:18 +0530 | feat(offline-data): read binance-spot-kline-csv/1 inputs with explicit timestamp units |
| Published slice 3 | `970c1fb57005036e4e162190edeecdebf7935ceb` | 2026-11-11 06:31:43 +0530 | test(offline-data): verify golden dataset registration in temporary sqlite |
| Published slice 4, fixed P2 snapshot | `19d4db1e77ae8053a9f3b7feecac78b9cb81f887` | 2026-11-11 10:23:50 +0530 | fix(offline-data): reject residual carriage returns and tighten entry-point guards |
| Preserved mission-3 alternative | `ae529fd79b0b158b4a604517f8d529a9533cd987` | 2026-11-11 05:13:46 +0530 | test(offline-data): verify golden dataset registration in temporary sqlite |
| Stage 9 comparison snapshot | `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1` | 2026-11-11 07:12:42 +0530 | feat: add stage 9 boundaries, documentation and status |
| Worktree HEAD, plan revision 3 | `bced68ffa737da8123219bc9e319d862335f902a` | 2026-11-11 11:06:47 +0530 | docs(offline-data): integration-readiness plan revision 3 (re-review citation MINOR folded: launcher profiles end at line 254) |

The two earlier plan commits of this branch are
`e4757049fe1e232e57f47aed6122a84ea1297590` (revision 1, parent `19d4db1e`) and
`72da059e0b7d44b7a6e137df516a7492b7c8b3f5` (revision 2), observed with
`git log --format=%H%x20%P%x20%s 19d4db1e..bced68ff` (three commits).

### 0.2 Worktree and reference convention

- Worktree `project-2-integration-readiness`, branch `project-2-integration-readiness`.
  `git rev-parse HEAD` observed `bced68ffa737da8123219bc9e319d862335f902a`;
  `git status --porcelain --untracked-files=all` observed no output before this file
  was created.
- `git diff --name-status 19d4db1e bced68ff` observed exactly one line:
  `A docs/superpowers/plans/2026-11-11-project-2-integration-readiness-preparation-plan.md`.
  Every other tracked path in the worktree therefore equals the fixed P2 snapshot
  `19d4db1e`. Unprefixed `path:line` references below identify that snapshot and were
  read from the worktree.
- Stage 9 content was never checked out. It was read through committed objects only:
  `git show 874fb51b:<path>` for whole files and
  `git diff 079395be 874fb51b -- <path>` for changes. Line numbers quoted for Stage 9
  files are lines of the file shown by `git show`; diff hunks are cited by command and
  observed result, never by line number.
- Admitted operations used: `git status`, `git diff`, `git log`, `git show`,
  `git rev-parse`, plus Read, Glob and Grep inside the worktree. No Git mutation was
  performed: no fetch, checkout, merge, rebase, reset, stash, commit, tag or index
  update, and no `hash-object` (section 0.3). The only path this task creates or
  edits is this brief at its single authorized path; `git status --porcelain
  --untracked-files=all` after creation observed exactly one entry,
  `?? offline_data/docs/2026-11-11-integration-readiness.md` (the quality profiles
  may write ignored caches, which that command does not show).
- Plan name `CTL` means `Crypto_Lab_Dev_Controller-dev` and `P2CTL` means
  `Crypto_Lab_Dev_Controller_P2` (plan:13).

### 0.3 Operations that were unavailable, and how the brief treats them

- Reading `P2CTL/config/mission_checkpoint.md`, `CTL/docs/programme-index.md` and
  `P2CTL/src/clabctl/gitops.py` was denied (paths outside the worktree, no approval
  surface in this session). Section 5 is therefore derived from the plan's cited
  ranges (plan:17, :18, :24) and from committed product-repository text, and every
  controller-side statement in section 5 is marked CONTROLLER-SIDE CONFIRMATION
  REQUIRED.
- `git rev-parse <ref>^{commit}` was rejected by the command guard (shell-expansion
  syntax). The tag was resolved with `git rev-parse <ref>` and `git log -1 <ref>`.
- `git hash-object <path>` and `git hash-object --no-filters <path>` on this brief were
  denied by the permission system (plan:79 lists `hash-object` as not admitted). No
  blob identity of this untracked file is recorded here; its byte hygiene was checked
  with Grep instead (section 7).
- `git log <commit> --not --remotes` was denied. Publication state in section 1.4
  therefore rests on `git log -1 --format=%H%x20%D <commit>` decorations, which show
  the local remote-tracking view at inspection time; no fetch was performed.

## 1. Preserved delivery inventory

### 1.1 Resolved identities

Section 0.1 holds the full identities. Abbreviations used in plan documents resolve
uniquely: `3a47d4c9`, `4d70f673`, `970c1fb5`, `19d4db1e`, `ae529fd7`, `079395be`,
`874fb51b`, `bced68ff` and `9e07ce23` each resolved to one commit.

### 1.2 Observed ancestry of the published stack

`git log --format=%H%x20%P%x20%s 079395be..19d4db1e` observed 36 commits, each with
exactly one parent, from `c273d4181dccfaca1ceee7747c33bfcdcc98f76b` (parent
`079395be`, "docs(plan): draft the Project 2 offline-data first-slice implementation
plan") to `19d4db1e` (parent `9e07ce23486f02f8ed95a2992d6766d61b69cb14`). The chain is
linear. The four slices sit in it in this order, each as the head of a run of plan and
task commits:

| Slice | Commit | Observed parent | Preceding run in the chain |
|---|---|---|---|
| 1 | `3a47d4c9` | `e0887d5e196bdb064a3fb6714b86ae80f7716a6f` | plan drafts and revisions from `c273d418`, scaffold `e06d3efd9dc8d395ea44dc1171daa775a25160d6`, reader `1976ca0047cfc1e76b761d547ce13a54e83e00c7`, validation and container `c13ee357fd9ae479ee71919bb3717e5b98e920b5` |
| 2 | `4d70f673` | `04abf63973dbc0f02d23650b3805176c86fab2a2` | three reader-plan commits `f97ba9b1`, `c2ad1c83`, `04abf639` |
| 3 | `970c1fb5` | `319326b090e2ada298c0c1e6f5a832780a975f00` | one registration-plan commit `319326b0` |
| 4 | `19d4db1e` | `9e07ce23` | three corrections-plan commits `d1fad5a98558d5bb5f19b8f0985a47352e696d7b`, `0f02f7e8a7d8595c9e87522624b5e84a01a985a3`, `9e07ce23` |

### 1.3 Latest-stack containment and divergence from Stage 9

- `git log --format=%H 874fb51b..19d4db1e` observed the same 36 commits as 1.2;
  `git log --format=%H 19d4db1e..874fb51b` observed the 9 Stage 9 commits of
  section 2.2. Neither list contains a member of the other. The first commit of each
  list (`c273d418` and `f441a45a53e806b06e5fd49be7c1f828da523360`) has parent
  `079395be` (observed in the `%P` fields of `git log --format=%H%x20%P%x20%s
  079395be..19d4db1e` and `079395be..874fb51b`). The common ancestor and divergence
  point is therefore `079395be`; `merge-base` was not needed and was not run.
- The latest stack contains every earlier delivery: `3a47d4c9`, `4d70f673` and
  `970c1fb5` all appear in `079395be..19d4db1e`, and `19d4db1e` is the parent of
  `e4757049`, the first commit of `19d4db1e..bced68ff`. No P2 commit is contained in
  `874fb51b`, and no Stage 9 commit is contained in `bced68ff`.

### 1.4 Publication view (local remote-tracking refs, no fetch)

`git log -1 --format=%H%x20%D <commit>` observed:

| Commit | Observed decorations |
|---|---|
| `3a47d4c9` | `origin/project-2-offline-data-implementation`, `project-2-offline-data-implementation` |
| `4d70f673` | `origin/project-2-binance-kline-reader`, `project-2-binance-kline-reader` |
| `970c1fb5` | `origin/project-2-sqlite-registration-contract`, `project-2-sqlite-registration-contract` |
| `19d4db1e` | `origin/project-2-offline-data-review-corrections`, `project-2-offline-data-review-corrections` |
| `ae529fd7` | `tag: preserved/p2-sqlite-registration-contract-mission3` only |
| `874fb51b` | `origin/project-1-stage-9-implementation`, `origin/main`, `origin/HEAD`, `project-1-stage-9-implementation`, `main` |
| `bced68ff` | `HEAD -> project-2-integration-readiness` only |

`git rev-parse origin/main` observed `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1`
(plan:9 records that origin/main has been `874fb51b` since 2026-11-11 05:03Z).
`git rev-parse origin/project-2-integration-readiness` observed exit code 128
(unknown revision): this branch is not yet published. Each published slice sits on
its own remote-tracking branch; none is contained in `origin/main`.

### 1.5 The preserved, unpublished mission-3 alternative

- `git rev-parse refs/tags/preserved/p2-sqlite-registration-contract-mission3`
  observed `ae529fd79b0b158b4a604517f8d529a9533cd987`, the same identity
  `git log -1 --format=%H%x20%P%x20%s` observed for the ref (parent
  `091e1ae5b15fca2eb8a6b340a50b1ceb266393a8`). The ref resolves directly to the commit
  (a lightweight tag).
- `git log --format=%H%x20%P%x20%s 079395be..ae529fd7` observed 34 commits: the 30
  commits up to and including `4d70f673` shared with the published chain, then
  `89d9e597b0eb7cf0963f4c47d42c3bb5f8180069` (parent `4d70f673`),
  `cf634239101740a78cb2a76717882317fefcc1e2`, `091e1ae5` and `ae529fd7`.
- Separate ancestry: `git log --format=%H 19d4db1e..ae529fd7` observed four commits
  (`ae529fd7`, `091e1ae5`, `cf634239`, `89d9e597`), so `ae529fd7` is not an ancestor
  of `19d4db1e`. `git log --format=%H ae529fd7..19d4db1e` observed six commits
  (`19d4db1e`, `9e07ce23`, `0f02f7e8`, `d1fad5a9`, `970c1fb5`, `319326b0`). Both
  `319326b0` and `89d9e597` have parent `4d70f673`, the divergence point.
- Test and README equivalence with published slice 3, by blob identity
  (`git rev-parse <commit>:<path>`):

| Path | `970c1fb5` | `ae529fd7` | `19d4db1e` |
|---|---|---|---|
| `offline_data/tests/integration/test_sqlite_dataset_registration.py` | `420c4afcfc4768d7d8871e9e442983d333edbf5e` | `420c4afcfc4768d7d8871e9e442983d333edbf5e` | `420c4afcfc4768d7d8871e9e442983d333edbf5e` |
| `offline_data/README.md` | `96bcdafbecce05360463447ae4116009f13582ef` | `96bcdafbecce05360463447ae4116009f13582ef` | `dc1cf9debe27269d3855f3ba25981e4fd8edfaf3` |

  The alternative's test module and README are byte-identical to published slice 3.
  The README differs from slice 4 only because slice 4 revised the README
  (corrections plan `docs/superpowers/plans/2026-11-11-project-2-offline-data-review-corrections-plan.md:23`).
- `git diff --name-status 970c1fb5 ae529fd7` observed exactly one line:
  `M docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md`.
  The alternative carries no product, test, fixture or README content beyond
  published slice 3; it differs only in that plan document's text.
- Conclusion: the later route consumes the published chain through `19d4db1e` (or an
  accepted descendant such as this branch) only. Replaying `ae529fd7` as well would
  re-apply an identical test module and a superseded README; the tag stays as a
  preserved record and is not an integration input.

## 2. Change and contract inventory

### 2.1 P2 stack against the common baseline

- `git diff --name-status 079395be 19d4db1e` observed 80 paths, every one `A`
  (added); `git diff --shortstat 079395be 19d4db1e` observed
  `80 files changed, 19373 insertions(+)` and no deletions.
- `git diff --shortstat 079395be 19d4db1e -- offline_data` observed
  `76 files changed, 17543 insertions(+)`. The remaining four paths are the P2 plan
  documents under `docs/superpowers/plans/` dated 2026-11-09 (first slice), 2026-11-10
  (Binance reader), 2026-11-11 (SQLite registration contract) and 2026-11-11 (review
  corrections).
- No path under `src/`, `tests/`, `schemas/`, `scripts/`, nor `pyproject.toml`,
  `uv.lock` or `README.md` at the repository root appears in the list. The P2 branch's
  core files equal `079395be`; this is the concrete meaning of "preserved core
  baseline" (plan:32; `offline_data/README.md:75-76` and `:736-738` state the same
  pin).

### 2.2 Stage 9 against the common baseline

- `git log --format=%H%x20%P%x20%s 079395be..874fb51b` observed nine linear commits:
  `f441a45a` (plan), `1b63214a902ac7d4d4f3369ead0e6cba51e19fa8`,
  `1ccae3010585684e90ec85194c296721508f8ca1`,
  `d4c65d4cdffb0319010fd1738e7d034ae77f5231`,
  `b8b71ab1113b04fe75123645b5a60b8e80c72eca`,
  `ab3b6de4a0b53c6bd0afcbfcd6f9a1bb4087243c`,
  `97f57d6e42fffe1312d2aeb399feb6427e77db51`,
  `d3a0793bdc21e5b0b199a4b70df3216118fa4cf4`, `874fb51b`.
- `git diff --shortstat 079395be 874fb51b` observed
  `125 files changed, 70651 insertions(+), 575 deletions(-)`; restricted to
  `src/crypto_lab` it observed `38 files changed, 21404 insertions(+), 181 deletions(-)`.
- `git diff --name-status 079395be 874fb51b` observed changes under: `README.md` (M),
  `docs/development/verification.md` (M), `docs/decisions/` (one A),
  `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` (M) and the Stage 9
  plan (A), thirteen new schema files under `schemas/artifacts`, `schemas/audit`,
  `schemas/domain` and `schemas/experiments`, `src/crypto_lab/{artifacts,audit,
  domain,experiments,persistence}` and `src/crypto_lab/schema_registry.py`, and the
  `tests/` tree. No path under `offline_data/` appears.

### 2.3 Actual overlapping paths

The intersection of the two `--name-status` path lists is empty. Both branches add
or modify files under `docs/superpowers/plans/`, but different files (P2: the four
2026-11-* plans; Stage 9: the master roadmap and the 2026-08-10 Stage 9 plan). Root
`pyproject.toml`, `uv.lock`, `scripts/invoke-uv.ps1` and `scripts/verify.ps1` are
changed by neither side: the section 7 `--stat` command whose path list includes
those four paths observed no output, and none of them is in the P2 list. This is a
textual finding: a three-way combination has no same-path conflict. It says nothing
about runtime behaviour (section 2.6).

### 2.4 Consumed core interfaces and their Stage 9 status

Consumers were enumerated with Grep for `crypto_lab.` under
`offline_data/src/crypto_lab_offline_data/` and for `^from crypto_lab` under
`offline_data/tests/`:

| Consumer | Core modules consumed |
|---|---|
| `binance_kline_csv.py:70` | `crypto_lab.domain.results` |
| `candle_csv.py:46-48` | `crypto_lab.domain.financial`, `.results`, `.time` |
| `cli.py:78-80` | `crypto_lab.domain.canonical_json`, `.records`, `.results` |
| `diagnostics.py:26-33` | `crypto_lab.domain.diagnostics`, `.identifiers`, `.results`, `.time` |
| `metadata.py:71-85` | `crypto_lab.datasets.hashing`, `crypto_lab.datasets.models`, `crypto_lab.domain.identifiers`, `.records`, `.results`, `.time` |
| `normalize.py:61-62` | `crypto_lab.domain.canonical_json`, `.results` |
| `providers.py:24-25` (docstring `:7` names `crypto_lab.domain.ports.Clock` structurally) | `crypto_lab.domain.identifiers`, `.time` |
| `validation.py:51-54` | `crypto_lab.datasets.models`, `crypto_lab.domain.financial`, `.results`, `.time` |
| `tests/integration/test_sqlite_dataset_registration.py:35-54` | `crypto_lab.datasets.hashing`, `.models`, `crypto_lab.domain.canonical_json`, `.ports`, `.results`, `.time`, `crypto_lab.persistence.database`, `.migration_runner`, `.registries` |
| `tests/integration/test_core_contract_roundtrip.py:29-40` and the unit suites | `crypto_lab.datasets.hashing`, `.models`, `crypto_lab.domain.canonical_json`, `.diagnostics`, `.identifiers`, `.records`, `.results`, `.time` |

Stage 9 status of each consumed module, from `git diff --stat 079395be 874fb51b --
<paths>` and the targeted diffs:

| Module | Stage 9 status | Evidence |
|---|---|---|
| `domain/canonical_json.py`, `domain/ports.py`, `domain/results.py`, `domain/time.py`, `domain/financial.py`, `domain/records.py`, `domain/diagnostics.py` | unchanged | the section 7 `--stat` commands that include these paths observed no entry for them |
| `datasets/` (all), `schemas/datasets/` | unchanged | the section 7 `--stat` commands that include these paths observed no entry for them |
| `persistence/migration_runner.py`, `persistence/registries.py` | unchanged | the section 7 `--stat` command that includes these paths observed no output |
| `artifacts/ownership.py`, `configuration/snapshot.py`, `domain/descriptors.py`, `domain/lifecycle.py`, `domain/versioning.py`, `persistence/diagnostics.py`, `strategy/versioning.py` (the remaining direct imports of `registries.py:84-131`) | unchanged | `git diff --stat 079395be 874fb51b -- <those seven paths>` (section 7) observed no output |
| `artifacts/__init__.py` (executed when `registries.py:84` imports `crypto_lab.artifacts.ownership`) | changed, large | `git diff 079395be 874fb51b -- src/crypto_lab/artifacts/__init__.py` observed the package module now importing the whole Stage 9 artifacts graph (`diagnostics`, `finalizer`, `hashing`, `journal`, `manifest`, `models`, `paths`, `ports`, `recovery`, `requests`, `store`, `validation`) and re-exporting their names; the `ownership` imports are retained |
| `domain/identifiers.py` | changed, additive | diff observed `24 insertions(+)`: two new `type` aliases `FinalizationId` and `RunManifestId` and their validators; no existing definition altered |
| `domain/hashing.py` (reached through `src/crypto_lab/datasets/hashing.py:10`, which imports `HashingProfile` and `profile_hash`) | changed, additive | diff observed `182 insertions(+)`: eight `HashingProfile` members appended after the existing ones and six new functions; no hunk touches `profile_hash` or an existing member |
| `domain/__init__.py` (executed on every `crypto_lab.domain.*` import) | changed, additive | diff observed `20 insertions(+)`: re-exports of the new names and a new import of `crypto_lab.domain.metrics` |
| `persistence/database.py` | changed, additive | diff observed `ConsistencyReport` gains four fields defaulting to zero and `consistency_report()` four Stage 9 queries; `SqliteDatabase.open` and `connection()` appear in no hunk and `close()` appears only as unchanged context, so no hunk changes them |
| `persistence/schema.py` (imported by `registries.py:122` and `migration_runner.py:68,76`) | changed, large | eight new tables, one column, Stage 9 indexes and triggers, `STAGE9_PARTIAL_INDEX_SQL` and `STAGE9_TRIGGER_SQL`; the only hunks naming `datasets` or `dataset_partitions` relocate the append-only trigger table list; no hunk changes `DatasetRow` or `DatasetPartitionRow` |
| `persistence/codecs.py` (imported by `registries.py:103`) | changed | diff confined to `encode_engine_run` and `egress_payload_engine_run` (the `finalization_deadline_utc` column); no dataset codec hunk |
| `persistence/migrations/versions/r0002_stage9_artifacts.py` | new | `git show 874fb51b:<path>` lines 32-33: `revision = "r0002_stage9_artifacts"`, `down_revision = "r0001_stage8_baseline"` |
| `persistence/repositories.py`, `persistence/unit_of_work.py`, `persistence/artifact_codecs.py`, `persistence/artifact_repositories.py`, `persistence/audit_sink.py` | changed or new, not imported by the sub-project directly | the `--name-status` list of section 2.2 |

The table covers the sub-project's direct imports and the direct imports of
`registries.py`. The full transitive import closure (for example `domain/base.py`,
`datasets/ports.py`, and every module the Stage 9 artifacts package reaches) was not
computed; a combined-tree import is a runtime fact (section 2.6).

Contract versions of plan:30-39 (descriptor and partition schemas `1.0.0`, hash
profile `dataset-metadata/v1`, formats `ohlcv-csv/1` and `binance-spot-kline-csv/1`,
provenance `1.0.0`, the two output versions of the table below, distribution
`crypto-lab-offline-data 0.1.0`) are defined by the unchanged `datasets/` and
`schemas/datasets/` modules and by the P2 sub-project itself, so Stage 9 leaves them
textually unchanged. Plan:38 (and corrections plan `:36`) requires two distinct
output versions, recorded separately here with their definitions:

| Required version | Value | Definition, carriers and pins |
|---|---|---|
| Output format (container label) | `normalized-ndjson/0.1.0` | `CONTAINER_FORMAT` at `offline_data/src/crypto_lab_offline_data/normalize.py:77`; pinned by `offline_data/tests/unit/test_normalize.py:1166`; documented at `offline_data/README.md:475` and `:724`. `metadata.py` does not import it; the label reaches descriptors and partitions only inside the P2-B1 limitation literal (`offline_data/src/crypto_lab_offline_data/metadata.py:146`) |
| Column schema | `0.1.0` | `COLUMN_SCHEMA_VERSION` at `normalize.py:75`; written as `column_schema_version` of every partition (`metadata.py:301`) and descriptor (`metadata.py:335`) into the core `SemanticVersion` fields of `DatasetPartition` (`src/crypto_lab/datasets/models.py:180`, class at `:164`) and `DatasetDescriptor` (`:328`, class at `:298`); pinned by `test_normalize.py:1165`, `offline_data/tests/unit/test_metadata.py:508`, `:542` and `offline_data/tests/integration/test_sqlite_dataset_registration.py:440-442`; documented at `offline_data/README.md:476` and `:587` |

The sub-project's pinned runtime closure
(`offline_data/pyproject.toml:38-50`: `alembic==1.20.0`, `pydantic==2.13.4`,
`sqlalchemy==2.0.54` and the rest) stays consistent with the core because the root
`uv.lock` is unchanged by Stage 9 (section 2.3).

### 2.5 Relevant Stage 9 persistence changes for the registration contract

- The migration runner is textually unchanged, but its behaviour follows the packaged
  versions directory: `src/crypto_lab/persistence/migration_runner.py:91`
  (`_PACKAGED_SCRIPT_LOCATION = Path(__file__).parent / "migrations"`), `:143-154`
  (`_single_head`, `expected_head`) and `:157-186` (`check_revision`, `CURRENT` only
  when the stamped revision equals the head). In a combined core the head becomes
  `r0002_stage9_artifacts`: the Stage 9 guard shown by
  `git show 874fb51b:tests/safety/test_stage9_boundaries.py` pins at lines 689-699
  `expected_head() == _STAGE9_REVISION` and a versions listing of exactly
  `__init__.py`, the baseline revision and the Stage 9 revision.
- Effect on `offline_data/tests/integration/test_sqlite_dataset_registration.py`:
  `_create_database` (`:230-241`) calls `apply_migrations`, which in a combined core
  would apply `r0001` and then `r0002`, so the temporary database would also receive
  the eight Stage 9 tables, the `engine_runs.finalization_deadline_utc` column, the
  Stage 9 indexes and triggers (migration docstring, `git show` lines 1-23).
  `_reopen_database` (`:244-248`) uses `open_database`, which admits only `CURRENT`
  (`migration_runner.py:227-251`), so the reopen would require the stamped head to
  equal whatever head the installed core reports. The test's assertions touch the
  `datasets` and `dataset_partitions` row counts (`:277-282`, `:310-315`), the
  registry file set (`:335-339`) and golden equality (`:342-348`, `:440-442`); no
  assertion names a migration revision or reads the stamped head (Grep for `r0001`,
  `r0002`, `expected_head`, `check_revision`, `CURRENT` and `revision` in the module
  observed no match). The test therefore does not explicitly pin the head; whether it
  passes under an `r0002` head is a runtime fact (section 2.6).
- The Stage 9 migration docstring (lines 18-19 of the shown file) states that the
  Stage 9 tests prove a database upgraded from `r0001` equals a fresh `r0002` render.
  That proof lives in the core suite and runs in the core environment.
- The dataset tables, their codecs and `SqliteDatasetRepository` are not modified
  (section 2.4 rows for `schema.py`, `codecs.py` and `registries.py`).

### 2.6 Textual findings versus runtime evidence

Proven textually by the inspected sources and diffs above: no overlapping paths; the
consumed-module change set; unchanged dataset contracts, hashing entry points,
registry and migration runner; unchanged root lock, launcher and verifier; the
additive shape of the changed consumed modules.

Not proven here, and producible only on a combined tree in its own environments:

- that the sub-project suite passes against a core whose migration head is `r0002`
  (section 2.5), including the import of the Stage 9 `crypto_lab.domain` package
  graph inside `offline_data/.venv`;
- that importing `crypto_lab.persistence.registries` inside `offline_data/.venv`
  succeeds when `registries.py:84` executes the Stage 9 `crypto_lab.artifacts`
  package module, which then imports the whole artifacts graph (section 2.4, last
  rows), under the sub-project's pinned closure;
- that `apply_migrations` on the registration test's temporary database reaches
  `CURRENT` at `r0002` inside `offline_data/.venv` rather than in the root
  environment;
- that the core guards at `874fb51b` pass with `offline_data/` and the P2 plan
  documents present. Textually they scope to `src/crypto_lab` and to specific files:
  `tests/safety/test_stage3_boundaries.py:329-330` defines `_source_files` as the
  `rglob("*.py")` under `src/crypto_lab`, the Stage 9 guard imports that helper
  (shown file lines 59-84) and asserts `len(_source_files(repository_root)) == 135`
  (line 515), counts `schemas/**/*.schema.json` (line 675) and reads `README.md`, the
  verification guide and the roadmap (lines 272-274, 724-728). Grep for
  `offline_data` under `tests/` at `19d4db1e` observed no match. The P2 stack adds no
  file under `src/crypto_lab`, `schemas/` or those three documents, so no textual
  trip is visible; the runtime result is still owed;
- that the core `ruff-format-all` and `ruff-check-all` stages, which traverse
  `offline_data/` from the repository root (`offline_data/README.md:162-165`), stay
  clean on the combined tree.

## 3. Environment binding

### 3.1 How the core enters the sub-project

- `offline_data/pyproject.toml:11-13` declares the single runtime dependency
  `crypto-trading-lab`; `:52-53` binds it as
  `crypto-trading-lab = { path = "../", editable = false }`.
- `offline_data/uv.lock:104` records `requires-dist = [{ name = "crypto-trading-lab",
  directory = "../" }]`; `:126-128` records the package as `name = "crypto-trading-lab"`,
  `version = "0.1.0"`, `source = { directory = "../" }`. The lock holds no content
  hash and no commit for this source.
- `offline_data/README.md:40-53` describes the arrangement; the guards pin it:
  `offline_data/tests/safety/test_boundaries.py:187-188` (`EXPECTED_SOURCES` with
  `"editable": False`), `:1851-1861` and `:1900-1920` (the lock's directory source).
- The only synchronizing profile is `sync` = `uv --offline sync --frozen
  --no-build-isolation` (`offline_data/scripts/invoke-offline-uv.ps1:187-197`), run by
  `offline_data/scripts/verify-offline.ps1:27-29` after `lock-check` (`:23-25`). It
  builds the core wheel from the parent checkout into `offline_data/.venv`
  (`offline_data/README.md:128`).

### 3.2 Why a stale installation is possible and may escape the identified identity checks

- The core distribution version is `0.1.0` at both `079395be` and `874fb51b`:
  `pyproject.toml:7` and the empty output of the section 7 `--stat` command that
  includes `pyproject.toml`. Version metadata cannot distinguish a Stage 8 build
  from a Stage 9 build.
- Inspected facts: the lock records no content identity for the path source
  (`offline_data/uv.lock:126-128`); `lock-check` runs `uv --offline lock --check`
  (profile arguments at `offline_data/scripts/invoke-offline-uv.ps1:168-177`); and
  the root `pyproject.toml` is unchanged by Stage 9 (section 2.3). Inference, not
  documented in the repository: a lock check that sees the same declarations and no
  content identity has nothing with which to detect a change in the parent's source
  files. Its actual outcome on a combined tree has not been observed.
- The registration test's assertions do not explicitly pin the migration head
  (section 2.5). A stale Stage 8 installation inside `offline_data/.venv` may
  therefore escape the identity checks identified here: the version string, the lock
  comparison and the test's own assertions. No pass of the sub-project suite against
  the Stage 9 core has been observed, and success of every existing gate with a stale
  installation has not been demonstrated either; both are runtime facts owed by the
  later route (section 2.6). What follows is only that a GREEN sub-project suite on a
  combined tree would not by itself show which core was exercised.
- Untracked local observation, valid for this worktree's sub-project environment
  only and not for any other checkout: the installed
  `crypto_lab/persistence/migrations/versions/` directory under
  `offline_data/.venv/Lib/site-packages/` holds `__init__.py` and
  `r0001_stage8_baseline.py` only, consistent with the preserved baseline; the
  installed `crypto_trading_lab-0.1.0.dist-info` holds a `direct_url.json` with
  `"dir_info":{"editable":false}` and a file URL naming this worktree's root, and a
  `uv_cache.json` holding a `timestamp` entry, a `directories` entry for `src`, and
  `"commit":null` and `"tags":null`. Nothing in the repository documents what these
  entries mean or how uv decides from them whether to rebuild the path dependency,
  so this brief claims neither that `sync --frozen` will rebuild after a combination
  nor that it will not.
- Because `direct_url.json` names one checkout root, an environment synchronized in
  one worktree proves nothing about another checkout.

### 3.3 Evidence a later route must retain

1. The exact combined commit id and the worktree and branch in which it is checked
   out, recorded with `git rev-parse HEAD` and an empty
   `git status --porcelain --untracked-files=all`.
2. That both environments were synchronized from that checkout after the
   combination: the root `.venv` (`scripts/invoke-uv.ps1:240` pins
   `.venv\Scripts\python.exe`) through `scripts/verify.ps1:21-29`, and
   `offline_data/.venv` (`offline_data/scripts/invoke-offline-uv.ps1:199-200`) through
   `offline_data/scripts/verify-offline.ps1:23-29`.
3. Positive identity evidence for the installed core inside `offline_data/.venv`,
   independent of the version string: at minimum (a) the installed
   `crypto_lab/persistence/migrations/versions/` directory lists
   `r0002_stage9_artifacts.py`, and (b) the installed bytes of the consumed modules
   of section 2.4 equal the blobs of the combined commit (identities from
   `git rev-parse <combined>:src/crypto_lab/<module>` compared by a reviewed method);
   preferably also (c) an observation from inside `offline_data/.venv` that
   `crypto_lab.persistence.migration_runner.expected_head()` returns
   `r0002_stage9_artifacts`.
4. The installed distribution's `direct_url.json` and `uv_cache.json`, captured as
   evidence, with the URL expected to name the combined worktree; what the other
   entries prove is for the later route's review to settle, not assumed here.
5. Coverage and gate outputs of both verifiers bound to the same commit (section 4).

### 3.4 Separate environments and the unresolved execution capability

- The two environments stay separate: the core launcher resolves `.venv` under the
  repository root and the sub-project launcher resolves `.venv` under
  `offline_data/`; both refuse reparse points along that path
  (`scripts/invoke-uv.ps1:147`; `offline_data/scripts/invoke-offline-uv.ps1:125-140`).
  Nothing may share, link or substitute one for the other.
- Unresolved execution capability: no admitted profile produces item 3(c) of
  section 3.3. The sub-project launcher's closed profile set is `lock-check`,
  `lock-resolve-offline`, `sync`, `pytest-focused`, `pytest-all`, `ruff-format-all`,
  `ruff-check-all` and `mypy-all` (`offline_data/scripts/invoke-offline-uv.ps1:30-33`,
  `:167-337`); `pytest-focused` runs only existing targets under `tests/`
  (`:261-331`); there is no probe, rebuild, reinstall or command-line profile
  (`offline_data/README.md:111-113`). The core launcher's `migration-check`
  (`scripts/verify.ps1:51-54`) runs in the root `.venv` and proves nothing about the
  sub-project's installed copy. Closing the gap requires either a reviewed new test
  under `offline_data/tests/` (a product change outside this task) or a reviewed,
  recorded operator step. This brief invents neither command.

## 4. Combined-tree acceptance requirements

### 4.1 Existing suites that must run against the eventual combined tree

All live under `offline_data/tests/` and are collected by `pytest-all`
(`offline_data/pyproject.toml:81-90`: `testpaths = ["tests"]`, branch coverage, floor
98.61). Paths below are relative to `offline_data/`.

| Suite | Module and docstring lines | What it holds |
|---|---|---|
| Metadata round trip | `tests/unit/test_metadata.py:1-12`; `tests/integration/test_core_contract_roundtrip.py:1-20` | field-by-field descriptor and partition emission, recomputed identity through the core, byte-for-byte goldens, strict re-parse through the core models |
| Temporary SQLite registration | `tests/integration/test_sqlite_dataset_registration.py:1-24` | register, commit, close, reopen, read back by hash and ordinal through `SqliteDatasetRepository`; idempotent re-registration; two structured negative controls |
| Normalization | `tests/unit/test_normalize.py:1-10`; `tests/unit/test_validation.py:1-10` | container bytes and checksums; the section 4 rule matrix with explicit intervals |
| Readers | `tests/unit/test_candle_csv.py:1-10`; `tests/unit/test_binance_kline_csv.py:1-12` | `ohlcv-csv/1` and `binance-spot-kline-csv/1` refusals on three edges, including the field-12 residual carriage return of slice 4 |
| CLI | `tests/unit/test_cli.py:1-12` | exit table, accepted write sequence, cleanup, the nine Binance goldens pinned byte for byte |
| Providers and package | `tests/unit/test_providers.py:1-10`; `tests/unit/test_package.py:1-8` | provider contract and fault class; version pin |
| Safety | `tests/safety/test_boundaries.py:1-47`; `TestDependencyPins` at `:1841-1920` | package census, import roots, no environment, network or process reach, write pins, dependency and lock pins including the core's `directory = "../"` and `editable: False` |

The focused trio named by `offline_data/README.md:87-91` (registration, round trip,
boundaries) is the fast consumer check; it is not a substitute for `pytest-all`.

Core suites that the combination makes relevant and that `scripts/verify.ps1`
already runs: `tests/safety/test_stage9_boundaries.py` (head pin, module census,
schema census, status rows), `tests/unit/persistence/test_sqlite_stage9_migration.py`,
`tests/unit/persistence/test_sqlite_migrations.py`,
`tests/unit/persistence/test_sqlite_registries.py` and
`tests/unit/test_package_layout.py` (all in the Stage 9 `--name-status` list).

### 4.2 Both complete verifiers and every existing gate

- `offline_data/scripts/verify-offline.ps1:21-49`: `lock-check`, `sync`,
  `ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`, then
  `git diff --check -- .`; branch-coverage floor 98.61
  (`offline_data/pyproject.toml:88`, `:97`; `offline_data/README.md:156-160`).
- `scripts/verify.ps1:19-73`: `lock-check`, `sync`, `ruff-format-all`,
  `ruff-check-all`, `mypy-all`, `schema-generate-check`, `migration-check`,
  `pytest-all`, `build`, `schema-distribution`, then `git diff --check`;
  branch-coverage floor 90 (`pyproject.toml:96`, `:105`).
- Hygiene: both `git diff --check` stages examine tracked changes; an untracked file
  is outside them, which is why this task's byte rules (UTF-8 without BOM, LF, no
  trailing whitespace) are checked and reported separately by the worker.
- Independent implementation review APPROVE on the exact final subject, worker idle,
  no concurrent tests or verifier (plan:115).
- Order and serialization: the offline verifier first, then the core verifier, on
  the same subject, never concurrently (plan:104-111; `offline_data/README.md:165`),
  serial under `.crypto-lab-host/verifier.lock` with
  `dispatch_wait_markers=[verify.ps1]` (plan:113).

### 4.3 Binding to the exact combined subject and environments

For each verifier run the route must record: the combined commit id and clean
status; the blob identities of `scripts/verify.ps1`, `scripts/invoke-uv.ps1`,
`offline_data/scripts/verify-offline.ps1` and
`offline_data/scripts/invoke-offline-uv.ps1` at that commit (`git rev-parse
<commit>:<path>`); which `.venv` each launcher validated; the section 3.3 installed-core
evidence; the coverage figures against the unchanged floors; and every warning, skip
and failure. Earlier passes do not transfer: the slice passes ran on the `079395be`
core and the Stage 9 merged-main pass ran without `offline_data/` (plan:111). A
changed subject after verification requires renewed verification and review
(plan:117).

## 5. Controller integration gaps and handoff

CONTROLLER-SIDE CONFIRMATION REQUIRED for every controller-side statement in this
section (what the controller implements, records or requires): the CTL and P2CTL
trees were not readable (section 0.3). Statements about committed product-repository
text are inspected facts; the controller-side statements rest on that text and on the
plan's citations of controller sources (plan:17, :18, :24).

### 5.1 Capabilities described in committed plan text (controller implementation uninspected)

Two of the capabilities below were observed: bounded dispatch (this task's own
execution) and feature-branch publication (the section 1.4 decorations). For the
rest, the plan text describes the route; the controller implementation was not
inspected.

- Bounded IMPLEMENT dispatch with a single writable path and read-only Git for the
  worker (plan:71-79; observed in this task's own execution).
- VERIFY with `verification_scope=full` and `verification_targets=[]`, running the
  two verifiers in order on one subject (plan:102-111).
- Serial heavy verification under `.crypto-lab-host/verifier.lock`,
  `dispatch_wait_markers=[verify.ps1]`, and priority for the parked Workstream A
  (plan:113; registration plan
  `docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md:220-222`).
- Independent implementation review and advisor ACCEPT_TASK (plan:115, :121).
- Commit of exactly the accepted manifest, an outgoing-range publication-safety scan,
  non-force publication to `origin/<task branch>` through a registered single-branch
  refspec, and identity recording (plan:122-125). Consistent observation: each
  published slice sits on its own remote-tracking branch (section 1.4).
- Plan:24 cites `P2CTL/src/clabctl/gitops.py:540-549` for "main-acceptance and
  checked-out-branch publication requirements"; the content was not readable here,
  so what those requirements are and whether they are implemented is unknown to this
  brief.

### 5.2 Transitions without evidence in this brief (controller trees unreadable)

The CTL and P2CTL trees were not readable (section 0.3), so this brief cannot say
whether the controller implements any transition below. "No evidence here" means not
inspected, not absent. The product-repository documents inspected for these
statements are the five P2 plan documents under `docs/superpowers/plans/` dated
2026-11-09 to 2026-11-11 (Glob `2026-11-*`), searched with Grep for `merge` together
with `main` and for `milestone`.

- Combining branches. This task excludes branch combination, rebase and reset
  (plan:77); the registration and corrections plans exclude a Stage 9/main merge from
  their tasks and require a separately reviewed route (registration plan `:60`,
  `:225`; corrections plan `:40`, `:103`); the readiness plan states that the combined
  integration "still needs its own reviewed route" (plan:9). The `merge` search
  observed only those exclusions, the references to Workstream A's merged-main pass
  and verifier (plan:111; corrections plan `:194`), and the first-slice plan's
  prerequisite that Stages 1-8 are merged into `main`
  (`docs/superpowers/plans/2026-11-09-project-2-offline-data-first-slice-implementation-plan.md:126`);
  the `milestone` search added that plan's "Stage 9 milestone merge" references
  (`:130`, `:260`). None of the five documents describes a controller transition that
  combines a `project-2-*` branch with `main` or records the resulting commit. Whether
  `P2CTL/src/clabctl/gitops.py` implements such a transition is unconfirmed (plan:24
  cites `:540-549` for main-acceptance and checked-out-branch publication
  requirements; unread here).
- Verifying a combined tree. The committed VERIFY description binds a verification to
  one task branch and worktree (plan:102-111). None of the five documents binds a
  verification to a merge-result commit in two environments together with the
  section 3.3 evidence; controller-side availability unconfirmed.
- Recording milestone acceptance. A milestone-acceptance note is excluded from this
  task (plan:77) and required of the later route (plan:55). The `milestone` search
  observed only plan:55, plan:77 and the first-slice plan's "Stage 9 milestone merge"
  (`:130`, `:260`); none of the five documents describes where or how the controller
  records a P2 milestone. The recording artefact is in the unread programme-authority
  range (plan:17); unconfirmed.
- Publishing the checked-out destination. Slices were published to feature branches
  (section 1.4). Plan:3 observes that the owner published `main` for Stage 9 at
  05:03Z; plan:129 lists main publication as pending for P2. Whether `main` is a
  registered controller destination, and under which requirements, is recorded at
  plan:24's unread range; unconfirmed.

### 5.3 Implementation gaps, delegated decisions and owner-held boundaries

Plan:55 asks for implementation gaps to be distinguished from owner-held permissions.
Each item below is sorted into one of three classes with the evidence it rests on.

Confirmed by inspected source (an implementation gap or a reserved boundary):

- The section 3.4 execution-capability gap: no admitted sub-project profile observes
  the installed migration head or the installed-module identities inside
  `offline_data/.venv` (closed profile set at
  `offline_data/scripts/invoke-offline-uv.ps1:30-33`, `:167-337`).
- Acquisition stays reserved: lifting P2-B1 is "a separately authorized acquisition
  and a later task" (`offline_data/README.md:175`; first-slice plan `:258`), and
  `AGENTS.md:18` admits network acquisition only through an exact one-time command
  named in an approved plan and separately approved by the user. The P2-B2 boundary
  report itself asks the owner how to continue (`offline_data/README.md:187-189`).
  P2-B3 has two halves (`offline_data/README.md:726-729`): retaining Binance fields 7
  to 12 would be a reviewed product change, and replacing synthetic fixtures entails
  ingesting a real Binance archive, which the next item reserves.
- Real-source execution stays reserved: the real-source adapter and any claim of
  real-source execution "wait for the authorized source verification"
  (`offline_data/README.md:750-752`).
- The standing boundaries (no live trading, no network, no GitNexus, no Docker or
  deployment) are fixed by `AGENTS.md` and every plan; they are not decisions.

Delegated under the standing authorization, as recorded in committed plan text:

- This plan and the registration and corrections plans were proposed under STANDING
  OWNER AUTHORIZATION 2026-11-10, AUTONOMOUS PROGRAMME DELIVERY (plan:3; registration
  plan `:6-7`; corrections plan `:3`). The registration and corrections plans record
  model decisions "under standing owner delegation; not a human message or approval"
  (registration plan `:45`; corrections plan `:48`), and this plan records its
  scheduling choice as a "Model scheduling decision" of class task_sequencing
  (plan:113). Selecting and planning a
  bounded integration route, including its direction, destination branch and the
  commit that represents P2, and scheduling that work, are therefore programme
  decisions taken through the existing gates: independent plan APPROVE and advisor
  DELEGATED_PLAN_ACCEPTED on the exact plan bytes, registered branch, worktree and
  refspec, unique mission (plan:69), exact-subject verification (plan:102-111),
  independent implementation review and ACCEPT_TASK (plan:115, :121), and controller
  commit and publication (plan:122-125). No fresh human decision is a prerequisite of
  selecting or scheduling that route. The full scope of the delegation is recorded in
  `P2CTL/config/mission_checkpoint.md:232-314` (plan:17), which was not readable
  here; this brief relies on the committed plan headers only.

Unresolved, CONTROLLER-SIDE CONFIRMATION REQUIRED (this brief asserts neither
"owner-held" nor "delegated" for them):

- Publication of `main`. It stays a required destination gate (section 5.4 item 9;
  plan:129). The only `main` publication observed in committed text is the owner's
  Stage 9 publication (plan:3), an observation and not a rule; the controller's
  main-acceptance and checked-out-branch publication requirements are cited at
  plan:24 (`P2CTL/src/clabctl/gitops.py:540-549`) and were not readable.
- Milestone acceptance. It stays required to be recorded (plan:55) and is excluded
  from this task (plan:77). Which party records it and in which artefact is in the
  unread range of plan:17.

### 5.4 Ordered requirements checklist for a later reviewed integration route

This is a list of requirements. It is not an executable route. Section 5.1 lists the
dispatch, verification, review, acceptance, commit and feature-branch publication
capabilities that committed plan text describes and that items 2, 5, 7 and 9 reuse;
of those, only bounded dispatch and feature-branch publication were observed, and
the controller implementation of the rest is uninspected. For the combination
transition, the combined-subject verification, the milestone record and a `main`
destination (items 3, 4 and 8, and the destination of item 9), this brief holds no
evidence of availability either way, because the controller trees were not readable
(section 0.3); each is a requirement the later route must establish, with
controller-side confirmation of whatever already exists.

1. Route selection recorded through item 2's gates under the standing authorization
   (section 5.3): direction (P2 stack onto `main` at `874fb51b`, or `main` into the
   P2 branch); destination branch; and which commit represents P2 (`19d4db1e` or an
   accepted descendant such as this branch's accepted commit). No fresh human
   decision is a prerequisite of this selection; the reserved boundaries of
   section 5.3 (acquisition, real-source execution) are not inputs to it.
2. A reviewed integration plan with exact base commits, independent plan APPROVE and
   advisor DELEGATED_PLAN_ACCEPTED, registered branch, worktree and refspec, and a
   unique mission (the prerequisites of plan:69).
3. A controller transition, or a recorded operator step, that performs the
   combination and records the result commit id, its parents and an empty
   `git status --porcelain --untracked-files=all`; the route verifies the result
   textually against both parents even though section 2.3 found no overlapping path.
4. Fresh synchronization of both environments in the combined worktree with the
   section 3.3 evidence, including a reviewed resolution of the section 3.4
   capability gap (how `r0002` presence and the installed-module identities inside
   `offline_data/.venv` are observed).
5. Both verifiers in order on the combined subject, every gate retained, floors 90
   and 98.61 unchanged, all warnings, skips and failures reported (plan:104-111).
6. Reconciliation of closed-world guards that may trip on the combined tree (the
   Stage 9 counts and status rows named in section 2.6); any required change is a
   reviewed core change owned by Workstream A, never a side effect of the
   combination.
7. Independent implementation review APPROVE on the exact combined subject.
8. Milestone acceptance recorded in the controller's record of authority (plan:55);
   the recording party and artefact are controller-side facts (section 5.3).
9. Publication of the destination through a registered refspec, non-force, with the
   remote commit confirmed and recorded; whether `main` is a registered destination
   and what its publication requires is controller-side (section 5.3).
10. Follow-up tasks queued rather than folded in: the README pending-finalization
    text (`offline_data/README.md:23-26`, `:746-749`); the README's pin of the
    registration test to core `079395be` (`offline_data/README.md:75-76`,
    `:736-738`), which becomes stale once the sub-project runs against a combined
    core; the README line-376 follow-up (section 6); and the P2-B1 lift.

## 6. Explicit residuals

- **P2-B1 (Parquet).** Preserved. `offline_data/README.md:169-180`; the limitation
  literal `offline_data/src/crypto_lab_offline_data/metadata.py:144-148` carried in
  every `known_limitations` and `quality_observations`; the interim container
  `normalized-ndjson/0.1.0` (`offline_data/README.md:724-725`). Lifting it is a
  separately authorized acquisition.
- **P2-B2 (offline lock resolution).** Preserved. `offline_data/README.md:181-189`:
  a lock, check or sync that the local uv cache cannot satisfy is reported once with
  the exact uv message and nothing is acquired.
- **P2-B3 (Binance fields 7 to 12 not retained; synthetic fixtures only).**
  Preserved. `offline_data/README.md:726-732`; literal at
  `offline_data/src/crypto_lab_offline_data/metadata.py:149-156`.
- **Pending dataset finalization.** Preserved. `offline_data/README.md:23-26` and
  `:746-749`: no interim container enters a persistent registry; registration is
  exercised only as the temporary-database contract test; finalization through the
  artifact finalizer follows the Stage 9 merge and stays pending. Stage 9 adds the
  finalizer (`src/crypto_lab/artifacts/finalizer.py` in the `874fb51b` list). The
  inspected sub-project holds no finalization route or command (Grep for `finaliz`
  under `offline_data/src/` observed no match; the README names finalization only as
  pending, `:24-25` and `:748-749`); whether any finalization authorization is
  recorded controller-side is unconfirmed.
- **Core ownership of shared validation.** Preserved. `offline_data/README.md:78-82`
  and the registration plan `:50-51`: Workstream A retains sole authority over shared
  core code, contracts and migrations; the sub-project owns only its tests and README
  explanation. The owner-delegated decisions in force for this mission repeat the
  same ownership.
- **README line-376 follow-up.** Identified, not edited. The refusal-table row
  `offline_data/README.md:376` reads `OFFLINE_DATA.CSV_ROW_SHAPE | a line without
  exactly twelve fields | the line, its length`. It omits the residual-carriage-return
  case that the same README defines at `:344` (field 12: `CSV_ROW_SHAPE` with the
  complete logical row's length for a residual carriage return, checked after fields
  1 to 11) and at `:352-358` (a lone trailing carriage return on the final line, the
  first carriage return of a CR CR LF ending, or a carriage return embedded in field
  12; `value_length` is the complete logical row's length with every carriage return
  counted and the consumed LF or CRLF excluded). The follow-up is recorded at plan:22
  and plan:57 and by the corrections task's delegated decision; the README is
  unchanged by this task.

## 7. Evidence log

Exact admitted Git commands run from the worktree root, with observed results:

| Command | Observed result |
|---|---|
| `git rev-parse HEAD` | `bced68ffa737da8123219bc9e319d862335f902a` |
| `git status --porcelain --untracked-files=all` | no output (before this file existed) |
| `git status --porcelain --untracked-files=all` | `?? offline_data/docs/2026-11-11-integration-readiness.md` (after creation; the only entry) |
| `git rev-parse 3a47d4c9 4d70f673 970c1fb5 19d4db1e ae529fd7 079395be 874fb51b bced68ff 9e07ce23` | the nine full identities of section 0.1 and 1.2 |
| `git show -s --format=%H%x20%ci%x20%s 3a47d4c9 4d70f673 970c1fb5 19d4db1e ae529fd7 079395be 874fb51b bced68ff` | the dates and subjects of section 0.1 |
| `git log --format=%H%x20%P%x20%s 079395be..19d4db1e` | 36 single-parent commits, `c273d418` first (parent `079395be`) |
| `git log --format=%H%x20%P%x20%s 079395be..ae529fd7` | 34 commits; `89d9e597` has parent `4d70f673` |
| `git log --format=%H 19d4db1e..ae529fd7` | `ae529fd7`, `091e1ae5`, `cf634239`, `89d9e597` |
| `git log --format=%H ae529fd7..19d4db1e` | `19d4db1e`, `9e07ce23`, `0f02f7e8`, `d1fad5a9`, `970c1fb5`, `319326b0` |
| `git log --format=%H%x20%P%x20%s 079395be..874fb51b` | 9 single-parent commits, `f441a45a` first (parent `079395be`) |
| `git log --format=%H 19d4db1e..874fb51b` | the same 9 commits |
| `git log --format=%H 874fb51b..19d4db1e` | the same 36 commits as `079395be..19d4db1e` |
| `git log --format=%H%x20%P%x20%s 19d4db1e..bced68ff` | `e4757049` (parent `19d4db1e`), `72da059e`, `bced68ff` |
| `git diff --name-status 19d4db1e bced68ff` | one `A`: the readiness plan |
| `git rev-parse refs/tags/preserved/p2-sqlite-registration-contract-mission3` | `ae529fd79b0b158b4a604517f8d529a9533cd987` |
| `git log -1 --format=%H%x20%P%x20%s refs/tags/preserved/p2-sqlite-registration-contract-mission3` | `ae529fd7`, parent `091e1ae5` |
| `git rev-parse 19d4db1e:offline_data/tests/integration/test_sqlite_dataset_registration.py ae529fd7:offline_data/tests/integration/test_sqlite_dataset_registration.py 970c1fb5:offline_data/tests/integration/test_sqlite_dataset_registration.py 19d4db1e:offline_data/README.md ae529fd7:offline_data/README.md 970c1fb5:offline_data/README.md` | the six blob identities of section 1.5 |
| `git diff --name-status 970c1fb5 ae529fd7` | one `M`: the registration-contract plan |
| `git log -1 --format=%H%x20%D 3a47d4c9` | `origin/project-2-offline-data-implementation`, `project-2-offline-data-implementation` |
| `git log -1 --format=%H%x20%D 4d70f673` | `origin/project-2-binance-kline-reader`, `project-2-binance-kline-reader` |
| `git log -1 --format=%H%x20%D 970c1fb5` | `origin/project-2-sqlite-registration-contract`, `project-2-sqlite-registration-contract` |
| `git log -1 --format=%H%x20%D 19d4db1e` | `origin/project-2-offline-data-review-corrections`, `project-2-offline-data-review-corrections` |
| `git log -1 --format=%H%x20%D ae529fd7` | `tag: preserved/p2-sqlite-registration-contract-mission3` |
| `git log -1 --format=%H%x20%D 874fb51b` | `origin/project-1-stage-9-implementation`, `origin/main`, `origin/HEAD`, `project-1-stage-9-implementation`, `main` |
| `git log -1 --format=%H%x20%D bced68ff` | `HEAD -> project-2-integration-readiness` |
| `git rev-parse origin/main` | `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1` |
| `git rev-parse origin/main origin/project-2-integration-readiness` | exit 128; `874fb51b...` printed, `origin/project-2-integration-readiness` unknown |
| `git rev-parse origin/project-2-integration-readiness` | exit 128, unknown revision |
| `git diff --name-status 079395be 19d4db1e` | 80 `A` paths, 76 under `offline_data/` |
| `git diff --shortstat 079395be 19d4db1e` | `80 files changed, 19373 insertions(+)` |
| `git diff --shortstat 079395be 19d4db1e -- offline_data` | `76 files changed, 17543 insertions(+)` |
| `git diff --name-status 079395be 874fb51b` | 125 paths, none under `offline_data/` |
| `git diff --shortstat 079395be 874fb51b` | `125 files changed, 70651 insertions(+), 575 deletions(-)` |
| `git diff --shortstat 079395be 874fb51b -- src/crypto_lab` | `38 files changed, 21404 insertions(+), 181 deletions(-)` |
| `git diff --stat 079395be 874fb51b -- src/crypto_lab/datasets src/crypto_lab/persistence/migration_runner.py src/crypto_lab/persistence/registries.py src/crypto_lab/domain/canonical_json.py src/crypto_lab/domain/ports.py src/crypto_lab/domain/results.py src/crypto_lab/domain/time.py pyproject.toml uv.lock scripts/invoke-uv.ps1 scripts/verify.ps1` | no output |
| `git diff --stat 079395be 874fb51b -- src/crypto_lab/domain/financial.py src/crypto_lab/domain/records.py src/crypto_lab/domain/diagnostics.py src/crypto_lab/domain/identifiers.py schemas/datasets src/crypto_lab/datasets` | only `src/crypto_lab/domain/identifiers.py`, 24 insertions |
| `git diff 079395be 874fb51b -- src/crypto_lab/domain/identifiers.py` | two new `type` aliases, no deletions |
| `git diff 079395be 874fb51b -- src/crypto_lab/domain/hashing.py src/crypto_lab/domain/__init__.py` | additive hunks only |
| `git diff 079395be 874fb51b -- src/crypto_lab/persistence/database.py` | `ConsistencyReport` and `consistency_report()` hunks only |
| `git diff 079395be 874fb51b -- src/crypto_lab/persistence/schema.py` | large; the only `datasets`/`dataset_partitions` hunks relocate the append-only trigger list |
| `git diff 079395be 874fb51b -- src/crypto_lab/persistence/codecs.py` | `encode_engine_run` and `egress_payload_engine_run` hunks only |
| `git diff 079395be 874fb51b -- src/crypto_lab/artifacts/__init__.py` | the package module imports and re-exports the whole Stage 9 artifacts graph; `ownership` imports retained |
| `git diff --stat 079395be 874fb51b -- src/crypto_lab/artifacts/ownership.py src/crypto_lab/configuration/snapshot.py src/crypto_lab/domain/descriptors.py src/crypto_lab/domain/lifecycle.py src/crypto_lab/domain/versioning.py src/crypto_lab/persistence/diagnostics.py src/crypto_lab/strategy/versioning.py` | no output |
| `git diff --stat 079395be 874fb51b -- src/crypto_lab/persistence/migrations` | one new file, `r0002_stage9_artifacts.py`, 1149 insertions |
| `git show 874fb51b:src/crypto_lab/persistence/migrations/versions/r0002_stage9_artifacts.py` | docstring lines 1-23; `revision`/`down_revision` at lines 32-33 |
| `git show 874fb51b:tests/safety/test_stage9_boundaries.py` | head pin at lines 689-699; census at line 515; schema count at line 675 |
| `git diff 079395be 874fb51b -- tests/unit/test_package_layout.py` | module list additions only, including `r0002_stage9_artifacts` |
| `git diff --stat 079395be 874fb51b -- tests/safety tests/unit/test_package_layout.py tests/architecture docs/development/verification.md README.md` | 11 files, 2363 insertions, 280 deletions |

Denied or rejected across the sessions that produced this brief, recorded without
result: `git log 19d4db1e --not --remotes` (and the same for `ae529fd7` and
`bced68ff`), `git rev-parse <tag>^{commit}`, every `git diff --no-index` form
(rejected by the command guard, so no Git-side byte check of this untracked file was
possible), `git hash-object` with and without `--no-filters` on this brief (denied by
the permission system), and every read of the CTL and P2CTL trees.

Byte hygiene of this untracked file was checked with the Grep tool after the final
edit: the patterns `\r`, `[ \t]+$`, `\t` and `[^\x00-\x7F]` each observed zero
matches, so the file is pure ASCII with LF endings and no trailing whitespace. The
`\r` detector was proven on the CRLF batch files under `offline_data/.venv/Scripts/`
(132 matches). A leading UTF-8 byte-order mark may be stripped by the Grep tool's
decoder before matching, so that pattern does not prove its absence. A separate
Edit-tool match probe for U+FEFF immediately before the first heading found no match
in either its literal or its escaped form; this is limited evidence, because it
assumes the tool preserves a byte-order mark in the content it matches against.

The three quality profiles required by plan section 3 (`ruff-format-all`,
`ruff-check-all`, `mypy-all` through `offline_data/scripts/invoke-offline-uv.ps1`)
were run after this brief was written and again after its correction; their results
belong to the task report, not to this document. Full verification, independent
review, acceptance, commit and publication remain controller-managed steps (plan
section 4).
