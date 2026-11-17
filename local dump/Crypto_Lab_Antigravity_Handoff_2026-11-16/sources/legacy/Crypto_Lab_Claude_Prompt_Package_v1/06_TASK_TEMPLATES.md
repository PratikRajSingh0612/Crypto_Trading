# 06 - Short delegation templates

Use these as task bodies, not installed agent files. Resolve actual paths and identities before dispatch. Give workers the relevant installed skill names/entrypoints; do not assume inherited context. The controller remains responsible for accepting their evidence.

## Implementer

ROLE: Implement one dependency-ready slice, not the entire product in a subagent.
ROOT/BRANCH/BASE: [actual values]
TASK: [observable behavior and its source contract]
READ: [exact relevant source/spec/plan sections]
WRITE: [owned file set, explicit allowed boundary]
SKILLS: [relevant locally resolved process skills]
ACCEPTANCE: [tests/fixtures, key negative cases, quality checks]
LIMITS: [no network/acquisition/publication unless specifically supplied; no other writer; no lowering guards]

Read before editing. Use genuine RED/GREEN for new production behavior.
Return changed paths, exact test exits, actual findings, unresolved limits and
final content identity. Do not claim an unrun full verifier or independent
review. Do not commit/push unless the controller explicitly assigns that role.

## Independent reviewer

ROLE: Fresh, read-only review of a stable diff.
SUBJECT: [base, subject commit or complete reviewed path/blob manifest]
CONTRACT: [active spec/plan and approved decisions]
EVIDENCE: [focused exits, relevant controls and full-run record if present]

Check constructibility, semantics, wrong-success paths, transaction/process
ownership, privacy, actual integration rather than mocks, tests and truth of
documentation. Cite exact code and reproducible effect for material findings.
Classify Critical / Important-blocking / Important-nonblocking / Minor, not
style preferences as architecture failures. No writes, reformatting, package
install or concurrent full suite. Return APPROVE, APPROVE_WITH_MINOR or
REQUEST_CHANGES with specific findings and limits. Reverify the changed
material when fixes land; do not demand a new reviewer swarm.

## Debugger

ROLE: Determine a failing boundary from preserved evidence, not force a pass.
FAILURE: [actual node/stage/exception and full log path]
SUBJECT: [exact tree/runtime/evidence identities]
HYPOTHESES: [few distinct possibilities with discriminating observations]
BOUND: [specific focused runs/diagnostics; no full suite by default]

Separate facts from hypotheses. Do not open mutable failed evidence as an
experiment, kill foreign processes, suppress failure, retry indefinitely,
modify production behavior or acquire a runtime. Propose the smallest
supported correction and its proof. Say what remains unknown.

## Adapter researcher

ROLE: Verify one real engine's feasible scope before implementation.
ENGINE/PIN: [candidate exact version, still unapproved for acquisition]
CONSTRAINTS: Windows-local, isolated runtime, credential-free, no Docker/WSL
requirement, historical/simulated only.

Use official versioned docs/source/license. Return supported vs unsupported
capabilities, runtime/data needs, allowed execution route, exact acquisition
proposal and material gaps. Documentation claims are not executed evidence.
Do not install packages, download binaries/models or invent compatibility.

## UI worker

ROLE: Implement the approved local UI slice over real application services.
JOURNEY: [goal and actual data/service interfaces]
STATES: [normal, empty, loading, failed, cancelled, stale]
STYLE: [approved tokens/reference; no fabricated available screenshot]

Read the selected design skill. Produce a viewable mockup or actual render,
implement interactions, test accessibility and inspect screenshots. Do not
put business logic in the view, substitute dummy callbacks, deploy to cloud,
connect to a personal browser or use real credentials. Report screenshot
artifacts and functional checks separately.
