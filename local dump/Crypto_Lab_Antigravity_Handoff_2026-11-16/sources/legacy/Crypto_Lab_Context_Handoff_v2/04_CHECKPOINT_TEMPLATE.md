# Minimal checkpoint fields - reuse existing records

This is a field checklist, not a requirement to add another state store.

- Recorded at:
- Mission ID / advisor session ID / source bundle digest:
- Product root, worktree, branch, HEAD, dirty/index state:
- Controller commit, active policy/config identity:
- Last accepted milestone and evidence references:
- Current project/stage/task and owner:
- Active subject/file identities:
- What is implemented versus reviewed versus verified versus published:
- Current native process/attempt/marker identity, or none:
- Verification evidence, actual exits, skips and coverage when relevant:
- Decisions adopted, source, scope, conditions and whether consumed:
- Proposed or unresolved decisions, kept separate:
- Known limitations and their owning milestone:
- Next action and exact prerequisites:
- Relevant local source pointers:
- Credential references only, never values:
- Remaining configured usage limits, with accounting source:

After each accepted change, update this concise checkpoint and append the
significant decision/rationale to the existing log. Keep the full raw evidence
where it belongs, with bounded retrieval and secret-safe handling.

On restart, reconcile current Git/process/evidence facts. A journal entry is not
proof that a process finished. A stale summary is not permission to discard
newer work. Never resume an unrelated last session or replay a consumed action.
