# COST-AWARE MODEL ROUTING — ADD GEMINI 3.8 FLASH

Update the existing Gemini-only agent workflow.
Replace conflicting earlier model assignments rather than appending another
inconsistent policy.

OBJECTIVE

Minimize total cost per accepted task while preserving correctness.
Do not optimize token price by accepting incomplete implementations,
weak tests or repeated failed attempts.

1. ROUTING

Use these defaults where the actual API/tool supports them:

A. Routine coordination, checkpoint summaries, file discovery and task packets:
   Gemini 3.8 Flash Medium.

B. Documentation, bounded log summaries and mechanical non-behavioral edits:
   Gemini 3.8 Flash Low or Medium.

C. Small, well-defined, low-risk code changes and focused tests:
   Gemini 3.8 Flash High.

D. Ordinary multi-file implementation and nontrivial debugging:
   Gemini 4 Hydrogen High.

E. Architecture, ambiguous contracts and critical implementation:
   Gemini 4 Carbon High; Argon High if Carbon is unavailable.

F. Independent review:
   - Ordinary substantive code: Hydrogen High in a fresh read-only context.
   - Critical code: Carbon/Argon High in a fresh read-only context.
   - Documentation-only changes: Flash in a separate review context.

G. Verification:
   Actual commands establish results.
   Flash may prepare an already-approved invocation and summarize its output.
   Do not spend premium-model calls continuously watching a running command.

The routine Flash coordinator may dispatch clearly classified work within
the accepted plan. It must not independently weaken contracts, decide an
architectural ambiguity or treat its summary as acceptance evidence.

2. CHECK REAL MODEL SELECTION

Verify models against the configured Gemini API and supported Antigravity
selection controls.

The documented Flash API identifier is gemini-3.8-flash.
Do not invent effort-suffixed API IDs or unsupported agent configuration.

A model name written in a prompt does not change the executing model.
Record the actual selected model and reasoning setting.

Keep the existing authentication and billing project.
Never print or copy the API key.

If a preferred model is unavailable, report the actual substitution.
Do not silently switch providers or authentication.

3. CLASSIFY BY RISK, NOT FILE COUNT

Do not assign Flash critical behavior merely because the patch is short.

Use Carbon/Argon directly for:
- scheduler claims and concurrency;
- SQLite transactions, migrations and recovery;
- process ownership and cancellation;
- security and permission boundaries;
- authoritative audit/provenance behavior;
- financial semantics where an incorrect assumption changes results.

Hydrogen handles ordinary implementation with settled interfaces.
Flash handles bounded low-risk work with explicit acceptance examples.

The previously identified scheduler concerns remain critical until
reinspection proves they are corrected.

4. ESCALATE WITHOUT WASTING THE CHEAPER MODEL'S SAVINGS

When a worker encounters a substantive contract ambiguity, escalate immediately.

When a low-cost worker has made an initial attempt and a reasoned correction
but still cannot satisfy the same requirement, escalate rather than repeating
the same approach.

Preserve useful changes and pass a compact evidence packet:
- requirement and relevant production interfaces;
- current diff;
- failing test and exact error;
- approaches tried;
- remaining uncertainty.

Do not make the next model repeat the entire investigation.
Return to the lower-cost model once the difficult question is resolved.

Missing permissions, missing dependencies and unavailable tools are not
model-reasoning failures. Handle those boundaries directly.

5. REDUCE REPEATED CONTEXT AND REVIEW COST

Supply the relevant task section and code, not the entire repository history.

Keep one concise continuation record with source references.
Use targeted file reads and bounded log excerpts; retain complete logs on disk.

Use existing supported caching where available. Do not build a cache framework
or assume cached tokens were billed cheaply without usage evidence.

Use one independent review at the appropriate checkpoint.
Re-review the correction and affected behavior, not unrelated accepted code.

Do not run Flash, Hydrogen and Carbon on every task as a mandatory ladder.
Select the appropriate starting model and escalate only when justified.

6. MEASURE ACTUAL VALUE

For each accepted task, record available:
- model(s) and reasoning settings;
- input, cached-input, output and reasoning usage;
- estimated cost using the applicable dated rate;
- implementation attempts and review corrections;
- elapsed execution time and accepted result.

Use provider usage metadata where available.
Mark unavailable accounting UNKNOWN, not zero.
Do not double-count reasoning when it is already included in output usage.

Keep rate dates explicit and reassess after promotional pricing ends.
Do not claim a saving by comparing only token prices while excluding rework.

Honor existing billing controls. Do not create new arbitrary turn ceilings,
change spending limits or enable another paid service.

7. KEEP THE EXISTING DELIVERY SAFEGUARDS

No changes to acceptance requirements, security, test assertions,
publication permissions or core/adapter isolation.

At most two implementation workers on independent worktrees.
One heavy verifier at a time, with no competing heavy work.

A cheap worker does not approve its own implementation.
An expensive model does not override a failed test.
A passing weak test does not establish the promised behavior.

NEXT ACTION

Reconcile the active task and select the appropriate model without
interrupting an active verifier.

Return:
Role | Actual model | Task | Reason for selection

Then continue the existing task. Do not start another controller project
or repeat completed setup.
