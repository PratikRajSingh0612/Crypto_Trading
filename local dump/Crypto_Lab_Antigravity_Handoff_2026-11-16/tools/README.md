# Optional read-only collector

Review the script before use. It requires only an already-installed Python and Git;
it is a developer inventory tool, not a product test runner. It installs nothing.

```powershell
python .\collect_local_context.py --repo "C:\path\to\Crypto_Trading" --out "C:\path\outside-repository\new-context-snapshot"
```

The output must be a NEW directory outside every registered worktree. The collector
copies selected tracked documentation and script/configuration sources, extracts exact
plan headings with line numbers, and records local Git state. It does not fetch, push,
run tests, delete files, edit the repository, inspect credentials/environment values,
or manage processes. It does not automatically copy untracked files or private
controller journals. Preserve those separately in the takeover.

This is not an atomic snapshot. Re-read changing sources before accepting a product
candidate. The output contains local paths and must not be automatically published.
The utility was syntax-checked and smoke-tested in a disposable repository in this
chat container, not run against your Windows checkout.
