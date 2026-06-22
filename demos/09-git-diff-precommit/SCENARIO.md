# Demo 09 - block a leak in a pre-commit hook (stdin)

The highest-value place to catch a leak is *before* it ever lands in history.
cloudkeys reads from stdin (`-`), so you can pipe `git diff` straight in from a
pre-commit hook and reject the commit.

> The diff contains **fake** placeholder keys shaped like the real format.

## Run

Scan a captured diff (this demo's `staged.diff`):

```bash
cat demos/09-git-diff-precommit/staged.diff | cloudkeys scan -
```

In a real `.git/hooks/pre-commit` (or via `pre-commit` framework):

```bash
#!/usr/bin/env bash
if ! git diff --cached | cloudkeys scan - ; then
  echo "Commit blocked: leaked cloud credential in staged changes." >&2
  exit 1
fi
```

## What to expect

**2 findings**, located against `<stdin>` line numbers:

- `aws_secret_access_key` — CRITICAL
- `aws_access_key_id` — HIGH

Exit code is `1`, which fails the hook and aborts the commit.

## How to act

The commit never happens, so there is nothing to rotate yet — remove the keys
from `app/settings.py`, load them from the environment / a secret manager
instead, and re-stage. If you'd already committed before adding the hook, treat
the keys as leaked and rotate (see demos 01/04).
