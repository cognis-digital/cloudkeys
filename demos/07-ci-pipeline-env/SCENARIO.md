# Demo 07 - secrets hard-coded into a CI workflow `env:`

Instead of GitHub Actions secrets / OIDC, someone pasted temporary STS
credentials and a GCP API key straight into the workflow's `env:` block. These
are now in the repo (and in every fork and CI log).

> All values are **fake** placeholders shaped like the real formats. No live
> secrets.

## Run

```bash
cloudkeys scan demos/07-ci-pipeline-env/deploy.yml
```

## What to expect

**3 HIGH findings:**

- `aws_access_key_id` — note the `ASIA` prefix (a *temporary* STS key)
- `aws_session_token` — the matching long-lived-looking session token
- `gcp_api_key` — `AIza...`

Exit code is `1`.

## How to act

1. The STS pair is time-limited but **live until expiry** — revoke the issuing
   role's active sessions (`aws iam ...` / role trust) and rotate the source
   key; you cannot revoke a session token individually.
2. Regenerate the GCP API key and add API/application restrictions.
3. Replace inline `env:` secrets with the platform's secret store, and prefer
   **OIDC cloud federation** so CI never holds static keys.
4. Rotate even if the commit was quickly reverted — assume CI logs captured it.

This is also the canonical CI-gate use case:

```bash
cloudkeys --format json scan . || { echo "Leaked cloud credential"; exit 1; }
```
