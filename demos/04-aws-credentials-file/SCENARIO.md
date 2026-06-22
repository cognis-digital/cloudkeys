# Demo 04 - committed `~/.aws/credentials` file (two profiles)

A developer ran `aws configure`, which writes long-lived keys into
`~/.aws/credentials`, then later copied the file into a project folder and
`git add .` swept it in. This is one of the most common real AWS leaks.

> Every value in `credentials` is **fake / non-functional**, shaped like the
> real format. CLOUDKEYS only detects, redacts, and classifies — it never
> uses any discovered secret.

## Run

```bash
cloudkeys scan demos/04-aws-credentials-file/credentials
```

## What to expect

Two profiles (`[default]`, `[ci-deploy]`) each contribute an access-key-id +
secret pair, so the scan reports **4 findings**:

- `aws_access_key_id` x2 — HIGH (20-char, `AKIA` prefix-validated)
- `aws_secret_access_key` x2 — CRITICAL (keyword-anchored, entropy-gated)

Exit code is `1`.

## How to act

1. **Both profiles are compromised** — the `ci-deploy` key is the higher-blast
   one if it has deploy/admin policies. Deactivate then delete both access keys
   in IAM (Console → IAM → Users → Security credentials).
2. Rotate and store the replacements in a secret manager (AWS Secrets Manager,
   Vault) or short-lived role credentials — never on disk in a repo.
3. Purge the file from history (`git filter-repo` / BFG) and add
   `**/credentials` and `.aws/` to `.gitignore`.
4. Audit CloudTrail for use of either key id since the commit date.
