# Demo 01 - basic leaked-credential scan

This demo shows CLOUDKEYS triaging a realistic, accidentally-committed config
file that mixes several cloud providers' credentials.

> All credentials in `leaked_config.env` are **fake / non-functional** values
> shaped like the real formats. CLOUDKEYS never uses any discovered secret; it
> only detects, redacts, and classifies them so you can rotate.

## Run

```bash
# Human-readable triage table
python -m cloudkeys scan demos/01-basic/leaked_config.env

# Machine-readable JSON (for CI / ticketing)
python -m cloudkeys --format json scan demos/01-basic/leaked_config.env
```

## What to expect

The scanner reports findings such as:

- `aws_access_key_id` (AKIA... 20-char, prefix-validated) - HIGH
- `aws_secret_access_key` (keyword-anchored 40-char, entropy-gated) - CRITICAL
- `gcp_api_key` (AIza...) - HIGH
- `azure_storage_key` (AccountKey=...==) - CRITICAL

Each finding includes a redacted match, Shannon entropy, a **blast-radius**
explanation (what an attacker could reach with that credential type), and a
**remediation** step (how to revoke/rotate).

Exit code is `1` because findings exist - wire this into CI to fail builds that
leak secrets:

```bash
python -m cloudkeys scan . || echo "secrets found - rotate before merge"
```
