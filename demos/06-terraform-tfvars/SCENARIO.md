# Demo 06 - Terraform `terraform.tfvars` with hard-coded secrets

`terraform.tfvars` is supposed to be gitignored, but it routinely gets
committed with live values baked in — here mixing Azure and AWS credentials in
one infrastructure-as-code file.

> All values are **fake** placeholders in the real wire formats. The Azure
> storage `AccountKey` is left as a labelled placeholder (the real-format
> 88-char base64 case is exercised by the test suite). No live secrets.

## Run

```bash
cloudkeys scan demos/06-terraform-tfvars/terraform.tfvars

# Emit SARIF for GitHub code-scanning / Azure DevOps:
cloudkeys --format sarif scan demos/06-terraform-tfvars/terraform.tfvars
```

## What to expect

**2 findings spanning two providers:**

- `azure_client_secret` — CRITICAL
- `aws_access_key_id` — HIGH

(In a real leak the `AccountKey=` placeholder would be a live Azure storage key
— `azure_storage_key`, CRITICAL — giving full data-plane access to the tfstate
account and exposing your Terraform *state*, which often contains more secrets.)

Exit code is `1`.

## How to act

1. **Rotate the Azure storage key** (key1/key2 swap) first — it gates the
   remote state backend; treat everything in that state file as exposed too.
2. Rotate the Azure AD client secret and the AWS access key.
3. Move secrets out of `.tfvars`: use `TF_VAR_*` env vars, a secrets backend,
   or OIDC-federated CI so no static keys exist.
4. Add `*.tfvars` and `*.tfstate*` to `.gitignore`; purge from history.
