# Demo 08 - Kubernetes Secret manifest in a GitOps repo

A `kind: Secret` manifest was committed to a GitOps/ArgoCD repo. A common
misconception is that the base64 in `data:` is encrypted — it is only encoding.
Worse, this one carries a TLS private key and an Azure SAS backup URL in
plaintext `stringData`.

> All values are **fake** placeholders shaped like the real formats. No live
> secrets.

## Run

```bash
cloudkeys scan demos/08-kubernetes-secret/secret.yaml
```

## What to expect

**2 findings:**

- `private_key_pem` — CRITICAL (the `tls.key` RSA private key)
- `azure_sas_token` — HIGH (the `backup_sas_url`, a delegated, long-lived SAS
  granting `rwdlac` on the backups container)

(The base64 `app_password` in `data:` is intentionally low-entropy/short and is
*not* flagged — cloudkeys avoids base64 false positives unless keyword-anchored.)

Exit code is `1`.

## How to act

1. **Treat the TLS key as compromised** — reissue the certificate and rotate.
2. **Invalidate the SAS** by rotating the storage account key that signed it
   (a SAS can't be revoked individually); reissue a least-privilege,
   short-lived SAS.
3. Stop committing raw Secrets. Use **Sealed Secrets**, **SOPS + age/KMS**, or
   an external secret store (External Secrets Operator) so only ciphertext is
   in git.
4. Purge from history.
