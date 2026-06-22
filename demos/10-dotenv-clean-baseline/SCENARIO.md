# Demo 10 - clean `.env.example` baseline (the negative case)

A scanner is only useful if it stays quiet on clean input. This is a
well-formed `.env.example` that documents required config **by name** with
placeholder values — exactly what belongs in a repo.

## Run

```bash
cloudkeys scan demos/10-dotenv-clean-baseline/.env.example
echo "exit code: $?"
```

## What to expect

```
No leaked credentials found. (files scanned: 1)
exit code: 0
```

**0 findings, exit code 0.** Note what is deliberately *not* flagged:

- Placeholder values like `__SET_VIA_SECRET_MANAGER__`
- A GUID-style `AZURE_CLIENT_ID` (an identifier, not a secret)
- A path in `GOOGLE_APPLICATION_CREDENTIALS` (points at a key, isn't one)
- Ordinary config (`MAX_CONNECTIONS`, region strings)

## How to act

Nothing to do — this is the green-CI baseline. Use this file as the model for
committed env templates: reference secret *names*, keep real values in a secret
manager, and keep the actual `.env` gitignored.
