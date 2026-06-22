# Demo 05 - unrestricted GCP / Firebase API key in a frontend bundle

A web app shipped its Firebase/GCP config (`apiKey: "AIza..."`) in client
JavaScript. Firebase web keys are designed to be embeddable, but an
**unrestricted** key can call billable Google Cloud APIs — making it a real,
frequently-abused leak when no API/referrer restrictions are set.

> The key is a **fake** placeholder shaped like the real `AIza...` format.
> CLOUDKEYS only detects, redacts, and classifies it.

## Run

```bash
cloudkeys scan demos/05-gcp-api-key/firebase-config.js
```

## What to expect

**1 HIGH finding:**

- `gcp_api_key` — matched on the `AIza` + 35-char shape.

Exit code is `1`.

## How to act

1. **Regenerate the key** in GCP Console → APIs & Services → Credentials.
2. **Add restrictions** to the new key: HTTP-referrer (for web), and an API
   allowlist limited to exactly the Firebase/GCP APIs the app uses. This is the
   single most important step — restriction is what makes a public web key safe.
3. Audit API usage / billing for anomalous calls since the key shipped.
4. Don't treat this as "secret in git" alone — the key is in every user's
   browser, so restriction (not just rotation) is the real fix.
