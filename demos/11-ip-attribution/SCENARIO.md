# Demo 11 — leaked credential + cloud IP attribution (offline)

A leaked AWS access key sits in the same file as several endpoints. cloudkeys
finds the credential **and** attributes the IPs to AWS/GCP using the real
published IP-range feeds — so you immediately see which cloud the blast radius
touches. This runs fully offline against the committed fixture cache.

## Run it (air-gapped)

```bash
# point the feed cache at the committed test fixture (no network needed)
export COGNIS_FEEDS_CACHE="$(git rev-parse --show-toplevel)/tests/fixtures/cognis-feeds"

cloudkeys scan --attribute --offline demos/11-ip-attribution/leaked_with_endpoints.env
```

Expected: one `aws_access_key_id` finding, plus an attribution block:

```
Cloud IP attribution (AWS/GCP IP-range feeds):
  3.4.12.4    -> AWS AMAZON eu-west-1
  34.1.208.1  -> GCP Google Cloud africa-south1
  10.0.0.1    -> (not in AWS/GCP ranges)
```

## Live data

Drop `--offline` after `cloudkeys feeds update` to attribute against the
current ranges fetched from:

* AWS — https://ip-ranges.amazonaws.com/ip-ranges.json
* GCP — https://www.gstatic.com/ipranges/cloud.json
