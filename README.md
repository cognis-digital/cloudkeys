<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=CLOUDKEYS&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="CLOUDKEYS"/>

# CLOUDKEYS

### Find leaked cloud keys (AWS/GCP/Azure) + classify blast radius

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Find+leaked+cloud+keys+AWSGCPAzure++classify+blast+radius;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-cloudkeys.svg?color=6b46c1)](https://pypi.org/project/cognis-cloudkeys/) [![CI](https://github.com/cognis-digital/cloudkeys/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/cloudkeys/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-cloudkeys
cloudkeys scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install:**

   ```bash
   pip install -e .
   ```

2. **Scan a path** (files and/or directories, recursively) for leaked AWS/GCP/Azure credentials with the `scan` subcommand. The `paths` argument is variadic and accepts `-` for stdin:

   ```bash
   cloudkeys scan ./src
   ```

   Scan multiple targets, or pipe content in:

   ```bash
   cloudkeys scan ./src ./config
   git show HEAD | cloudkeys scan -
   ```

3. **Get machine-readable output** with the global `--format` flag (placed before the subcommand). `json` for any tooling, `sarif` for code-scanning dashboards:

   ```bash
   cloudkeys --format json  scan ./src
   cloudkeys --format sarif scan ./src > cloudkeys.sarif   # SARIF 2.1.0
   ```

4. **Read the result.** Each finding lists `SEVERITY`, `DETECTOR`, provider, file:line, the matched secret, its entropy, a `blast:` (blast-radius) assessment, and a `fix:` remediation, plus a severity-count summary. The process **exits 1 when any credential is found**, **0 when clean**, **2 on runtime error with nothing scanned**.

5. **Use it in CI** — block a commit/build that leaks a cloud key:

   ```bash
   cloudkeys --format json scan . || { echo "Leaked cloud credential detected"; exit 1; }
   ```


## Contents

- [Why cloudkeys?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [SARIF export](#sarif) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why cloudkeys?

key triage

`cloudkeys` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Shannon Entropy
- ✅ Redact
- ✅ Blast Radius
- ✅ Scan Text
- ✅ Scan Path
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-cloudkeys
cloudkeys --version
cloudkeys scan .                       # scan current project
cloudkeys scan . --format json         # machine-readable
cloudkeys scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ cloudkeys scan .
  [HIGH    ] CLO-001  example finding             (./src/app.py)
  [MEDIUM  ] CLO-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real-world leak scenarios

Runnable, self-contained scenarios under [`demos/`](demos). Each folder has a
realistic input file (in the format the leak actually shows up in) and a
`SCENARIO.md` explaining where the data came from, the exact command, what to
expect, and **how to act**. Every credential is a fake placeholder shaped like
the real format — cloudkeys never uses a discovered secret.

| Demo | Scenario | Detectors exercised |
|---|---|---|
| [`01-basic`](demos/01-basic) | Accidentally committed app config (`.env`) | aws akid/secret, gcp api key, azure storage/client-secret |
| [`02-clean`](demos/02-clean) | Clean file — no findings | — |
| [`03-mixed`](demos/03-mixed) | Mixed signal text | — |
| [`04-aws-credentials-file`](demos/04-aws-credentials-file) | A committed `~/.aws/credentials` with two profiles | aws_access_key_id, aws_secret_access_key |
| [`05-gcp-api-key`](demos/05-gcp-api-key) | Unrestricted GCP/Firebase API key in a frontend bundle | gcp_api_key |
| [`06-terraform-tfvars`](demos/06-terraform-tfvars) | Secrets baked into `terraform.tfvars` | azure_client_secret, aws_access_key_id |
| [`07-ci-pipeline-env`](demos/07-ci-pipeline-env) | Secrets pasted into a CI workflow `env:` | aws_access_key_id (STS), aws_session_token, gcp_api_key |
| [`08-kubernetes-secret`](demos/08-kubernetes-secret) | A `kind: Secret` manifest in a GitOps repo | private_key_pem, azure_sas_token |
| [`09-git-diff-precommit`](demos/09-git-diff-precommit) | Block a leak in a pre-commit hook (stdin) | aws_access_key_id, aws_secret_access_key |
| [`10-dotenv-clean-baseline`](demos/10-dotenv-clean-baseline) | A correct `.env.example` (the green-CI baseline) | — (exit 0) |

```bash
cloudkeys scan demos/04-aws-credentials-file/credentials          # 4 findings
git diff --cached | cloudkeys scan -                              # pre-commit gate (demo 09)
cloudkeys scan demos/10-dotenv-clean-baseline/.env.example        # clean, exit 0
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="sarif"></a>
## SARIF 2.1.0 export

Emit OASIS [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) so
findings flow into GitHub code-scanning, Azure DevOps, or any SARIF viewer.
Severities map to SARIF `level` (`error`/`warning`/`note`) and a numeric
`security-severity` for ranking, one rule per detector.

```bash
cloudkeys --format sarif scan . > cloudkeys.sarif
```

In GitHub Actions:

```yaml
- run: cloudkeys --format sarif scan . > cloudkeys.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cloudkeys.sarif
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="feeds"></a>
## Cloud IP attribution — real data feeds (edge / air-gap)

A leaked key is more actionable when you can also say **which cloud the
endpoints in the same file belong to**. cloudkeys ships an
edge/air-gap-deployable ingestion layer (`cloudkeys/datafeeds.py`) that pulls
two **real, authoritative, keyless** public feeds, caches them to disk, and
re-serves them **offline**:

| feed id | source | what it gives |
|---|---|---|
| `aws-ip-ranges` | <https://ip-ranges.amazonaws.com/ip-ranges.json> | AWS CIDR → service + region |
| `gcp-ip-ranges` | <https://www.gstatic.com/ipranges/cloud.json> | GCP CIDR → service + scope/region |

### The `feeds` command

```bash
cloudkeys feeds list                       # the two feeds + cache freshness
cloudkeys feeds update                     # fetch + cache (online)
cloudkeys feeds get aws-ip-ranges --offline
cloudkeys feeds attribute 3.4.12.4         # -> AWS AMAZON eu-west-1 (3.4.12.4/32)
cloudkeys feeds attribute 34.1.208.1 --offline
```

### Enrich a scan

`--attribute` extracts IPs found while scanning and attributes each to AWS/GCP;
`--offline` serves from cache only (never touches the network):

```bash
cloudkeys --format json scan --attribute --offline demos/11-ip-attribution/
```

The JSON gains an `ip_attributions` map (`ip → {cloud,service,region,cidr}`);
the table output gets a **Cloud IP attribution** block.

### Edge / air-gap workflow

The cache lives at `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).
To run on a disconnected enclave, refresh on a connected host, snapshot the
cache, sneakernet it across, and import:

```bash
# connected host
cloudkeys feeds update
python -m cloudkeys.datafeeds snapshot-export feeds.tar.gz

# air-gapped host
export COGNIS_FEEDS_CACHE=/opt/cognis-feeds
python -m cloudkeys.datafeeds snapshot-import feeds.tar.gz
cloudkeys feeds attribute 3.4.12.4 --offline      # works with zero network
```

Tests run fully offline against a trimmed fixture cache committed under
`tests/fixtures/cognis-feeds/`, so CI is green air-gapped.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[cloudkeys<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`cloudkeys` is interoperable with every popular way of using AI:

- **MCP server** — `cloudkeys mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `cloudkeys scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis cloudkeys** | trufflehog |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **trufflehog**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`cloudkeys mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/cloudkeys.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/cloudkeys.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/cloudkeys.git" # uv
pip install cognis-cloudkeys                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/cloudkeys:latest --help        # Docker
brew install cognis-digital/tap/cloudkeys                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/cloudkeys/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/cloudkeys` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`portfan`](https://github.com/cognis-digital/portfan) — Summarize and diff nmap XML into prioritized, attackable findings
- [`subhunt`](https://github.com/cognis-digital/subhunt) — Aggregate & dedupe subdomain enumeration from multiple sources
- [`dirsight`](https://github.com/cognis-digital/dirsight) — Analyze web content-discovery output (ffuf/gobuster) into ranked endpoints
- [`jwtinspect`](https://github.com/cognis-digital/jwtinspect) — Decode JWTs and lint for alg=none, weak secrets, and missing claims
- [`corsaudit`](https://github.com/cognis-digital/corsaudit) — Detect permissive/misconfigured CORS from headers or a config
- [`headerscan`](https://github.com/cognis-digital/headerscan) — Grade HTTP security headers (CSP/HSTS/XFO) A-F from a response dump

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `cloudkeys` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
