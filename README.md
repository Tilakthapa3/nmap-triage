# nmap-triage

Turn raw Nmap XML into a prioritized, human-readable remediation list.

Nmap tells you what's open. It doesn't tell you what to fix first. This CLI parses Nmap XML output, sends the discovered services and versions to an LLM for analysis, and returns each finding ranked **HIGH / MEDIUM / LOW** with a short justification and a suggested remediation step.

The LLM can be NVIDIA's hosted Nemotron model or a model running on your own machine through [Lemonade](https://lemonade-server.ai), so scan data never has to leave your laptop.

Built as a learning project while studying for CompTIA Security+ and working through an M.S. in Cybersecurity.

---

## What it does

- Parses standard Nmap XML (`nmap -oX`) — hosts, ports, services, versions
- Sends structured findings to NVIDIA's hosted Nemotron model via the [build.nvidia.com](https://build.nvidia.com) API, or with `--backend lemonade` to a local model served by [Lemonade](https://lemonade-server.ai), so nothing leaves your machine
- Returns a severity-ranked triage report with reasoning and remediation guidance
- Compares cloud and local triage of the same scan with `--compare`: severity agreement and speed
- Optionally ships findings to [Axiom](https://axiom.co) for run history and cross-scan querying
- Runs entirely from the command line, no dashboard required

Models: `nvidia/nemotron-3-ultra-550b-a55b` (cloud, default) · `Qwen3-4B-Instruct-2507-GGUF` via Lemonade (local)

## Why

Junior analysts get handed scan output and are expected to know what matters. An open port 22 running a patched OpenSSH is noise; port 445 exposed to the internet is not. This tool is an attempt to encode that first-pass judgment so the analyst starts from a ranked list instead of a wall of XML.

---

## Requirements

- Python 3.9+
- Nmap 7.9+ (to generate the input XML)
- For cloud triage: an API key from [build.nvidia.com](https://build.nvidia.com) (free tier available)
- For local triage: [Lemonade](https://lemonade-server.ai) on Windows, Linux, or an Apple Silicon Mac (no key, no account)
- An [Axiom](https://axiom.co) token — optional, only needed for log ingestion

## Setup

```bash
git clone https://github.com/Tilakthapa3/nmap-triage.git
cd nmap-triage
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
NVIDIA_API_KEY=your_key_here
AXIOM_TOKEN=your_axiom_token
AXIOM_DATASET=nmap-triage
```

`.env` is gitignored. Never commit your key.

`NVIDIA_API_KEY` is only needed for the cloud backend; local runs with Lemonade need no key. Omit the Axiom variables and run with `--no-axiom` if you don't need ingestion.

## Usage

Generate a scan:

```bash
nmap -sV -oX scan.xml scanme.nmap.org
```

Run the triage:

```bash
python nmap_triage.py scan.xml
```

### Options

| Flag | Effect |
|------|--------|
| `--output FILE` | Write the report to a file instead of stdout |
| `--format FORMAT` | Report format: `text` (default), `json`, or `markdown` |
| `--backend NAME` | `nvidia` (cloud, default) or `lemonade` (local, no key) |
| `--model ID` | Model to use; the default depends on the backend |
| `--base-url URL` | OpenAI-compatible endpoint (Lemonade default: `http://localhost:13305/api/v1`) |
| `--timeout SECONDS` | How long to wait for the model (default: 90 cloud, 600 local) |
| `--compare` | Run the scan through both backends and compare them (see below) |
| `--no-ai` | Parse and print findings only — no API call, no key needed |
| `--no-axiom` | Skip Axiom ingestion for this run |

### Export formats

`--format json` writes a structured document (scan metadata plus one finding per open port with host, port, service, severity, and remediation), and `--format markdown` writes a readable report with a findings table. Both work with `--output FILE` or to stdout. Severities in structured exports come from the AI triage when one ran, and from a built-in service heuristic otherwise; the default text output is unchanged.

```bash
python nmap_triage.py scan.xml --no-ai --format json --output report.json
python nmap_triage.py scan.xml --no-ai --format markdown
```

`--no-ai` is the fastest way to confirm the parser works against your XML before setting up any credentials.

> Only scan hosts you own or have written permission to test. `scanme.nmap.org` is provided by the Nmap project for exactly this purpose.

---

## Run fully local with Lemonade

Nmap output is a map of a network: its hosts, open ports, and exact software versions. Sending that to a cloud API is fine for `scanme.nmap.org`, but on a real engagement it is often data you aren't allowed to share. [Lemonade](https://lemonade-server.ai) is AMD's open-source local AI server. It speaks the OpenAI API, so nmap-triage sends it the same request it sends the cloud, just to `localhost`: the scan never leaves your machine and no API key is needed.

1. Install Lemonade for Windows, Linux, or macOS from the [Lemonade repo](https://github.com/lemonade-sdk/lemonade). On a Mac it needs Apple Silicon.
2. Check that the server is running:

   ```bash
   lemonade status
   ```

3. Download the default model (about 2.5 GB):

   ```bash
   lemonade pull Qwen3-4B-Instruct-2507-GGUF
   ```

4. Run the triage locally:

   ```bash
   python nmap_triage.py scan.xml --backend lemonade
   ```

Any chat model from `lemonade list` works with `--model`. Larger models such as `Qwen3-8B-GGUF` are slower but often more accurate. You can also set these in `.env`:

| Variable | Purpose |
|----------|---------|
| `LEMONADE_MODEL` | Default local model |
| `LEMONADE_BASE_URL` | Lemonade on another port or machine (default `http://localhost:13305/api/v1`) |
| `LEMONADE_API_KEY` | Only if your Lemonade server was started with an API key |

For local runs, nmap-triage asks Lemonade to skip the model's thinking step (`enable_thinking: false`). Reasoning models then answer directly, which keeps them fast and inside the token budget on a laptop.

### Compare cloud and local

```bash
python nmap_triage.py scan.xml --compare
```

This sends the same findings to NVIDIA's cloud model and to your Lemonade model. It prints each model's time and output speed, a table with every open port's severity from both models, and the severity agreement, followed by both full reports.

- **Severity agreement** is the share of open ports where both models gave the same label. `—` means a model did not flag the port. Two dashes count as agreement, because skipping a port is a judgment too.
- **Time** is wall-clock seconds for the whole request. **tok/s** is output tokens divided by that time, so for the cloud model it includes network latency.
- `--compare` needs `NVIDIA_API_KEY` and a running Lemonade server. `--model` and `--base-url` set the Lemonade side. Axiom ingestion is skipped.

---

## Example output

Run against `scanme.nmap.org`:

```
=== Scan Summary ===
Hosts up with open ports: 1
Open ports total:         4

45.33.32.156 (scanme.nmap.org)
  22/tcp  ssh — OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
  80/tcp  http — Apache httpd 2.4.7
  9929/tcp  nping-echo — Nping echo
  31337/tcp  tcpwrapped

=== Triage ===

[HIGH] 45.33.32.156:22 — ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
  This version shipped with Ubuntu 14.04 which reached end-of-life in April 2019 and contains multiple known vulnerabilities including pre-authentication flaws. Upgrade the host to a supported Ubuntu release or at minimum apply all available security patches for OpenSSH.

[HIGH] 45.33.32.156:80 — http (Apache httpd 2.4.7)
  Apache 2.4.7 is from 2013 and lacks patches for numerous critical vulnerabilities including HTTP request smuggling and memory corruption issues. Upgrade to a current Apache 2.4.x release on a supported operating system.

[HIGH] 45.33.32.156:31337 — tcpwrapped (unknown)
  Port 31337 is historically associated with backdoor trojans (e.g., Back Orifice) and the tcpwrapped label suggests access controls hiding the true service. Investigate the listening process immediately with `ss -ltnp` or `lsof -i :31337` and remove if unauthorized.

[MEDIUM] 45.33.32.156:9929 — nping-echo (Nping echo)
  This Nmap testing service reflects traffic and can be abused for amplification or reconnaissance. Disable the service unless explicitly required for authorized network testing.

No other findings.
```

---

## Testing

Tests use only the Python standard library:

```bash
python3 -m unittest discover -s tests -v
```

They cover XML parsing, severity assignment, and the JSON/Markdown exporters, using the bundled `examples/scanme.xml` sample. `tests/test_backends.py` covers the NVIDIA and Lemonade backends and `--compare` against a small fake OpenAI-compatible server, so no network, API key, or Lemonade install is needed. Importing the test modules requires `requests` (listed in `requirements.txt`); nothing else third-party is needed.

---

## Roadmap

- [ ] Map findings to NIST 800-53 / CIS control IDs
- [x] JSON and Markdown export for reporting
- [x] Local inference via Lemonade (`--backend lemonade`) and cloud-vs-local comparison (`--compare`)
- [ ] Batch mode for multi-host scans

## Notes

This is a portfolio and learning project, not a production security tool. LLM output should be verified before acting on it — treat the ranking as a starting point for analysis, not a substitute for it. Small local models make more mistakes than large cloud models; `--compare` shows where they disagree.

## Author

**Tilak Thapa** — M.S. Cybersecurity, Avila University

[tilakthapa.com](https://tilakthapa.com) · [github.com/Tilakthapa3](https://github.com/Tilakthapa3)
