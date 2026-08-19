# nmap-triage

Turn raw Nmap XML into a prioritized, human-readable remediation list.

Nmap tells you what's open. It doesn't tell you what to fix first. This CLI parses Nmap XML output, sends the discovered services and versions to an LLM for analysis, and returns each finding ranked **HIGH / MEDIUM / LOW** with a short justification and a suggested remediation step.

Built as a learning project while studying for CompTIA Security+ and working through an M.S. in Cybersecurity.

---

## What it does

- Parses standard Nmap XML (`nmap -oX`) — hosts, ports, services, versions
- Sends structured findings to NVIDIA's hosted Nemotron model via the [build.nvidia.com](https://build.nvidia.com) API
- Returns a severity-ranked triage report with reasoning and remediation guidance
- Runs entirely from the command line, no dashboard required

## Why

Junior analysts get handed scan output and are expected to know what matters. An open port 22 running a patched OpenSSH is noise; port 445 exposed to the internet is not. This tool is an attempt to encode that first-pass judgment so the analyst starts from a ranked list instead of a wall of XML.

---

## Requirements

- Python 3.9+
- Nmap 7.9+ (to generate the input XML)
- An API key from [build.nvidia.com](https://build.nvidia.com) (free tier available)

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
```

`.env` is gitignored. Never commit your key.

## Usage

Generate a scan:

```bash
nmap -sV -oX scan.xml scanme.nmap.org
```

Run the triage:

```bash
python nmap_triage.py scan.xml
```

> Only scan hosts you own or have written permission to test. `scanme.nmap.org` is provided by the Nmap project for exactly this purpose.

---

## Example output

```
Host: 45.33.32.156 (scanme.nmap.org)

[HIGH]   port 22/tcp — OpenSSH 6.6.1p1
         Outdated SSH version with known CVEs. Exposed to the public internet.
         → Upgrade OpenSSH, disable password auth, restrict source IPs.

[MEDIUM] port 80/tcp — Apache httpd 2.4.7
         Web server version disclosed in banner; version is end-of-life.
         → Upgrade Apache, suppress ServerTokens in config.

[LOW]    port 9929/tcp — Nping echo
         Diagnostic service, low exposure risk.
         → Confirm intentional; close if unused.
```

---

## Roadmap

- [ ] Map findings to NIST 800-53 / CIS control IDs
- [ ] Ship log ingestion via [Axiom](https://axiom.co) for run history and observability
- [ ] JSON and Markdown export for reporting
- [ ] Batch mode for multi-host scans

## Notes

This is a portfolio and learning project, not a production security tool. LLM output should be verified before acting on it — treat the ranking as a starting point for analysis, not a substitute for it.

## Author

**Tilak Thapa** — M.S. Cybersecurity, Avila University
[tilakthapa.com](https://tilakthapa.com) · [github.com/Tilakthapa3](https://github.com/Tilakthapa3)
