# nmap-triage

Turn raw Nmap XML into a prioritized, human-readable remediation list.

Nmap tells you what's open. It doesn't tell you what to fix first. This CLI parses Nmap XML output, sends the discovered services and versions to an LLM for analysis, and returns each finding ranked **HIGH / MEDIUM / LOW** with a short justification and a suggested remediation step.

Built as a learning project while studying for CompTIA Security+ and working through an M.S. in Cybersecurity.

---

## What it does

- Parses standard Nmap XML (`nmap -oX`) — hosts, ports, services, versions
- Sends structured findings to NVIDIA's hosted Nemotron model via the [build.nvidia.com](https://build.nvidia.com) API
- Returns a severity-ranked triage report with reasoning and remediation guidance
<<<<<<< HEAD
- Optionally ships findings to [Axiom](https://axiom.co) for run history and cross-scan querying
- Runs entirely from the command line, no dashboard required

Model: `nvidia/nemotron-3-ultra-550b-a55b`

=======
- Runs entirely from the command line, no dashboard required

>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
## Why

Junior analysts get handed scan output and are expected to know what matters. An open port 22 running a patched OpenSSH is noise; port 445 exposed to the internet is not. This tool is an attempt to encode that first-pass judgment so the analyst starts from a ranked list instead of a wall of XML.

---

## Requirements

- Python 3.9+
- Nmap 7.9+ (to generate the input XML)
- An API key from [build.nvidia.com](https://build.nvidia.com) (free tier available)
<<<<<<< HEAD
- An [Axiom](https://axiom.co) token — optional, only needed for log ingestion
=======
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7

## Setup

```bash
git clone https://github.com/Tilakthapa3/nmap-triage.git
cd nmap-triage
<<<<<<< HEAD
python3 -m venv .venv
source .venv/bin/activate
=======

python3 -m venv .venv
source .venv/bin/activate

>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
NVIDIA_API_KEY=your_key_here
<<<<<<< HEAD
AXIOM_TOKEN=your_axiom_token
AXIOM_DATASET=nmap-triage
=======
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
```

`.env` is gitignored. Never commit your key.

<<<<<<< HEAD
Only `NVIDIA_API_KEY` is required. Omit the Axiom variables and run with `--no-axiom` if you don't need ingestion.

=======
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
## Usage

Generate a scan:

```bash
nmap -sV -oX scan.xml scanme.nmap.org
```

Run the triage:

```bash
python nmap_triage.py scan.xml
```

<<<<<<< HEAD
### Options

| Flag | Effect |
|------|--------|
| `--output FILE` | Write the report to a file instead of stdout |
| `--no-ai` | Parse and print findings only — no API call, no key needed |
| `--no-axiom` | Skip Axiom ingestion for this run |

`--no-ai` is the fastest way to confirm the parser works against your XML before setting up any credentials.

> Only scan hosts you own or have written permission to test. `scanme.nmap.org` is provided by the Nmap project for exactly this purpose.

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
=======
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
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
```

---

## Roadmap

- [ ] Map findings to NIST 800-53 / CIS control IDs
<<<<<<< HEAD
=======
- [ ] Ship log ingestion via [Axiom](https://axiom.co) for run history and observability
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
- [ ] JSON and Markdown export for reporting
- [ ] Batch mode for multi-host scans

## Notes

This is a portfolio and learning project, not a production security tool. LLM output should be verified before acting on it — treat the ranking as a starting point for analysis, not a substitute for it.

## Author

**Tilak Thapa** — M.S. Cybersecurity, Avila University
<<<<<<< HEAD

=======
>>>>>>> 9f9a0b04213f69bc290936af85443ef3f1a823f7
[tilakthapa.com](https://tilakthapa.com) · [github.com/Tilakthapa3](https://github.com/Tilakthapa3)
