# nmap-triage

A command-line tool that parses Nmap XML output and returns prioritized triage findings.

## What it does

Nmap tells you what's open. It doesn't tell you what to fix first. This tool parses Nmap's XML scan output, sends the findings to an LLM, and returns each one classified as HIGH, MEDIUM, or LOW with reasoning and suggested remediation.

## Requirements

- Python 3.9+
- nmap 7.9+
- An API key from build.nvidia.com

## Setup

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export NVIDIA_API_KEY="your-key-here"
```

## Usage

```
nmap -sV -oX scan.xml <target>
python nmap_triage.py scan.xml
```

## Note

Model: nemotron-3-ultra-550b-a55b via build.nvidia.com

Only scan systems you own or have written authorization to test.
