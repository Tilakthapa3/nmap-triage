#!/usr/bin/env python3
"""
nmap-triage — AI-assisted triage for Nmap scan results.

Parses Nmap XML output, sends the findings to an LLM for analysis, and prints
a prioritized remediation report. Findings are optionally shipped to Axiom
for querying and trend analysis across scans.

Usage:
    nmap -sV -oX scan.xml 192.168.1.0/24
    python nmap_triage.py scan.xml
    python nmap_triage.py scan.xml --output report.md
    python nmap_triage.py scan.xml --no-ai
    python nmap_triage.py scan.xml --no-axiom
"""

import argparse
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: pip install requests")

# Load .env if python-dotenv is available. Optional: the script still works
# with plain environment variables if it isn't installed.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"
AXIOM_DATASET = os.environ.get("AXIOM_DATASET", "nmap-triage")

# Matches the model's finding header, e.g.
#   [HIGH] 192.168.1.10:445 — microsoft-ds (Samba 3.0.20)
SEVERITY_LINE = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW)\]\s+(\S+?):(\d+)")

SYSTEM_PROMPT = """You are a security analyst triaging the results of an Nmap scan.

You will receive a JSON list of hosts with their open ports, services, and
version banners.

For each finding that matters, output a block in exactly this format:

[SEVERITY] host:port — service (version)
  Two sentences maximum. First: why this matters. Second: the concrete
  remediation step.

Rules:
- SEVERITY is HIGH, MEDIUM, or LOW.
- Order the output HIGH first, then MEDIUM, then LOW.
- Base severity on exposure, whether the version is end-of-life, and whether
  the service is commonly targeted. Say when a version is too vague to judge.
- Do not invent CVE numbers. If you are not certain a CVE applies, describe
  the weakness class instead.
- Skip ports that are unremarkable and say so in one closing line.
- Output only the blocks. No preamble, no markdown headers."""


def parse_nmap_xml(path):
    """Extract hosts, ports, and services from an Nmap XML file."""
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        sys.exit(f"File not found: {path}")
    except ET.ParseError as e:
        sys.exit(f"Could not parse XML (is this an 'nmap -oX' file?): {e}")

    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            svc = port.find("service")
            service_name = svc.get("name") if svc is not None else "unknown"
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None

            banner = " ".join(p for p in [product, version] if p) or None

            scripts = []
            for script in port.findall("script"):
                out = script.get("output", "").strip()
                if out:
                    scripts.append({
                        "id": script.get("id"),
                        "output": out[:500],
                    })

            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service_name,
                "version": banner,
                "scripts": scripts or None,
            })

        if ports:
            hosts.append({
                "address": address,
                "hostname": hostname,
                "open_ports": ports,
            })

    return hosts


def summarize(hosts):
    """Plain summary of what was parsed, printed with or without AI."""
    total_ports = sum(len(h["open_ports"]) for h in hosts)
    lines = [
        "=== Scan Summary ===",
        f"Hosts up with open ports: {len(hosts)}",
        f"Open ports total:         {total_ports}",
        "",
    ]
    for h in hosts:
        label = h["address"]
        if h["hostname"]:
            label += f" ({h['hostname']})"
        lines.append(label)
        for p in h["open_ports"]:
            ver = f" — {p['version']}" if p["version"] else ""
            lines.append(f"  {p['port']}/{p['protocol']}  {p['service']}{ver}")
        lines.append("")
    return "\n".join(lines)


def analyze(hosts, model, api_key):
    """Send findings to the model and return the triage report text."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(hosts, indent=2)},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    try:
        resp = requests.post(API_URL, headers=headers, json=payload, timeout=90)
    except requests.exceptions.RequestException as e:
        return None, f"Could not reach the API: {e}"

    if resp.status_code == 401:
        return None, "API rejected the key (401). Check NVIDIA_API_KEY."
    if resp.status_code != 200:
        return None, f"API returned {resp.status_code}: {resp.text[:300]}"

    try:
        return resp.json()["choices"][0]["message"]["content"], None
    except (KeyError, IndexError, ValueError):
        return None, f"Unexpected API response shape: {resp.text[:300]}"


def extract_severities(triage_text):
    """Map (host, port) -> severity by reading the model's finding headers.

    Returns an empty dict if the model was skipped or wrote in another format,
    in which case findings ship without a severity field rather than failing.
    """
    severities = {}
    if not triage_text:
        return severities

    for line in triage_text.splitlines():
        match = SEVERITY_LINE.match(line)
        if match:
            severity, host, port = match.groups()
            severities[(host, int(port))] = severity
    return severities


def build_events(hosts, scan_file, triage_text=None):
    """Flatten the scan into one event per open port, ready for ingestion."""
    severities = extract_severities(triage_text)
    run_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    events = []

    for host in hosts:
        address = host["address"]
        for port in host["open_ports"]:
            events.append({
                "_time": now,
                "run_id": run_id,
                "scan_file": os.path.basename(scan_file),
                "host": address,
                "hostname": host["hostname"],
                "port": port["port"],
                "protocol": port["protocol"],
                "service": port["service"],
                "version": port["version"],
                "severity": severities.get((address, port["port"])),
                "ai_triaged": bool(triage_text),
            })

    return events, run_id


def ship_to_axiom(events):
    """Send events to Axiom. Returns an error string, or None on success.

    Never raises: a logging backend being unavailable should not stop a
    security triage run from completing.
    """
    if not events:
        return None

    try:
        import axiom_py
    except ImportError:
        return "axiom-py is not installed. Run: pip install axiom-py"

    if not os.environ.get("AXIOM_TOKEN"):
        return "AXIOM_TOKEN is not set."

    try:
        client = axiom_py.Client()
        client.ingest_events(dataset=AXIOM_DATASET, events=events)
    except Exception as e:
        return f"{type(e).__name__}: {e}"

    return None


def main():
    ap = argparse.ArgumentParser(
        description="Triage Nmap XML output into a prioritized remediation report."
    )
    ap.add_argument("xmlfile", help="Nmap XML file (from: nmap -oX)")
    ap.add_argument("--output", help="Write the report to this file")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Model ID to use")
    ap.add_argument("--no-ai", action="store_true",
                    help="Parse and summarize only, skip the API call")
    ap.add_argument("--no-axiom", action="store_true",
                    help="Skip shipping findings to Axiom")
    args = ap.parse_args()

    hosts = parse_nmap_xml(args.xmlfile)

    if not hosts:
        print("No hosts with open ports found in that scan.")
        return

    summary = summarize(hosts)
    report = summary
    triage = None

    if not args.no_ai:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            print(summary)
            sys.exit("NVIDIA_API_KEY is not set. Set it, or run with --no-ai.")

        print("Analyzing findings...", file=sys.stderr)
        triage, error = analyze(hosts, args.model, api_key)

        if error:
            print(summary)
            sys.exit(error)

        report = summary + "\n=== Triage ===\n\n" + triage

    if not args.no_axiom:
        events, run_id = build_events(hosts, args.xmlfile, triage)
        error = ship_to_axiom(events)
        if error:
            print(f"Warning: could not ship findings to Axiom — {error}",
                  file=sys.stderr)
        else:
            print(f"Shipped {len(events)} findings to Axiom "
                  f"(dataset: {AXIOM_DATASET}, run_id: {run_id})",
                  file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
