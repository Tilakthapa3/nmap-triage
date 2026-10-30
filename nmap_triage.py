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
    python nmap_triage.py scan.xml --no-ai --format json --output report.json
    python nmap_triage.py scan.xml --no-ai --format markdown
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
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
AXIOM_DATASET = os.environ.get("AXIOM_DATASET", "nmap-triage")

# Matches the model's finding header, e.g.
#   [HIGH] 192.168.1.10:445 — microsoft-ds (Samba 3.0.20)
SEVERITY_LINE = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW)\]\s+(\S+?):(\d+)")

# Offline first-pass guidance for the structured (JSON/Markdown) exports
# only. These are heuristics, not vulnerability verdicts: a severity here
# is a starting point for analysis, never a substitute for it. The
# default text report is unaffected by this table.
SERVICE_GUIDANCE = {
    "microsoft-ds": ("HIGH", "SMB is a common lateral-movement target. Restrict port 445 to trusted hosts, disable SMBv1, and confirm the version is patched."),
    "netbios-ssn": ("HIGH", "NetBIOS session service. Restrict to trusted hosts and disable it if not required."),
    "ms-wbt-server": ("HIGH", "RDP exposed to the network is a common initial-access vector. Require VPN access and MFA, and confirm the version is patched."),
    "ftp": ("HIGH", "FTP sends credentials in cleartext. Replace it with SFTP or FTPS, or disable it if not required."),
    "telnet": ("HIGH", "Telnet sends credentials in cleartext. Disable it and use SSH instead."),
    "mysql": ("HIGH", "A database port should never face untrusted networks. Restrict it to the application hosts and confirm the version is patched."),
    "postgresql": ("HIGH", "A database port should never face untrusted networks. Restrict it to the application hosts and confirm the version is patched."),
    "mongodb": ("HIGH", "MongoDB has shipped with weak defaults historically. Restrict it to the application hosts, require authentication, and confirm the version is patched."),
    "redis": ("HIGH", "Redis has no authentication by default. Bind it to localhost or trusted hosts only and require authentication."),
    "elasticsearch": ("HIGH", "Elasticsearch has shipped open by default historically. Restrict it to trusted hosts, require authentication, and confirm the version is patched."),
    "ssh": ("MEDIUM", "Confirm the version is patched and supported, disable password authentication where possible, and restrict access to trusted hosts."),
    "http": ("MEDIUM", "Confirm the web server version is patched and supported, and redirect traffic to HTTPS."),
    "smtp": ("MEDIUM", "Confirm the mail service is patched and verify it is not acting as an open relay."),
    "snmp": ("MEDIUM", "Use SNMPv3 with authentication and encryption; disable SNMPv1/v2c community strings."),
    "domain": ("LOW", "Confirm the DNS service is patched and is only exposed where intended."),
    "https": ("LOW", "Confirm the TLS configuration and certificate are current and the server version is patched."),
}

PORT_GUIDANCE = {
    31337: ("HIGH", "Port 31337 is historically associated with backdoor trojans, and the tcpwrapped label suggests access controls hiding the true service. Identify the listening process and remove it if unauthorized."),
}

DEFAULT_GUIDANCE = ("LOW", "Review whether this service needs to be exposed, and confirm the version is patched and supported.")


def assess_finding(service, port):
    """Heuristic (severity, remediation) for one open port.

    Used only by the structured exports. When an AI triage ran, the
    model's severity overrides this; the remediation text always comes
    from here so structured exports stay deterministic.
    """
    name = (service or "").lower()
    if name in SERVICE_GUIDANCE:
        return SERVICE_GUIDANCE[name]
    if port in PORT_GUIDANCE:
        return PORT_GUIDANCE[port]
    return DEFAULT_GUIDANCE

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


def build_findings(hosts, triage_text=None):
    """One structured finding per open port.

    Severity comes from the AI triage when one ran; otherwise from the
    offline heuristic. Remediation always comes from the heuristic, so
    structured exports are deterministic.
    """
    severities = extract_severities(triage_text)
    findings = []
    for host in hosts:
        for port in host["open_ports"]:
            severity, remediation = assess_finding(port["service"],
                                                   port["port"])
            severity = severities.get((host["address"], port["port"]),
                                      severity)
            findings.append({
                "host": host["address"],
                "hostname": host["hostname"],
                "port": port["port"],
                "protocol": port["protocol"],
                "service": port["service"],
                "version": port["version"],
                "severity": severity,
                "remediation": remediation,
            })
    return findings


def render_json_report(hosts, scan_file, triage_text, report):
    """Structured report: metadata + findings + the full text report."""
    findings = build_findings(hosts, triage_text)
    document = {
        "tool": "nmap-triage",
        "scan_file": os.path.basename(scan_file),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_up": len(hosts),
        "open_ports_total": sum(len(h["open_ports"]) for h in hosts),
        "ai_triaged": bool(triage_text),
        "findings": findings,
        "triage": triage_text,
        "report": report,
    }
    return json.dumps(document, indent=2) + "\n"


def _md_cell(value):
    return str(value if value is not None else "—").replace("|", "\\|")


def render_markdown_report(hosts, scan_file, triage_text, summary):
    """Readable report: headings, a findings table, and the raw summary."""
    findings = build_findings(hosts, triage_text)
    total = sum(len(h["open_ports"]) for h in hosts)
    lines = [
        "# Nmap Triage Report",
        "",
        f"Scan file: `{os.path.basename(scan_file)}`",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Hosts up: {len(hosts)} · Open ports: {total} · "
        f"AI triaged: {'yes' if triage_text else 'no'}",
        "",
        "## Findings",
        "",
        "| Severity | Host | Port | Service | Version | Remediation |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            "| {severity} | {host} | {port} | {service} | {version} | {remediation} |".format(
                severity=_md_cell(f["severity"]),
                host=_md_cell(f["host"]),
                port=_md_cell(f"{f['port']}/{f['protocol']}"),
                service=_md_cell(f["service"]),
                version=_md_cell(f["version"]),
                remediation=_md_cell(f["remediation"]),
            )
        )
    lines += [
        "",
        "## Scan Summary",
        "",
        "```",
        summary.rstrip("\n"),
        "```",
        "",
        "## AI Triage",
        "",
        triage_text if triage_text else "Skipped (--no-ai).",
    ]
    return "\n".join(lines) + "\n"


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
    ap.add_argument("--format", choices=["text", "json", "markdown"],
                    default="text",
                    help="Report format: text (default), json, or markdown")
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

    if args.format == "json":
        document = render_json_report(hosts, args.xmlfile, triage, report)
    elif args.format == "markdown":
        document = render_markdown_report(hosts, args.xmlfile, triage,
                                          summary)
    else:
        document = report

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(document)
        print(f"Report written to {args.output}")
    else:
        print(document)


if __name__ == "__main__":
    main()
