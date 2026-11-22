#!/usr/bin/env python3
"""
nmap-triage — AI-assisted triage for Nmap scan results.

Parses Nmap XML output, sends the findings to an LLM for analysis, and prints
a prioritized remediation report. The LLM is either NVIDIA's hosted Nemotron
model (cloud) or a chat model served locally by Lemonade, in which case the
scan data never leaves the machine. Findings are optionally shipped to Axiom
for querying and trend analysis across scans.

Usage:
    nmap -sV -oX scan.xml 192.168.1.0/24
    python nmap_triage.py scan.xml
    python nmap_triage.py scan.xml --backend lemonade
    python nmap_triage.py scan.xml --backend lemonade --model Qwen3-8B-GGUF
    python nmap_triage.py scan.xml --compare
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
import time
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


# Cloud backend: NVIDIA's hosted API (build.nvidia.com). Needs NVIDIA_API_KEY.
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

# Local backend: Lemonade (https://lemonade-server.ai), an open-source local
# AI server with an OpenAI-compatible API. No key is needed unless the server
# was started with LEMONADE_API_KEY. The default model is a ~2.5 GB instruct
# model that fits on most laptops; any chat model from `lemonade list` works.
LEMONADE_BASE_URL = "http://localhost:13305/api/v1"
LEMONADE_DEFAULT_MODEL = "Qwen3-4B-Instruct-2507-GGUF"

# Seconds to wait for a triage. Local runs get longer because the first
# request can include Lemonade downloading and loading the model.
CLOUD_TIMEOUT = 90
LOCAL_TIMEOUT = 600

BACKENDS = ("nvidia", "lemonade")
AXIOM_DATASET = os.environ.get("AXIOM_DATASET", "nmap-triage")

# Matches the model's finding header, e.g.
#   [HIGH] 192.168.1.10:445 — microsoft-ds (Samba 3.0.20)
SEVERITY_LINE = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW)\]\s+(\S+?):(\d+)")

# Markdown that smaller local models sometimes add around finding headers
# despite the prompt, e.g. "- **[HIGH] 10.0.0.5:445** — microsoft-ds".
# Stripped from a line before SEVERITY_LINE is applied.
MARKDOWN_NOISE = re.compile(r"\*\*|__|`")
LIST_MARKER = re.compile(r"^\s*(?:[-*•>]|#+|\d+[.)])\s+")

# Reasoning that some models write inline instead of in reasoning_content.
# An unclosed block (the model ran out of tokens mid-thought) is dropped too.
THINK_BLOCK = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL | re.IGNORECASE)

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


def resolve_backend(name, model=None, base_url=None, timeout=None):
    """Connection settings for one AI backend, as a plain dict.

    Command-line flags win, then environment variables, then the defaults
    at the top of this file. key_env names the variable that must be set
    for the backend to work, or is None when no key is required.
    """
    if name == "lemonade":
        return {
            "name": "lemonade",
            "label": "lemonade (local)",
            "base_url": (base_url or os.environ.get("LEMONADE_BASE_URL")
                         or LEMONADE_BASE_URL).rstrip("/"),
            "model": (model or os.environ.get("LEMONADE_MODEL")
                      or LEMONADE_DEFAULT_MODEL),
            # Only needed when the Lemonade server was started with a key.
            "api_key": os.environ.get("LEMONADE_API_KEY"),
            "key_env": None,
            "timeout": timeout or LOCAL_TIMEOUT,
        }
    if name == "nvidia":
        return {
            "name": "nvidia",
            "label": "nvidia (cloud)",
            "base_url": (base_url or NVIDIA_BASE_URL).rstrip("/"),
            "model": model or DEFAULT_MODEL,
            "api_key": os.environ.get("NVIDIA_API_KEY"),
            "key_env": "NVIDIA_API_KEY",
            "timeout": timeout or CLOUD_TIMEOUT,
        }
    raise ValueError(f"Unknown backend: {name}")


def clean_model_text(text):
    """Drop inline <think> reasoning blocks and surrounding whitespace."""
    return THINK_BLOCK.sub("", text or "").strip()


def _error_detail(resp):
    """Best-effort human-readable message from an error response body."""
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300]
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])[:300]
    if isinstance(error, str):
        return error[:300]
    return resp.text[:300]


def analyze(hosts, backend):
    """Send findings to a backend's chat-completions endpoint.

    backend is a dict from resolve_backend(). Returns (triage_text, error,
    stats). On success error is None and stats holds the wall-clock seconds
    plus the token counts the backend reported. On failure triage_text and
    stats are None and error says what to fix.
    """
    local = backend["name"] == "lemonade"
    payload = {
        "model": backend["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(hosts, indent=2)},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }
    if local:
        # Lemonade extension: reasoning models answer directly instead of
        # thinking first, which keeps laptop runs fast and inside max_tokens.
        payload["enable_thinking"] = False

    headers = {"Accept": "application/json"}
    if backend["api_key"]:
        headers["Authorization"] = f"Bearer {backend['api_key']}"

    url = backend["base_url"] + "/chat/completions"
    start = time.perf_counter()
    try:
        resp = requests.post(url, headers=headers, json=payload,
                             timeout=backend["timeout"])
    except requests.exceptions.ConnectionError as e:
        if local:
            return None, (f"Could not reach Lemonade at {backend['base_url']}. "
                          "Is the Lemonade server running? Check with: "
                          "lemonade status"), None
        return None, f"Could not reach the API: {e}", None
    except requests.exceptions.Timeout:
        hint = ""
        if local:
            hint = (" The first local run can include downloading and loading "
                    f"the model: run `lemonade pull {backend['model']}` first, "
                    "or raise --timeout.")
        return None, (f"No answer from {backend['label']} within "
                      f"{backend['timeout']:g} s.{hint}"), None
    except requests.exceptions.RequestException as e:
        return None, f"Could not reach the API: {e}", None
    seconds = time.perf_counter() - start

    if resp.status_code == 401:
        if local:
            return None, ("Lemonade rejected the request (401). The server has "
                          "an API key set; put the same value in "
                          "LEMONADE_API_KEY."), None
        return None, "API rejected the key (401). Check NVIDIA_API_KEY.", None
    if local and resp.status_code == 404:
        detail = _error_detail(resp).rstrip(".")
        if "model_not" in resp.text:  # model_not_found / model_not_supported
            return None, (f"Lemonade can't run model '{backend['model']}': "
                          f"{detail}. Run `lemonade list` to see the models "
                          "it can run, then pass one with --model."), None
        return None, (f"Lemonade returned 404 for {url}: {detail}. Check "
                      f"--base-url (the default is {LEMONADE_BASE_URL})."), None
    if resp.status_code != 200:
        return None, f"API returned {resp.status_code}: {resp.text[:300]}", None

    try:
        data = resp.json()
        content = data["choices"][0]["message"].get("content")
    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
        return None, f"Unexpected API response shape: {resp.text[:300]}", None

    text = clean_model_text(content)
    if not text:
        return None, (f"{backend['label']} returned an empty answer. If "
                      f"{backend['model']} is a reasoning model it may have "
                      "spent its whole token budget thinking; try a "
                      "non-reasoning model with --model."), None

    usage = data.get("usage") or {}
    stats = {
        "seconds": round(seconds, 2),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
    }
    return text, None, stats


def describe_stats(stats):
    """'8.4 s · 52 tok/s': wall-clock time and end-to-end output tokens/s."""
    if not stats:
        return "—"
    text = f"{stats['seconds']:.1f} s"
    tokens = stats.get("completion_tokens")
    if tokens and stats["seconds"] > 0:
        text += f" · {tokens / stats['seconds']:.0f} tok/s"
    return text


def extract_severities(triage_text):
    """Map (host, port) -> severity by reading the model's finding headers.

    Returns an empty dict if the model was skipped or wrote in another format,
    in which case findings ship without a severity field rather than failing.
    """
    severities = {}
    if not triage_text:
        return severities

    for line in triage_text.splitlines():
        line = LIST_MARKER.sub("", MARKDOWN_NOISE.sub("", line))
        match = SEVERITY_LINE.match(line)
        if match:
            severity, host, port = match.groups()
            severities[(host, int(port))] = severity
    return severities


def build_events(hosts, scan_file, triage_text=None, ai_info=None):
    """Flatten the scan into one event per open port, ready for ingestion.

    ai_info, when an AI triage ran, is {"backend", "model", "seconds"} and
    lets Axiom queries compare cloud and local runs.
    """
    severities = extract_severities(triage_text)
    ai_info = ai_info or {}
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
                "ai_backend": ai_info.get("backend"),
                "ai_model": ai_info.get("model"),
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


def render_json_report(hosts, scan_file, triage_text, report, ai_info=None):
    """Structured report: metadata + findings + the full text report.

    ai_info records which backend and model produced the triage, or is
    None when the AI step was skipped.
    """
    findings = build_findings(hosts, triage_text)
    document = {
        "tool": "nmap-triage",
        "scan_file": os.path.basename(scan_file),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_up": len(hosts),
        "open_ports_total": sum(len(h["open_ports"]) for h in hosts),
        "ai_triaged": bool(triage_text),
        "ai": ai_info,
        "findings": findings,
        "triage": triage_text,
        "report": report,
    }
    return json.dumps(document, indent=2) + "\n"


def _md_cell(value):
    return str(value if value is not None else "—").replace("|", "\\|")


def render_markdown_report(hosts, scan_file, triage_text, summary,
                           ai_info=None):
    """Readable report: headings, a findings table, and the raw summary."""
    findings = build_findings(hosts, triage_text)
    total = sum(len(h["open_ports"]) for h in hosts)
    triaged = "yes" if triage_text else "no"
    if triage_text and ai_info:
        triaged += f" ({ai_info['backend']} · {ai_info['model']})"
    lines = [
        "# Nmap Triage Report",
        "",
        f"Scan file: `{os.path.basename(scan_file)}`",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Hosts up: {len(hosts)} · Open ports: {total} · "
        f"AI triaged: {triaged}",
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


def render_comparison(hosts, summary, runs):
    """Text report comparing several backends' triage of the same scan.

    runs is a list of {"backend", "text", "error", "stats"}: a backend dict
    from resolve_backend() plus what analyze() returned for it. Severity
    agreement counts the open ports where every backend gave the same
    label. "—" means a backend did not flag the port; matching dashes count
    as agreement, because skipping a port is a judgment too.
    """
    tags = [chr(ord("A") + i) for i in range(len(runs))]
    label_width = max(len(run["backend"]["label"]) for run in runs)
    model_width = max(len(run["backend"]["model"]) for run in runs)

    lines = ["=== Backend comparison ===", ""]
    for tag, run in zip(tags, runs):
        backend = run["backend"]
        result = (f"error: {run['error']}" if run["error"]
                  else describe_stats(run["stats"]))
        lines.append(f"{tag}: {backend['label']:<{label_width}}  "
                     f"{backend['model']:<{model_width}}  {result}")
    lines.append("")

    keys = [(h["address"], p["port"]) for h in hosts for p in h["open_ports"]]
    if any(run["error"] for run in runs):
        lines.append("Severity agreement: not computed (a backend failed).")
    elif keys:
        severities = [extract_severities(run["text"]) for run in runs]
        names = [f"{address}:{port}" for address, port in keys]
        name_width = max([len("Finding")] + [len(name) for name in names])
        lines.append((f"{'Finding':<{name_width}}  "
                      + "  ".join(f"{tag:<6}" for tag in tags)).rstrip())
        agree = 0
        for key, name in zip(keys, names):
            labels = [found.get(key, "—") for found in severities]
            if len(set(labels)) == 1:
                agree += 1
            lines.append((f"{name:<{name_width}}  "
                          + "  ".join(f"{label:<6}" for label in labels)).rstrip())
        lines += [
            "",
            f"Severity agreement: {agree} of {len(keys)} open ports "
            f"({100 * agree / len(keys):.0f}%)",
            "— = the model did not flag that port; matching dashes count "
            "as agreement.",
        ]

    lines += ["", summary.rstrip("\n")]
    for tag, run in zip(tags, runs):
        backend = run["backend"]
        lines += ["", f"=== Triage {tag}: {backend['label']} · "
                      f"{backend['model']} ===", ""]
        lines.append(run["text"] if run["text"]
                     else f"No triage: {run['error']}")
    return "\n".join(lines) + "\n"


def write_report(document, output=None):
    """Write the report to a file, or print it to stdout."""
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(document)
        print(f"Report written to {output}")
    else:
        print(document)


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
    ap.add_argument("--backend", choices=BACKENDS, default="nvidia",
                    help="AI backend: nvidia (cloud, default) or lemonade "
                         "(local, no API key; scan data stays on this machine)")
    ap.add_argument("--model",
                    help=f"Model ID (default: {DEFAULT_MODEL} for nvidia, "
                         f"{LEMONADE_DEFAULT_MODEL} for lemonade; with "
                         "--compare it sets the Lemonade model)")
    ap.add_argument("--base-url",
                    help="OpenAI-compatible base URL (lemonade default: "
                         f"{LEMONADE_BASE_URL}; with --compare it sets the "
                         "Lemonade URL)")
    ap.add_argument("--timeout", type=float,
                    help=f"Seconds to wait for the model (default: "
                         f"{CLOUD_TIMEOUT} cloud, {LOCAL_TIMEOUT} local)")
    ap.add_argument("--compare", action="store_true",
                    help="Run the scan through nvidia (cloud) and lemonade "
                         "(local) and compare severities and speed; writes "
                         "a text report and skips Axiom")
    ap.add_argument("--no-ai", action="store_true",
                    help="Parse and summarize only, skip the API call")
    ap.add_argument("--no-axiom", action="store_true",
                    help="Skip shipping findings to Axiom")
    args = ap.parse_args()

    if args.timeout is not None and args.timeout <= 0:
        ap.error("--timeout must be a positive number of seconds")
    if args.compare and args.no_ai:
        ap.error("--compare runs the AI triage; drop --no-ai")
    if args.compare and args.format != "text":
        ap.error("--compare writes a text report; drop --format")

    hosts = parse_nmap_xml(args.xmlfile)

    if not hosts:
        print("No hosts with open ports found in that scan.")
        return

    summary = summarize(hosts)

    if args.compare:
        backends = [
            resolve_backend("nvidia", timeout=args.timeout),
            resolve_backend("lemonade", args.model, args.base_url,
                            args.timeout),
        ]
        if not backends[0]["api_key"]:
            sys.exit("--compare needs NVIDIA_API_KEY for the cloud side.")
        runs = []
        for backend in backends:
            print(f"Analyzing findings with {backend['label']} · "
                  f"{backend['model']}...", file=sys.stderr)
            text, error, stats = analyze(hosts, backend)
            runs.append({"backend": backend, "text": text,
                         "error": error, "stats": stats})
        write_report(render_comparison(hosts, summary, runs), args.output)
        if any(run["error"] for run in runs):
            sys.exit(1)
        return

    report = summary
    triage = None
    ai_info = None

    if not args.no_ai:
        backend = resolve_backend(args.backend, args.model, args.base_url,
                                  args.timeout)
        if backend["key_env"] and not backend["api_key"]:
            print(summary)
            sys.exit(f"{backend['key_env']} is not set. Set it, use a local "
                     "model with --backend lemonade, or run with --no-ai.")

        note = (" (the first run may download the model)"
                if backend["name"] == "lemonade" else "")
        print(f"Analyzing findings with {backend['label']} · "
              f"{backend['model']}{note}...", file=sys.stderr)
        triage, error, stats = analyze(hosts, backend)

        if error:
            print(summary)
            sys.exit(error)

        print(f"Triage done in {describe_stats(stats)}.", file=sys.stderr)
        ai_info = {"backend": backend["name"], "model": backend["model"],
                   "seconds": stats["seconds"]}
        report = summary + "\n=== Triage ===\n\n" + triage

    if not args.no_axiom:
        events, run_id = build_events(hosts, args.xmlfile, triage, ai_info)
        error = ship_to_axiom(events)
        if error:
            print(f"Warning: could not ship findings to Axiom — {error}",
                  file=sys.stderr)
        else:
            print(f"Shipped {len(events)} findings to Axiom "
                  f"(dataset: {AXIOM_DATASET}, run_id: {run_id})",
                  file=sys.stderr)

    if args.format == "json":
        document = render_json_report(hosts, args.xmlfile, triage, report,
                                      ai_info)
    elif args.format == "markdown":
        document = render_markdown_report(hosts, args.xmlfile, triage,
                                          summary, ai_info)
    else:
        document = report

    write_report(document, args.output)


if __name__ == "__main__":
    main()
