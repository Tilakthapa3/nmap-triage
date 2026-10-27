#!/usr/bin/env python3
"""
nmap-triage web app: a browser front end for nmap_triage.py.

Start it:
    python app.py              # opens http://127.0.0.1:8765 in your browser
    (on a Mac you can double-click start-app.command instead)

Online demo mode (upload-only: no scanning, no Axiom, AI runs capped per hour):
    PUBLIC_MODE=1 SECRET_KEY=<random> ALLOWED_HOSTS=your-domain.com \
        gunicorn -w 1 --threads 4 -b 0.0.0.0:8000 app:app

All parsing, AI triage, and Axiom logic comes from nmap_triage.py, unchanged.
This file only adds the web page around it, plus the safety checks a web
page needs.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from flask import Flask, abort, render_template, request
    import defusedxml
    import defusedxml.ElementTree as SafeET
except ImportError:
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

# The existing CLI module. Importing it also loads .env (NVIDIA_API_KEY, ...).
import nmap_triage as nt


# --- Settings -----------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_SCAN = BASE_DIR / "samples" / "scanme-sample.xml"
SCANS_DIR = BASE_DIR / "scans"
REPO_URL = "https://github.com/Tilakthapa3/nmap-triage"


def env_flag(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# Public mode is the upload-only version for a public link.
PUBLIC_MODE = env_flag("PUBLIC_MODE")

DEFAULT_PORT = 8765          # not 5000: macOS AirPlay Receiver already uses it
MAX_UPLOAD_MB = 5
SCAN_TIMEOUT_SECONDS = 600
SMALLEST_CIDR_PREFIX = 24    # refuse ranges bigger than a /24 from the page
MODEL = os.environ.get("NVIDIA_MODEL", nt.DEFAULT_MODEL)

# Public mode caps AI runs per hour so visitors can't burn through the key's
# credits. 0 means no cap (the default when running locally).
AI_HOURLY_LIMIT = int(os.environ.get("AI_HOURLY_LIMIT", "20" if PUBLIC_MODE else "0"))

# Host names the app answers to. Locally that's only 127.0.0.1/localhost,
# which blocks DNS-rebinding attacks (a malicious site pointing its own
# domain at 127.0.0.1 to reach this scanner from your browser).
if PUBLIC_MODE:
    ALLOWED_HOSTS = {h.strip().lower() for h in
                     os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
else:
    ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

# Every form carries this token. Another website can't read it, so it can't
# make your browser submit a scan request to this app (CSRF).
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
CSRF_TOKEN = hmac.new(SECRET_KEY.encode(), b"nmap-triage-forms",
                      hashlib.sha256).hexdigest()

# One hostname, IPv4 address, IPv4 CIDR range, or Nmap range (10.0.0.1-20).
# It must start with a letter or digit, so it can never be read as an option
# such as "-oN /some/file".
TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}(/\d{1,2})?$")

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, None: 3}

# A finding header from the model, e.g.
#   [HIGH] 45.33.32.156:22 — ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
FINDING_HEADER = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW)\]\s+(.+?)\s*$")
FINDING_TITLE = re.compile(r"^(\S+?:\d+)\s*(?:[—–-]+\s*(.*))?$")
SERVICE_AND_VERSION = re.compile(r"^(\S+)\s*\((.*)\)\s*$")


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# --- Request guards -----------------------------------------------------------

@app.before_request
def guard_request():
    host = (request.host or "").lower()
    if host.startswith("["):              # IPv6 literal, e.g. [::1]:8765
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        abort(400, "Unexpected host name.")

    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(token, CSRF_TOKEN):
            abort(400, "This page expired. Reload it and try again.")


@app.after_request
def security_headers(resp):
    # No inline scripts or styles, nothing loaded from other sites, and the
    # page can't be framed (clickjacking).
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Reading scans ------------------------------------------------------------

def load_scan(data):
    """Parse Nmap XML bytes. Returns (hosts, error_message)."""
    if not data or not data.strip():
        return None, "That file is empty."

    # defusedxml blocks XML bombs and external entities. Nmap never writes
    # either, so a file that uses them is not a normal scan.
    try:
        root = SafeET.fromstring(data)
    except defusedxml.DefusedXmlException:
        return None, ("That file uses XML features this app blocks for safety "
                      "(entities or external references), so it isn't a "
                      "normal Nmap scan.")
    except SafeET.ParseError:
        return None, ("That file isn't valid XML. Save your scan with: "
                      "nmap -sV -oX scan.xml <target>")

    if root.tag != "nmaprun":
        return None, ("That XML file isn't an Nmap scan. Save your scan with: "
                      "nmap -sV -oX scan.xml <target>")

    # Reuse the CLI's parser on a temporary copy, deleted right after.
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return nt.parse_nmap_xml(path), None
    except SystemExit as e:  # the CLI parser exits on bad input
        return None, str(e.code)
    finally:
        os.remove(path)


# --- Turning the AI's answer into cards ---------------------------------------

def split_findings(triage_text):
    """Split the model's reply into finding blocks plus closing notes."""
    findings, notes = [], []
    current = None

    for raw in (triage_text or "").splitlines():
        if not raw.strip():
            continue

        header = FINDING_HEADER.match(raw)
        if header:
            severity, title = header.groups()
            target, service, version = title, "", ""
            parts = FINDING_TITLE.match(title)
            if parts:
                target, service = parts.group(1), (parts.group(2) or "").strip()
                sv = SERVICE_AND_VERSION.match(service)
                if sv:
                    service, version = sv.group(1), sv.group(2).strip()
            current = {
                "severity": severity,
                "target": target,
                "service": service,
                "version": version,
                "lines": [],
                "anchor": "f-" + re.sub(r"[^A-Za-z0-9_-]", "-", target),
            }
            findings.append(current)
            continue

        line = raw.strip()
        # Indented lines explain the finding above. Unindented text after a
        # finding is the model's closing note ("No other findings.").
        if current is not None and (raw[:1].isspace() or not current["lines"]):
            current["lines"].append(line)
        else:
            current = None
            notes.append(line)

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    for f in findings:
        f["text"] = " ".join(f.pop("lines"))
        # `commands` in the reply: odd-numbered parts are shown as code
        f["parts"] = re.split(r"`([^`]+)`", f["text"])
    return findings, notes


def port_rows(hosts, triage_text, findings):
    """One row per open port, with the severity the AI gave it (if any)."""
    by_target = nt.extract_severities(triage_text)  # (host, port) -> severity
    anchors = {f["target"]: f["anchor"] for f in findings}

    rows = []
    for host in hosts:
        names = [host["address"]] + ([host["hostname"]] if host["hostname"] else [])
        for p in host["open_ports"]:
            severity, anchor = None, None
            for name in names:  # the model may use the IP or the hostname
                severity = severity or by_target.get((name, p["port"]))
                anchor = anchor or anchors.get("%s:%d" % (name, p["port"]))
            rows.append({
                "address": host["address"],
                "hostname": host["hostname"],
                "port": p["port"],
                "protocol": p["protocol"],
                "service": p["service"],
                "version": p["version"] or "",
                "severity": severity,
                "anchor": anchor,
            })
    return rows


# --- Report files -------------------------------------------------------------

def md_escape(text):
    """Keep scanned-host text from becoming Markdown tables or HTML."""
    text = str(text or "").replace("\\", "\\\\")
    for ch in "|<>":
        text = text.replace(ch, "\\" + ch)
    return text.replace("\n", " ")


def build_markdown(result):
    lines = [
        "# nmap-triage report",
        "",
        "- Scan: %s" % md_escape(result["source"]),
        "- Generated: %s" % result["generated"],
        "- AI triage: %s" % (md_escape(MODEL) if result["ai_used"] else "off"),
        "",
        "## Open ports",
        "",
        "| Host | Port | Service | Version | Triage |",
        "|------|------|---------|---------|--------|",
    ]
    for r in result["rows"]:
        host = r["address"] + (" (%s)" % r["hostname"] if r["hostname"] else "")
        lines.append("| %s | %d/%s | %s | %s | %s |" % (
            md_escape(host), r["port"], md_escape(r["protocol"]),
            md_escape(r["service"]), md_escape(r["version"]),
            r["severity"] or "-"))

    if result["findings"]:
        lines += ["", "## What to fix first", ""]
        for f in result["findings"]:
            title = f["target"]
            if f["service"]:
                title += " - " + f["service"]
            if f["version"]:
                title += " (%s)" % f["version"]
            lines += ["### [%s] %s" % (f["severity"], md_escape(title)), "",
                      md_escape(f["text"]), ""]
    elif result["triage"]:
        lines += ["", "## AI triage", "", "```", result["triage"], "```", ""]

    for note in result["notes"]:
        lines += [md_escape(note), ""]

    if result["ai_used"]:
        lines += ["> AI-generated triage. Check each finding before acting on it."]
    return "\n".join(lines).rstrip() + "\n"


# --- Running the triage -------------------------------------------------------

_ai_calls = deque()
_ai_lock = threading.Lock()


def ai_allowed_now():
    """True if another AI run fits under the hourly cap."""
    if AI_HOURLY_LIMIT <= 0:
        return True
    now = time.monotonic()
    with _ai_lock:
        while _ai_calls and now - _ai_calls[0] > 3600:
            _ai_calls.popleft()
        if len(_ai_calls) >= AI_HOURLY_LIMIT:
            return False
        _ai_calls.append(now)
        return True


def axiom_available():
    return not PUBLIC_MODE and bool(os.environ.get("AXIOM_TOKEN"))


def run_triage(hosts, source, use_ai, use_axiom):
    triage, ai_error = None, None

    if use_ai:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            ai_error = ("AI triage didn't run: NVIDIA_API_KEY isn't set. Add it "
                        "to your .env file and restart the app.")
        elif not ai_allowed_now():
            ai_error = ("AI triage didn't run: this demo reached its hourly "
                        "limit. The open ports are listed below.")
        else:
            triage, error = nt.analyze(hosts, MODEL, api_key)
            if error:
                ai_error = "AI triage didn't run: " + error

    findings, notes = split_findings(triage)
    rows = port_rows(hosts, triage, findings)
    rows_by_severity = sorted(rows, key=lambda r: SEVERITY_ORDER[r["severity"]])

    lanes = []
    for level in ("HIGH", "MEDIUM", "LOW", None):
        lane_rows = [r for r in rows_by_severity if r["severity"] == level]
        if level or (triage and lane_rows):
            lanes.append({"severity": level, "rows": lane_rows})

    # Same text the CLI prints, so the .txt download matches it exactly.
    summary = nt.summarize(hosts)
    report_txt = summary + ("\n=== Triage ===\n\n" + triage if triage else "")

    events, run_id = nt.build_events(hosts, source, triage)

    axiom_message, axiom_ok = None, False
    if use_axiom and axiom_available():
        error = nt.ship_to_axiom(events)
        if error:
            axiom_message = "Couldn't log findings to Axiom: " + error
        else:
            axiom_ok = True
            axiom_message = "Logged %d findings to Axiom (dataset %s, run %s)." % (
                len(events), nt.AXIOM_DATASET, run_id)

    result = {
        "source": source,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "host_count": len(hosts),
        "port_count": len(rows),
        "triage": triage,
        "ai_used": bool(triage),
        "ai_error": ai_error,
        "findings": findings,
        "notes": notes,
        "rows": rows,
        "lanes": lanes,
        "counts": {level: sum(1 for r in rows if r["severity"] == level)
                   for level in ("HIGH", "MEDIUM", "LOW")},
        "axiom_message": axiom_message,
        "axiom_ok": axiom_ok,
        "saved_to": None,
    }

    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(source).stem) or "scan"
    result["downloads"] = {
        "name": "nmap-triage-" + stem,
        "md": build_markdown(result),
        "json": json.dumps(events, indent=2),
        "txt": report_txt,
    }
    return result


# --- Pages --------------------------------------------------------------------

def page(status=200, **context):
    defaults = {
        "public_mode": PUBLIC_MODE,
        "csrf_token": CSRF_TOKEN,
        "ai_available": bool(os.environ.get("NVIDIA_API_KEY")),
        "axiom_available": axiom_available(),
        "nmap_available": (not PUBLIC_MODE) and bool(shutil.which("nmap")),
        "max_upload_mb": MAX_UPLOAD_MB,
        "model": MODEL,
        "repo_url": REPO_URL,
        "result": None,
        "error": None,
        "notice": None,
        "tab": "upload",
        "form": {},
    }
    defaults.update(context)
    return render_template("index.html", **defaults), status


def chosen_options():
    return {
        "ai": request.form.get("ai") == "on",
        "axiom": request.form.get("axiom") == "on",
    }


@app.get("/")
def index():
    return page()


@app.post("/analyze")
def analyze_upload():
    options = chosen_options()
    form = dict(options)

    if request.form.get("sample") == "1":
        data, source = SAMPLE_SCAN.read_bytes(), SAMPLE_SCAN.name
    else:
        upload = request.files.get("scan")
        if upload is None or not upload.filename:
            return page(400, error="Choose an Nmap XML file first, or try the sample scan.",
                        form=form)
        data = upload.read()
        source = Path(upload.filename).name[:120]

    hosts, error = load_scan(data)
    if error:
        return page(400, error=error, form=form)
    if not hosts:
        return page(notice="No open ports in %s, so there's nothing to triage." % source,
                    form=form)

    result = run_triage(hosts, source, options["ai"], options["axiom"])
    return page(result=result, form=form)


@app.post("/scan")
def scan_and_analyze():
    if PUBLIC_MODE:
        abort(404)

    options = chosen_options()
    target = request.form.get("target", "").strip()
    size = "quick" if request.form.get("size") == "quick" else "standard"
    form = dict(options, target=target, size=size)

    def fail(message):
        return page(400, error=message, tab="scan", form=form)

    if request.form.get("permission") != "yes":
        return fail("Confirm that you own this target or have permission to scan it.")
    if not TARGET_PATTERN.match(target):
        return fail("Enter one hostname, IP address, or range, like scanme.nmap.org "
                    "or 192.168.1.0/24.")
    if "/" in target and int(target.rsplit("/", 1)[1]) < SMALLEST_CIDR_PREFIX:
        return fail("Ranges bigger than a /24 take too long for the page. "
                    "Use the command line for those.")

    nmap = shutil.which("nmap")
    if not nmap:
        return fail("Nmap isn't installed. Install it with: brew install nmap")

    SCANS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    xml_path = SCANS_DIR / ("%s-%s.xml" % (re.sub(r"[^A-Za-z0-9.-]", "_", target), stamp))

    # A list of arguments and no shell: the target can't add commands or options.
    cmd = [nmap, "-sV", "-oX", str(xml_path)]
    if size == "quick":
        cmd.append("-F")
    cmd.append(target)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return fail("The scan ran longer than %d minutes and was stopped. Try a quick "
                    "scan or a smaller range." % (SCAN_TIMEOUT_SECONDS // 60))

    if "Failed to resolve" in (proc.stderr or ""):
        return fail("Nmap couldn't find %s. Check the spelling, or use an IP address."
                    % target)
    if proc.returncode != 0 or not xml_path.exists():
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        return fail("Nmap couldn't finish the scan. " + " ".join(detail))

    hosts, error = load_scan(xml_path.read_bytes())
    if error:
        return fail(error)
    if not hosts:
        return page(notice="Nmap found no open ports on %s. The scan is saved as "
                    "scans/%s." % (target, xml_path.name), tab="scan", form=form)

    result = run_triage(hosts, xml_path.name, options["ai"], options["axiom"])
    result["saved_to"] = "scans/" + xml_path.name
    return page(result=result, tab="scan", form=form)


@app.errorhandler(413)
def too_large(_err):
    return page(413, error="That file is bigger than %d MB. Nmap XML for a normal "
                "scan is much smaller, so check that it's the right file." % MAX_UPLOAD_MB)


@app.errorhandler(400)
def bad_request(err):
    return page(400, error=getattr(err, "description", None) or "Bad request.")


@app.errorhandler(404)
def not_found(_err):
    return page(404, error="That page doesn't exist here.")


# --- Starting the app ---------------------------------------------------------

def port_in_use(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def main():
    ap = argparse.ArgumentParser(description="Start the nmap-triage web app.")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", DEFAULT_PORT)))
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--no-browser", action="store_true",
                    help="Don't open the page in your browser")
    args = ap.parse_args()

    if not PUBLIC_MODE and args.host not in ("127.0.0.1", "localhost"):
        sys.exit("The local app can run scans, so it only listens on 127.0.0.1. "
                 "Set PUBLIC_MODE=1 to serve the upload-only demo on other addresses.")

    url = "http://127.0.0.1:%d/" % args.port
    check_host = "127.0.0.1" if args.host in ("0.0.0.0", "localhost") else args.host
    if port_in_use(check_host, args.port):
        print("Port %d is already in use. If nmap-triage is already running, it's at %s"
              % (args.port, url))
        if not args.no_browser and not PUBLIC_MODE:
            webbrowser.open(url)
        return

    if not args.no_browser and not PUBLIC_MODE:
        threading.Timer(1.0, webbrowser.open, [url]).start()

    print("nmap-triage is running at %s" % url)
    print("Keep this window open while you use it. Press Ctrl+C to stop.\n")
    # debug stays off: Werkzeug's debugger lets anyone who reaches it run code.
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
