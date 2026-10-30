"""Tests for nmap_triage.py — standard library only.

Run from the repo root:

    python3 -m unittest discover -s tests -v

Or directly:

    python3 tests/test_parser.py

The tests import nmap_triage, which requires the `requests` package
(listed in requirements.txt). Everything else asserted here is pure
standard library. The bundled examples/scanme.xml sample is the only
fixture that touches the network-free parser path.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nmap_triage

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_XML = os.path.join(REPO_ROOT, "examples", "scanme.xml")

# Byte-for-byte what summarize() returns for examples/scanme.xml today.
# This locks the default text output: any change to the summary format
# must update this string deliberately, not by accident.
EXPECTED_SUMMARY = (
    "=== Scan Summary ===\n"
    "Hosts up with open ports: 1\n"
    "Open ports total:         3\n"
    "\n"
    "45.33.32.156 (scanme.nmap.org)\n"
    "  22/tcp  ssh \u2014 OpenSSH 8.9p1\n"
    "  80/tcp  http \u2014 Apache httpd 2.4.52\n"
    "  9929/tcp  nping-echo \u2014 Nping\n"
)

FIXTURE_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="25"><state state="closed"/><service name="smtp"/></port></ports></host>
</nmaprun>
"""


def write_temp_xml(content):
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class TestParseNmapXml(unittest.TestCase):
    def test_parse_scanme_returns_expected_host(self):
        hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["address"], "45.33.32.156")
        self.assertEqual(hosts[0]["hostname"], "scanme.nmap.org")

    def test_parse_scanme_returns_expected_ports(self):
        hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)
        ports = hosts[0]["open_ports"]
        self.assertEqual(
            [(p["port"], p["protocol"], p["service"], p["version"])
             for p in ports],
            [(22, "tcp", "ssh", "OpenSSH 8.9p1"),
             (80, "tcp", "http", "Apache httpd 2.4.52"),
             (9929, "tcp", "nping-echo", "Nping")],
        )

    def test_parse_skips_down_hosts_and_non_open_ports(self):
        path = write_temp_xml(FIXTURE_XML)
        try:
            hosts = nmap_triage.parse_nmap_xml(path)
        finally:
            os.unlink(path)
        # Down host skipped; closed/filtered ports skipped; the host
        # with no open ports at all is skipped too.
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["address"], "10.0.0.2")
        self.assertEqual(len(hosts[0]["open_ports"]), 1)
        self.assertEqual(hosts[0]["open_ports"][0]["port"], 22)
        self.assertEqual(hosts[0]["open_ports"][0]["version"], "OpenSSH 9.0")

    def test_parse_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            nmap_triage.parse_nmap_xml("/nonexistent/scan.xml")

    def test_parse_malformed_xml_exits(self):
        path = write_temp_xml("<nmaprun><host><unclosed>")
        try:
            with self.assertRaises(SystemExit):
                nmap_triage.parse_nmap_xml(path)
        finally:
            os.unlink(path)


class TestSeverityAssignment(unittest.TestCase):
    def test_assess_known_services(self):
        cases = [
            ("microsoft-ds", 445, "HIGH"),
            ("telnet", 23, "HIGH"),
            ("ftp", 21, "HIGH"),
            ("mysql", 3306, "HIGH"),
            ("redis", 6379, "HIGH"),
            ("ssh", 22, "MEDIUM"),
            ("http", 80, "MEDIUM"),
            ("https", 443, "LOW"),
            ("domain", 53, "LOW"),
            ("something-obscure", 12345, "LOW"),
        ]
        for service, port, expected in cases:
            severity, remediation = nmap_triage.assess_finding(service, port)
            self.assertEqual(severity, expected, service)
            self.assertTrue(remediation, service)

    def test_assess_port_fallback_for_tcpwrapped(self):
        # Port 31337 is the classic backdoor-associated port; the
        # service name alone ("tcpwrapped") says nothing useful.
        severity, _ = nmap_triage.assess_finding("tcpwrapped", 31337)
        self.assertEqual(severity, "HIGH")

    def test_findings_prefer_model_severity(self):
        hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)
        triage = ("[HIGH] 45.33.32.156:22 \u2014 ssh (OpenSSH 8.9p1)\n"
                  "  Why it matters. Fix it this way.\n")
        findings = nmap_triage.build_findings(hosts, triage)
        by_port = {f["port"]: f for f in findings}
        # Model severity overrides the heuristic for port 22...
        self.assertEqual(by_port[22]["severity"], "HIGH")
        # ...while the other ports keep their heuristic severities,
        # and every remediation still comes from the heuristic table.
        self.assertEqual(by_port[80]["severity"], "MEDIUM")
        self.assertEqual(by_port[9929]["severity"], "LOW")
        for f in findings:
            self.assertTrue(f["remediation"])


class TestExports(unittest.TestCase):
    def setUp(self):
        self.hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)
        self.summary = nmap_triage.summarize(self.hosts)

    def test_text_summary_byte_identical(self):
        self.assertEqual(self.summary, EXPECTED_SUMMARY)

    def test_json_export_is_valid_and_matches_text(self):
        rendered = nmap_triage.render_json_report(
            self.hosts, SAMPLE_XML, None, self.summary)
        document = json.loads(rendered)
        self.assertEqual(document["tool"], "nmap-triage")
        self.assertEqual(document["scan_file"], "scanme.xml")
        self.assertEqual(document["hosts_up"], 1)
        self.assertEqual(document["open_ports_total"], 3)
        self.assertFalse(document["ai_triaged"])
        self.assertIsNone(document["triage"])
        self.assertEqual(document["report"], self.summary)
        findings = document["findings"]
        self.assertEqual(len(findings), 3)
        for f in findings:
            for key in ("host", "port", "service", "severity", "remediation"):
                self.assertIn(key, f)
        parsed_ports = {(h["address"], p["port"])
                        for h in self.hosts for p in h["open_ports"]}
        finding_ports = {(f["host"], f["port"]) for f in findings}
        self.assertEqual(finding_ports, parsed_ports)

    def test_markdown_export_structure(self):
        rendered = nmap_triage.render_markdown_report(
            self.hosts, SAMPLE_XML, None, self.summary)
        self.assertIn("# Nmap Triage Report", rendered)
        self.assertIn("## Findings", rendered)
        self.assertIn("| Severity | Host | Port | Service | Version | Remediation |",
                      rendered)
        for token in ("22/tcp", "80/tcp", "9929/tcp", "ssh", "http",
                      "nping-echo", "MEDIUM", "LOW"):
            self.assertIn(token, rendered)
        self.assertIn("## Scan Summary", rendered)
        self.assertIn("## AI Triage", rendered)
        self.assertIn("Skipped (--no-ai).", rendered)

    def test_renderers_include_triage_text(self):
        triage = "[HIGH] 45.33.32.156:22 \u2014 ssh\n  Why. Fix."
        document = json.loads(nmap_triage.render_json_report(
            self.hosts, SAMPLE_XML, triage, self.summary))
        self.assertEqual(document["triage"], triage)
        self.assertTrue(document["ai_triaged"])
        markdown = nmap_triage.render_markdown_report(
            self.hosts, SAMPLE_XML, triage, self.summary)
        self.assertIn(triage, markdown)


if __name__ == "__main__":
    unittest.main()
