"""Tests for the AI backends (NVIDIA cloud, Lemonade local) — no network.

A small standard-library HTTP server stands in for the OpenAI-compatible
chat-completions API that both Lemonade and build.nvidia.com serve, so
these tests run offline. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nmap_triage

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_XML = os.path.join(REPO_ROOT, "examples", "scanme.xml")

# Variables the backends read. Cleared around every test so a developer's
# own .env or shell settings can't change the results.
BACKEND_ENV = ("NVIDIA_API_KEY", "LEMONADE_API_KEY", "LEMONADE_BASE_URL",
               "LEMONADE_MODEL")

TRIAGE = (
    "[HIGH] 45.33.32.156:80 — http (Apache httpd 2.4.52)\n"
    "  Why it matters. How to fix it.\n"
    "\n"
    "[MEDIUM] 45.33.32.156:22 — ssh (OpenSSH 8.9p1)\n"
    "  Why it matters. How to fix it.\n"
    "\n"
    "No other findings."
)


def chat_response(content, completion_tokens=120, **message_fields):
    """A chat-completions response body in the OpenAI shape."""
    message = {"role": "assistant", "content": content}
    message.update(message_fields)
    return {
        "object": "chat.completion",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 400,
                  "completion_tokens": completion_tokens,
                  "total_tokens": 400 + completion_tokens},
    }


class FakeChatServer:
    """OpenAI-compatible stand-in: answers every POST with one canned
    response and records the requests it received."""

    def __init__(self, body, status=200):
        self.body = body
        self.status = status
        self.requests = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                server.requests.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "json": json.loads(raw or b"{}"),
                })
                payload = json.dumps(server.body).encode("utf-8")
                self.send_response(server.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # keep test output quiet
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05},
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        host, port = self.httpd.server_address[:2]
        self.base_url = f"http://{host}:{port}/api/v1"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendTestCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in BACKEND_ENV:
            os.environ.pop(name, None)
        self.hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)


class TestResolveBackend(BackendTestCase):
    def test_lemonade_defaults(self):
        backend = nmap_triage.resolve_backend("lemonade")
        self.assertEqual(backend["base_url"], "http://localhost:13305/api/v1")
        self.assertEqual(backend["model"], "Qwen3-4B-Instruct-2507-GGUF")
        self.assertIsNone(backend["key_env"])  # no key required
        self.assertIsNone(backend["api_key"])
        self.assertEqual(backend["timeout"], nmap_triage.LOCAL_TIMEOUT)

    def test_lemonade_environment_then_flags(self):
        os.environ["LEMONADE_BASE_URL"] = "http://lab-box:13305/api/v1/"
        os.environ["LEMONADE_MODEL"] = "Qwen3-8B-GGUF"
        backend = nmap_triage.resolve_backend("lemonade")
        self.assertEqual(backend["base_url"], "http://lab-box:13305/api/v1")
        self.assertEqual(backend["model"], "Qwen3-8B-GGUF")

        backend = nmap_triage.resolve_backend(
            "lemonade", model="Gemma-3-4b-it-GGUF",
            base_url="http://127.0.0.1:9000/v1", timeout=30)
        self.assertEqual(backend["base_url"], "http://127.0.0.1:9000/v1")
        self.assertEqual(backend["model"], "Gemma-3-4b-it-GGUF")
        self.assertEqual(backend["timeout"], 30)

    def test_nvidia_defaults_unchanged(self):
        os.environ["NVIDIA_API_KEY"] = "nvapi-test"
        backend = nmap_triage.resolve_backend("nvidia")
        self.assertEqual(backend["base_url"],
                         "https://integrate.api.nvidia.com/v1")
        self.assertEqual(backend["model"], "nvidia/nemotron-3-ultra-550b-a55b")
        self.assertEqual(backend["key_env"], "NVIDIA_API_KEY")
        self.assertEqual(backend["api_key"], "nvapi-test")
        self.assertEqual(backend["timeout"], nmap_triage.CLOUD_TIMEOUT)

    def test_unknown_backend(self):
        with self.assertRaises(ValueError):
            nmap_triage.resolve_backend("ollama")


class TestAnalyze(BackendTestCase):
    def lemonade(self, server, **overrides):
        return nmap_triage.resolve_backend(
            "lemonade", base_url=server.base_url, **overrides)

    def test_lemonade_request_and_result(self):
        with FakeChatServer(chat_response(TRIAGE)) as server:
            text, error, stats = nmap_triage.analyze(
                self.hosts, self.lemonade(server))
        self.assertIsNone(error)
        self.assertEqual(text, TRIAGE)
        self.assertEqual(stats["completion_tokens"], 120)
        self.assertGreaterEqual(stats["seconds"], 0)

        request = server.requests[0]
        self.assertEqual(request["path"], "/api/v1/chat/completions")
        self.assertEqual(request["json"]["model"], "Qwen3-4B-Instruct-2507-GGUF")
        self.assertIs(request["json"]["enable_thinking"], False)
        messages = request["json"]["messages"]
        self.assertEqual([m["role"] for m in messages], ["system", "user"])
        self.assertEqual(json.loads(messages[1]["content"]), self.hosts)
        self.assertNotIn("authorization", request["headers"])

    def test_lemonade_sends_key_when_server_requires_one(self):
        os.environ["LEMONADE_API_KEY"] = "local-secret"
        with FakeChatServer(chat_response(TRIAGE)) as server:
            nmap_triage.analyze(self.hosts, self.lemonade(server))
        self.assertEqual(server.requests[0]["headers"]["authorization"],
                         "Bearer local-secret")

    def test_nvidia_request_has_key_and_no_lemonade_extension(self):
        os.environ["NVIDIA_API_KEY"] = "nvapi-test"
        with FakeChatServer(chat_response(TRIAGE)) as server:
            backend = nmap_triage.resolve_backend("nvidia",
                                                  base_url=server.base_url)
            text, error, _ = nmap_triage.analyze(self.hosts, backend)
        self.assertIsNone(error)
        self.assertEqual(text, TRIAGE)
        request = server.requests[0]
        self.assertEqual(request["headers"]["authorization"],
                         "Bearer nvapi-test")
        self.assertEqual(request["json"]["model"], nmap_triage.DEFAULT_MODEL)
        self.assertNotIn("enable_thinking", request["json"])

    def test_inline_reasoning_is_stripped(self):
        content = "<think>\nPort 80 looks old...\n</think>\n\n" + TRIAGE
        with FakeChatServer(chat_response(content)) as server:
            text, error, _ = nmap_triage.analyze(self.hosts,
                                                 self.lemonade(server))
        self.assertIsNone(error)
        self.assertEqual(text, TRIAGE)

    def test_reasoning_only_answer_is_an_error(self):
        body = chat_response("", reasoning_content="Thinking about port 22...")
        with FakeChatServer(body) as server:
            text, error, stats = nmap_triage.analyze(self.hosts,
                                                     self.lemonade(server))
        self.assertIsNone(text)
        self.assertIsNone(stats)
        self.assertIn("empty answer", error)

    def test_unknown_model(self):
        # The body Lemonade sends for a model that isn't in its registry.
        body = {"error": {"message": "Model Not-A-Model-GGUF not found",
                          "type": "model_not_found", "param": "model",
                          "code": "model_not_found",
                          "requested_model": "Not-A-Model-GGUF"}}
        with FakeChatServer(body, status=404) as server:
            text, error, _ = nmap_triage.analyze(
                self.hosts, self.lemonade(server, model="Not-A-Model-GGUF"))
        self.assertIsNone(text)
        self.assertIn("Not-A-Model-GGUF", error)
        self.assertIn("lemonade list", error)

    def test_wrong_base_url(self):
        body = {"error": {"message": "The requested endpoint does not exist",
                          "type": "not_found",
                          "path": "/wrong/chat/completions"}}
        with FakeChatServer(body, status=404) as server:
            text, error, _ = nmap_triage.analyze(self.hosts,
                                                 self.lemonade(server))
        self.assertIsNone(text)
        self.assertIn("--base-url", error)

    def test_lemonade_401_points_at_key(self):
        body = {"error": "Invalid or missing API key"}
        with FakeChatServer(body, status=401) as server:
            _, error, _ = nmap_triage.analyze(self.hosts,
                                              self.lemonade(server))
        self.assertIn("LEMONADE_API_KEY", error)

    def test_server_not_running(self):
        backend = nmap_triage.resolve_backend(
            "lemonade", base_url=f"http://127.0.0.1:{unused_port()}/api/v1",
            timeout=5)
        text, error, stats = nmap_triage.analyze(self.hosts, backend)
        self.assertIsNone(text)
        self.assertIsNone(stats)
        self.assertIn("lemonade status", error)


class TestSeverityParsing(unittest.TestCase):
    def test_markdown_wrapped_headers_still_parse(self):
        # Small local models often add list markers and bold text.
        triage = "\n".join([
            "- **[HIGH] 10.0.0.5:445** — microsoft-ds (Samba 3.0.20)",
            "  Why. Fix.",
            "1. [MEDIUM] 10.0.0.5:22 — ssh",
            "### [LOW] 10.0.0.5:53 — domain",
            "`[HIGH]` 10.0.0.6:21 — ftp",
            "[HIGH] 10.0.0.7:23 — telnet",
        ])
        self.assertEqual(nmap_triage.extract_severities(triage), {
            ("10.0.0.5", 445): "HIGH",
            ("10.0.0.5", 22): "MEDIUM",
            ("10.0.0.5", 53): "LOW",
            ("10.0.0.6", 21): "HIGH",
            ("10.0.0.7", 23): "HIGH",
        })

    def test_prose_mentioning_a_severity_is_ignored(self):
        triage = "Nothing here is [HIGH] risk: 10.0.0.5:80 is fine."
        self.assertEqual(nmap_triage.extract_severities(triage), {})


def run_for(label, model, text=None, error=None, seconds=10.0, tokens=250):
    """One entry of the runs list that render_comparison() takes."""
    backend = {"name": label.split()[0], "label": label, "model": model}
    stats = None if error else {"seconds": seconds, "prompt_tokens": 400,
                                "completion_tokens": tokens}
    return {"backend": backend, "text": text, "error": error, "stats": stats}


class TestComparison(unittest.TestCase):
    def setUp(self):
        # examples/scanme.xml has open ports 22, 80, and 9929.
        self.hosts = nmap_triage.parse_nmap_xml(SAMPLE_XML)
        self.summary = nmap_triage.summarize(self.hosts)

    def test_agreement_counts_matching_labels(self):
        cloud = ("[HIGH] 45.33.32.156:22 — ssh\n  x\n"
                 "[HIGH] 45.33.32.156:80 — http\n  x\n"
                 "[MEDIUM] 45.33.32.156:9929 — nping-echo\n  x")
        local = ("[HIGH] 45.33.32.156:22 — ssh\n  x\n"
                 "[MEDIUM] 45.33.32.156:80 — http\n  x")
        report = nmap_triage.render_comparison(self.hosts, self.summary, [
            run_for("nvidia (cloud)", "nvidia/nemotron-3-ultra-550b-a55b",
                    cloud, seconds=8.0, tokens=400),
            run_for("lemonade (local)", "Qwen3-4B-Instruct-2507-GGUF",
                    local, seconds=20.0, tokens=300),
        ])
        self.assertIn("Severity agreement: 1 of 3 open ports (33%)", report)
        self.assertIn("8.0 s · 50 tok/s", report)
        self.assertIn("20.0 s · 15 tok/s", report)
        rows = {line.split()[0]: line.split()[1:]
                for line in report.splitlines()
                if line.startswith("45.33.32.156:")}
        self.assertEqual(rows["45.33.32.156:22"], ["HIGH", "HIGH"])
        self.assertEqual(rows["45.33.32.156:80"], ["HIGH", "MEDIUM"])
        self.assertEqual(rows["45.33.32.156:9929"], ["MEDIUM", "—"])
        # Both full triage texts follow, for side-by-side reading.
        self.assertIn("=== Triage A: nvidia (cloud)", report)
        self.assertIn("=== Triage B: lemonade (local)", report)

    def test_matching_dashes_count_as_agreement(self):
        text = "[HIGH] 45.33.32.156:80 — http\n  x"
        report = nmap_triage.render_comparison(self.hosts, self.summary, [
            run_for("nvidia (cloud)", "model-a", text),
            run_for("lemonade (local)", "model-b", text),
        ])
        self.assertIn("Severity agreement: 3 of 3 open ports (100%)", report)

    def test_failed_backend_skips_agreement(self):
        error = "Could not reach Lemonade at http://localhost:13305/api/v1."
        report = nmap_triage.render_comparison(self.hosts, self.summary, [
            run_for("nvidia (cloud)", "model-a",
                    "[HIGH] 45.33.32.156:80 — http"),
            run_for("lemonade (local)", "model-b", error=error),
        ])
        self.assertIn("Severity agreement: not computed", report)
        self.assertIn("error: Could not reach Lemonade", report)
        self.assertIn("No triage: Could not reach Lemonade", report)

    def test_describe_stats(self):
        self.assertEqual(nmap_triage.describe_stats(
            {"seconds": 10.0, "completion_tokens": 250}), "10.0 s · 25 tok/s")
        self.assertEqual(nmap_triage.describe_stats(
            {"seconds": 3.0, "completion_tokens": None}), "3.0 s")
        self.assertEqual(nmap_triage.describe_stats(None), "—")


class TestCommandLine(BackendTestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        argv = ["nmap_triage.py"] + list(args)
        with mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                nmap_triage.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_lemonade_json_report_records_model(self):
        with FakeChatServer(chat_response(TRIAGE)) as server:
            code, out, err = self.run_cli(
                SAMPLE_XML, "--backend", "lemonade",
                "--base-url", server.base_url, "--no-axiom", "--format", "json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertTrue(document["ai_triaged"])
        self.assertEqual(document["ai"]["backend"], "lemonade")
        self.assertEqual(document["ai"]["model"], "Qwen3-4B-Instruct-2507-GGUF")
        severity = {f["port"]: f["severity"] for f in document["findings"]}
        self.assertEqual(severity[80], "HIGH")    # from the model
        self.assertEqual(severity[22], "MEDIUM")  # from the model
        self.assertEqual(severity[9929], "LOW")   # heuristic fallback
        self.assertIn("Triage done in", err)

    def test_missing_nvidia_key_suggests_lemonade(self):
        code, _, _ = self.run_cli(SAMPLE_XML, "--no-axiom")
        self.assertIn("NVIDIA_API_KEY is not set", str(code))
        self.assertIn("--backend lemonade", str(code))

    def test_compare_runs_both_backends(self):
        os.environ["NVIDIA_API_KEY"] = "nvapi-test"
        with FakeChatServer(chat_response(TRIAGE)) as server, \
                mock.patch.object(nmap_triage, "NVIDIA_BASE_URL",
                                  server.base_url):
            code, out, err = self.run_cli(SAMPLE_XML, "--compare",
                                          "--base-url", server.base_url)
        self.assertEqual(code, 0, err)
        self.assertEqual([r["json"]["model"] for r in server.requests],
                         [nmap_triage.DEFAULT_MODEL,
                          "Qwen3-4B-Instruct-2507-GGUF"])
        self.assertIn("Severity agreement: 3 of 3 open ports (100%)", out)

    def test_compare_rejects_no_ai(self):
        code, _, err = self.run_cli(SAMPLE_XML, "--compare", "--no-ai")
        self.assertEqual(code, 2)
        self.assertIn("drop --no-ai", err)


if __name__ == "__main__":
    unittest.main()
