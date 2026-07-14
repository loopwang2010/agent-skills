"""Regression tests for bestai_imagegen.py — stdlib unittest only (no pip install).

Run:  python -m unittest discover -s tests -v      (from the project root)

Covers the 2026-07-13 security/robustness review fixes:
  P0-1  redirect guard (credentials must never follow a 30x off-host)
  P0-2  host_allowed() enforces https
  P0-3  --image magic-byte sniffing + size cap
  P0-4  --out refuses existing files without --force
  P0-5  --n / --retries bounds
  P0-6  key redaction in error output
  P1-5  SSE data lines that are valid JSON but not dicts must not crash
  P1-6  gemini 200-with-non-JSON body must not crash (returns retryable err)
  P1-7  save_png guards: bad base64, short PNG-magic data, unwritable path
"""
import base64
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

# Locate bestai_imagegen.py in either layout:
#   source project:  <root>/bestai_imagegen.py  +  <root>/tests/
#   skill package:   <skill>/scripts/bestai_imagegen.py  +  <skill>/tests/
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _cand in (_PARENT, os.path.join(_PARENT, "scripts")):
    if os.path.exists(os.path.join(_cand, "bestai_imagegen.py")):
        sys.path.insert(0, _cand)
        break
import bestai_imagegen as big  # noqa: E402

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _drain(handler):
    """Read the request body before responding. Responding + closing while
    unread bytes sit in the socket buffer makes Windows RST the connection
    (client sees WinError 10053) — a flaky-test classic."""
    length = int(handler.headers.get("Content-Length", 0) or 0)
    if length:
        handler.rfile.read(length)


class _Server:
    """Tiny threaded HTTP server; handler_factory(state) -> BaseHTTPRequestHandler."""

    def __init__(self, handler_cls):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class HostAllowedTests(unittest.TestCase):
    """P0-2: https enforcement, plus the original bypass suite must still hold."""

    def test_allows_https_on_allowed_domains_and_subdomains(self):
        for url in (
            "https://api.bestai.codes/v1",
            "https://bestai.codes",
            "https://relay01.favcodes.win/x",
            "https://cccode.ai",
            "https://a.b.unitoks.com",
            "https://API.BESTAI.CODES/v1",       # case
            "https://api.bestai.codes.:443/v1",  # trailing dot + port
        ):
            self.assertTrue(big.host_allowed(url), url)

    def test_rejects_non_https_schemes(self):
        for url in (
            "http://api.bestai.codes/v1",   # cleartext -> key sniffable
            "ftp://bestai.codes/v1",
            "//api.bestai.codes/v1",        # scheme-relative
            "api.bestai.codes/v1",          # no scheme
        ):
            self.assertFalse(big.host_allowed(url), url)

    def test_rejects_classic_bypasses(self):
        for url in (
            "https://evilbestai.codes",              # prefix trick
            "https://bestai.codes.evil.com",         # suffix trick
            "https://bestai.codes@evil.com/v1",      # userinfo trick (real host evil.com)
            "https://evil.com",
            "https://",                              # empty host
        ):
            self.assertFalse(big.host_allowed(url), url)

    def test_userinfo_with_real_allowed_host_passes(self):
        self.assertTrue(big.host_allowed("https://evil.com@api.bestai.codes/v1"))


class RedirectGuardTests(unittest.TestCase):
    """P0-1: the opener must refuse to follow ANY redirect (auth headers would
    otherwise be re-sent to the Location target, bypassing the allowlist)."""

    @classmethod
    def setUpClass(cls):
        cls.attacker_hits = []

        class Attacker(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                _drain(self)
                cls.attacker_hits.append(dict(self.headers))
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_POST = do_GET  # noqa: N815
            def log_message(self, *a):  # silence
                pass

        cls.attacker = _Server(Attacker)
        attacker_base = cls.attacker.base

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                _drain(self)
                self.send_response(302)
                self.send_header("Location", attacker_base + "/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_GET = do_POST  # noqa: N815
            def log_message(self, *a):
                pass

        cls.redirector = _Server(Redirector)

    @classmethod
    def tearDownClass(cls):
        cls.redirector.stop()
        cls.attacker.stop()

    def test_redirect_is_blocked_and_auth_never_reaches_target(self):
        opener = big.make_opener(None)
        req = urllib.request.Request(
            self.redirector.base + "/responses",
            data=b"{}",
            method="POST",
            headers={"Authorization": "Bearer sk-TEST-SECRET"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(req, timeout=10)
        self.assertEqual(ctx.exception.code, 302)
        self.assertEqual(self.attacker_hits, [],
                         "auth header was forwarded to the redirect target!")


class ImageSniffTests(unittest.TestCase):
    """P0-3: --image inputs are validated by content, not extension."""

    def test_sniff_known_formats(self):
        self.assertEqual(big._sniff_image(PNG_MAGIC + b"\0" * 20), "image/png")
        self.assertEqual(big._sniff_image(b"\xff\xd8\xff\xe0" + b"\0" * 20), "image/jpeg")
        self.assertEqual(
            big._sniff_image(b"RIFF\x00\x00\x00\x00WEBP" + b"\0" * 20), "image/webp")

    def test_sniff_rejects_non_images(self):
        self.assertIsNone(big._sniff_image(b"-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertIsNone(big._sniff_image(b'{"json": true}'))
        self.assertIsNone(big._sniff_image(b""))

    def test_read_image_bytes_rejects_non_image_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "secrets.png")  # image extension, non-image content
            with open(p, "w") as f:
                f.write("AKIA-fake-credential-material")
            with self.assertRaises(SystemExit):
                big._read_image_bytes(p)

    def test_read_image_bytes_rejects_oversize(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.png")
            with open(p, "wb") as f:
                f.write(PNG_MAGIC + b"\0" * 64)
            orig = big.MAX_IMAGE_BYTES
            big.MAX_IMAGE_BYTES = 16
            try:
                with self.assertRaises(SystemExit):
                    big._read_image_bytes(p)
            finally:
                big.MAX_IMAGE_BYTES = orig

    def test_read_image_bytes_ok_and_mime_from_content(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "actually_a_png.jpg")  # lying extension
            payload = PNG_MAGIC + b"\0" * 32
            with open(p, "wb") as f:
                f.write(payload)
            raw, mime = big._read_image_bytes(p)
            self.assertEqual(raw, payload)
            self.assertEqual(mime, "image/png")  # content wins over extension


class OutPathGuardTests(unittest.TestCase):
    """P0-4: refuse to overwrite an existing --out unless --force."""

    def test_new_path_ok(self):
        with tempfile.TemporaryDirectory() as d:
            big._check_out(os.path.join(d, "new.png"), force=False)  # no raise

    def test_existing_refused_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "precious.png")
            with open(p, "w") as f:
                f.write("do not clobber")
            with self.assertRaises(SystemExit):
                big._check_out(p, force=False)
            with open(p) as f:  # untouched
                self.assertEqual(f.read(), "do not clobber")

    def test_existing_allowed_with_force(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "old.png")
            with open(p, "w") as f:
                f.write("x")
            big._check_out(p, force=True)  # no raise

    def test_symlink_refused_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target.txt")
            with open(target, "w") as f:
                f.write("t")
            link = os.path.join(d, "link.png")
            try:
                os.symlink(target, link)
            except OSError:
                self.skipTest("symlink not permitted on this Windows setup")
            with self.assertRaises(SystemExit):
                big._check_out(link, force=False)


class BatchBoundsTests(unittest.TestCase):
    """P0-5: --n in [1, MAX_BATCH], --retries >= 1 — validated before any network."""

    def _run_main(self, argv):
        old = sys.argv
        sys.argv = ["bestai_imagegen.py"] + argv
        try:
            with self.assertRaises(SystemExit) as ctx:
                big.main()
            return ctx.exception.code
        finally:
            sys.argv = old

    def test_n_zero_rejected(self):
        self.assertNotEqual(self._run_main(["-p", "x", "--n", "0"]), 0)

    def test_n_over_cap_rejected(self):
        self.assertNotEqual(
            self._run_main(["-p", "x", "--n", str(big.MAX_BATCH + 1)]), 0)

    def test_retries_zero_rejected(self):
        self.assertNotEqual(self._run_main(["-p", "x", "--retries", "0"]), 0)


class RedactionTests(unittest.TestCase):
    """P0-6: registered secrets never appear in emitted error text."""

    def test_redact_replaces_registered_secret(self):
        big._SECRETS.append("sk-VERY-SECRET-VALUE")
        try:
            out = big._redact("upstream said: bad key sk-VERY-SECRET-VALUE here")
            self.assertNotIn("sk-VERY-SECRET-VALUE", out)
            self.assertIn("***", out)
        finally:
            big._SECRETS.remove("sk-VERY-SECRET-VALUE")

    def test_redact_handles_empty_registry(self):
        self.assertEqual(big._redact("plain"), "plain")


class SSERobustnessTests(unittest.TestCase):
    """P1-5: SSE `data:` payloads that are valid JSON but not objects must be
    skipped, not crash stream_once with AttributeError."""

    @classmethod
    def setUpClass(cls):
        img_b64 = _b64(b"fake-image-bytes")
        body = "\n".join([
            "event: weird",
            "data: []",
            "data: null",
            "data: 42",
            'data: "just a string"',
            'data: {"type":"response.image_generation_call.partial_image",'
            f'"partial_image_b64":"{img_b64}"}}',
            "data: [DONE]",
            "",
        ]).encode()

        class SSE(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                _drain(self)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *a):
                pass

        cls.expected_b64 = img_b64
        cls.server = _Server(SSE)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_non_dict_json_lines_are_skipped(self):
        opener = big.make_opener(None)
        images, text, err = big.stream_once(
            opener, self.server.base, "k", {"input": []}, verbose=False)
        self.assertEqual(images, [self.expected_b64])
        self.assertIsNone(err)


class GeminiNonJsonTests(unittest.TestCase):
    """P1-6: a 200 response with a non-JSON body (e.g. Cloudflare HTML) must
    surface as a retryable error, not an uncaught JSONDecodeError."""

    @classmethod
    def setUpClass(cls):
        class Html(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                _drain(self)
                page = b"<html>Attention Required! | Cloudflare</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
            def log_message(self, *a):
                pass

        cls.server = _Server(Html)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_non_json_body_returns_retryable_error(self):
        opener = big.make_opener(None)
        images, err = big.gemini_generate(
            opener, self.server.base, "k", "m", "prompt", None, None)
        self.assertEqual(images, [])
        self.assertIsInstance(err, dict)
        self.assertTrue(big._retryable(str(err.get("message"))),
                        f"error should be retryable: {err}")


class SavePngGuardTests(unittest.TestCase):
    """P1-7: save_png must _die cleanly, never traceback."""

    def test_bad_base64_dies_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):
                big.save_png("!!!not-base64!!!", os.path.join(d, "x.png"))

    def test_short_png_magic_data_does_not_struct_crash(self):
        # PNG magic + only 10 bytes: old code hit struct.error on raw[16:24]
        b64 = _b64(PNG_MAGIC + b"\0" * 10)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "tiny.png")
            nbytes, dims = big.save_png(b64, p)
            self.assertEqual(nbytes, 18)
            self.assertEqual(dims, "")  # too short to parse dims — no crash

    def test_unwritable_path_dies_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            # a *file* used as a directory component -> OSError on makedirs
            blocker = os.path.join(d, "blocker")
            with open(blocker, "w") as f:
                f.write("x")
            bad_out = os.path.join(blocker, "sub", "x.png")
            with self.assertRaises(SystemExit):
                big.save_png(_b64(b"data"), bad_out)


class IndexedOutTests(unittest.TestCase):
    def test_single_unchanged(self):
        self.assertEqual(big._indexed_out("a/b.png", 0, 1), "a/b.png")

    def test_batch_indexed(self):
        self.assertEqual(big._indexed_out("hero.png", 0, 3), "hero_1.png")
        self.assertEqual(big._indexed_out("hero.png", 2, 3), "hero_3.png")

    def test_batch_no_ext_defaults_png(self):
        self.assertEqual(big._indexed_out("hero", 1, 2), "hero_2.png")


if __name__ == "__main__":
    unittest.main(verbosity=2)
