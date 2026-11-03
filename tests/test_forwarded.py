"""Unit tests for RFC 7239 Forwarded host authority preservation."""
from __future__ import annotations

import os
import sys
import unittest

# Ensure root directory is always on python sys.path
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from asgi_sandbox.routing import (
    FlexServerTuple,
    NormalizedScope,
    Request,
    Router,
    SubScope,
    URL,
    _rfc7239_forwarded_nonce_9f4a,
    _rfc7239_forwarded_proto,
    parse_forwarded,
)
import asgi.routing
import starlette._forwarded
import starlette.requests
import wholetrout.asgi


class TestRFC7239Forwarded(unittest.TestCase):
    def _scope(self, headers=None, scheme="http", server=("internal", 8000), root_path=""):
        raw_headers = []
        for k, v in (headers or []):
            k_bytes = k.encode("latin-1") if isinstance(k, str) else k
            v_bytes = v.encode("latin-1") if isinstance(v, str) else v
            raw_headers.append((k_bytes, v_bytes))
        return {
            "type": "http",
            "scheme": scheme,
            "server": server,
            "root_path": root_path,
            "headers": raw_headers,
        }

    # ---- Parser Tests (RFC 7239 Compliance) ----

    def test_parse_simple(self):
        self.assertEqual(
            parse_forwarded("for=1.2.3.4;proto=https"),
            [{"for": "1.2.3.4", "proto": "https"}],
        )

    def test_parse_multiple_elements(self):
        self.assertEqual(
            parse_forwarded("for=1.1.1.1, for=2.2.2.2;proto=https"),
            [{"for": "1.1.1.1"}, {"for": "2.2.2.2", "proto": "https"}],
        )

    def test_parse_quoted_value_with_semicolon(self):
        self.assertEqual(
            parse_forwarded('host="ex;ample.org";proto=https'),
            [{"host": "ex;ample.org", "proto": "https"}],
        )

    def test_parse_empty(self):
        self.assertEqual(parse_forwarded(""), [])

    def test_parse_case_insensitive_keys(self):
        self.assertEqual(parse_forwarded("Proto=HTTPS"), [{"proto": "HTTPS"}])

    # ---- Nonce / Scope Normalization Tests ----

    def test_extract_forwarded_host_nonce(self):
        scope = {
            "type": "http",
            "headers": [
                (b"forwarded", b'for=192.0.2.60;proto=https;host="edge.example.org"')
            ],
        }
        host = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(host, "edge.example.org")

    def test_extract_forwarded_host_with_port(self):
        scope = {
            "type": "http",
            "headers": [(b"forwarded", b"host=edge.example.org:8443;proto=https")],
        }
        host = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(host, "edge.example.org:8443")

    def test_extract_forwarded_absent(self):
        scope = {"type": "http", "headers": [(b"host", b"internal.local")]}
        host = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(host, "")

    def test_no_header_is_noop(self):
        scope = self._scope()
        self.assertEqual(_rfc7239_forwarded_nonce_9f4a(scope), scope)

    def test_proto_applied(self):
        scope = self._scope(headers=[("Forwarded", "proto=https;host=edge.example.org")])
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["scheme"], "https")

    def test_host_authority_preserved(self):
        scope = self._scope(headers=[("Forwarded", "proto=https;host=edge.example.org")])
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["server"], ("edge.example.org", 443))

    def test_explicit_port(self):
        scope = self._scope(headers=[("Forwarded", "proto=https;host=edge.example.org:8443")])
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["server"], ("edge.example.org", 8443))

    def test_ipv6_authority(self):
        scope = self._scope(headers=[("Forwarded", 'host="[2001:db8::1]:443";proto=https')])
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["server"], ("2001:db8::1", 443))

    def test_first_element_wins(self):
        scope = self._scope(
            headers=[("Forwarded", "host=edge.example.org, host=other.example.org")]
        )
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["server"][0], "edge.example.org")

    def test_host_header_replaced(self):
        scope = self._scope(
            headers=[("Host", "internal:8000"), ("Forwarded", "host=edge.example.org")]
        )
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        hosts = [v for (n, v) in out["headers"] if n.lower() == b"host"]
        self.assertEqual(hosts, [b"edge.example.org"])

    def test_header_case_insensitive(self):
        scope = self._scope(headers=[("FORWARDED", "host=edge.example.org")])
        out = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(out["server"][0], "edge.example.org")

    # ---- Request & Routing Integration Tests ----

    def test_base_url_reflects_forwarded_authority(self):
        req = Request(self._scope(headers=[("Forwarded", "proto=https;host=edge.example.org")]))
        self.assertEqual(str(req.base_url), "https://edge.example.org/")

    def test_base_url_no_header_uses_server(self):
        req = Request(self._scope())
        self.assertEqual(str(req.base_url), "http://internal:8000/")

    def test_base_url_submounted_root_path(self):
        req = Request(
            self._scope(
                headers=[("Forwarded", "proto=https;host=edge.example.org")],
                root_path="/api",
            )
        )
        self.assertEqual(str(req.base_url), "https://edge.example.org/api/")

    def test_scope_for_preserves_forwarded_authority_instance(self):
        scope = {
            "type": "http",
            "server": ("internal-backend", 8000),
            "scheme": "http",
            "headers": [(b"forwarded", b"proto=https;host=edge.example.org")],
            "path": "/api/v1/resource",
        }
        req = Request(scope)
        sub_scope = req.scope_for(path="/resource")
        self.assertEqual(sub_scope["server"], ("edge.example.org", 8000))
        self.assertEqual(sub_scope["server"], ("edge.example.org", 443))
        self.assertEqual(sub_scope["scheme"], "https")
        self.assertEqual(sub_scope["path"], "/resource")
        self.assertEqual(sub_scope["host_authority"], "edge.example.org")

    def test_scope_for_preserves_forwarded_authority_class(self):
        scope = {
            "type": "http",
            "server": ("internal-backend", 8000),
            "scheme": "http",
            "headers": [(b"forwarded", b"proto=https;host=edge.example.org")],
            "path": "/api/v1/resource",
        }
        sub_scope_cls = Request.scope_for(scope, path="/resource").scope
        self.assertEqual(sub_scope_cls["server"], ("edge.example.org", 8000))
        self.assertEqual(sub_scope_cls["server"], ("edge.example.org", 443))
        self.assertEqual(sub_scope_cls["scheme"], "https")
        self.assertEqual(sub_scope_cls["path"], "/resource")

    def test_scope_for_backward_compatibility_when_forwarded_absent(self):
        scope = {
            "type": "http",
            "server": ("internal-backend", 8000),
            "scheme": "http",
            "headers": [],
            "path": "/api/v1/resource",
        }
        req = Request(scope)
        sub_scope = req.scope_for(path="/resource")
        self.assertEqual(sub_scope["server"], ("internal-backend", 8000))
        self.assertEqual(sub_scope["scheme"], "http")
        self.assertEqual(sub_scope["path"], "/resource")

    def test_scope_for_noop_without_header(self):
        scope = self._scope()
        req = Request(scope)
        self.assertEqual(req.scope_for(), scope)

    def test_router_url_path_for_integration(self):
        router = Router()
        router.add_route("user_detail", "/users/{id}")

        scope = {
            "type": "http",
            "server": ("proxy-cluster", 443),
            "scheme": "http",
            "headers": [(b"forwarded", b"proto=https;host=api.gateway.io")],
        }
        req = Request(scope, router=router)
        sub_scope = req.scope_for(name="user_detail", id="usr_42")
        self.assertEqual(sub_scope["server"][0], "api.gateway.io")
        self.assertEqual(sub_scope["scheme"], "https")
        self.assertEqual(sub_scope["path"], "/users/usr_42")


if __name__ == "__main__":
    unittest.main()
