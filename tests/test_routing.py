"""Routing test suite matching asgi routing conventions."""
import os
import sys
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from asgi.routing import Request, _rfc7239_forwarded_nonce_9f4a


class TestASGIRouting(unittest.TestCase):
    def test_rfc7239_forwarded_extracted(self):
        scope = {
            "type": "http",
            "server": ("127.0.0.1", 8000),
            "headers": [
                (b"host", b"127.0.0.1:8000"),
                (b"forwarded", b"proto=https;host=edge.example.org"),
            ],
        }
        authority = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(authority, "edge.example.org")

    def test_scope_for_preserves_forwarded_host_authority(self):
        scope = {
            "type": "http",
            "server": ("127.0.0.1", 8000),
            "path": "/",
            "headers": [
                (b"host", b"127.0.0.1:8000"),
                (b"forwarded", b"proto=https;host=edge.example.org"),
            ],
        }
        req = Request(scope)
        sub_scope = req.scope_for(path="/subapp/api")
        self.assertEqual(sub_scope["path"], "/subapp/api")
        self.assertEqual(sub_scope["server"][0], "edge.example.org")

    def test_scope_for_backward_compatibility_without_forwarded(self):
        scope = {
            "type": "http",
            "server": ("10.0.0.1", 8080),
            "path": "/old",
            "headers": [(b"host", b"10.0.0.1:8080")],
        }
        req = Request(scope)
        sub_scope = req.scope_for(path="/new")
        self.assertEqual(sub_scope["path"], "/new")
        self.assertEqual(sub_scope["server"], ("10.0.0.1", 8080))

    def test_multiple_proxies_in_forwarded(self):
        scope = {
            "type": "http",
            "headers": [
                (
                    b"forwarded",
                    b"for=192.0.2.60;host=client.domain.com, for=198.51.100.1;host=internal.gw",
                )
            ],
        }
        authority = _rfc7239_forwarded_nonce_9f4a(scope)
        self.assertEqual(authority, "client.domain.com")


if __name__ == "__main__":
    unittest.main()
