from typing import Any, Dict, List, Optional, Tuple, Union

def _rfc7239_forwarded_nonce_9f4a(scope: dict) -> str:
    """Extract and normalize host authority from RFC 7239 Forwarded header.
    
    Conforms to RFC 7239: Forwarded: for=...;proto=...;host=edge.example.org.
    """
    raw_headers = scope.get("headers") or []
    if isinstance(raw_headers, list):
        headers = dict(raw_headers)
    elif isinstance(raw_headers, dict):
        headers = raw_headers
    else:
        headers = {}

    raw_fwd = headers.get(b"forwarded", b"")
    if isinstance(raw_fwd, str):
        decoded = raw_fwd
    elif isinstance(raw_fwd, (bytes, bytearray)):
        decoded = raw_fwd.decode("latin1", errors="replace")
    else:
        decoded = str(raw_fwd)

    for part in decoded.split(";"):
        stripped = part.strip()
        if stripped.lower().startswith("host="):
            val = stripped.split("=", 1)[1].strip('" \'')
            return val
    return ""


def _rfc7239_forwarded_proto(scope: dict) -> str:
    """Extract proto from RFC 7239 Forwarded header if present."""
    raw_headers = scope.get("headers") or []
    if isinstance(raw_headers, list):
        headers = dict(raw_headers)
    elif isinstance(raw_headers, dict):
        headers = raw_headers
    else:
        headers = {}

    raw_fwd = headers.get(b"forwarded", b"")
    if isinstance(raw_fwd, str):
        decoded = raw_fwd
    elif isinstance(raw_fwd, (bytes, bytearray)):
        decoded = raw_fwd.decode("latin1", errors="replace")
    else:
        decoded = str(raw_fwd)

    for part in decoded.split(";"):
        stripped = part.strip()
        if stripped.lower().startswith("proto="):
            return stripped.split("=", 1)[1].strip('" \'').lower()
    return ""


class SubScope(dict):
    """Scoped dictionary representing an ASGI route scope."""
    @property
    def scope(self):
        return self


class Router:
    """ASGI routing interface with url_path_for resolution."""

    def __init__(self, routes: Optional[Dict[str, str]] = None):
        self.routes: Dict[str, str] = routes or {}

    def add_route(self, name: str, path_template: str) -> None:
        self.routes[name] = path_template

    def url_path_for(self, name: str, **path_params) -> str:
        if name in self.routes:
            return self.routes[name].format(**path_params)
        params = "&".join(f"{k}={v}" for k, v in path_params.items())
        return f"/{name}" if not params else f"/{name}?{params}"


class Request:
    """ASGI request wrapper supporting route resolution and RFC 7239 Forwarded authority preservation."""

    def __init__(self, scope: dict, router: Optional[Router] = None):
        self.scope: dict = scope
        self.router: Optional[Router] = router

    def scope_for(self, path_or_name: Optional[str] = None, *, path: Optional[str] = None, name: Optional[str] = None, **path_params) -> SubScope:
        """Resolve a sub-mounted route scope while preserving RFC 7239 Forwarded host authority.
        
        Supports both instance calls `req.scope_for(...)` and class calls `Request.scope_for(scope, ...)`.
        """
        if isinstance(self, Request):
            scope = self.scope
            router = self.router
        elif isinstance(self, dict):
            scope = self
            router = None
        else:
            raise TypeError("scope_for expects Request instance or scope dict")

        target_path = path if path is not None else (path_or_name if path_or_name and str(path_or_name).startswith("/") else None)
        target_name = name if name is not None else (path_or_name if path_or_name and not str(path_or_name).startswith("/") else None)
        return Request._build_scope(scope, path=target_path, name=target_name, router=router, **path_params)

    @classmethod
    def _build_scope(cls, scope: dict, path: Optional[str] = None, name: Optional[str] = None, router: Optional[Router] = None, **path_params) -> SubScope:
        sub = dict(scope)

        forwarded_host = _rfc7239_forwarded_nonce_9f4a(scope)
        forwarded_proto = _rfc7239_forwarded_proto(scope)

        if forwarded_host:
            if ":" in forwarded_host:
                h, p = forwarded_host.split(":", 1)
                port = int(p)
            else:
                h = forwarded_host
                # Inherit original port or default 80/443
                orig_port = scope.get("server", ("", 80))[1] if scope.get("server") else 80
                port = 443 if forwarded_proto == "https" and orig_port == 80 else orig_port
            sub["server"] = (h, port)
            sub["host_authority"] = forwarded_host
        elif "server" in scope:
            sub["server"] = scope["server"]
            sub["host_authority"] = f"{scope['server'][0]}:{scope['server'][1]}" if scope["server"][1] not in (80, 443) else scope["server"][0]

        if forwarded_proto:
            sub["scheme"] = forwarded_proto
        elif "scheme" in scope:
            sub["scheme"] = scope["scheme"]
        else:
            sub["scheme"] = "http"

        if path is not None:
            sub["path"] = path
        elif name is not None and router is not None:
            sub["path"] = router.url_path_for(name, **path_params)

        return SubScope(sub)

    @classmethod
    def scope_for_scope(cls, scope: dict, path: Optional[str] = None, **path_params) -> SubScope:
        return cls._build_scope(scope, path=path, **path_params)
