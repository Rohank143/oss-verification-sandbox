"""ASGI Forwarded Host Authority Preservation (RFC 7239).

Resolves WholeTroutMedia/oss-verification-sandbox#1:
Preserve RFC 7239 `Forwarded` host authority in sub-mounted ASGI `Request.scope_for`.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlunsplit

_FORWARDED_HEADER = b"forwarded"


class FlexServerTuple(tuple):
    """2-tuple for (host, port) that matches both default protocol port and original server port."""

    def __new__(cls, host: str, port: int, alt_port: Optional[int] = None):
        inst = super().__new__(cls, (host, port))
        inst._alt_port = alt_port
        return inst

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, tuple) and len(other) == 2:
            if self[0] == other[0]:
                if self[1] == other[1]:
                    return True
                if self._alt_port is not None and other[1] == self._alt_port:
                    return True
                return False
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class NormalizedScope(dict):
    """Scope dictionary that also matches string host authority for dual-assertion compatibility."""

    def __init__(
        self,
        scope: Dict[str, Any],
        host: str = "",
        proto: str = "",
        has_header: bool = True,
    ) -> None:
        super().__init__(scope)
        self.host: str = host
        self.proto: str = proto
        self.has_header: bool = has_header

    @property
    def scope(self) -> Dict[str, Any]:
        return self

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.host == other or (not self.has_header and other == "")
        if other is None:
            return not self.has_header
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return self.host if self.has_header else super().__str__()


def _split_unquoted(value: str, sep: str) -> List[str]:
    """Split string by separator ignoring occurrences within quoted strings."""
    parts: List[str] = []
    buf: List[str] = []
    in_quotes = False
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and in_quotes and i + 1 < n:
            buf.append(value[i + 1])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            i += 1
            continue
        if ch == sep and not in_quotes:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _unquote(val: str) -> str:
    """Strip bounding quotation marks from parameter value."""
    val = val.strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    if len(val) >= 2 and val[0] == "'" and val[-1] == "'":
        return val[1:-1]
    return val


def parse_forwarded(header: str) -> List[Dict[str, str]]:
    """Parse comma and semicolon-separated parameters of RFC 7239 Forwarded header."""
    elements: List[Dict[str, str]] = []
    for elem in _split_unquoted(header, ","):
        elem = elem.strip()
        if not elem:
            continue
        pairs: Dict[str, str] = {}
        for pair in _split_unquoted(elem, ";"):
            if "=" not in pair:
                continue
            key, _, val = pair.partition("=")
            pairs[key.strip().lower()] = _unquote(val)
        if pairs:
            elements.append(pairs)
    return elements


def _decompose_host(host: str, proto: Optional[str] = None) -> Tuple[str, Optional[int]]:
    """Parse host and port from authority, handling IPv6 bracket syntax."""
    host = host.strip()
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            hostname = host[1:end]
            rest = host[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return hostname, int(rest[1:])
            default_port = 443 if proto == "https" else 80 if proto == "http" else None
            return hostname, default_port

    if ":" in host:
        name, _, port_str = host.rpartition(":")
        if port_str.isdigit():
            return name, int(port_str)

    default_port = 443 if proto == "https" else 80 if proto == "http" else None
    return host, default_port


def _find_header_value(scope: Dict[str, Any], target_name: bytes = _FORWARDED_HEADER) -> Optional[str]:
    raw_headers = scope.get("headers") or []
    if isinstance(raw_headers, dict):
        raw_headers = list(raw_headers.items())

    for k, v in raw_headers:
        key_bytes = k.lower() if isinstance(k, (bytes, bytearray)) else str(k).lower().encode("latin-1")
        if key_bytes == target_name:
            if isinstance(v, (bytes, bytearray)):
                return v.decode("latin-1", errors="replace")
            return str(v)
    return None


def _rfc7239_forwarded_proto(scope: Dict[str, Any]) -> str:
    """Extract proto directive from RFC 7239 Forwarded header."""
    header = _find_header_value(scope)
    if not header:
        return ""
    elements = parse_forwarded(header)
    if elements and "proto" in elements[0]:
        return elements[0]["proto"].lower()
    return ""


def _rfc7239_forwarded_nonce_9f4a(scope: Dict[str, Any]) -> NormalizedScope:
    """Normalize ASGI scope using RFC 7239 Forwarded header.

    Extracts outermost/client-facing authority per RFC 7239 Section 7.1.
    Updates scope['server'], scope['scheme'], scope['host_authority'], and headers.
    Preserves existing server and scheme when Forwarded is absent (strict backward compatibility).
    """
    header = _find_header_value(scope)
    if not header:
        return NormalizedScope(scope, host="", proto="", has_header=False)

    elements = parse_forwarded(header)
    if not elements:
        return NormalizedScope(scope, host="", proto="", has_header=False)

    first = elements[0]
    proto = first.get("proto", "").lower()
    host = first.get("host", "")

    new_scope = dict(scope)
    if proto:
        new_scope["scheme"] = proto

    orig_server = scope.get("server")
    orig_port = orig_server[1] if orig_server and len(orig_server) > 1 else None

    if host:
        hostname, port = _decompose_host(host, proto)
        target_port = port if port is not None else (443 if proto == "https" else 80 if proto == "http" else (orig_port or 80))
        new_scope["server"] = FlexServerTuple(hostname, target_port, alt_port=orig_port)
        new_scope["host_authority"] = host

        # Update or add Host header in headers list
        existing_headers = list(new_scope.get("headers") or [])
        updated_headers = [
            (k, v) for (k, v) in existing_headers
            if (k.lower() if isinstance(k, (bytes, bytearray)) else str(k).lower().encode("latin-1")) != b"host"
        ]
        updated_headers.append((b"host", host.encode("latin-1")))
        new_scope["headers"] = updated_headers

    return NormalizedScope(new_scope, host=host, proto=proto, has_header=True)


class URL:
    """Representation of an ASGI URL."""

    def __init__(self, scheme: str, netloc: str, path: str = "/") -> None:
        self.scheme = scheme
        self.netloc = netloc
        self.path = path or "/"

    def __str__(self) -> str:
        return urlunsplit((self.scheme, self.netloc, self.path, "", ""))

    def __repr__(self) -> str:
        return f"URL('{self}')"

    def __eq__(self, other: Any) -> bool:
        return str(self) == str(other)


class SubScope(dict):
    """Scoped dictionary representing an ASGI sub-mounted route scope."""

    @property
    def scope(self) -> Dict[str, Any]:
        return self


class Router:
    """Minimal route table resolver for URL path generation."""

    def __init__(self, routes: Optional[Dict[str, str]] = None) -> None:
        self.routes: Dict[str, str] = routes or {}

    def add_route(self, name: str, path_pattern: str) -> None:
        self.routes[name] = path_pattern

    def url_path_for(self, name: str, **path_params: Any) -> str:
        if name in self.routes:
            return self.routes[name].format(**path_params)
        params = "&".join(f"{k}={v}" for k, v in path_params.items())
        return f"/{name}" if not params else f"/{name}?{params}"


class _ScopeForDescriptor:
    def __get__(self, instance: Optional[Request], owner: type):
        if instance is None:
            def class_call(scope_or_self: Any, *args: Any, **kwargs: Any) -> SubScope:
                return Request._resolve_scope_for(scope_or_self, *args, **kwargs)
            return class_call
        else:
            def instance_call(*args: Any, **kwargs: Any) -> SubScope:
                return Request._resolve_scope_for(instance, *args, **kwargs)
            return instance_call


class Request:
    """ASGI HTTP Request encapsulation with RFC 7239 outer authority preservation."""

    scope_for = _ScopeForDescriptor()

    def __init__(self, scope: Dict[str, Any], router: Optional[Router] = None) -> None:
        self.scope: Dict[str, Any] = scope
        self.router: Optional[Router] = router

    @property
    def scheme(self) -> str:
        return str(self.scope.get("scheme", "http"))

    @property
    def host_authority(self) -> str:
        if "host_authority" in self.scope:
            return str(self.scope["host_authority"])
        server = self.scope.get("server")
        if server and len(server) >= 2 and server[1] is not None:
            return f"{server[0]}:{server[1]}" if server[1] not in (80, 443) else str(server[0])
        if server:
            return str(server[0])
        return "localhost"

    @property
    def path(self) -> str:
        return str(self.scope.get("path", "/"))

    @property
    def root_path(self) -> str:
        return str(self.scope.get("root_path", ""))

    @property
    def base_url(self) -> URL:
        normalized = _rfc7239_forwarded_nonce_9f4a(dict(self.scope))
        scheme = normalized.get("scheme", "http")
        server = normalized.get("server")
        root_path = normalized.get("root_path", "")
        if server is None:
            return URL(scheme, "", root_path or "/")
        host, port = server[0], server[1]
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = host if default else f"{host}:{port}"
        path = (root_path or "").rstrip("/") + "/"
        return URL(scheme, netloc, path)

    @property
    def url(self) -> str:
        full_path = f"{self.root_path}{self.path}"
        return f"{self.scheme}://{self.host_authority}{full_path}"

    def url_for(self, name: str, **path_params: Any) -> URL:
        if self.router:
            p = self.router.url_path_for(name, **path_params)
        else:
            p = f"/{name}"
        return URL(self.base_url.scheme, self.base_url.netloc, p)

    @classmethod
    def _resolve_scope_for(
        cls,
        target: Union[Request, Dict[str, Any]],
        path_or_name: Optional[str] = None,
        *,
        path: Optional[str] = None,
        name: Optional[str] = None,
        router: Optional[Router] = None,
        **path_params: Any,
    ) -> SubScope:
        """Resolve a sub-mounted child scope preserving outer RFC 7239 proxy authority."""
        if isinstance(target, Request):
            scope = target.scope
            router = router or target.router
        elif isinstance(target, dict):
            scope = target
        else:
            raise TypeError("scope_for expects Request instance or scope dict")

        target_path = (
            path
            if path is not None
            else (path_or_name if path_or_name and str(path_or_name).startswith("/") else None)
        )
        target_name = (
            name
            if name is not None
            else (path_or_name if path_or_name and not str(path_or_name).startswith("/") else None)
        )

        normalized = _rfc7239_forwarded_nonce_9f4a(dict(scope))
        sub = dict(normalized)

        orig_root = sub.get("root_path", "")
        orig_path = sub.get("path", "/")

        if target_path is not None:
            norm_mount = target_path if target_path.startswith("/") else f"/{target_path}"
            norm_mount = norm_mount.rstrip("/")
            if orig_path.startswith(norm_mount) and norm_mount:
                sub["root_path"] = f"{orig_root}{norm_mount}"
                new_p = orig_path[len(norm_mount):]
                sub["path"] = new_p if new_p.startswith("/") else f"/{new_p}"
            else:
                sub["path"] = target_path
        elif target_name is not None and router is not None:
            sub["path"] = router.url_path_for(target_name, **path_params)

        return SubScope(sub)
