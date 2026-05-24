"""
Universal proxy parser - supports all common proxy formats:

  http://1.2.3.4:80
  https://user:pass@1.2.3.4:443
  socks5://1.2.3.4:1080
  socks5://user:pass@1.2.3.4:1080
  socks4://1.2.3.4:4145
  1.2.3.4:80                            (no scheme = http)
  1.2.3.4:8080:user:pass                (IP:PORT:USER:PASS = http with auth)
  user:pass@1.2.3.4:8080
  socks5://1.2.3.4:1080:user:pass
  http://user:pass:1.2.3.4:8080         (scheme://USER:PASS:IP:PORT)
"""
import re
from typing import Optional, Tuple


def parse_proxy(raw: str) -> Optional[str]:
    """
    Parse any proxy format and return canonical URL: scheme://user:pass@host:port
    Returns None if not parseable.
    """
    if not raw:
        return None

    s = raw.strip().strip('"').strip("'")
    if not s or s.startswith("#"):
        return None

    # Detect explicit scheme
    scheme_match = re.match(r'^(https?|socks[45]h?)://', s, re.IGNORECASE)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        rest = s[scheme_match.end():]
    else:
        scheme = "http"
        rest = s

    # Normalize socks5h -> socks5
    if scheme == "socks5h":
        scheme = "socks5"

    user = pwd = None
    host = port = None

    # Try @ separator first: user:pass@host:port
    if "@" in rest:
        auth, hp = rest.rsplit("@", 1)
        if ":" in auth:
            user, pwd = auth.split(":", 1)
        else:
            user = auth
        rest = hp

    # Now `rest` should be host:port or host:port:user:pass or user:pass:host:port
    parts = rest.split(":")

    if len(parts) == 2:
        # host:port
        host, port = parts
    elif len(parts) == 4:
        # 4 parts - heuristic: IP:PORT:USER:PASS or USER:PASS:IP:PORT
        # If first part looks like IP (contains dots), assume IP:PORT:USER:PASS
        if "." in parts[0] and parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            host, port, user, pwd = parts
        elif "." in parts[2] and parts[3].isdigit() and 1 <= int(parts[3]) <= 65535:
            user, pwd, host, port = parts
        else:
            # Default to IP:PORT:USER:PASS
            host, port, user, pwd = parts
    elif len(parts) == 3:
        # ambiguous - could be user:pass@host:port that lost @ or just garbled
        # try host:port:user (no pass) or user:pass:host (no port)
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            host, port = parts[0], parts[1]
        else:
            return None
    else:
        return None

    if not host or not port:
        return None

    # Validate port
    try:
        p = int(port)
        if p < 1 or p > 65535:
            return None
    except ValueError:
        return None

    # Build canonical URL
    if user is not None:
        # URL-encode user/pass for special chars
        from urllib.parse import quote
        user_q = quote(user, safe="")
        pwd_q = quote(pwd or "", safe="")
        return f"{scheme}://{user_q}:{pwd_q}@{host}:{p}"
    else:
        return f"{scheme}://{host}:{p}"


def parse_proxy_lines(text: str) -> list:
    """Parse multiple proxies from text (one per line)"""
    out = []
    seen = set()
    for line in text.splitlines():
        url = parse_proxy(line)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def split_url_components(proxy_url: str) -> Tuple[str, str, str, int, str, str]:
    """
    Split a parsed proxy URL into components.
    Returns (scheme, user, pwd, port, host, port_str) or empty values.
    """
    from urllib.parse import urlparse, unquote
    p = urlparse(proxy_url)
    user = unquote(p.username) if p.username else ""
    pwd = unquote(p.password) if p.password else ""
    return (
        p.scheme or "http",
        user,
        pwd,
        p.hostname or "",
        p.port or 1080,
    )
