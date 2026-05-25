"""
HTTP/2 Browser Fingerprint Impersonation Module

Provides accurate HTTP/2 fingerprint impersonation for:
- Chrome 126+ (no PRIORITY frames, specific SETTINGS order)
- Firefox 130+ (PRIORITY frames on streams 3,5,7,9,11)

Integrates with tls_fingerprint.py for combined TLS + HTTP/2 impersonation.

Uses hyperframe v6.1.0 for low-level frame construction and h2 v4.3.0
for the protocol state machine.

Each browser profile defines:
  - SETTINGS frame order and values
  - Connection WINDOW_UPDATE size
  - PRIORITY frame patterns (if any)
  - User-Agent strings
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from hyperframe.frame import (
    HeadersFrame,
    PriorityFrame,
    SettingsFrame,
    WindowUpdateFrame,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HTTP2_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Settings identifiers (mirrors hyperframe.frame.SettingsFrame constants)
HEADER_TABLE_SIZE = 1
ENABLE_PUSH = 2
MAX_CONCURRENT_STREAMS = 3
INITIAL_WINDOW_SIZE = 4
MAX_FRAME_SIZE = 5
MAX_HEADER_LIST_SIZE = 6
ENABLE_CONNECT_PROTOCOL = 8

# ---------------------------------------------------------------------------
# Browser fingerprint definitions
# ---------------------------------------------------------------------------

BROWSER_HTTP2_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "chrome126": {
        "settings": {
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            MAX_CONCURRENT_STREAMS: 1000,
            INITIAL_WINDOW_SIZE: 6291456,
            MAX_HEADER_LIST_SIZE: 26280,
            MAX_FRAME_SIZE: 16384,
        },
        "settings_order": [
            HEADER_TABLE_SIZE,
            ENABLE_PUSH,
            MAX_CONCURRENT_STREAMS,
            INITIAL_WINDOW_SIZE,
            MAX_HEADER_LIST_SIZE,
            MAX_FRAME_SIZE,
        ],
        "connection_window_update": 15663105,
        "priority_frames": [],
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
    },
    "firefox130": {
        "settings": {
            HEADER_TABLE_SIZE: 65536,
            MAX_CONCURRENT_STREAMS: 100,
            INITIAL_WINDOW_SIZE: 131072,
            ENABLE_PUSH: 0,
            MAX_HEADER_LIST_SIZE: 26280,
        },
        "settings_order": [
            HEADER_TABLE_SIZE,
            MAX_CONCURRENT_STREAMS,
            INITIAL_WINDOW_SIZE,
            ENABLE_PUSH,
            MAX_HEADER_LIST_SIZE,
        ],
        "connection_window_update": 12517377,
        "priority_frames": [
            {"stream_id": 3, "depends_on": 0, "weight": 201, "exclusive": False},
            {"stream_id": 5, "depends_on": 0, "weight": 101, "exclusive": False},
            {"stream_id": 7, "depends_on": 0, "weight": 1, "exclusive": False},
            {"stream_id": 9, "depends_on": 0, "weight": 1, "exclusive": False},
            {"stream_id": 11, "depends_on": 0, "weight": 1, "exclusive": False},
        ],
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
            "Gecko/20100101 Firefox/130.0"
        ),
    },
}

PROFILES = list(BROWSER_HTTP2_FINGERPRINTS.keys())


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_browser_settings(profile_name: str) -> Dict[str, Any]:
    """
    Return the full fingerprint definition dict for *profile_name*.

    Raises ``KeyError`` when the profile is unknown.
    """
    if profile_name not in BROWSER_HTTP2_FINGERPRINTS:
        msg = f"Unknown browser profile: {profile_name!r}. Available: {PROFILES}"
        raise KeyError(msg)
    return BROWSER_HTTP2_FINGERPRINTS[profile_name]


def create_raw_settings_frame(profile_name: str) -> bytes:
    """
    Build a raw ``SettingsFrame`` byte-string using the exact setting
    order defined by the browser profile.

    Uses ``hyperframe`` for serialisation so the wire format is correct.
    """
    profile = get_browser_settings(profile_name)
    sf = SettingsFrame(stream_id=0)
    for key in profile["settings_order"]:
        sf.settings[key] = profile["settings"][key]
    return sf.serialize()


def create_connection_preface(profile_name: str) -> bytes:
    """
    Return the complete HTTP/2 connection preface bytes for *profile_name*:

        HTTP/2 Magic (24 bytes) + SETTINGS frame (profile-specific)
    """
    return HTTP2_MAGIC + create_raw_settings_frame(profile_name)


def get_random_profile() -> str:
    """Return a random browser profile name from the available fingerprints."""
    return random.choice(PROFILES)


# ---------------------------------------------------------------------------
# H2ConnectionManager
# ---------------------------------------------------------------------------


class H2ConnectionManager:
    """
    Creates and manages HTTP/2 connections that mimic a specific browser's
    wire-level fingerprint.

    The manager owns an ``h2.connection.H2Connection`` state machine and
    provides helpers to apply the browser-specific frames (SETTINGS,
    WINDOW_UPDATE, PRIORITY) before sending requests.

    Typical usage::

        mgr = H2ConnectionManager("chrome126")
        mgr.initiate(sock)
        mgr.send_request(sock, "example.com", "/", {...headers...})
    """

    def __init__(self, profile_name: str = "chrome126") -> None:
        if profile_name not in BROWSER_HTTP2_FINGERPRINTS:
            msg = f"Unknown browser profile: {profile_name!r}. Available: {PROFILES}"
            raise ValueError(msg)

        self.profile_name = profile_name
        self.profile = BROWSER_HTTP2_FINGERPRINTS[profile_name]
        self.connection: Optional["H2Connection"] = None  # noqa: F821
        self._init_connection()

    def _init_connection(self) -> None:
        """Create the internal ``h2`` connection object."""
        from h2.config import H2Configuration
        from h2.connection import H2Connection

        config = H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            validate_outbound_headers=False,
        )
        self.connection = H2Connection(config)

    def initiate(self, sock: Any) -> None:
        """
        Send the HTTP/2 connection preface, SETTINGS, WINDOW_UPDATE, and
        optional PRIORITY frames over *sock*.

        *sock* must be a connected, TLS-wrapped socket with ``h2`` ALPN
        already negotiated.
        """
        if self.connection is None:
            self._init_connection()

        self.connection.initiate_connection()
        sock.sendall(self.connection.data_to_send())

        # Replace the default SETTINGS with browser-specific ones
        # We send raw frames via hyperframe for exact ordering.
        sock.sendall(create_raw_settings_frame(self.profile_name))

        # Connection-level WINDOW_UPDATE
        wu = WindowUpdateFrame(
            stream_id=0,
            window_increment=self.profile["connection_window_update"],
        )
        sock.sendall(wu.serialize())

        # PRIORITY frames (if any)
        for pri in self.profile["priority_frames"]:
            pf = PriorityFrame(
                stream_id=pri["stream_id"],
                depends_on=pri["depends_on"],
                stream_weight=pri["weight"],
                exclusive=pri["exclusive"],
            )
            sock.sendall(pf.serialize())

        logger.info(
            "HTTP/2 preface sent for %s (window_update=%d, %d priority frames)",
            self.profile_name,
            self.profile["connection_window_update"],
            len(self.profile["priority_frames"]),
        )

    def send_request(
        self,
        sock: Any,
        host: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        end_stream: bool = True,
    ) -> None:
        """
        Send a HTTP/2 HEADERS frame (with END_STREAM) to initiate a request.

        Parameters
        ----------
        sock : socket
            Connected TLS socket.
        host : str
            The ``:authority`` pseudo-header value.
        path : str
            The ``:path`` pseudo-header value.
        headers : dict, optional
            Additional HTTP headers.
        end_stream : bool
            Whether to set END_STREAM (default ``True``).
        """
        if self.connection is None:
            msg = "Connection not initialised. Call initiate() first."
            raise RuntimeError(msg)

        pseudo = [
            (":method", "GET"),
            (":path", path),
            (":authority", host),
            (":scheme", "https"),
        ]
        extra = list((k, v) for k, v in (headers or {}).items())
        req_headers = pseudo + extra

        stream_id = self.connection.get_next_available_stream_id()
        self.connection.send_headers(
            stream_id=stream_id,
            headers=req_headers,
            end_stream=end_stream,
        )
        sock.sendall(self.connection.data_to_send())
        logger.debug(
            "Sent HEADERS on stream %d for %s%s", stream_id, host, path
        )

    def close(self, sock: Any) -> None:
        """Gracefully close the HTTP/2 connection."""
        if self.connection is not None:
            self.connection.close_connection()
            sock.sendall(self.connection.data_to_send())

    @property
    def user_agent(self) -> str:
        """The User-Agent string for the selected browser profile."""
        return self.profile["user_agent"]

    @property
    def settings(self) -> Dict[int, int]:
        """The SETTINGS dictionary for the selected browser profile."""
        return dict(self.profile["settings"])


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def create_h2_connection(
    profile_name: str,
    sock: Any,
) -> H2ConnectionManager:
    """
    Convenience factory: create an ``H2ConnectionManager`` for *profile_name*
    and immediately call ``initiate(sock)``.

    Returns the manager instance.
    """
    mgr = H2ConnectionManager(profile_name)
    mgr.initiate(sock)
    return mgr


def build_http2_request(
    host: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    profile_name: str = "chrome126",
) -> bytes:
    """
    Build a complete HTTP/2 request byte-string that can be written directly
    to a connected TLS socket.

    The returned bytes contain:

    - Connection preface (magic + SETTINGS)
    - WINDOW_UPDATE frame (browser-specific)
    - PRIORITY frames (when the profile defines them)
    - HEADERS frame with END_STREAM (pseudo-headers + extra headers)

    This is a *stateless* builder – it does **not** use the ``h2`` state
    machine and is suitable for one-shot / raw-frame scenarios.

    Parameters
    ----------
    host : str
        The ``:authority`` value.
    path : str
        The ``:path`` value.
    headers : dict, optional
        Extra HTTP headers.
    profile_name : str
        Browser profile key (default ``"chrome126"``).

    Returns
    -------
    bytes
        Complete HTTP/2 request suitable for ``sock.sendall()``.
    """
    profile = get_browser_settings(profile_name)

    chunks: List[bytes] = []

    # 1. Connection preface (magic + SETTINGS)
    chunks.append(create_connection_preface(profile_name))

    # 2. WINDOW_UPDATE frame
    wu = WindowUpdateFrame(
        stream_id=0,
        window_increment=profile["connection_window_update"],
    )
    chunks.append(wu.serialize())

    # 3. PRIORITY frames
    for pri in profile["priority_frames"]:
        pf = PriorityFrame(
            stream_id=pri["stream_id"],
            depends_on=pri["depends_on"],
            stream_weight=pri["weight"],
            exclusive=pri["exclusive"],
        )
        chunks.append(pf.serialize())

    # 4. HEADERS frame (END_STREAM set)
    pseudo_headers: List[Tuple[str, str]] = [
        (":method", "GET"),
        (":path", path),
        (":authority", host),
        (":scheme", "https"),
    ]

    extra_headers = list((k, v) for k, v in (headers or {}).items())
    serialized_headers = b"".join(
        _hpack_encode(k, v)
        for k, v in pseudo_headers + extra_headers
    )

    hf = HeadersFrame(stream_id=1, data=serialized_headers)
    hf.flags.add("END_STREAM")
    chunks.append(hf.serialize())

    result = b"".join(chunks)
    logger.debug(
        "Built HTTP/2 request (%d bytes) for %s profile: %s%s",
        len(result),
        profile_name,
        host,
        path,
    )
    return result


# ---------------------------------------------------------------------------
# HPACK helpers  (minimal static-table encoder for common headers)
# ---------------------------------------------------------------------------

_HPACK_STATIC_TABLE: Dict[str, Tuple[int, str]] = {
    ":authority": (1, ""),
    ":method": (2, "GET"),
    ":path": (4, "/"),
    ":scheme": (6, "https"),
    ":status": (8, "200"),
    "accept": (17, ""),
    "accept-encoding": (18, ""),
    "accept-language": (19, ""),
    "cache-control": (24, ""),
    "content-length": (28, ""),
    "content-type": (31, ""),
    "cookie": (32, ""),
    "user-agent": (58, ""),
    "referer": (41, ""),
}

# HPACK integer prefix helpers
_INT_PREFIX_5 = 0x1F
_INT_PREFIX_6 = 0x3F
_INT_PREFIX_7 = 0x7F


def _encode_integer(value: int, prefix: int) -> bytes:
    """HPACK integer encoding (RFC 7541 §5.1)."""
    mask = (1 << prefix) - 1
    if value < mask:
        return bytes([value])
    result = bytearray([mask])
    value -= mask
    while value >= 128:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _encode_hpack_string(s: str) -> bytes:
    """HPACK string literal (Huffman-coded for lowercase ascii; else raw)."""
    data = s.encode("utf-8")

    # Simple heuristic: use Huffman when the string looks like typical
    # ASCII HTTP header values; otherwise send raw.
    use_huffman = all(
        32 <= b < 127 for b in data
    ) and len(data) > 0

    if use_huffman:
        encoded = _huffman_encode(data)
        length_prefix = _encode_integer(len(encoded), 7)
        return bytes([0x80 | length_prefix[0]]) + (
            length_prefix[1:] if len(length_prefix) > 1 else b""
        ) + encoded
    else:
        length_prefix = _encode_integer(len(data), 7)
        return bytes([0x00 | length_prefix[0]]) + (
            length_prefix[1:] if len(length_prefix) > 1 else b""
        ) + data


def _hpack_encode(name: str, value: str) -> bytes:
    """
    Encode a single HTTP header using HPACK (RFC 7541).

    Uses static table indexing when possible, otherwise literal + indexing.
    """
    table_entry = _HPACK_STATIC_TABLE.get(name)
    if table_entry is not None:
        idx, _ = table_entry
        # Indexed header field
        return _encode_integer(idx, 7)

    # Literal header field with incremental indexing (name from static table)
    idx = _find_static_table_index(name)
    if idx is not None:
        prefix = _encode_integer(idx, 6)
        return bytes([0x40 | prefix[0]]) + (
            prefix[1:] if len(prefix) > 1 else b""
        ) + _encode_hpack_string(value)

    # Literal header field with incremental indexing (new name)
    name_enc = _encode_hpack_string(name)
    value_enc = _encode_hpack_string(value)

    prefix_byte = 0x40
    result = bytearray([prefix_byte])
    result.extend(name_enc)
    result.extend(value_enc)
    return bytes(result)


def _find_static_table_index(name: str) -> Optional[int]:
    """Return the HPACK static-table index for *name*, or ``None``."""
    entry = _HPACK_STATIC_TABLE.get(name)
    if entry is not None:
        return entry[0]
    return None


# ---------------------------------------------------------------------------
# Minimal Huffman encoder (HPACK static table subset)
# ---------------------------------------------------------------------------

_HPACK_HUFFMAN_TABLE: Dict[int, Tuple[int, int]] = {
    32: (0x00000000, 6),     # ' '
    101: (0x0000002C, 6),    # 'e'
    116: (0x0000005C, 7),    # 't'
    105: (0x00000070, 7),    # 'i'
    97: (0x0000002E, 6),     # 'a'
    111: (0x0000007E, 7),    # 'o'
    110: (0x0000006E, 7),    # 'n'
    115: (0x0000003C, 6),    # 's'
    114: (0x00000018, 6),    # 'r'
    108: (0x00000048, 7),    # 'l'
    99: (0x00000058, 7),     # 'c'
    100: (0x0000004E, 7),    # 'd'
    104: (0x0000000C, 6),    # 'h'
    109: (0x00000038, 6),    # 'm'
    112: (0x00000000, 5),    # 'p'
    103: (0x00000078, 7),    # 'g'
    117: (0x00000060, 7),    # 'u'
    98: (0x00000072, 7),     # 'b'
    102: (0x00000044, 7),    # 'f'
    121: (0x00000010, 6),    # 'y'
    107: (0x0000007A, 7),    # 'k'
    119: (0x00000056, 7),    # 'w'
    118: (0x00000064, 7),    # 'v'
    120: (0x00000076, 7),    # 'x'
    122: (0x00000014, 6),    # 'z'
    106: (0x0000006A, 7),    # 'j'
    113: (0x0000005A, 7),    # 'q'
    47: (0x00000024, 6),     # '/'
    45: (0x00000042, 7),     # '-'
    46: (0x00000066, 7),     # '.'
    58: (0x00000068, 7),     # ':'
    95: (0x00000040, 7),     # '_'
    48: (0x00000050, 7),     # '0'
    49: (0x00000052, 7),     # '1'
    50: (0x00000054, 7),     # '2'
    51: (0x00000046, 7),     # '3'
    52: (0x0000004C, 7),     # '4'
    53: (0x0000003A, 7),     # '5'
    54: (0x00000074, 7),     # '6'
    55: (0x00000062, 7),     # '7'
    56: (0x0000006C, 7),     # '8'
    57: (0x0000005E, 7),     # '9'
    59: (0x0000005E, 6),     # ';'
    44: (0x00000034, 6),     # ','
    61: (0x00000034, 5),     # '='
    34: (0x0000001E, 5),     # '"'
    38: (0x00000020, 6),     # '&'
    43: (0x00000034, 7),     # '+'
    33: (0x00000030, 6),     # '!'
    35: (0x0000003E, 6),     # '#'
    36: (0x00000042, 6),     # '$'
    37: (0x00000040, 6),     # '%'
    39: (0x00000038, 7),     # "'"
    40: (0x0000003A, 6),     # '('
    41: (0x0000003C, 6),     # ')'
    42: (0x0000003E, 7),     # '*'
    64: (0x0000000A, 5),     # '@'
}


def _huffman_encode(data: bytes) -> bytes:
    """
    Minimal Huffman encoder for HPACK (RFC 7541 §5.2).

    Only covers the ASCII-range characters that commonly appear in
    HTTP header values. Characters outside the table are sent as-is
    via an escape mechanism.
    """
    if not data:
        return b""

    bits: int = 0
    nbits: int = 0
    output = bytearray()

    for byte in data:
        if byte in _HPACK_HUFFMAN_TABLE:
            code, ncode = _HPACK_HUFFMAN_TABLE[byte]
        else:
            # Fallback: encode as literal 7-bit ASCII with EOS padding
            code = byte
            ncode = 8

        bits = (bits << ncode) | code
        nbits += ncode

        while nbits >= 8:
            nbits -= 8
            output.append((bits >> nbits) & 0xFF)

    if nbits:
        # Pad with 1s up to the next byte boundary
        bits = (bits << (8 - nbits)) | ((1 << (8 - nbits)) - 1)
        output.append(bits & 0xFF)

    return bytes(output)


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    "BROWSER_HTTP2_FINGERPRINTS",
    "PROFILES",
    "H2ConnectionManager",
    "create_h2_connection",
    "get_browser_settings",
    "create_raw_settings_frame",
    "create_connection_preface",
    "get_random_profile",
    "build_http2_request",
]
