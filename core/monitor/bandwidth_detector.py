"""
Client-side bandwidth & resource detector
Prevents self-DoS by throttling based on user's actual capacity
"""
import asyncio
import time
import socket
import logging
from typing import Dict

logger = logging.getLogger("bandwidth_detector")


class BandwidthDetector:
    """Detect upload/download speed and recommend safe attack settings"""

    def __init__(self):
        self.upload_mbps = 0.0
        self.download_mbps = 0.0
        self.latency_ms = 0.0
        self.recommended = {}

    async def detect(self) -> Dict:
        """Quick bandwidth probe (2-3 seconds)"""
        # Latency probe
        await self._probe_latency()
        # Upload probe (HEAD requests are cheap)
        await self._probe_upload()
        # Compute recommendations
        self._compute_recommendations()
        return {
            "upload_mbps": self.upload_mbps,
            "download_mbps": self.download_mbps,
            "latency_ms": self.latency_ms,
            "recommended": self.recommended,
        }

    async def _probe_latency(self):
        """Measure latency to a fast public endpoint"""
        try:
            start = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("1.1.1.1", 443),
                timeout=3,
            )
            elapsed = (time.monotonic() - start) * 1000
            self.latency_ms = elapsed
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            self.latency_ms = 999

    async def _probe_upload(self):
        """Estimate upload bandwidth via concurrent TCP connect + small POST"""
        try:
            # Open 10 parallel connections to measure raw socket capacity
            start = time.monotonic()

            async def open_close():
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("1.1.1.1", 443),
                        timeout=2,
                    )
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return True
                except Exception:
                    return False

            results = await asyncio.gather(*[open_close() for _ in range(20)],
                                            return_exceptions=True)
            elapsed = time.monotonic() - start
            successful = sum(1 for r in results if r is True)

            # Crude estimate: if can do 20 connects in <2s, decent connection
            # If <10s, slow connection
            if elapsed < 2 and successful >= 18:
                self.upload_mbps = 50.0  # likely fiber/cable
            elif elapsed < 5 and successful >= 15:
                self.upload_mbps = 10.0  # decent broadband
            elif elapsed < 10:
                self.upload_mbps = 2.0  # slow/mobile
            else:
                self.upload_mbps = 0.5  # very slow/congested
        except Exception:
            self.upload_mbps = 1.0

    def _compute_recommendations(self):
        """Compute safe attack settings based on detected bandwidth"""
        if self.upload_mbps >= 50:
            # Fast connection - can handle aggressive
            self.recommended = {
                "tier": "FAST",
                "max_concurrent": 2000,
                "max_rps": 5000,
                "allow_post_bomb": True,
                "allow_conn_flood": True,
                "allow_ws_storm": True,
                "max_threads_per_vec": 200,
                "warning": None,
            }
        elif self.upload_mbps >= 10:
            self.recommended = {
                "tier": "MEDIUM",
                "max_concurrent": 500,
                "max_rps": 1500,
                "allow_post_bomb": False,
                "allow_conn_flood": True,
                "allow_ws_storm": True,
                "max_threads_per_vec": 100,
                "warning": "POST Body Bomb disabled (saves upload bandwidth)",
            }
        elif self.upload_mbps >= 2:
            self.recommended = {
                "tier": "SLOW",
                "max_concurrent": 200,
                "max_rps": 500,
                "allow_post_bomb": False,
                "allow_conn_flood": False,
                "allow_ws_storm": False,
                "max_threads_per_vec": 50,
                "warning": "Resource-heavy vectors disabled (slow connection detected)",
            }
        else:
            self.recommended = {
                "tier": "VERY_SLOW",
                "max_concurrent": 50,
                "max_rps": 100,
                "allow_post_bomb": False,
                "allow_conn_flood": False,
                "allow_ws_storm": False,
                "max_threads_per_vec": 20,
                "warning": "Very slow connection - recommend running from VPS instead",
            }


async def detect_bandwidth() -> Dict:
    """One-shot bandwidth detection"""
    detector = BandwidthDetector()
    return await detector.detect()
