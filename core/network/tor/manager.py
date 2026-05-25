"""
Tor Manager v1.0
Auto-install, multi-instance, circuit rotation, health monitoring
Cross-platform: Windows, Linux, macOS
"""
import os
import sys
import time
import logging
import subprocess
import platform
import shutil
import asyncio
import requests
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("tor_manager")

# Tor configuration
TOR_BASE_SOCKS_PORT = 9250
TOR_BASE_CONTROL_PORT = 9251
TOR_HTTP_TUNNEL_PORT = 9280
DEFAULT_INSTANCES = 5
TOR_DATA_DIR = Path("data/tor")
TOR_CONFIG_DIR = Path("config/tor")
TOR_LOG_DIR = Path("logs/tor")

# Tor download URLs (2026 latest)
TOR_URLS = {
    "windows": [
        "https://downloads.sourceforge.net/project/tor-browser.mirror/15.0.14/tor-expert-bundle-windows-x86_64-15.0.14.tar.gz",
        "https://dist.torproject.org/torbrowser/15.0.14/tor-expert-bundle-windows-x86_64-15.0.14.tar.gz",
    ],
    "linux": None,  # Use apt/yum
    "darwin": None,  # Use brew
}


@dataclass
class TorInstance:
    """Single Tor instance configuration."""
    instance_id: int
    socks_port: int
    control_port: int
    data_dir: Path
    config_file: Path
    pid: Optional[int] = None
    is_healthy: bool = False
    exit_ip: str = ""
    last_rotation: float = 0.0


class TorManager:
    """Manage multiple Tor instances with auto-install and rotation."""
    
    def __init__(self, instances: int = DEFAULT_INSTANCES):
        self.instances: List[TorInstance] = []
        self.num_instances = instances
        self.current_instance_idx = 0
        self._setup_directories()
        self._detect_os()
    
    def _setup_directories(self):
        """Create necessary directories."""
        TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
        TOR_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        TOR_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    def _detect_os(self):
        """Detect operating system."""
        self.os_type = platform.system().lower()
        if self.os_type == "windows":
            self.tor_binary = "tor.exe"
        else:
            self.tor_binary = "tor"
        
        logger.info(f"Detected OS: {self.os_type}")
    
    def is_tor_installed(self) -> bool:
        """Check if Tor is installed."""
        # Check in PATH
        if shutil.which(self.tor_binary):
            return True
        
        # Check in local bin/
        local_tor = Path("bin") / self.tor_binary
        if local_tor.exists():
            return True
        
        return False
    
    def install_tor(self) -> bool:
        """Auto-install Tor based on OS."""
        logger.info(f"Installing Tor for {self.os_type}...")
        
        try:
            if self.os_type == "windows":
                return self._install_tor_windows()
            elif self.os_type == "linux":
                return self._install_tor_linux()
            elif self.os_type == "darwin":
                return self._install_tor_macos()
            else:
                logger.error(f"Unsupported OS: {self.os_type}")
                return False
        except Exception as e:
            logger.error(f"Tor installation failed: {e}")
            return False
    
    def _install_tor_windows(self) -> bool:
        """Install Tor on Windows."""
        import tarfile
        
        tar_path = Path("bin/tor-bundle.tar.gz")
        tar_path.parent.mkdir(exist_ok=True)
        
        # Try each URL in order
        urls = TOR_URLS["windows"]
        downloaded = False
        
        for url in urls:
            try:
                logger.info(f"Downloading Tor from {url.split('/')[2]}...")
                resp = requests.get(url, timeout=300, stream=True)
                resp.raise_for_status()
                
                with open(tar_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                downloaded = True
                break
            except Exception as e:
                logger.warning(f"Download from {url.split('/')[2]} failed: {e}")
                continue
        
        if not downloaded:
            logger.error("All download URLs failed")
            return False
        
        try:
            logger.info("Extracting Tor bundle...")
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(path="bin/")
            
            # Clean up tar
            tar_path.unlink(missing_ok=True)
            
            # Find tor.exe
            tor_exe = None
            for root, dirs, files in os.walk("bin/"):
                if "tor.exe" in files:
                    tor_exe = Path(root) / "tor.exe"
                    break
            
            if tor_exe and tor_exe.exists():
                dest = Path("bin/tor.exe")
                if dest.exists():
                    dest.unlink()
                shutil.move(str(tor_exe), "bin/tor.exe")
                logger.info("Tor installed successfully: bin/tor.exe")
                return True
            else:
                logger.error("tor.exe not found in bundle")
                return False
        except Exception as e:
            logger.error(f"Tor extraction failed: {e}")
            return False
    
    def _install_tor_linux(self) -> bool:
        """Install Tor on Linux."""
        try:
            logger.info("Installing Tor via apt...")
            subprocess.run(
                ["sudo", "apt", "update"],
                check=True,
                capture_output=True
            )
            subprocess.run(
                ["sudo", "apt", "install", "-y", "tor", "tor-geoipdb"],
                check=True,
                capture_output=True
            )
            logger.info("Tor installed successfully via apt")
            return True
        except subprocess.CalledProcessError:
            # Try yum
            try:
                logger.info("Trying yum...")
                subprocess.run(
                    ["sudo", "yum", "install", "-y", "tor"],
                    check=True,
                    capture_output=True
                )
                logger.info("Tor installed successfully via yum")
                return True
            except Exception as e:
                logger.error(f"Linux Tor install failed: {e}")
                return False
    
    def _install_tor_macos(self) -> bool:
        """Install Tor on macOS."""
        try:
            logger.info("Installing Tor via Homebrew...")
            subprocess.run(
                ["brew", "install", "tor"],
                check=True,
                capture_output=True
            )
            logger.info("Tor installed successfully via brew")
            return True
        except Exception as e:
            logger.error(f"macOS Tor install failed: {e}")
            return False
    
    def _get_tor_binary_path(self) -> str:
        """Get full path to Tor binary."""
        # Check local bin/
        local_tor = Path("bin") / self.tor_binary
        if local_tor.exists():
            return str(local_tor.absolute())
        
        # Check PATH
        tor_path = shutil.which(self.tor_binary)
        if tor_path:
            return tor_path
        
        raise FileNotFoundError(f"Tor binary not found: {self.tor_binary}")
    
    def create_instance_config(self, instance: TorInstance) -> str:
        """Create torrc config for instance."""
        config_content = f"""# Tor Instance {instance.instance_id}
SocksPort {instance.socks_port}
ControlPort {instance.control_port}
DataDirectory {instance.data_dir.absolute()}
CookieAuthentication 1

# Circuit rotation tuning
NewCircuitPeriod 30
MaxCircuitDirtiness 60

# Performance tuning
MaxClientCircuitsPending 64
UseEntryGuards 1
NumEntryGuards 8

# Logging
Log notice file {TOR_LOG_DIR / f'tor{instance.instance_id}.log'}
"""
        
        instance.config_file.write_text(config_content)
        return str(instance.config_file.absolute())
    
    def setup_instances(self) -> bool:
        """Setup multiple Tor instances."""
        logger.info(f"Setting up {self.num_instances} Tor instances...")
        
        for i in range(self.num_instances):
            instance = TorInstance(
                instance_id=i + 1,
                socks_port=TOR_BASE_SOCKS_PORT + (i * 2),
                control_port=TOR_BASE_CONTROL_PORT + (i * 2),
                data_dir=TOR_DATA_DIR / f"tor{i+1}",
                config_file=TOR_CONFIG_DIR / f"tor{i+1}.conf"
            )
            
            # Create data directory
            instance.data_dir.mkdir(parents=True, exist_ok=True)
            
            # Create config
            self.create_instance_config(instance)
            
            self.instances.append(instance)
            logger.info(f"Instance {instance.instance_id}: SOCKS={instance.socks_port}, Control={instance.control_port}")
        
        return True
    
    def start_instance(self, instance: TorInstance) -> bool:
        """Start single Tor instance."""
        try:
            tor_binary = self._get_tor_binary_path()
            
            cmd = [
                tor_binary,
                "-f", str(instance.config_file.absolute())
            ]
            
            logger.info(f"Starting Tor instance {instance.instance_id}...")
            
            # Start Tor process
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            instance.pid = proc.pid
            
            # Wait for bootstrap
            time.sleep(5)
            
            # Check if still running
            if proc.poll() is None:
                logger.info(f"Tor instance {instance.instance_id} started (PID: {instance.pid})")
                return True
            else:
                logger.error(f"Tor instance {instance.instance_id} failed to start")
                return False
        
        except Exception as e:
            logger.error(f"Failed to start Tor instance {instance.instance_id}: {e}")
            return False
    
    def start_all(self, wait_bootstrap: bool = True) -> int:
        """Start all Tor instances. Returns number of successful starts."""
        success_count = 0
        
        for instance in self.instances:
            if self.start_instance(instance):
                success_count += 1
            time.sleep(2)  # Stagger starts
        
        # Wait for bootstrap on all instances
        if wait_bootstrap and success_count > 0:
            logger.info("Waiting for Tor bootstrap (up to 120s)...")
            for instance in self.instances:
                if instance.pid:
                    bootstrapped = self.wait_for_bootstrap(instance, timeout=120)
                    if bootstrapped:
                        logger.info(f"Instance {instance.instance_id} fully bootstrapped")
                    else:
                        logger.warning(f"Instance {instance.instance_id} bootstrap timeout")
        
        logger.info(f"Started {success_count}/{self.num_instances} Tor instances")
        return success_count
    
    def wait_for_bootstrap(self, instance: TorInstance, timeout: int = 120) -> bool:
        """Wait for Tor instance to reach 100% bootstrap."""
        log_path = TOR_LOG_DIR / f"tor{instance.instance_id}.log"
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            try:
                if log_path.exists():
                    content = log_path.read_text(encoding='utf-8', errors='replace')
                    if 'Bootstrapped 100%' in content:
                        return True
                    # Extract progress
                    for line in content.split('\n'):
                        if 'Bootstrapped' in line and '%' in line:
                            pct = line.split('Bootstrapped')[1].split('%')[0].strip()
                            try:
                                pct_int = int(pct)
                                if pct_int > 50:
                                    # Close to done, check more frequently
                                    time.sleep(1)
                                    continue
                            except: pass
            except Exception:
                pass
            time.sleep(3)
        
        return False
    
    def check_instance_health(self, instance: TorInstance) -> Dict:
        """Check if Tor instance is healthy."""
        try:
            proxies = {
                'http': f'socks5h://127.0.0.1:{instance.socks_port}',
                'https': f'socks5h://127.0.0.1:{instance.socks_port}'
            }
            
            resp = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=proxies,
                timeout=25
            )
            
            data = resp.json()
            
            instance.is_healthy = data.get('IsTor', False)
            instance.exit_ip = data.get('IP', 'unknown')
            
            return {
                'instance_id': instance.instance_id,
                'is_tor': instance.is_healthy,
                'exit_ip': instance.exit_ip,
                'status': 'healthy' if instance.is_healthy else 'blocked'
            }
        
        except Exception as e:
            instance.is_healthy = False
            return {
                'instance_id': instance.instance_id,
                'status': 'dead',
                'error': str(e)
            }
    
    async def check_all_health(self) -> List[Dict]:
        """Check health of all instances."""
        loop = asyncio.get_event_loop()
        tasks = []
        for instance in self.instances:
            task = loop.run_in_executor(None, self.check_instance_health, instance)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]
    
    def rotate_circuit(self, instance: TorInstance) -> bool:
        """Rotate circuit for instance using stem."""
        try:
            from stem import Signal
            from stem.control import Controller
            
            with Controller.from_port(port=instance.control_port) as controller:
                controller.authenticate()
                
                # Check cooldown
                wait = controller.get_newnym_wait()
                if wait > 0:
                    logger.debug(f"Instance {instance.instance_id}: Cooldown {wait}s")
                    time.sleep(wait)
                
                controller.signal(Signal.NEWNYM)
                instance.last_rotation = time.time()
                
                logger.info(f"Circuit rotated for instance {instance.instance_id}")
                return True
        
        except ImportError:
            logger.warning("stem library not installed. Run: pip install stem")
            return False
        except Exception as e:
            logger.error(f"Circuit rotation failed for instance {instance.instance_id}: {e}")
            return False
    
    def get_proxy(self) -> str:
        """Get proxy URL for current instance (round-robin)."""
        if not self.instances:
            raise RuntimeError("No Tor instances available")
        
        instance = self.instances[self.current_instance_idx]
        
        # Round-robin to next instance
        self.current_instance_idx = (self.current_instance_idx + 1) % len(self.instances)
        
        return f"socks5h://127.0.0.1:{instance.socks_port}"
    
    def get_proxy_for_module(self, module_id: int) -> str:
        """
        Get proxy for a specific module.
        Different modules get different Tor instances for load distribution.
        """
        if not self.instances:
            raise RuntimeError("No Tor instances available")
        
        idx = module_id % len(self.instances)
        instance = self.instances[idx]
        return f"socks5h://127.0.0.1:{instance.socks_port}"
    
    async def rotation_loop(self, interval: int = 45):
        """
        Continuously rotate circuits every `interval` seconds.
        Uses stem library to send NEWNYM signal.
        """
        logger.info(f"Starting circuit rotation loop every {interval}s")
        while True:
            await asyncio.sleep(interval)
            for instance in self.instances:
                if instance.is_healthy:
                    self.rotate_circuit(instance)
            logger.info(f"Circuit rotation complete for {len(self.instances)} instances")
    
    async def health_monitor_loop(self, check_interval: int = 30, max_retries: int = 3):
        """
        Monitor Tor instance health and auto-restart dead instances.
        """
        logger.info(f"Starting health monitor loop every {check_interval}s")
        while True:
            await asyncio.sleep(check_interval)
            results = await self.check_all_health()
            for result in results:
                inst_id = result.get('instance_id', 0)
                if result.get('status') in ('dead', 'blocked'):
                    instance = next(
                        (i for i in self.instances if i.instance_id == inst_id),
                        None
                    )
                    if instance:
                        logger.warning(f"Instance {inst_id} unhealthy, restarting...")
                        self.stop_instance(instance)
                        for attempt in range(max_retries):
                            if self.start_instance(instance):
                                await asyncio.sleep(5)
                                check = self.check_instance_health(instance)
                                if check.get('is_tor'):
                                    logger.info(f"Instance {inst_id} restarted successfully")
                                    break
                            await asyncio.sleep(3)
    
    def stop_instance(self, instance: TorInstance) -> bool:
        """Stop Tor instance."""
        if not instance.pid:
            return True
        
        try:
            if sys.platform == 'win32':
                subprocess.run(["taskkill", "/F", "/PID", str(instance.pid)], check=False)
            else:
                os.kill(instance.pid, 15)  # SIGTERM
            
            logger.info(f"Stopped Tor instance {instance.instance_id}")
            instance.pid = None
            return True
        except Exception as e:
            logger.error(f"Failed to stop instance {instance.instance_id}: {e}")
            return False
    
    def stop_all(self):
        """Stop all Tor instances."""
        for instance in self.instances:
            self.stop_instance(instance)
        
        logger.info("All Tor instances stopped")


# Global singleton
_tor_manager: Optional[TorManager] = None


def get_tor_manager(instances: int = DEFAULT_INSTANCES) -> TorManager:
    """Get global Tor manager instance."""
    global _tor_manager
    if _tor_manager is None:
        _tor_manager = TorManager(instances=instances)
    return _tor_manager


def is_tor_available() -> bool:
    """Quick check if Tor is available."""
    manager = get_tor_manager()
    return manager.is_tor_installed()


async def setup_tor(instances: int = DEFAULT_INSTANCES, auto_install: bool = True) -> Tuple[bool, str]:
    """
    Setup Tor with auto-install.
    
    Returns:
        (success, message)
    """
    manager = get_tor_manager(instances)
    
    # Check if installed
    if not manager.is_tor_installed():
        if not auto_install:
            return False, "Tor not installed. Set auto_install=True to install automatically."
        
        # Auto-install
        if not manager.install_tor():
            return False, "Tor installation failed. Please install manually."
    
    # Setup instances
    if not manager.setup_instances():
        return False, "Failed to setup Tor instances"
    
    # Start all (includes bootstrap wait)
    success_count = manager.start_all(wait_bootstrap=True)
    
    if success_count == 0:
        return False, "Failed to start any Tor instances"
    
    # Check health
    health_results = await manager.check_all_health()
    healthy_count = sum(1 for r in health_results if r.get('is_tor'))
    
    if healthy_count == 0:
        return False, f"No healthy Tor instances ({success_count} started but not connected)"
    
    return True, f"Tor ready: {healthy_count}/{instances} instances healthy"
