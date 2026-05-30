import os, json, time
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._last_save = 0.0
        self._report_data: Dict[str, Any] = {}

    def init_report(self, target: str, duration: int, engine: str = "auto_mode_v5"):
        ts = datetime.now()
        report_id = f"report_{target.replace('https://','').replace('http://','').replace('/','_')}_{ts:%Y%m%d_%H%M%S}"
        self._report_data = {
            "report_id": report_id,
            "target": target,
            "engine": engine,
            "started_at": ts.isoformat(),
            "duration": duration,
            "phases": {
                "phase_0": {"name": "Profiling", "status": "pending", "start": 0, "findings": {}},
                "phase_0b": {"name": "WAF Probing", "status": "pending", "start": 0, "findings": {}},
                "phase_0c": {"name": "Orchestrator", "status": "pending", "start": 0, "findings": {}},
                "phase_1": {"name": "Probing", "status": "pending", "start": 0, "findings": {}},
                "phase_2": {"name": "Attack", "status": "pending", "start": 0, "metrics": {}},
                "phase_3": {"name": "Report", "status": "pending", "start": 0, "findings": {}},
            },
            "summary": {},
            "bypass": {},
            "errors": [],
            "completed_at": "",
        }
        return report_id

    def start_phase(self, phase: str):
        if phase in self._report_data.get("phases", {}):
            self._report_data["phases"][phase]["start"] = time.time()
            self._report_data["phases"][phase]["status"] = "running"

    def end_phase(self, phase: str, findings: dict = None):
        if phase in self._report_data.get("phases", {}):
            p = self._report_data["phases"][phase]
            p["status"] = "completed"
            p["elapsed"] = time.time() - p.get("start", time.time())
            if findings:
                p["findings"].update(findings)

    def update_metrics(self, metrics: dict):
        self._report_data.setdefault("phases", {}).setdefault("phase_2", {}).setdefault("metrics", {}).update(metrics)
        self._auto_save()

    def set_bypass_info(self, bypass: dict):
        self._report_data["bypass"] = bypass
        self._auto_save()

    def add_error(self, error: str):
        self._report_data.setdefault("errors", []).append(error)

    def finalize(self, summary: dict = None):
        self._report_data["completed_at"] = datetime.now().isoformat()
        if summary:
            self._report_data["summary"] = summary
        self._report_data["phases"]["phase_3"]["status"] = "completed"
        self._save_json()
        self._save_html()
        self._save_pdf()

    def _auto_save(self):
        now = time.time()
        if now - self._last_save > 30:
            self._last_save = now
            self._save_json_light()

    def _save_json(self):
        path = os.path.join(self.output_dir, f"{self._report_data.get('report_id', 'report')}.json")
        try:
            with open(path, "w") as f:
                json.dump(self._report_data, f, indent=2, default=str)
        except Exception:
            pass

    def _save_json_light(self):
        path = os.path.join(self.output_dir, "latest_report.json")
        try:
            with open(path, "w") as f:
                json.dump(self._report_data, f, indent=2, default=str)
        except Exception:
            pass

    def _save_html(self):
        d = self._report_data
        s = d.get("summary", {})
        total = s.get("grand_total", 0)
        bypass = d.get("bypass", {})
        p0 = d.get("phases", {}).get("phase_0", {}).get("findings", {})
        p2m = d.get("phases", {}).get("phase_2", {}).get("metrics", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Report - {d.get('target','')}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0a0a0f; color:#e0e0e0; padding:20px; }}
h1 {{ color:#00ff88; font-size:24px; margin-bottom:5px; }}
h2 {{ color:#00ccff; font-size:18px; margin:20px 0 10px; border-bottom:1px solid #333; padding-bottom:5px; }}
.meta {{ color:#888; font-size:13px; margin-bottom:20px; }}
.stat-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:10px 0; }}
.stat {{ background:#1a1a2e; border:1px solid #2a2a4e; padding:12px; border-radius:6px; text-align:center; }}
.stat .val {{ font-size:22px; font-weight:bold; color:#00ff88; }}
.stat .lbl {{ font-size:11px; color:#888; margin-top:4px; }}
table {{ width:100%; border-collapse:collapse; margin:10px 0; }}
th,td {{ padding:8px 12px; text-align:left; border:1px solid #2a2a4e; }}
th {{ background:#1a1a2e; color:#00ccff; font-size:12px; text-transform:uppercase; }}
td {{ font-size:13px; }}
tr:nth-child(even) td {{ background:#0f0f1a; }}
.section {{ background:#111122; border:1px solid #2a2a3e; border-radius:8px; padding:15px; margin:15px 0; }}
.green {{ color:#00ff88; }}
.red {{ color:#ff4444; }}
.yellow {{ color:#ffcc00; }}
.cyan {{ color:#00ccff; }}
pre {{ background:#000; padding:10px; border-radius:4px; overflow-x:auto; font-size:12px; }}
</style>
</head>
<body>
<h1>MPC Layer Attack Report</h1>
<div class="meta">Target: {d.get('target','')} | Engine: {d.get('engine','')} | Duration: {d.get('duration',0)}s</div>
<div class="meta">Started: {d.get('started_at','')} | Completed: {d.get('completed_at','')}</div>

<div class="section">
<h2>Executive Summary</h2>
<div class="stat-grid">
<div class="stat"><div class="val">{total:,}</div><div class="lbl">Total Requests</div></div>
<div class="stat"><div class="val">{s.get('rr_ok',0):,}</div><div class="lbl">Successful</div></div>
<div class="stat"><div class="val">{s.get('rr_fail',0):,}</div><div class="lbl">Failed</div></div>
<div class="stat"><div class=\"val\">{s.get('peak_rps',0):.0f}</div><div class=\"lbl\">Peak RPS</div></div>
</div>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Server Type</td><td>{s.get('server_type','?')}</td></tr>
<tr><td>Top Methods</td><td>{', '.join(s.get('top_methods',[]))}</td></tr>
<tr><td>WAF Detected</td><td>{s.get('waf_detected',False)}</td></tr>
<tr><td>Origin IP</td><td>{s.get('origin_ip','not found')}</td></tr>
<tr><td>HTTP/2 Support</td><td>{s.get('has_http2',False)}</td></tr>
</table>
</div>

<div class=\"section\">
<h2>Bypass Intelligence</h2>
<table>
<tr><th>Technique</th><th>Status</th></tr>
<tr><td>WAF Bypass Methods</td><td>{bypass.get('waf_methods',0)}</td></tr>
<tr><td>Cookie Warming</td><td>{'OK' if bypass.get('cookies_warmed') else 'SKIPPED'}</td></tr>
<tr><td>Header Pool Categories</td><td>{bypass.get('header_pool_categories',0)}</td></tr>
<tr><td>Encoding Tricks</td><td>{bypass.get('encoding_tricks',0)}/10</td></tr>
</table>
</div>

<div class=\"section\">
<h2>Phase Breakdown</h2>
<table>
<tr><th>Phase</th><th>Status</th><th>Elapsed</th></tr>"""
        for pid, pdata in d.get("phases", {}).items():
            name = pdata.get("name", pid)
            status = pdata.get("status", "pending")
            elapsed = pdata.get("elapsed", 0)
            color = {"completed": "green", "running": "yellow", "pending": "red"}.get(status, "red")
            html += f"<tr><td>{name}</td><td class=\"{color}\">{status.upper()}</td><td>{elapsed:.1f}s</td></tr>"
        html += """</table></div>"""

        if p2m:
            html += """<div class="section"><h2>Attack Metrics</h2><table>"""
            for k, v in p2m.items():
                html += f"<tr><td>{k}</td><td>{v}</td></tr>"
            html += "</table></div>"

        if d.get("errors"):
            html += """<div class="section"><h2>Errors Encountered</h2><pre>"""
            for e in d["errors"]:
                html += f"{e}\n"
            html += "</pre></div>"

        html += """<br><div style="text-align:center;color:#555;font-size:11px;">MPC-Layer v6.0 | Generated by Auto Mode V5</div></body></html>"""

        path = os.path.join(self.output_dir, f"{d.get('report_id','report')}.html")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception:
            pass

    def _save_pdf(self):
        try:
            from weasyprint import HTML
            json_path = os.path.join(self.output_dir, f"{self._report_data.get('report_id','report')}.json")
            html_path = os.path.join(self.output_dir, f"{self._report_data.get('report_id','report')}.html")
            if os.path.exists(html_path):
                pdf_path = os.path.join(self.output_dir, f"{self._report_data.get('report_id','report')}.pdf")
                HTML(filename=html_path).write_pdf(pdf_path)
        except ImportError:
            pass
        except Exception:
            pass
