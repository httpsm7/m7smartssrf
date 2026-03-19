"""
Report Generator - JSON, CSV, TXT output
"""

import json
import csv
import os
import time
from datetime import datetime


class ReportGenerator:
    def __init__(self, config):
        self.config = config
        os.makedirs('reports', exist_ok=True)

    def generate(self, findings):
        if not findings:
            print("[*] No vulnerabilities found. No report generated.")
            return

        base = os.path.join('reports', self.config.output)
        fmt = self.config.format

        if fmt in ['json', 'all']:
            self._write_json(findings, base + '.json')
        if fmt in ['txt', 'all']:
            self._write_txt(findings, base + '.txt')
        if fmt in ['csv', 'all']:
            self._write_csv(findings, base + '.csv')

        print(f"[+] Reports saved to reports/")

    def _write_json(self, findings, path):
        report = {
            'tool': 'm7smartssrf',
            'author': 'Sharlix | Milkyway Intelligence',
            'handle': 'httpsm7',
            'timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(findings),
            'findings': findings
        }
        with open(path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] JSON report: {path}")

    def _write_txt(self, findings, path):
        with open(path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("  m7smartssrf - SSRF Vulnerability Report\n")
            f.write("  By: Sharlix | Milkyway Intelligence | httpsm7\n")
            f.write(f"  Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"  Total Findings: {len(findings)}\n")
            f.write("=" * 60 + "\n\n")

            for i, finding in enumerate(findings, 1):
                sev = finding.get('severity', 'MEDIUM')
                f.write(f"[{i}] [{sev}] {finding.get('type', 'unknown').upper()}\n")
                f.write(f"  URL      : {finding.get('url', '-')}\n")
                f.write(f"  Param    : {finding.get('param', '-')}\n")
                f.write(f"  Payload  : {finding.get('payload', '-')}\n")
                f.write(f"  Evidence : {finding.get('evidence', '-')}\n")
                f.write(f"  Status   : {finding.get('status_code', '-')}\n")
                f.write(f"  Resp Size: {finding.get('response_size', '-')}\n")
                if finding.get('exploit_chains'):
                    f.write(f"  Chains   : {', '.join(finding['exploit_chains'][:3])}\n")
                f.write("\n")

        print(f"[+] TXT report: {path}")

    def _write_csv(self, findings, path):
        fields = ['severity', 'type', 'url', 'param', 'payload', 'evidence',
                  'status_code', 'response_size', 'task_type']
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(findings)
        print(f"[+] CSV report: {path}")
