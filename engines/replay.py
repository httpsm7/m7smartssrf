"""
Request Replay Engine - Replay specific requests by ID
"""

import json
import os


class ReplayEngine:
    def __init__(self, config):
        self.config = config

    async def replay(self, request_id):
        """Replay a specific saved request"""
        log_path = f"logs/requests.log"
        if not os.path.exists(log_path):
            print(f"[!] Request log not found: {log_path}")
            return

        with open(log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if str(entry.get('id')) == str(request_id):
                        print(f"[*] Replaying request {request_id}")
                        print(f"    URL    : {entry.get('url')}")
                        print(f"    Method : {entry.get('method')}")
                        print(f"    Payload: {entry.get('payload')}")
                        print(f"    Param  : {entry.get('param')}")
                        return
                except Exception:
                    continue

        print(f"[!] Request ID {request_id} not found in logs")
