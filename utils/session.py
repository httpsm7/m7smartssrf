"""
Session Manager - Save/load scan state for resume support
"""

import json
import os
import time


class SessionManager:
    def __init__(self, config):
        self.config = config
        self.session_file = f"scan_{int(time.time())}.session"

    def save_session(self, state):
        try:
            os.makedirs('logs', exist_ok=True)
            path = os.path.join('logs', self.session_file)
            with open(path, 'w') as f:
                json.dump(state, f, default=str)
            print(f"[*] Session saved: {path}")
        except Exception as e:
            print(f"[!] Session save error: {e}")

    def load_session(self, path):
        try:
            with open(path) as f:
                state = json.load(f)
            # Restore config fields
            from core.config import Config
            cfg = Config()
            for k, v in state.get('config', {}).items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
            return cfg
        except Exception as e:
            print(f"[!] Session load error: {e}")
            return self.config
