"""
Request Cache - prevent duplicate scans
"""

import hashlib
import json


class RequestCache:
    def __init__(self):
        self._seen = set()

    def _key(self, task):
        data = f"{task.get('url','')}{task.get('param','')}{task.get('payload','')}{task.get('type','')}"
        return hashlib.md5(data.encode()).hexdigest()

    def exists(self, task):
        return self._key(task) in self._seen

    def add(self, task):
        self._seen.add(self._key(task))

    def size(self):
        return len(self._seen)
