"""
Core Scanner Engine - Orchestrates all scan modules
"""

import asyncio
import time
import random
from urllib.parse import urlparse

from engines.input_engine import InputEngine
from engines.param_extractor import ParamExtractor
from engines.param_bruteforce import ParamBruteforce
from engines.payload_engine import PayloadEngine
from engines.protocol_fuzzer import ProtocolFuzzer
from engines.header_injector import HeaderInjector
from engines.request_engine import RequestEngine
from engines.response_analyzer import ResponseAnalyzer
from engines.oob_engine import OOBEngine
from engines.exploit_engine import ExploitEngine
from engines.bypass_engine import BypassEngine
from engines.redirect_chain import RedirectChainEngine
from modules.report_generator import ReportGenerator
from utils.cache import RequestCache
from utils.logger import get_logger


class Scanner:
    def __init__(self, config, logger, session_mgr):
        self.config = config
        self.logger = logger
        self.session_mgr = session_mgr
        self.findings = []
        self.scanned_count = 0
        self.total_requests = 0
        self.start_time = time.time()
        self.cache = RequestCache()

        # Init engines
        self.input_engine = InputEngine(config)
        self.param_extractor = ParamExtractor()
        self.param_bruteforce = ParamBruteforce(config)
        self.payload_engine = PayloadEngine(config)
        self.protocol_fuzzer = ProtocolFuzzer(config)
        self.header_injector = HeaderInjector(config)
        self.request_engine = RequestEngine(config)
        self.response_analyzer = ResponseAnalyzer(config)
        self.oob_engine = OOBEngine(config)
        self.exploit_engine = ExploitEngine(config)
        self.bypass_engine = BypassEngine(config)
        self.redirect_engine = RedirectChainEngine(config)
        self.report_gen = ReportGenerator(config)

    async def run(self):
        self.logger.info(f"\n[*] Starting m7smartssrf scan")
        self.logger.info(f"[*] Mode: {self.config.mode.upper()} | Threads: {self.config.threads} | Timeout: {self.config.timeout}s")

        # Load URLs
        urls = self.input_engine.load(self.config.target)
        if not urls:
            self.logger.error("[!] No valid URLs found. Exiting.")
            return

        self.logger.info(f"[*] Loaded {len(urls)} unique URLs")

        # OOB setup
        if self.config.oob:
            oob_domain = await self.oob_engine.setup()
            self.logger.info(f"[+] OOB callback domain: {oob_domain}")

        # Build scan tasks
        all_tasks = []
        for url in urls:
            tasks = await self._build_tasks_for_url(url)
            all_tasks.extend(tasks)

        self.logger.info(f"[*] Total scan tasks: {len(all_tasks)}")
        self.logger.info(f"[*] Scanning...\n")

        # Run with semaphore
        sem = asyncio.Semaphore(self.config.threads)
        tasks_coros = [self._run_task_with_sem(sem, task) for task in all_tasks]

        results = await asyncio.gather(*tasks_coros, return_exceptions=True)

        # Filter valid findings
        for r in results:
            if r and isinstance(r, dict) and r.get('vulnerable'):
                self.findings.append(r)

        # Check OOB results
        if self.config.oob:
            oob_hits = await self.oob_engine.get_hits()
            for hit in oob_hits:
                self.findings.append(hit)

        # Generate report
        self._print_summary()
        self.report_gen.generate(self.findings)

    async def _build_tasks_for_url(self, url):
        tasks = []

        # Extract params
        params = self.param_extractor.extract(url)

        # Add bruteforce hidden params
        hidden_params = self.param_bruteforce.get_priority_params(url)
        all_params = list(set(params + hidden_params))

        # Build payloads
        payloads = self.payload_engine.get_payloads(self.config.mode)

        # Apply bypass techniques
        if self.config.bypass:
            bypass_payloads = self.bypass_engine.generate(self.config.bypass)
            payloads.extend(bypass_payloads)

        # Add OOB payloads
        if self.config.oob:
            oob_payloads = self.oob_engine.get_payloads()
            payloads.extend(oob_payloads)

        # Param injection tasks
        if not self.config.headers_only:
            for param in all_params:
                for payload in payloads:
                    task = {
                        'type': 'param',
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'method': 'GET'
                    }
                    if not self.cache.exists(task):
                        tasks.append(task)

            # POST body tasks (deep mode)
            if self.config.mode == 'deep':
                for param in all_params:
                    for payload in payloads[:5]:  # Limit POST tasks
                        task = {
                            'type': 'param_post',
                            'url': url,
                            'param': param,
                            'payload': payload,
                            'method': 'POST'
                        }
                        if not self.cache.exists(task):
                            tasks.append(task)

        # Header injection tasks
        if not self.config.params_only:
            header_tasks = self.header_injector.build_tasks(url, payloads[:10])
            tasks.extend(header_tasks)

        # Protocol fuzzing tasks
        if self.config.mode in ['deep', 'stealth']:
            proto_tasks = self.protocol_fuzzer.build_tasks(url)
            tasks.extend(proto_tasks)

        return tasks

    async def _run_task_with_sem(self, sem, task):
        async with sem:
            # Delay handling
            delay = self.config.delay
            if self.config.stealth_delay and delay > 0:
                delay = random.uniform(delay * 0.5, delay * 2)
            if delay > 0:
                await asyncio.sleep(delay)

            return await self._execute_task(task)

    async def _execute_task(self, task):
        self.total_requests += 1
        url = task['url']
        payload = task.get('payload', '')
        param = task.get('param', '')
        task_type = task.get('type', 'param')

        try:
            # Build request
            if task_type == 'param':
                req_url = self._inject_param(url, param, payload)
                response = await self.request_engine.get(req_url)
            elif task_type == 'param_post':
                response = await self.request_engine.post(url, {param: payload})
            elif task_type == 'header':
                response = await self.request_engine.get(url, headers=task.get('headers', {}))
            elif task_type == 'protocol':
                req_url = self._inject_param(url, param, payload)
                response = await self.request_engine.get(req_url)
            else:
                return None

            if response is None:
                return None

            # Analyze response
            result = self.response_analyzer.analyze(response, task)
            if result and result.get('vulnerable'):
                self.logger.success(f"[VULN] {task_type.upper()} | {url[:60]} | Param: {param} | Payload: {payload[:40]}")
                # Try exploitation
                if not self.config.safe and result.get('type') in ['internal', 'blind']:
                    await self.exploit_engine.try_exploit(result)
                # Check redirect chain
                if result.get('redirect'):
                    chain = await self.redirect_engine.follow(result)
                    result['redirect_chain'] = chain
                return result

        except Exception as e:
            if self.config.verbose:
                self.logger.debug(f"[DEBUG] Task error: {e}")

        self.cache.add(task)
        return None

    def _inject_param(self, url, param, payload):
        from urllib.parse import urlencode, urljoin, urlparse, parse_qs
        parsed = urlparse(url)
        from urllib.parse import parse_qs, urlencode
        params = {}
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0]
        params[param] = payload
        new_query = urlencode(params)
        return parsed._replace(query=new_query).geturl()

    def _print_summary(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"  SCAN SUMMARY - m7smartssrf by Sharlix")
        print(f"{'='*60}")
        print(f"  Total Requests : {self.total_requests}")
        print(f"  Vulnerabilities: {len(self.findings)}")
        print(f"  Time Elapsed   : {elapsed:.1f}s")
        print(f"  Report saved   : {self.config.output}.*")
        print(f"{'='*60}\n")

        if self.findings:
            print(f"  [+] VULNERABILITIES FOUND:")
            for i, f in enumerate(self.findings, 1):
                sev = f.get('severity', 'MEDIUM')
                color = '\033[31m' if sev == 'HIGH' else '\033[33m'
                print(f"  {i}. {color}[{sev}]\033[0m {f.get('url', '')[:70]}")
                print(f"     Type: {f.get('type','unknown')} | Param: {f.get('param','-')}")
            print()

    def get_state(self):
        return {
            'config': self.config.__dict__,
            'findings': self.findings,
            'scanned_count': self.scanned_count
        }
