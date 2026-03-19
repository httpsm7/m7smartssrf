#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          m7smartssrf - Smart SSRF Discovery Tool             ║
║          By: Sharlix | Milkyway Intelligence                 ║
║          Handle: httpsm7                                     ║
║          For: Authorized Penetration Testing Only            ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import argparse
import asyncio
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.config import Config
from core.scanner import Scanner
from utils.logger import setup_logger
from utils.session import SessionManager

def parse_args():
    parser = argparse.ArgumentParser(
        prog='m7smartssrf',
        description='Smart SSRF Discovery & Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  m7smartssrf scan urls.txt
  m7smartssrf scan urls.txt --threads 50 --oob
  m7smartssrf scan urls.txt --bypass all --mode deep
  m7smartssrf scan urls.txt --resume scan.session
  m7smartssrf scan urls.txt --proxy http://127.0.0.1:8080
  m7smartssrf scan urls.txt --config config.yaml --output report
        """
    )

    subparsers = parser.add_subparsers(dest='command')

    # Scan subcommand
    scan_parser = subparsers.add_parser('scan', help='Start SSRF scan')
    scan_parser.add_argument('target', help='URL list file or single URL')
    scan_parser.add_argument('--threads', type=int, default=20, help='Thread count (default: 20)')
    scan_parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds (default: 10)')
    scan_parser.add_argument('--retries', type=int, default=2, help='Retry count (default: 2)')
    scan_parser.add_argument('--delay', type=float, default=0, help='Delay between requests (seconds)')
    scan_parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    scan_parser.add_argument('--proxy-list', help='Proxy list file for rotation')
    scan_parser.add_argument('--mode', choices=['fast', 'deep', 'stealth'], default='fast', help='Scan mode (default: fast)')
    scan_parser.add_argument('--oob', action='store_true', help='Enable OOB/blind detection via Interactsh')
    scan_parser.add_argument('--oob-server', help='Custom OOB callback server')
    scan_parser.add_argument('--bypass', help='Filter bypass techniques (localhost, metadata, all)')
    scan_parser.add_argument('--protocols', help='Comma-separated protocols to fuzz (default: all)')
    scan_parser.add_argument('--headers-only', action='store_true', help='Test header injection only')
    scan_parser.add_argument('--params-only', action='store_true', help='Test parameter injection only')
    scan_parser.add_argument('--payloads', help='Custom payload file')
    scan_parser.add_argument('--output', default='report', help='Output file base name (default: report)')
    scan_parser.add_argument('--format', choices=['json', 'csv', 'txt', 'all'], default='all', help='Output format')
    scan_parser.add_argument('--resume', help='Resume from session file')
    scan_parser.add_argument('--save-session', action='store_true', help='Save session for resume')
    scan_parser.add_argument('--config', help='Config YAML file')
    scan_parser.add_argument('--cookies', help='Cookies string for authenticated scanning')
    scan_parser.add_argument('--headers', help='Custom headers (key:value,key:value)')
    scan_parser.add_argument('--auth', help='Bearer token for auth scanning')
    scan_parser.add_argument('--safe', action='store_true', help='Safe mode - avoid destructive payloads')
    scan_parser.add_argument('--stealth-delay', action='store_true', help='Random delays for stealth')
    scan_parser.add_argument('--rotate-ua', action='store_true', help='Rotate User-Agent headers')
    scan_parser.add_argument('--replay', help='Replay a specific request by ID')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    scan_parser.add_argument('--silent', action='store_true', help='Silent mode - only show findings')

    # Version
    parser.add_argument('--version', action='version', version='m7smartssrf v1.0.0 by Sharlix')

    return parser.parse_args()


async def main():
    args = parse_args()

    if args.command is None:
        print_banner()
        print("\n[!] Usage: m7smartssrf scan <urls.txt> [options]")
        print("[!] Use --help for full options\n")
        sys.exit(1)

    # Print banner unless silent
    if not (hasattr(args, 'silent') and args.silent):
        print_banner()

    # Load config
    config = Config(args)

    # Setup logger
    logger = setup_logger(config.verbose, config.silent)

    # Session manager
    session_mgr = SessionManager(config)

    if args.command == 'scan':
        # Resume support
        if args.resume:
            logger.info(f"[*] Resuming session: {args.resume}")
            config = session_mgr.load_session(args.resume)

        # Replay mode
        if hasattr(args, 'replay') and args.replay:
            from engines.replay import ReplayEngine
            replayer = ReplayEngine(config)
            await replayer.replay(args.replay)
            return

        scanner = Scanner(config, logger, session_mgr)
        start_time = time.time()

        try:
            await scanner.run()
        except KeyboardInterrupt:
            logger.warning("\n[!] Scan interrupted by user")
            if config.save_session:
                session_mgr.save_session(scanner.get_state())
                logger.info(f"[*] Session saved. Resume with: --resume {session_mgr.session_file}")
        finally:
            elapsed = time.time() - start_time
            logger.info(f"\n[+] Scan completed in {elapsed:.1f}s")


if __name__ == '__main__':
    asyncio.run(main())
