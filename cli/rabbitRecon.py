#!/usr/bin/env python3
"""
rabbitRecon - Reconnaissance and Fuzzing Tool
CLI Interface and Command Dispatcher
"""

import argparse
import logging
import sys
from typing import List, Dict, Optional

from utils.logger import setup_logging
from utils.config import load_config
from utils.thread_pool import ThreadPoolManager

# Module imports will be dynamically loaded based on commands
MODULES_PACKAGE = "modules"

class rabbitReconXCLI:
    """Main CLI handler for rabbitRecon tool"""

    def __init__(self):
        self.config = load_config()
        self.parser = self._create_parser()
        self.subparsers = None
        self.log = setup_logging()
        self.thread_pool = ThreadPoolManager(
            max_workers=self.config.get('max_threads', 10)
        )

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser with common options"""
        parser = argparse.ArgumentParser(
            prog='rabbitRecon',
            description='Advanced Reconnaissance & Fuzzing Tool For Researchers And Professionals',
            epilog='For detailed module help: rabbitRecon <module> -h'
        )

        # Global arguments
        parser.add_argument(
            '-v', '--verbose',
            action='count',
            default=0,
            help='Increase verbosity level (-v, -vv, -vvv)'
        )
        parser.add_argument(
            '-c', '--config',
            default='rabbitRecon.conf',
            help='Path to configuration file'
        )
        parser.add_argument(
            '-o', '--output',
            help='Output file path for results'
        )
        parser.add_argument(
            '--json',
            action='store_true',
            help='Output results in JSON format'
        )

        # Subcommands
        self.subparsers = parser.add_subparsers(
            dest='command',
            title='modules',
            description='Available reconnaissance modules',
            required=True
        )

        self._register_modules()
        return parser

    def _register_modules(self):
        """Dynamically register available modules as subcommands"""
        # Port Scanning
        port_scan = self.subparsers.add_parser(
            'port-scan',
            help='Perform port scanning operations'
        )
        port_scan.add_argument(
            'target',
            help='Target host or IP address'
        )
        port_scan.add_argument(
            '-p', '--ports',
            default='1-1024',
            help='Port range or list (e.g. 80,443 or 1-1000)'
        )
        port_scan.add_argument(
            '-t', '--scan-type',
            choices=['syn', 'connect', 'udp'],
            default='syn',
            help='Type of scan to perform'
        )
        port_scan.add_argument(
            '--timeout',
            type=float,
            default=2.0,
            help='Connection timeout in seconds'
        )

        # Banner Grabbing
        banner_grab = self.subparsers.add_parser(
            'banner',
            help='Grab service banners from open ports'
        )
        banner_grab.add_argument(
            'target',
            help='Target host or IP address'
        )
        banner_grab.add_argument(
            '-p', '--ports',
            required=True,
            help='Port(s) to grab banners from (comma-separated)'
        )

        # DNS Enumeration
        dns_enum = self.subparsers.add_parser(
            'dns',
            help='Perform DNS enumeration'
        )
        dns_enum.add_argument(
            'domain',
            help='Target domain name'
        )
        dns_enum.add_argument(
            '--types',
            default='A,AAAA,MX,TXT,NS',
            help='DNS record types to query (comma-separated)'
        )
        dns_enum.add_argument(
            '--bruteforce',
            action='store_true',
            help='Enable subdomain bruteforcing'
        )

        # HTTP Fuzzing
        http_fuzz = self.subparsers.add_parser(
            'fuzz',
            help='HTTP fuzzing operations'
        )
        http_fuzz.add_argument(
            'url',
            help='Base URL to fuzz'
        )
        http_fuzz.add_argument(
            '-w', '--wordlist',
            required=True,
            help='Path to wordlist file'
        )
        http_fuzz.add_argument(
            '-H', '--headers',
            action='append',
            help='Additional headers (format: "Header: Value")'
        )

    def _setup_logging(self, verbosity: int):
        """Configure logging based on verbosity level"""
        log_level = logging.WARNING
        if verbosity == 1:
            log_level = logging.INFO
        elif verbosity >= 2:
            log_level = logging.DEBUG

        self.log.setLevel(log_level)

    def _dispatch_command(self, args) -> bool:
        """Route commands to appropriate module handlers"""
        try:
            if args.command == 'port-scan':
                from modules.port_scan import PortScanner
                scanner = PortScanner(self.config)
                results = scanner.run(
                    target=args.target,
                    ports=args.ports,
                    scan_type=args.scan_type,
                    timeout=args.timeout
                )
            elif args.command == 'banner':
                from modules.banner_grab import BannerGrabber
                grabber = BannerGrabber(self.config)
                results = grabber.run(
                    target=args.target,
                    ports=args.ports
                )
            elif args.command == 'dns':
                from modules.dns_enum import DNSEnumerator
                enumerator = DNSEnumerator(self.config)
                results = enumerator.run(
                    domain=args.domain,
                    record_types=args.types,
                    bruteforce=args.bruteforce
                )
            elif args.command == 'fuzz':
                from modules.http_fuzzer import HTTPFuzzer
                fuzzer = HTTPFuzzer(self.config)
                results = fuzzer.run(
                    url=args.url,
                    wordlist=args.wordlist,
                    headers=args.headers or []
                )
            else:
                raise ValueError(f"Unknown command: {args.command}")

            self._output_results(results, args)
            return True

        except Exception as e:
            self.log.error(f"Command failed: {str(e)}")
            if self.log.level == logging.DEBUG:
                self.log.exception("Detailed error trace:")
            return False

    def _output_results(self, results, args):
        """Handle output formatting and display"""
        if args.json:
            import json
            output = json.dumps(results, indent=2)
        else:
            # Default human-readable output
            from reports.report_writer import format_console
            output = format_console(results)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    def run(self, argv=None):
        """Main entry point for CLI execution"""
        args = self.parser.parse_args(argv)
        self._setup_logging(args.verbose)

        try:
            success = self._dispatch_command(args)
            sys.exit(0 if success else 1)
        except KeyboardInterrupt:
            self.log.info("\nScan interrupted by user")
            self.thread_pool.shutdown()
            sys.exit(1)

def main():
    """Entry point for console scripts"""
    cli = rabitReconCLI()
    cli.run()

if __name__ == '__main__':
    main()
