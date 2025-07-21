"""
rabbitRecon HTTP Fuzzer Module
CLI interface to the core HTTP fuzzing functionality
"""

import argparse
from typing import Dict, Any
from pathlib import Path

from fuzz.http_fuzzer import HTTPFuzzer
from utils.logger import get_logger
from reports.report_writer import write_report

logger = get_logger('http_fuzzer_module')

class HTTPFuzzerModule:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the HTTP fuzzer module

        Args:
            config: Configuration dictionary from CLI and/or config file
        """
        self.config = config
        self.fuzzer = HTTPFuzzer(config)

        # Set default wordlist if not specified
        if 'wordlist' not in self.config:
            default_wl = Path(__file__).parent.parent / 'data' / 'wordlists' / 'common_paths.txt'
            if default_wl.exists():
                self.config['wordlist'] = str(default_wl)

    @staticmethod
    def setup_parser(parser: argparse.ArgumentParser) -> None:
        """
        Configure the argument parser for HTTP fuzzing

        Args:
            parser: ArgumentParser instance to configure
        """
        parser.add_argument('url', help='Base URL to fuzz')
        parser.add_argument('-w', '--wordlist', required=True,
                          help='Path to wordlist file')
        parser.add_argument('-t', '--fuzz-type', default='path',
                          choices=['path', 'param', 'header', 'method'],
                          help='Type of fuzzing to perform')
        parser.add_argument('--param-value', default='FUZZ',
                          help='Value to use when fuzzing parameters')
        parser.add_argument('--header-value', default='FUZZ',
                          help='Value to use when fuzzing headers')
        parser.add_argument('--rate-limit', type=int,
                          help='Maximum requests per second')
        parser.add_argument('--follow-redirects', action='store_true',
                          help='Follow HTTP redirects')
        parser.add_argument('--no-follow-redirects', dest='follow_redirects',
                          action='store_false', help='Do not follow redirects')
        parser.set_defaults(follow_redirects=True)

    def run(self, args: argparse.Namespace) -> Dict[str, Any]:
        """
        Execute the HTTP fuzzing based on CLI arguments

        Args:
            args: Parsed CLI arguments

        Returns:
            Dictionary containing fuzzing results
        """
        if not args.url.startswith(('http://', 'https://')):
            logger.warning('URL should start with http:// or https://')

        # Merge CLI args with config
        fuzz_config = {
            **self.config,
            'follow_redirects': args.follow_redirects,
            'param_value': args.param_value,
            'header_value': args.header_value
        }

        if args.rate_limit:
            fuzz_config['rate_limit'] = args.rate_limit

        try:
            logger.info(f"Starting HTTP fuzzing on {args.url}")
            logger.info(f"Fuzz type: {args.fuzz_type}, Wordlist: {args.wordlist}")

            results = self.fuzzer.run(
                base_url=args.url,
                wordlist_path=args.wordlist,
                fuzz_type=args.fuzz_type,
                **fuzz_config
            )

            if args.output:
                output_format = 'json' if args.json else 'text'
                write_report(results, args.output, output_format)
                logger.info(f"Results saved to {args.output}")

            return {
                'status': 'completed',
                'results': results,
                'stats': self._generate_stats(results)
            }
        except Exception as e:
            logger.error(f"Fuzzing failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def _generate_stats(self, results: Dict[str, Any]) -> Dict[str, int]:
        """
        Generate statistics from fuzzing results

        Args:
            results: Raw fuzzing results

        Returns:
            Dictionary of statistics
        """
        stats = {
            'total_requests': len(results),
            'successful': 0,
            'failed': 0,
            'status_codes': {},
            'interesting_findings': 0
        }

        for url, result in results.items():
            if result.get('status') == 'success':
                stats['successful'] += 1
                status = result.get('status_code', 0)
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1

                if result.get('patterns', {}).get('interesting_strings'):
                    stats['interesting_findings'] += 1
            else:
                stats['failed'] += 1

        return stats

def run_module(args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Module entry point for CLI integration

    Args:
        args: Parsed CLI arguments
        config: Configuration dictionary

    Returns:
        Dictionary with results and status
    """
    module = HTTPFuzzerModule(config)
    return module.run(args)
