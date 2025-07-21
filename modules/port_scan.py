"""
rabbitRecon Port Scanner Module
CLI interface to the core port scanning functionality
"""

import argparse
from typing import Dict, List, Optional, Tuple
from ctypes import c_int, byref, POINTER
from pathlib import Path

from core.scanner_wrapper import (
    scan_ports,
    SCAN_SYN,
    SCAN_CONNECT,
    SCAN_UDP,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_OPEN_OR_FILTERED,
    PORT_ERROR
)
from utils.logger import get_logger
from utils.thread_pool import ThreadPoolManager
from reports.report_writer import write_report

logger = get_logger('port_scan')

class PortScanner:
    """Main port scanning module handling CLI interface and scan execution"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize port scanner with configuration

        Args:
            config: Dictionary of configuration parameters
        """
        self.config = config or {}
        self.thread_pool = ThreadPoolManager(
            max_workers=self.config.get('max_threads', 10)
        )

        # Scan type mapping
        self.scan_types = {
            'syn': SCAN_SYN,
            'connect': SCAN_CONNECT,
            'udp': SCAN_UDP
        }

        # Port status descriptions
        self.status_desc = {
            PORT_OPEN: 'open',
            PORT_CLOSED: 'closed',
            PORT_FILTERED: 'filtered',
            PORT_OPEN_OR_FILTERED: 'open|filtered',
            PORT_ERROR: 'error'
        }

    @staticmethod
    def setup_parser(parser: argparse.ArgumentParser) -> None:
        """
        Configure argument parser for port scanning

        Args:
            parser: ArgumentParser instance to configure
        """
        parser.add_argument(
            'target',
            help='Target host or IP address to scan'
        )
        parser.add_argument(
            '-p', '--ports',
            default='1-1024',
            help='Port range (e.g. 80,443 or 1-1000)'
        )
        parser.add_argument(
            '-t', '--scan-type',
            choices=['syn', 'connect', 'udp'],
            default='syn',
            help='Type of scan to perform'
        )
        parser.add_argument(
            '--timeout',
            type=float,
            default=2.0,
            help='Connection timeout in seconds'
        )
        parser.add_argument(
            '--rate-limit',
            type=int,
            help='Maximum packets per second'
        )
        parser.add_argument(
            '--top-ports',
            type=int,
            help='Scan N most common ports instead of range'
        )

    def _parse_ports(self, port_spec: str) -> List[int]:
        """
        Parse port specification into list of ports

        Args:
            port_spec: Port range string (e.g. "80,443,1000-2000")

        Returns:
            List of port numbers
        """
        ports = set()
        for part in port_spec.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def _get_top_ports(self, count: int) -> List[int]:
        """
        Get list of most common ports

        Args:
            count: Number of top ports to return

        Returns:
            List of port numbers
        """
        # Top 100 ports from nmap
        top_ports = [
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
            143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
            5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
            81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443,
            8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008,
            49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
            2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513,
            990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009,
            3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
            13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899,
            9100, 119, 37
        ]
        return top_ports[:count]

    def _port_scan_core(self, target: str, ports: List[int], scan_type: str, 
                       timeout: float) -> Dict[int, str]:
        """
        Execute core port scanning through C wrapper

        Args:
            target: Target host/IP
            ports: List of ports to scan
            scan_type: Type of scan (syn/connect/udp)
            timeout: Timeout per port

        Returns:
            Dictionary mapping ports to status
        """
        try:
            # Convert to C-compatible scan type
            c_scan_type = self.scan_types[scan_type]

            # Get port range
            start_port = min(ports)
            end_port = max(ports)

            # Execute scan
            ret, results = scan_ports(
                target=target,
                start_port=start_port,
                end_port=end_port,
                scan_type=c_scan_type,
                thread_count=self.config.get('threads', 10),
                timeout=timeout
            )

            # Filter and map results
            port_status = {}
            for port in ports:
                status_code = results[port]
                port_status[port] = self.status_desc.get(status_code, 'unknown')

            return port_status

        except Exception as e:
            logger.error(f"Core scan failed: {str(e)}")
            raise

    def run(self, args: argparse.Namespace) -> Dict:
        """
        Execute port scan based on CLI arguments

        Args:
            args: Parsed CLI arguments

        Returns:
            Dictionary containing scan results and metadata
        """
        try:
            # Determine ports to scan
            if args.top_ports:
                ports = self._get_top_ports(args.top_ports)
                logger.info(f"Scanning top {args.top_ports} ports on {args.target}")
            else:
                ports = self._parse_ports(args.ports)
                logger.info(f"Scanning {len(ports)} ports on {args.target}")

            # Execute scan
            results = self._port_scan_core(
                target=args.target,
                ports=ports,
                scan_type=args.scan_type,
                timeout=args.timeout
            )

            # Generate statistics
            stats = self._generate_stats(results)

            # Output results
            if args.output:
                output_format = 'json' if args.json else 'text'
                write_report(results, args.output, output_format)
                logger.info(f"Results saved to {args.output}")

            return {
                'status': 'completed',
                'target': args.target,
                'scan_type': args.scan_type,
                'results': results,
                'stats': stats
            }

        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def _generate_stats(self, results: Dict[int, str]) -> Dict[str, int]:
        """
        Generate statistics from scan results

        Args:
            results: Dictionary of port statuses

        Returns:
            Dictionary of statistics
        """
        stats = {
            'total': len(results),
            'open': 0,
            'filtered': 0,
            'closed': 0,
            'error': 0,
            'services': {}
        }

        for port, status in results.items():
            if status == 'open':
                stats['open'] += 1
            elif status == 'filtered':
                stats['filtered'] += 1
            elif status == 'closed':
                stats['closed'] += 1
            elif status == 'error':
                stats['error'] += 1

            # TODO: Integrate with service detection
            if status == 'open':
                stats['services'][port] = 'unknown'

        return stats

def run_module(args: argparse.Namespace, config: Dict) -> Dict:
    """
    Module entry point for CLI integration

    Args:
        args: Parsed CLI arguments
        config: Configuration dictionary

    Returns:
        Dictionary with results and status
    """
    scanner = PortScanner(config)
    return scanner.run(args)
