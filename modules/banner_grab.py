"""
rabbitRecon Banner Grabbing Module
Service identification and banner collection for open ports
"""

import socket
import re
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum, auto

from utils.logger import get_logger
from utils.thread_pool import ThreadPoolManager
from utils.config import load_config
from reports.report_writer import write_report

logger = get_logger('banner_grab')

class ServiceType(Enum):
    HTTP = auto()
    HTTPS = auto()
    FTP = auto()
    SSH = auto()
    SMTP = auto()
    DNS = auto()
    UNKNOWN = auto()

@dataclass
class BannerResult:
    port: int
    service: ServiceType
    banner: str
    raw_response: bytes
    error: Optional[str] = None

class BannerGrabber:
    """Main banner grabbing engine with protocol detection"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize banner grabber with configuration

        Args:
            config: Dictionary of configuration parameters
        """
        self.config = config or load_config()
        self.timeout = self.config.get('banner_timeout', 5.0)
        self.thread_pool = ThreadPoolManager(
            max_workers=self.config.get('max_threads', 10)
        )

        # Protocol-specific settings
        self.protocol_handlers = {
            ServiceType.HTTP: self._grab_http,
            ServiceType.HTTPS: self._grab_http,
            ServiceType.FTP: self._grab_ftp,
            ServiceType.SSH: self._grab_ssh,
            ServiceType.SMTP: self._grab_smtp,
            ServiceType.DNS: self._grab_dns
        }

        # Common service ports mapping
        self.common_ports = {
            21: ServiceType.FTP,
            22: ServiceType.SSH,
            25: ServiceType.SMTP,
            53: ServiceType.DNS,
            80: ServiceType.HTTP,
            443: ServiceType.HTTPS,
            3306: ServiceType.MYSQL,
            3389: ServiceType.RDP
        }

    @staticmethod
    def setup_parser(parser: argparse.ArgumentParser) -> None:
        """
        Configure argument parser for banner grabbing

        Args:
            parser: ArgumentParser instance to configure
        """
        parser.add_argument(
            'target',
            help='Target host or IP address'
        )
        parser.add_argument(
            '-p', '--ports',
            required=True,
            help='Port(s) to grab banners from (comma-separated)'
        )
        parser.add_argument(
            '--timeout',
            type=float,
            default=5.0,
            help='Connection timeout in seconds'
        )
        parser.add_argument(
            '--protocol',
            choices=['auto', 'http', 'ftp', 'ssh', 'smtp', 'dns'],
            default='auto',
            help='Force specific protocol'
        )
        parser.add_argument(
            '--max-threads',
            type=int,
            default=10,
            help='Maximum concurrent connections'
        )

    def _detect_service(self, port: int) -> ServiceType:
        """
        Detect likely service based on port number

        Args:
            port: Target port number

        Returns:
            Most likely ServiceType
        """
        return self.common_ports.get(port, ServiceType.UNKNOWN)

    def _create_connection(self, target: str, port: int, proto: str = 'tcp') -> Optional[socket.socket]:
        """
        Create socket connection to target

        Args:
            target: Hostname or IP address
            port: Target port
            proto: 'tcp' or 'udp'

        Returns:
            Connected socket or None
        """
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
            )
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            return sock
        except Exception as e:
            logger.debug(f"Connection failed to {target}:{port}: {str(e)}")
            return None

    def _grab_generic_banner(self, target: str, port: int) -> BannerResult:
        """
        Generic banner grabbing for unknown services

        Args:
            target: Hostname or IP
            port: Target port

        Returns:
            BannerResult with captured data
        """
        try:
            sock = self._create_connection(target, port)
            if not sock:
                return BannerResult(port, ServiceType.UNKNOWN, "", b"", "Connection failed")

            # Try to read initial response
            banner = sock.recv(1024)
            sock.close()

            # Clean the banner
            clean_banner = self._clean_banner(banner)
            service = self._detect_service(port)

            return BannerResult(port, service, clean_banner, banner)
        except Exception as e:
            return BannerResult(port, ServiceType.UNKNOWN, "", b"", str(e))

    def _grab_http(self, target: str, port: int) -> BannerResult:
        """
        HTTP/HTTPS banner grabbing

        Args:
            target: Hostname or IP
            port: Target port

        Returns:
            BannerResult with HTTP headers
        """
        try:
            sock = self._create_connection(target, port)
            if not sock:
                return BannerResult(port, ServiceType.HTTP, "", b"", "Connection failed")

            # Send HTTP request
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(4096)
            sock.close()

            # Parse headers
            headers = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
            service = ServiceType.HTTPS if port == 443 else ServiceType.HTTP

            return BannerResult(port, service, headers, response)
        except Exception as e:
            return BannerResult(port, ServiceType.HTTP, "", b"", str(e))

    def _grab_ftp(self, target: str, port: int) -> BannerResult:
        """FTP banner grabbing implementation"""
        try:
            sock = self._create_connection(target, port)
            if not sock:
                return BannerResult(port, ServiceType.FTP, "", b"", "Connection failed")

            banner = sock.recv(1024)
            sock.close()

            clean_banner = self._clean_banner(banner)
            return BannerResult(port, ServiceType.FTP, clean_banner, banner)
        except Exception as e:
            return BannerResult(port, ServiceType.FTP, "", b"", str(e))

    def _grab_ssh(self, target: str, port: int) -> BannerResult:
        """SSH banner grabbing implementation"""
        try:
            sock = self._create_connection(target, port)
            if not sock:
                return BannerResult(port, ServiceType.SSH, "", b"", "Connection failed")

            banner = sock.recv(1024)
            sock.close()

            clean_banner = self._clean_banner(banner)
            return BannerResult(port, ServiceType.SSH, clean_banner, banner)
        except Exception as e:
            return BannerResult(port, ServiceType.SSH, "", b"", str(e))

    def _clean_banner(self, banner: bytes) -> str:
        """
        Clean and sanitize banner data

        Args:
            banner: Raw banner bytes

        Returns:
            Cleaned string representation
        """
        try:
            # Remove non-printable characters
            cleaned = re.sub(rb'[^\x20-\x7E]', b' ', banner).decode('utf-8', errors='ignore')
            return cleaned.strip()
        except:
            return str(banner)

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

    def grab_banners(self, target: str, ports: List[int],
                   protocol: str = 'auto') -> List[BannerResult]:
        """
        Main banner grabbing execution

        Args:
            target: Hostname or IP address
            ports: List of ports to check
            protocol: Force specific protocol or 'auto'

        Returns:
            List of BannerResult objects
        """
        results = []

        with ThreadPoolExecutor(max_workers=self.config.get('max_threads', 10)) as executor:
            futures = []

            for port in ports:
                if protocol == 'auto':
                    service = self._detect_service(port)
                    handler = self.protocol_handlers.get(service, self._grab_generic_banner)
                else:
                    handler = {
                        'http': self._grab_http,
                        'ftp': self._grab_ftp,
                        'ssh': self._grab_ssh,
                        'smtp': self._grab_smtp,
                        'dns': self._grab_dns
                    }.get(protocol, self._grab_generic_banner)

                futures.append(executor.submit(handler, target, port))

            for future in as_completed(futures):
                results.append(future.result())

        return results

    def run(self, args: argparse.Namespace) -> Dict:
        """
        Execute banner grabbing based on CLI arguments

        Args:
            args: Parsed CLI arguments

        Returns:
            Dictionary containing results and metadata
        """
        try:
            # Parse ports
            ports = self._parse_ports(args.ports)
            logger.info(f"Grabbing banners from {args.target} ports: {ports}")

            # Execute banner grabbing
            results = self.grab_banners(
                target=args.target,
                ports=ports,
                protocol=args.protocol
            )

            # Generate report data
            report_data = self._prepare_report(results)

            # Save results if requested
            if args.output:
                output_format = 'json' if args.json else 'text'
                write_report(report_data, args.output, output_format)
                logger.info(f"Results saved to {args.output}")

            return {
                'status': 'completed',
                'target': args.target,
                'results': report_data,
                'stats': self._generate_stats(results)
            }

        except Exception as e:
            logger.error(f"Banner grabbing failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def _prepare_report(self, results: List[BannerResult]) -> Dict:
        """
        Prepare banner results for reporting

        Args:
            results: List of BannerResult objects

        Returns:
            Dictionary formatted for reporting
        """
        report = {}
        for result in results:
            report[result.port] = {
                'service': result.service.name,
                'banner': result.banner,
                'error': result.error
            }
        return report

    def _generate_stats(self, results: List[BannerResult]) -> Dict:
        """
        Generate statistics from banner results

        Args:
            results: List of BannerResult objects

        Returns:
            Dictionary of statistics
        """
        stats = {
            'total': len(results),
            'successful': 0,
            'failed': 0,
            'services': {}
        }

        for result in results:
            if result.error:
                stats['failed'] += 1
            else:
                stats['successful'] += 1
                stats['services'][result.service.name] = stats['services'].get(result.service.name, 0) + 1

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
    grabber = BannerGrabber(config)
    return grabber.run(args)
