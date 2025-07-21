"""
rabbitRecon WAF Detection Module
Web Application Firewall fingerprinting and detection
"""

import requests
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto

from utils.logger import get_logger
from utils.config import load_config
from reports.report_writer import write_report

logger = get_logger('waf_detect')

class WAFType(Enum):
    CLOUDFLARE = auto()
    AKAMAI = auto()
    INCAPSULA = auto()
    AWS_WAF = auto()
    MODSECURITY = auto()
    BARRAKUDDA = auto()
    UNKNOWN = auto()

@dataclass
class WAFDetectionResult:
    waf_type: WAFType
    confidence: float
    evidence: List[str]
    vendor: Optional[str] = None
    version: Optional[str] = None

class WAFDetector:
    """WAF detection engine with multiple fingerprinting techniques"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize WAF detector with configuration

        Args:
            config: Configuration dictionary
        """
        self.config = config or load_config()
        self.timeout = self.config.get('waf_timeout', 5.0)
        self.session = requests.Session()
        self._configure_session()

        # WAF fingerprint database
        self.waf_signatures = [
            {
                'name': 'Cloudflare',
                'type': WAFType.CLOUDFLARE,
                'signatures': [
                    (r'cloudflare', 'server'),
                    (r'__cfduid', 'cookie'),
                    (r'cf-ray', 'header'),
                    (r'cloudflare-nginx', 'server')
                ]
            },
            {
                'name': 'Akamai',
                'type': WAFType.AKAMAI,
                'signatures': [
                    (r'akamai', 'server'),
                    (r'X-Akamai-Transformed', 'header')
                ]
            },
            {
                'name': 'Incapsula',
                'type': WAFType.INCAPSULA,
                'signatures': [
                    (r'incap_ses', 'cookie'),
                    (r'visid_incap', 'cookie'),
                    (r'X-Iinfo', 'header')
                ]
            },
            {
                'name': 'AWS WAF',
                'type': WAFType.AWS_WAF,
                'signatures': [
                    (r'aws', 'server'),
                    (r'X-AWS-', 'header')
                ]
            },
            {
                'name': 'ModSecurity',
                'type': WAFType.MODSECURITY,
                'signatures': [
                    (r'Mod_Security', 'server'),
                    (r'NS-', 'header')
                ]
            },
            {
                'name': 'Barracuda',
                'type': WAFType.BARRAKUDDA,
                'signatures': [
                    (r'barracuda', 'server'),
                    (r'barra_counter_session', 'cookie')
                ]
            }
        ]

        # Malicious payloads to trigger WAF responses
        self.test_payloads = [
            ("../../etc/passwd", "Path Traversal"),
            ("<script>alert(1)</script>", "XSS"),
            ("' OR 1=1 --", "SQL Injection"),
            ("|cat /etc/passwd", "Command Injection")
        ]

    def _configure_session(self):
        """Configure HTTP session with project settings"""
        if self.config.get('user_agent'):
            self.session.headers.update({
                'User-Agent': self.config['user_agent']
            })

        if self.config.get('proxy'):
            self.session.proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }

    @staticmethod
    def setup_parser(parser: argparse.ArgumentParser) -> None:
        """
        Configure argument parser for WAF detection

        Args:
            parser: ArgumentParser instance to configure
        """
        parser.add_argument(
            'url',
            help='Target URL to test for WAF'
        )
        parser.add_argument(
            '--aggressive',
            action='store_true',
            help='Use aggressive detection techniques'
        )
        parser.add_argument(
            '--skip-evasion',
            action='store_true',
            help='Skip WAF evasion techniques'
        )
        parser.add_argument(
            '--timeout',
            type=float,
            default=5.0,
            help='Request timeout in seconds'
        )

    def _send_probe(self, url: str, payload: Optional[str] = None) -> requests.Response:
        """
        Send a probe request to detect WAF presence

        Args:
            url: Target URL
            payload: Optional malicious payload

        Returns:
            HTTP response object
        """
        try:
            if payload:
                # Use evasion techniques if not skipped
                if not self.config.get('skip_evasion'):
                    payload = self._apply_evasion(payload)

                # Append payload as query parameter
                test_url = f"{url}?test={payload}"
            else:
                test_url = url

            return self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False
            )
        except requests.RequestException as e:
            logger.debug(f"Probe request failed: {str(e)}")
            raise

    def _apply_evasion(self, payload: str) -> str:
        """
        Apply WAF evasion techniques to payload

        Args:
            payload: Original malicious payload

        Returns:
            Obfuscated payload
        """
        # Simple URL encoding
        payload = payload.replace(' ', '%20')
        payload = payload.replace('=', '%3D')

        # Case variation
        if '<script>' in payload.lower():
            payload = payload.replace('<script>', '<ScRiPt>')

        return payload

    def _analyze_response(self, response: requests.Response) -> List[WAFDetectionResult]:
        """
        Analyze HTTP response for WAF fingerprints

        Args:
            response: HTTP response to analyze

        Returns:
            List of WAFDetectionResult objects
        """
        results = []

        # Check headers, cookies, and server info
        response_data = {
            'headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'server': response.headers.get('Server', ''),
            'body': response.text[:5000]  # Only check first part of body
        }

        # Check against known WAF signatures
        for waf in self.waf_signatures:
            evidence = []
            for pattern, location in waf['signatures']:
                if location in response_data:
                    if re.search(pattern, response_data[location], re.I):
                        evidence.append(f"{location}: {pattern}")

            if evidence:
                confidence = min(90 + (len(evidence) * 5, 100)
                results.append(WAFDetectionResult(
                    waf_type=waf['type'],
                    confidence=confidence,
                    evidence=evidence,
                    vendor=waf['name']
                ))

        # Check for generic WAF indicators
        if not results:
            generic_indicators = [
                (r'Access Denied', 'body'),
                (r'security violation', 'body'),
                (r'Web Application Firewall', 'body'),
                (r'Request Rejected', 'body')
            ]

            evidence = []
            for pattern, location in generic_indicators:
                if location in response_data:
                    if re.search(pattern, response_data[location], re.I):
                        evidence.append(f"{location}: {pattern}")

            if evidence:
                results.append(WAFDetectionResult(
                    waf_type=WAFType.UNKNOWN,
                    confidence=75,
                    evidence=evidence,
                    vendor='Generic WAF'
                ))

        return results

    def _check_block_page(self, response: requests.Response) -> bool:
        """
        Check if response is a WAF block page

        Args:
            response: HTTP response to check

        Returns:
            True if response appears to be a block page
        """
        if response.status_code in [403, 406, 419]:
            return True

        content = response.text.lower()
        block_indicators = [
            'blocked',
            'forbidden',
            'security',
            'waf',
            'access denied'
        ]

        return any(indicator in content for indicator in block_indicators)

    def detect_waf(self, url: str, aggressive: bool = False) -> List[WAFDetectionResult]:
        """
        Detect WAF presence using multiple techniques

        Args:
            url: Target URL to test
            aggressive: Whether to use intrusive detection

        Returns:
            List of WAFDetectionResult objects
        """
        results = []

        # Step 1: Initial benign request
        try:
            response = self._send_probe(url)
            initial_results = self._analyze_response(response)
            results.extend(initial_results)

            # If we already found clear WAF signatures, return early
            if any(r.confidence > 90 for r in results):
                return results
        except:
            pass

        # Step 2: Malicious payload probes
        if aggressive:
            for payload, payload_type in self.test_payloads:
                try:
                    response = self._send_probe(url, payload)

                    # Check if we got blocked
                    if self._check_block_page(response):
                        results.append(WAFDetectionResult(
                            waf_type=WAFType.UNKNOWN,
                            confidence=85,
                            evidence=[f"Blocked {payload_type} payload"],
                            vendor='Behavior-based detection'
                        ))

                    # Analyze response for WAF fingerprints
                    payload_results = self._analyze_response(response)
                    results.extend(payload_results)

                except:
                    continue

        # Deduplicate results
        unique_results = []
        seen_types = set()
        for result in sorted(results, key=lambda x: x.confidence, reverse=True):
            if result.waf_type not in seen_types:
                unique_results.append(result)
                seen_types.add(result.waf_type)

        return unique_results

    def run(self, args: argparse.Namespace) -> Dict:
        """
        Execute WAF detection based on CLI arguments

        Args:
            args: Parsed CLI arguments

        Returns:
            Dictionary containing results and metadata
        """
        try:
            # Update config from CLI args
            self.config.update({
                'skip_evasion': args.skip_evasion,
                'waf_timeout': args.timeout
            })
            self._configure_session()

            logger.info(f"Starting WAF detection for {args.url}")
            results = self.detect_waf(args.url, args.aggressive)

            # Prepare report data
            report_data = self._prepare_report(results)

            # Save results if requested
            if args.output:
                output_format = 'json' if args.json else 'text'
                write_report(report_data, args.output, output_format)
                logger.info(f"Results saved to {args.output}")

            return {
                'status': 'completed',
                'url': args.url,
                'results': report_data,
                'waf_detected': len(results) > 0
            }

        except Exception as e:
            logger.error(f"WAF detection failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def _prepare_report(self, results: List[WAFDetectionResult]) -> List[Dict]:
        """
        Prepare WAF results for reporting

        Args:
            results: List of WAFDetectionResult objects

        Returns:
            List of dictionaries for reporting
        """
        return [
            {
                'type': result.waf_type.name,
                'vendor': result.vendor,
                'confidence': result.confidence,
                'evidence': result.evidence,
                'version': result.version
            }
            for result in results
        ]

def run_module(args: argparse.Namespace, config: Dict) -> Dict:
    """
    Module entry point for CLI integration

    Args:
        args: Parsed CLI arguments
        config: Configuration dictionary

    Returns:
        Dictionary with results and status
    """
    detector = WAFDetector(config)
    return detector.run(args)
