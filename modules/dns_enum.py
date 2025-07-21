"""
rabbitRecon DNS Enumeration Module
Active and passive DNS reconnaissance techniques
"""

import dns.resolver
import dns.reversename
import socket
import argparse
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from utils.logger import get_logger
from utils.thread_pool import ThreadPoolManager
from reports.report_writer import write_report
from modules.passive.dns_passive import PassiveDNSEnumerator

logger = get_logger('dns_enum')

@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: Optional[int] = None

class DNSEnumeration:
    """DNS enumeration module with active and passive techniques"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize DNS enumerator

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('dns_timeout', 5.0)
        self.resolver = self._configure_resolver()
        self.thread_pool = ThreadPoolManager(
            max_workers=self.config.get('max_threads', 10)
        )
        self.passive_enumerator = PassiveDNSEnumerator(config)

        # Common record types to check
        self.common_records = [
            'A', 'AAAA', 'MX', 'TXT',
            'NS', 'SOA', 'CNAME', 'SRV'
        ]

    def _configure_resolver(self) -> dns.resolver.Resolver:
        """
        Configure DNS resolver with project settings

        Returns:
            Configured dns.resolver.Resolver instance
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        if 'dns_servers' in self.config:
            resolver.nameservers = self.config['dns_servers']

        return resolver

    @staticmethod
    def setup_parser(parser: argparse.ArgumentParser) -> None:
        """
        Configure argument parser for DNS enumeration

        Args:
            parser: ArgumentParser instance to configure
        """
        parser.add_argument(
            'domain',
            help='Target domain name to enumerate'
        )
        parser.add_argument(
            '--types',
            default='A,AAAA,MX,TXT,NS',
            help='DNS record types to query (comma-separated)'
        )
        parser.add_argument(
            '--bruteforce',
            action='store_true',
            help='Enable subdomain bruteforcing'
        )
        parser.add_argument(
            '--wordlist',
            help='Wordlist for subdomain bruteforcing'
        )
        parser.add_argument(
            '--passive',
            action='store_true',
            help='Include passive DNS enumeration'
        )
        parser.add_argument(
            '--dns-server',
            help='Custom DNS server to use for queries'
        )

    def query_record(self, domain: str, record_type: str) -> List[DNSRecord]:
        """
        Perform DNS record query

        Args:
            domain: Domain name to query
            record_type: DNS record type (A, MX, TXT, etc.)

        Returns:
            List of DNSRecord objects
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [
                DNSRecord(
                    record_type=record_type,
                    value=str(r),
                    ttl=getattr(r, 'ttl', None)
                )
                for r in answers
            ]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception as e:
            logger.debug(f"DNS query failed for {record_type} {domain}: {str(e)}")
            return []

    def reverse_lookup(self, ip: str) -> List[str]:
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address to lookup

        Returns:
            List of PTR records
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return [str(r) for r in answers]
        except Exception:
            return []

    def _get_wordlist(self, wordlist_path: Optional[str] = None) -> List[str]:
        """
        Get subdomain bruteforce wordlist

        Args:
            wordlist_path: Custom wordlist path

        Returns:
            List of subdomain candidates
        """
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.warning(f"Couldn't load wordlist: {str(e)}")

        # Default built-in wordlist
        return [
            'www', 'mail', 'ftp', 'admin', 'webmail',
            'ns1', 'ns2', 'api', 'dev', 'test',
            'mx', 'static', 'cdn', 'app', 'blog'
        ]

    def bruteforce_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> Dict[str, List[DNSRecord]]:
        """
        Perform subdomain bruteforcing

        Args:
            domain: Base domain name
            wordlist: List of subdomain candidates

        Returns:
            Dictionary mapping subdomains to their A records
        """
        wordlist = wordlist or self._get_wordlist()
        results = {}

        with ThreadPoolExecutor(max_workers=self.config.get('max_threads', 10)) as executor:
            futures = {
                executor.submit(self.query_record, f"{sub}.{domain}", 'A'): sub
                for sub in wordlist
            }

            for future in as_completed(futures):
                sub = futures[future]
                records = future.result()
                if records:
                    results[sub] = records

        return results

    def run_enumeration(self, domain: str, record_types: List[str],
                       bruteforce: bool = False, wordlist: Optional[str] = None,
                       passive: bool = False) -> Dict:
        """
        Complete DNS enumeration workflow

        Args:
            domain: Target domain name
            record_types: List of record types to query
            bruteforce: Whether to perform subdomain bruteforcing
            wordlist: Path to wordlist file
            passive: Whether to include passive enumeration

        Returns:
            Dictionary containing all enumeration results
        """
        results = {
            'active': {},
            'passive': {},
            'bruteforce': {}
        }

        # Standard record queries
        for record_type in record_types:
            records = self.query_record(domain, record_type)
            if records:
                results['active'][record_type] = records

        # Subdomain bruteforcing
        if bruteforce:
            logger.info(f"Starting subdomain bruteforce on {domain}")
            wordlist_content = self._get_wordlist(wordlist)
            results['bruteforce'] = self.bruteforce_subdomains(domain, wordlist_content)

        # Passive DNS enumeration
        if passive:
            logger.info(f"Starting passive DNS enumeration on {domain}")
            results['passive'] = self.passive_enumerator.query(domain)

        return results

    def run(self, args: argparse.Namespace) -> Dict:
        """
        Execute DNS enumeration based on CLI arguments

        Args:
            args: Parsed CLI arguments

        Returns:
            Dictionary containing results and metadata
        """
        try:
            # Parse record types
            record_types = [rt.strip() for rt in args.types.split(',') if rt.strip()]

            # Configure custom DNS server if specified
            if args.dns_server:
                self.resolver.nameservers = [args.dns_server]

            # Run enumeration
            results = self.run_enumeration(
                domain=args.domain,
                record_types=record_types,
                bruteforce=args.bruteforce,
                wordlist=args.wordlist,
                passive=args.passive
            )

            # Generate statistics
            stats = self._generate_stats(results)

            # Save results if requested
            if args.output:
                output_format = 'json' if args.json else 'text'
                write_report(results, args.output, output_format)
                logger.info(f"Results saved to {args.output}")

            return {
                'status': 'completed',
                'domain': args.domain,
                'results': results,
                'stats': stats
            }

        except Exception as e:
            logger.error(f"DNS enumeration failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def _generate_stats(self, results: Dict) -> Dict:
        """
        Generate statistics from enumeration results

        Args:
            results: Dictionary of enumeration results

        Returns:
            Dictionary of statistics
        """
        stats = {
            'record_types': {},
            'subdomains_found': 0,
            'passive_results': 0,
            'ip_addresses': set()
        }

        # Active records
        for rt, records in results['active'].items():
            stats['record_types'][rt] = len(records)
            if rt in ['A', 'AAAA']:
                stats['ip_addresses'].update(r.value for r in records)

        # Bruteforce results
        stats['subdomains_found'] = len(results['bruteforce'])
        for records in results['bruteforce'].values():
            stats['ip_addresses'].update(r.value for r in records)

        # Passive results
        if 'A' in results['passive']:
            stats['passive_results'] = len(results['passive']['A'])
            stats['ip_addresses'].update(r['value'] for r in results['passive']['A'])

        stats['unique_ips'] = len(stats['ip_addresses'])
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
    enumerator = DNSEnumeration(config)
    return enumerator.run(args)
