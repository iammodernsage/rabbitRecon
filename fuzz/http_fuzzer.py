#!/usr/bin/env python3
"""
rabbitRecon HTTP Fuzzer - Flexible web application fuzzing tool
Supports path, header, parameter, and method fuzzing
"""

import requests
import random
import time
from typing import List, Dict, Optional, Tuple, Generator
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from utils.thread_pool import ThreadPoolManager

class HTTPFuzzer:
    """Main HTTP fuzzing engine"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.log = get_logger('http_fuzzer')
        self.session = requests.Session()
        self.thread_pool = ThreadPoolManager(
            max_workers=self.config.get('max_threads', 10)
        )
        self.fuzz_types = {
            'path': self._fuzz_path,
            'param': self._fuzz_parameter,
            'header': self._fuzz_header,
            'method': self._fuzz_method
        }

        # Configure session
        self._configure_session()

    def _configure_session(self):
        """Setup HTTP session with configured settings"""
        if self.config.get('user_agent'):
            self.session.headers.update({
                'User-Agent': self.config['user_agent']
            })

        if self.config.get('proxy'):
            self.session.proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }

        if self.config.get('auth'):
            self.session.auth = (
                self.config['auth']['username'],
                self.config['auth']['password']
            )

        if self.config.get('headers'):
            self.session.headers.update(self.config['headers'])

    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load fuzzing wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log.error(f"Failed to load wordlist: {str(e)}")
            raise

    def _generate_payloads(self, wordlist: List[str], fuzz_type: str) -> Generator:
        """Generate fuzzing payloads based on type"""
        if fuzz_type == 'path':
            for word in wordlist:
                yield f"/{word}"
        elif fuzz_type == 'param':
            for word in wordlist:
                yield {word: self.config.get('param_value', 'FUZZ')}
        elif fuzz_type == 'header':
            for word in wordlist:
                yield {word: self.config.get('header_value', 'FUZZ')}
        elif fuzz_type == 'method':
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            for method in methods:
                yield method
        else:
            raise ValueError(f"Unknown fuzz type: {fuzz_type}")

    def _fuzz_path(self, base_url: str, payload: str) -> Tuple[str, Dict]:
        """Fuzz URL paths"""
        url = urljoin(base_url, payload)
        try:
            response = self.session.get(
                url,
                timeout=self.config.get('timeout', 10),
                allow_redirects=self.config.get('follow_redirects', True)
            )
            return (url, self._process_response(response))
        except Exception as e:
            self.log.debug(f"Path fuzz error on {url}: {str(e)}")
            return (url, {'error': str(e), 'status': 'failed'})

    def _fuzz_parameter(self, base_url: str, payload: Dict) -> Tuple[str, Dict]:
        """Fuzz query parameters"""
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query.update(payload)

        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(query, doseq=True),
            parsed.fragment
        ))

        try:
            response = self.session.get(
                new_url,
                timeout=self.config.get('timeout', 10),
                allow_redirects=self.config.get('follow_redirects', True)
            )
            return (new_url, self._process_response(response))
        except Exception as e:
            self.log.debug(f"Param fuzz error on {new_url}: {str(e)}")
            return (new_url, {'error': str(e), 'status': 'failed'})

    def _fuzz_header(self, base_url: str, payload: Dict) -> Tuple[str, Dict]:
        """Fuzz HTTP headers"""
        headers = {**self.session.headers, **payload}
        try:
            response = self.session.get(
                base_url,
                headers=headers,
                timeout=self.config.get('timeout', 10),
                allow_redirects=self.config.get('follow_redirects', True)
            )
            return (base_url, self._process_response(response))
        except Exception as e:
            self.log.debug(f"Header fuzz error on {base_url}: {str(e)}")
            return (base_url, {'error': str(e), 'status': 'failed'})

    def _fuzz_method(self, base_url: str, payload: str) -> Tuple[str, Dict]:
        """Fuzz HTTP methods"""
        try:
            response = self.session.request(
                payload,
                base_url,
                timeout=self.config.get('timeout', 10),
                allow_redirects=self.config.get('follow_redirects', True)
            )
            return (base_url, self._process_response(response))
        except Exception as e:
            self.log.debug(f"Method fuzz error ({payload}) on {base_url}: {str(e)}")
            return (base_url, {'error': str(e), 'status': 'failed'})

    def _process_response(self, response: requests.Response) -> Dict:
        """Analyze and normalize HTTP response"""
        return {
            'status': 'success',
            'status_code': response.status_code,
            'content_length': len(response.content),
            'headers': dict(response.headers),
            'redirects': [r.url for r in response.history],
            'final_url': response.url,
            'response_time': response.elapsed.total_seconds(),
            'patterns': self._detect_patterns(response)
        }

    def _detect_patterns(self, response: requests.Response) -> Dict:
        """Detect interesting patterns in responses"""
        content = response.text.lower()
        patterns = {
            'error_strings': [],
            'success_strings': [],
            'interesting_strings': []
        }

        # Detect common error patterns
        error_indicators = [
            'error', 'exception', 'stack trace', 'syntax error',
            'database error', 'failed', 'not found', 'invalid'
        ]
        patterns['error_strings'] = [
            s for s in error_indicators if s in content
        ]

        # Detect success patterns
        success_indicators = [
            'success', 'welcome', 'logged in', 'admin', 'dashboard',
            'password', 'username', 'login'
        ]
        patterns['success_strings'] = [
            s for s in success_indicators if s in content
        ]

        # Detect other interesting patterns
        interesting_indicators = [
            'password', 'secret', 'key', 'token', 'auth',
            'debug', 'config', 'backup', 'sql', 'query'
        ]
        patterns['interesting_strings'] = [
            s for s in interesting_indicators if s in content
        ]

        return patterns

    def run(
        self,
        base_url: str,
        wordlist_path: str,
        fuzz_type: str = 'path',
        rate_limit: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Dict]:
        """
        Main fuzzing execution method

        Args:
            base_url: Target URL to fuzz
            wordlist_path: Path to wordlist file
            fuzz_type: Type of fuzzing (path, param, header, method)
            rate_limit: Maximum requests per second
            **kwargs: Additional fuzzing parameters

        Returns:
            Dictionary of results with URLs as keys
        """
        if fuzz_type not in self.fuzz_types:
            raise ValueError(f"Invalid fuzz type. Choose from: {list(self.fuzz_types.keys())}")

        # Update config from kwargs
        self.config.update(kwargs)
        self._configure_session()

        # Load wordlist
        wordlist = self._load_wordlist(wordlist_path)
        if not wordlist:
            raise ValueError("Wordlist is empty or could not be loaded")

        self.log.info(f"Starting {fuzz_type} fuzzing on {base_url} with {len(wordlist)} payloads")

        results = {}
        fuzz_func = self.fuzz_types[fuzz_type]
        payloads = self._generate_payloads(wordlist, fuzz_type)

        # Execute fuzzing with thread pool
        futures = []
        for payload in payloads:
            if rate_limit:
                time.sleep(1 / rate_limit)

            future = self.thread_pool.submit_task(fuzz_func, base_url, payload)
            futures.append(future)

            # Early exit if we have too many errors
            if len(futures) > 100 and \
               sum(1 for f in futures if f.done() and 'error' in f.result()[1]) > 50:
                self.log.warning("Too many errors, stopping fuzzing")
                break

        # Process results as they complete
        for future in as_completed(futures):
            url, result = future.result()
            results[url] = result

            # Log interesting findings
            if result.get('status') == 'success':
                if result['status_code'] in [200, 301, 302, 403, 500]:
                    self.log.info(
                        f"Found [{result['status_code']}] {url} "
                        f"(Length: {result['content_length']})"
                    )
                    if result['patterns']['interesting_strings']:
                        self.log.warning(
                            f"Interesting strings in response: "
                            f"{result['patterns']['interesting_strings']}"
                        )

        return results

    def save_results(self, results: Dict, output_path: str, format: str = 'json'):
        """Save fuzzing results to file"""
        from reports.report_writer import write_report
        write_report(results, output_path, format)
