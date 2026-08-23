"""
Scanner module for Sentinel.

This module contains all security scanners that check websites
for vulnerabilities and misconfigurations.

The scanners are organized as follows:
- BaseScanner: Abstract base class for all scanners
- HTTPScanner: Basic HTTP checks (redirects, status codes, server headers)
- SecurityHeadersScanner: Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- TLSScanner: TLS/SSL certificate validation and configuration
- DNSScanner: DNS record analysis (SPF, DMARC, DKIM)
- CookieScanner: Cookie security analysis (Secure, HttpOnly, SameSite)
- RobotsScanner: robots.txt analysis for information disclosure
- SitemapScanner: sitemap.xml analysis for URL discovery
- TechnologyScanner: Technology/framework detection
- PassiveScanner: Passive vulnerability detection (no active requests)
- ScannerOrchestrator: Orchestrates all scanners for a complete scan

Usage:
    orchestrator = ScannerOrchestrator("https://example.com")
    results = await orchestrator.run_scan(scan_type="full")
"""

from app.scanners.base import BaseScanner
from app.scanners.http_scanner import HTTPScanner
from app.scanners.security_headers_scanner import SecurityHeadersScanner
from app.scanners.tls_scanner import TLSScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.cookie_scanner import CookieScanner
from app.scanners.robots_scanner import RobotsScanner
from app.scanners.sitemap_scanner import SitemapScanner
from app.scanners.technology_scanner import TechnologyScanner
from app.scanners.passive_scanner import PassiveScanner
from app.scanners.orchestrator import ScannerOrchestrator

__all__ = [
    "BaseScanner",
    "HTTPScanner",
    "SecurityHeadersScanner",
    "TLSScanner",
    "DNSScanner",
    "CookieScanner",
    "RobotsScanner",
    "SitemapScanner",
    "TechnologyScanner",
    "PassiveScanner",
    "ScannerOrchestrator",
]