"""
DNS Scanner for Sentinel.

Analyzes DNS configuration and records:
- A/AAAA records
- MX records
- SPF records
- DMARC records
- DKIM records
- CNAME records
- NS records
- SOA records
"""

import dns.resolver
import dns.exception
import socket
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

from app.scanners.base import BaseScanner


class DNSScanner(BaseScanner):
    """
    DNS Scanner.

    Checks:
    - DNS resolution
    - SPF records
    - DMARC records
    - DKIM detection
    - MX records
    - NS records
    """

    def __init__(self, target_url: str, **kwargs):
        super().__init__(target_url, **kwargs)
        self._extract_domain()

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "dns"

    def _extract_domain(self) -> None:
        """Extract domain from target URL."""
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc or self.target_url
        # Remove port if present
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]
        # Remove www prefix for better DNS checks
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the DNS scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting DNS scan for {self.domain}")
        self.findings = []

        try:
            # Run DNS checks
            await self._check_dns_resolution()
            await self._check_spf_record()
            await self._check_dmarc_record()
            await self._check_dkim_records()
            await self._check_mx_records()
            await self._check_ns_records()
            await self._check_cname_records()
            await self._check_ipv6_support()

        except Exception as e:
            self._log_error(f"DNS scan failed: {e}")
            finding = self._create_finding(
                severity="high",
                title="DNS Scan Failed",
                description=f"Failed to perform DNS checks: {str(e)}",
                evidence=f"Error: {str(e)}",
                remediation=(
                    "Ensure the domain is valid and DNS servers are responding."
                ),
                confidence=0.9,
            )
            self._add_finding(finding)

        self._log_info(f"DNS scan completed. Found {len(self.findings)} findings.")
        return self.findings

    async def _check_dns_resolution(self) -> None:
        """Check if domain resolves to an IP address."""
        try:
            # Try to resolve domain
            answers = dns.resolver.resolve(self.domain, "A")
            ips = [str(r) for r in answers]

            self._log_info(f"Domain resolves to: {', '.join(ips)}")

            # Check if any IPs are private (for informational purposes)
            private_ips = [ip for ip in ips if self._is_private_ip(ip)]
            if private_ips:
                self._log_warning(f"Domain resolves to private IPs: {private_ips}")

        except dns.resolver.NXDOMAIN:
            finding = self._create_finding(
                severity="critical",
                title="Domain Does Not Exist",
                description=f"The domain '{self.domain}' does not exist in DNS.",
                evidence=f"NXDOMAIN for {self.domain}",
                remediation="Check if the domain is registered and DNS is configured correctly.",
                confidence=1.0,
            )
            self._add_finding(finding)

        except dns.resolver.NoAnswer:
            finding = self._create_finding(
                severity="high",
                title="No A Record Found",
                description=f"No A record found for '{self.domain}'. The website may not be reachable.",
                evidence=f"No A record for {self.domain}",
                remediation="Add an A record pointing to the server's IP address.",
                confidence=0.95,
            )
            self._add_finding(finding)

        except dns.exception.Timeout:
            finding = self._create_finding(
                severity="medium",
                title="DNS Resolution Timeout",
                description=f"DNS resolution for '{self.domain}' timed out.",
                evidence="DNS query timeout",
                remediation="Check DNS server availability and network connectivity.",
                confidence=0.8,
            )
            self._add_finding(finding)

        except Exception as e:
            self._log_warning(f"DNS resolution error: {e}")

    async def _check_spf_record(self) -> None:
        """Check SPF (Sender Policy Framework) record."""
        try:
            answers = dns.resolver.resolve(self.domain, "TXT")
            spf_records = []

            for answer in answers:
                txt = "".join(answer.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)

            if not spf_records:
                finding = self._create_finding(
                    severity="medium",
                    title="SPF Record Missing",
                    description=(
                        "No SPF record found. This increases the risk of email spoofing "
                        "and phishing attacks against the domain."
                    ),
                    evidence=f"No SPF record for {self.domain}",
                    remediation=(
                        "Add an SPF record: `v=spf1 mx -all` (or a more specific policy). "
                        "Use a tool like spf.greenend.org.uk to generate a proper SPF record."
                    ),
                    confidence=0.9,
                    references=[
                        "https://dmarc.org/",
                        "https://www.rfc-editor.org/rfc/rfc7208.html",
                    ],
                )
                self._add_finding(finding)
            else:
                self._log_info(f"Found SPF record: {spf_records[0]}")

                # Check if SPF is properly configured
                if "~all" in spf_records[0] and "?all" not in spf_records[0]:
                    self._log_info("SPF uses soft fail (~all) - good practice")
                elif "-all" in spf_records[0]:
                    self._log_info("SPF uses hard fail (-all) - strict policy")
                elif "?all" in spf_records[0]:
                    finding = self._create_finding(
                        severity="low",
                        title="SPF Uses Neutral Fail",
                        description="SPF policy uses '?all' which is a neutral policy. This provides minimal protection.",
                        evidence=f"SPF: {spf_records[0]}",
                        remediation="Use '~all' (soft fail) or '-all' (hard fail) for better protection.",
                        confidence=0.8,
                    )
                    self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            self._log_warning(f"No SPF record for {self.domain}")
        except dns.resolver.NoAnswer:
            self._log_warning(f"No TXT records for {self.domain}")
        except Exception as e:
            self._log_warning(f"SPF check error: {e}")

    async def _check_dmarc_record(self) -> None:
        """Check DMARC record."""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = []

            for answer in answers:
                txt = "".join(answer.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)

            if not dmarc_records:
                finding = self._create_finding(
                    severity="high",
                    title="DMARC Record Missing",
                    description=(
                        "No DMARC record found. This allows email spoofing and phishing "
                        "attacks using the domain."
                    ),
                    evidence=f"No DMARC record for {self.domain}",
                    remediation=(
                        "Add a DMARC record: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`. "
                        "Start with p=none, then move to p=quarantine, then p=reject."
                    ),
                    confidence=0.9,
                    references=[
                        "https://dmarc.org/",
                        "https://www.rfc-editor.org/rfc/rfc7489.html",
                    ],
                )
                self._add_finding(finding)
            else:
                self._log_info(f"Found DMARC record: {dmarc_records[0]}")

                # Check policy
                if "p=reject" in dmarc_records[0].lower():
                    self._log_info("DMARC policy: reject (good)")
                elif "p=quarantine" in dmarc_records[0].lower():
                    self._log_info("DMARC policy: quarantine (good)")
                elif "p=none" in dmarc_records[0].lower():
                    finding = self._create_finding(
                        severity="low",
                        title="DMARC Policy is None",
                        description="DMARC policy is set to 'none', which means no action is taken on failures.",
                        evidence=f"DMARC: {dmarc_records[0]}",
                        remediation="Change DMARC policy to 'quarantine' or 'reject' after monitoring.",
                        confidence=0.8,
                    )
                    self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            self._log_warning(f"No DMARC record for {self.domain}")
        except dns.resolver.NoAnswer:
            self._log_warning(f"No TXT records for _dmarc.{self.domain}")
        except Exception as e:
            self._log_warning(f"DMARC check error: {e}")

    async def _check_dkim_records(self) -> None:
        """Check DKIM records."""
        try:
            # Common DKIM selectors
            selectors = ["default", "dkim", "mail", "google", "selector1", "selector2"]
            found_dkim = []

            for selector in selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{self.domain}"
                    answers = dns.resolver.resolve(dkim_domain, "TXT")
                    for answer in answers:
                        txt = "".join(answer.strings).decode("utf-8", errors="ignore")
                        if "v=DKIM1" in txt:
                            found_dkim.append(f"{selector}: {txt[:100]}...")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception:
                    continue

            if not found_dkim:
                finding = self._create_finding(
                    severity="medium",
                    title="DKIM Records Missing",
                    description=(
                        "No DKIM records found. This allows email spoofing and phishing "
                        "attacks against the domain."
                    ),
                    evidence=f"No DKIM records for {self.domain}",
                    remediation=(
                        "Configure DKIM signing for your email domain. "
                        "Contact your email provider for specific DKIM setup instructions."
                    ),
                    confidence=0.8,
                    references=[
                        "https://www.dkim.org/",
                        "https://www.rfc-editor.org/rfc/rfc6376.html",
                    ],
                )
                self._add_finding(finding)
            else:
                self._log_info(f"Found {len(found_dkim)} DKIM records")

        except Exception as e:
            self._log_warning(f"DKIM check error: {e}")

    async def _check_mx_records(self) -> None:
        """Check MX records."""
        try:
            answers = dns.resolver.resolve(self.domain, "MX")
            mx_records = sorted(answers, key=lambda x: x.preference)

            if mx_records:
                self._log_info(f"Found {len(mx_records)} MX records")
                for mx in mx_records[:5]:
                    self._log_debug(f"MX: {mx.preference} -> {mx.exchange}")
            else:
                finding = self._create_finding(
                    severity="low",
                    title="No MX Records Found",
                    description="No MX records found. The domain may not have email configured.",
                    evidence=f"No MX records for {self.domain}",
                    remediation="If email is needed, add MX records pointing to your email provider.",
                    confidence=0.7,
                )
                self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            self._log_warning(f"No MX records for {self.domain}")
        except dns.resolver.NoAnswer:
            self._log_warning(f"No MX records for {self.domain}")
        except Exception as e:
            self._log_warning(f"MX check error: {e}")

    async def _check_ns_records(self) -> None:
        """Check NS records."""
        try:
            answers = dns.resolver.resolve(self.domain, "NS")
            ns_records = [str(r) for r in answers]

            if ns_records:
                self._log_info(f"Found NS records: {', '.join(ns_records[:5])}")

                # Check if there are multiple NS records (redundancy)
                if len(ns_records) < 2:
                    finding = self._create_finding(
                        severity="low",
                        title="Single DNS Server",
                        description="Only one NS record found. This creates a single point of failure.",
                        evidence=f"NS records: {ns_records}",
                        remediation="Add at least two NS records for redundancy.",
                        confidence=0.7,
                    )
                    self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            self._log_warning(f"No NS records for {self.domain}")
        except dns.resolver.NoAnswer:
            self._log_warning(f"No NS records for {self.domain}")
        except Exception as e:
            self._log_warning(f"NS check error: {e}")

    async def _check_cname_records(self) -> None:
        """Check CNAME records."""
        try:
            answers = dns.resolver.resolve(self.domain, "CNAME")
            cname = str(answers[0])

            finding = self._create_finding(
                severity="info",
                title="Domain is a CNAME",
                description=f"The domain '{self.domain}' is a CNAME to '{cname}'.",
                evidence=f"CNAME: {self.domain} -> {cname}",
                remediation="No action required. This is informational.",
                confidence=1.0,
                metadata={"cname": cname},
            )
            self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            pass  # No CNAME record, that's fine
        except dns.resolver.NoAnswer:
            pass  # No CNAME record
        except Exception as e:
            self._log_warning(f"CNAME check error: {e}")

    async def _check_ipv6_support(self) -> None:
        """Check if domain has IPv6 support (AAAA record)."""
        try:
            answers = dns.resolver.resolve(self.domain, "AAAA")
            ipv6_addresses = [str(r) for r in answers]

            if ipv6_addresses:
                self._log_info(f"IPv6 supported: {', '.join(ipv6_addresses[:3])}")
            else:
                finding = self._create_finding(
                    severity="info",
                    title="IPv6 Not Supported",
                    description="No AAAA records found. The domain does not have IPv6 support.",
                    evidence=f"No AAAA records for {self.domain}",
                    remediation="Consider adding AAAA records for IPv6 support if needed.",
                    confidence=0.8,
                )
                self._add_finding(finding)

        except dns.resolver.NXDOMAIN:
            self._log_warning(f"No AAAA records for {self.domain}")
        except dns.resolver.NoAnswer:
            self._log_warning(f"No AAAA records for {self.domain}")
        except Exception as e:
            self._log_warning(f"IPv6 check error: {e}")

    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.

        Args:
            ip: IP address string.

        Returns:
            bool: True if private IP.
        """
        # Simplified private IP check
        private_ranges = [
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
            "::1",
            "fe80::",
            "fd00::",
        ]

        return any(ip.startswith(prefix) for prefix in private_ranges)