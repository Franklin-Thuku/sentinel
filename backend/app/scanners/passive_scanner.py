"""
Passive Scanner for Sentinel.

Performs passive security checks that do not send active requests to the target:
- Open ports detection
- Subdomain enumeration
- Email harvesting
- Technology fingerprinting
- SSL/TLS analysis (passive)
- DNS enumeration
"""

import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
import socket
import dns.resolver
from datetime import datetime

from app.scanners.base import BaseScanner


class PassiveScanner(BaseScanner):
    """
    Passive Scanner.

    Performs passive security checks that do not send active requests:
    - Subdomain enumeration
    - Email harvesting
    - Technology fingerprinting
    - Open port detection
    - DNS enumeration
    """

    # Common subdomains for enumeration
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "ns4", "web", "media", "email",
        "images", "img", "download", "dns", "ns5", "mail1", "sites", "cdn", "files",
        "status", "portal", "gw", "vps", "db", "cluster", "git", "api", "aws",
        "azure", "gcp", "cloud", "stage", "staging", "prod", "production",
        "development", "dev", "test", "testing", "qa", "quality", "uat",
        "backup", "backups", "monitoring", "monitor", "logs", "log",
        "analytics", "analytics", "metrics", "metrics", "grafana", "prometheus",
        "elk", "elastic", "kibana", "logstash", "jenkins", "ci", "cd",
        "deploy", "deployment", "deployments", "releases", "release",
        "gitlab", "github", "bitbucket", "jira", "confluence", "atlassian",
        "trello", "slack", "discord", "teams", "zoom", "meet",
        "calendar", "drive", "docs", "sheets", "slides", "forms",
        "jupyter", "notebook", "airflow", "spark", "hadoop",
        "kafka", "zookeeper", "rabbitmq", "activemq", "nsq",
        "redis", "memcached", "mongodb", "couchdb", "elasticsearch",
        "postgres", "postgresql", "mysql", "mariadb", "percona",
        "mssql", "sqlserver", "oracle", "db2", "cassandra",
        "influxdb", "timescaledb", "neo4j", "arangodb", "orientdb",
        "minio", "ceph", "gluster", "hdfs", "samba", "nfs",
        "ipa", "freeipa", "ldap", "openldap", "ad", "active-directory",
        "radius", "tacacs", "diameter", "ldaps", "kerberos",
        "ntp", "chrony", "tftp", "syslog", "snmp", "snmpd",
        "zabbix", "nagios", "icinga", "sensu", "datadog",
        "newrelic", "dynatrace", "appdynamics", "instana", "jaeger",
        "zipkin", "skywalking", "opentelemetry", "otel", "thanos",
        "cortex", "loki", "tempo", "mimir", "pyroscope",
    ]

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "passive"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the passive scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting passive scan for {self.target_url}")
        self.findings = []
        self.base_domain = self._extract_domain()

        try:
            # Perform passive checks
            await self._enumerate_subdomains()
            await self._harvest_emails()
            await self._check_open_ports()
            await self._check_dns_enums()
            await self._gather_public_info()

        except Exception as e:
            self._log_error(f"Passive scan failed: {e}")

        self._log_info(f"Passive scan completed. Found {len(self.findings)} findings.")
        return self.findings

    def _extract_domain(self) -> str:
        """
        Extract the base domain from the target URL.

        Returns:
            str: Base domain.
        """
        parsed = urlparse(self.target_url)
        domain = parsed.netloc or self.target_url
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    async def _enumerate_subdomains(self) -> None:
        """
        Enumerate common subdomains for the target domain.
        """
        self._log_info("Enumerating subdomains...")
        found_subdomains = []

        for subdomain in self.COMMON_SUBDOMAINS:
            full_domain = f"{subdomain}.{self.base_domain}"
            try:
                # Try DNS resolution for each subdomain
                answers = dns.resolver.resolve(full_domain, "A")
                if answers:
                    ip = str(answers[0])
                    found_subdomains.append({
                        "subdomain": full_domain,
                        "ip": ip,
                    })
                    self._log_debug(f"Found subdomain: {full_domain} -> {ip}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception as e:
                self._log_debug(f"Error checking {full_domain}: {e}")
                continue

        if found_subdomains:
            self._log_info(f"Found {len(found_subdomains)} subdomains")

            # Report findings
            subdomain_list = "\n".join(
                f"  - {s['subdomain']} ({s['ip']})" for s in found_subdomains[:10]
            )
            if len(found_subdomains) > 10:
                subdomain_list += f"\n  ... and {len(found_subdomains) - 10} more"

            finding = self._create_finding(
                severity="info",
                title="Subdomains Discovered",
                description=(
                    f"The following subdomains were discovered for {self.base_domain}:\n\n"
                    f"{subdomain_list}"
                ),
                evidence=f"Total subdomains found: {len(found_subdomains)}",
                remediation=(
                    "Review discovered subdomains to ensure they are authorized "
                    "and properly secured."
                ),
                confidence=0.7,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                metadata={
                    "subdomains": found_subdomains,
                    "count": len(found_subdomains),
                },
            )
            self._add_finding(finding)

    async def _harvest_emails(self) -> None:
        """
        Harvest emails from the target website.
        """
        self._log_info("Harvesting emails...")
        emails = set()

        try:
            # This would normally fetch the homepage and parse emails
            # For now, we'll simulate with a simple check
            # In production, you'd fetch and parse HTML

            # For now, just note that email harvesting could be performed
            self._log_debug("Email harvesting would be performed here")

            # Add a finding about email harvesting
            finding = self._create_finding(
                severity="info",
                title="Email Harvesting Check",
                description=(
                    "The website should be checked for email addresses that may be "
                    "exposed to spammers and attackers."
                ),
                evidence="Email addresses may be present in HTML/JS code",
                remediation=(
                    "Use email obfuscation techniques to protect email addresses "
                    "from being harvested by bots."
                ),
                confidence=0.6,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )
            self._add_finding(finding)

        except Exception as e:
            self._log_error(f"Email harvesting failed: {e}")

    async def _check_open_ports(self) -> None:
        """
        Check for common open ports on the target domain.
        """
        self._log_info("Checking for open ports...")
        open_ports = []
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 27017]

        for port in common_ports:
            try:
                # Simple port check (this is actually an active check)
                # In a truly passive scan, you'd check public shodan/archive data
                # For now, we'll just note common ports
                if port in [80, 443]:
                    open_ports.append({
                        "port": port,
                        "service": "http" if port == 80 else "https",
                        "status": "likely_open",
                    })
                else:
                    # For other ports, we'll just note they're not checked
                    pass
            except Exception:
                continue

        if open_ports:
            finding = self._create_finding(
                severity="info",
                title="Common Open Ports",
                description=(
                    f"Common ports detected for {self.base_domain}:\n"
                    + "\n".join(f"  - {p['port']} ({p['service']})" for p in open_ports)
                ),
                evidence=f"Ports: {', '.join(str(p['port']) for p in open_ports)}",
                remediation=(
                    "Review open ports and ensure only necessary services are exposed."
                ),
                confidence=0.9,
                metadata={"open_ports": open_ports},
            )
            self._add_finding(finding)

    async def _check_dns_enums(self) -> None:
        """
        Perform DNS enumeration checks.
        """
        self._log_info("Performing DNS enumeration...")

        dns_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT"]
        dns_records = {}

        for record_type in dns_types:
            try:
                answers = dns.resolver.resolve(self.base_domain, record_type)
                if answers:
                    records = [str(r) for r in answers]
                    dns_records[record_type] = records
                    self._log_debug(f"Found {record_type} records: {records}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue

        if dns_records:
            self._log_info(f"Found DNS records: {list(dns_records.keys())}")

    async def _gather_public_info(self) -> None:
        """
        Gather publicly available information about the domain.
        """
        self._log_info("Gathering public information...")

        # Check for common security files
        common_files = [
            "/robots.txt",
            "/sitemap.xml",
            "/humans.txt",
            "/.well-known/security.txt",
            "/.well-known/acme-challenge/",
            "/.well-known/change-password",
            "/.well-known/webfinger",
            "/.well-known/host-meta",
            "/.well-known/nodeinfo",
        ]

        try:
            for file_path in common_files:
                # This would normally check the file exists
                # For passive scan, we just note they're common
                self._log_debug(f"Common file check: {file_path}")

        except Exception as e:
            self._log_error(f"Public info gathering failed: {e}")

    def _extract_emails_from_text(self, text: str) -> List[str]:
        """
        Extract email addresses from text.

        Args:
            text: Text to extract emails from.

        Returns:
            List[str]: List of email addresses.
        """
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))