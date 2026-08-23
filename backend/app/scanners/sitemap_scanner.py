"""
Sitemap Scanner for Sentinel.

Analyzes sitemap.xml file for:
- Presence and accessibility
- URL discovery
- Information disclosure
- Sensitive URL detection
- Site structure mapping
"""

from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
import re

from app.scanners.base import BaseScanner


class SitemapScanner(BaseScanner):
    """
    Sitemap.xml Scanner.

    Checks:
    - sitemap.xml presence
    - URL discovery and enumeration
    - Sensitive URL detection
    - Information disclosure
    - Site structure mapping
    """

    # Common sensitive URL patterns to check for
    SENSITIVE_URL_PATTERNS = [
        r'/admin',
        r'/administrator',
        r'/wp-admin',
        r'/wp-login',
        r'/cms',
        r'/dashboard',
        r'/login',
        r'/signin',
        r'/auth',
        r'/api/',
        r'/graphql',
        r'/dev/',
        r'/test/',
        r'/tests/',
        r'/staging/',
        r'/stage/',
        r'/internal/',
        r'/private/',
        r'/confidential/',
        r'/secret/',
        r'/backup/',
        r'/backups/',
        r'/tmp/',
        r'/temp/',
        r'/logs/',
        r'/debug/',
        r'/phpinfo',
        r'/config/',
        r'/settings/',
        r'/console/',
        r'/webmail/',
        r'/mail/',
        r'/cgi-bin/',
        r'/phpmyadmin',
        r'/pma',
        r'/mysql/',
        r'/db/',
        r'/database/',
        r'/\.env',
        r'/\.git',
        r'/\.svn',
        r'/\.hg',
        r'/\.aws',
        r'/\.ssh',
        r'/\.github',
        r'/\.vscode',
        r'/\.idea',
        r'/\.htaccess',
        r'/\.htpasswd',
        r'\.sql$',
        r'\.dump$',
        r'\.log$',
        r'\.bak$',
        r'\.backup$',
        r'\.pem$',
        r'\.key$',
        r'\.crt$',
        r'\.cer$',
    ]

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "sitemap"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the sitemap scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting sitemap scan for {self.target_url}")
        self.findings = []
        self.discovered_urls = []

        try:
            # Parse base domain
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            self.base_url = base_url

            # Check common sitemap locations
            sitemap_urls = [
                urljoin(base_url, "/sitemap.xml"),
                urljoin(base_url, "/sitemap_index.xml"),
                urljoin(base_url, "/sitemap/index.xml"),
                urljoin(base_url, "/sitemap/sitemap.xml"),
                urljoin(base_url, "/sitemap/sitemap-index.xml"),
                urljoin(base_url, "/sitemap.xml.gz"),
            ]

            found_sitemap = False

            for sitemap_url in sitemap_urls:
                try:
                    client = await self._get_client()
                    response = await client.get(sitemap_url, follow_redirects=True)

                    if response.status_code == 200:
                        self._log_info(f"Found sitemap: {sitemap_url}")
                        found_sitemap = True
                        await self._analyze_sitemap(response.text, sitemap_url)
                        break  # Stop after finding the first valid sitemap

                except Exception:
                    continue

            if not found_sitemap:
                self._log_info("No sitemap found")
                finding = self._create_finding(
                    severity="info",
                    title="Sitemap Not Found",
                    description=(
                        "No sitemap.xml file was found. This may make it harder "
                        "for search engines to discover all pages on your site."
                    ),
                    evidence="No sitemap found at common locations",
                    remediation=(
                        "Consider creating a sitemap to help search engines "
                        "crawl your site more effectively."
                    ),
                    confidence=0.9,
                    references=[
                        "https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview",
                        "https://www.sitemaps.org/",
                    ],
                )
                self._add_finding(finding)

        except Exception as e:
            self._log_error(f"Sitemap scan failed: {e}")

        self._log_info(f"Sitemap scan completed. Found {len(self.findings)} findings.")
        return self.findings

    async def _analyze_sitemap(self, content: str, sitemap_url: str) -> None:
        """
        Analyze sitemap content for security issues.

        Args:
            content: Sitemap XML content.
            sitemap_url: URL of the sitemap.
        """
        try:
            # Parse XML
            root = ET.fromstring(content)

            # Define namespaces
            namespaces = {
                '': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                'image': 'http://www.google.com/schemas/sitemap-image/1.1',
                'news': 'http://www.google.com/schemas/sitemap-news/0.9',
                'video': 'http://www.google.com/schemas/sitemap-video/1.1',
            }

            # Check if it's a sitemap index
            is_index = root.tag.endswith('sitemapindex')
            urls = []

            if is_index:
                self._log_info("This is a sitemap index file")
                # Parse sitemap index
                for sitemap in root.findall('.//sitemap:loc', namespaces):
                    sitemap_location = sitemap.text.strip()
                    if sitemap_location:
                        self._log_debug(f"Found sitemap reference: {sitemap_location}")
                        # Recursively analyze referenced sitemaps
                        try:
                            client = await self._get_client()
                            response = await client.get(sitemap_location, follow_redirects=True)
                            if response.status_code == 200:
                                await self._analyze_sitemap(response.text, sitemap_location)
                        except Exception as e:
                            self._log_warning(f"Failed to fetch referenced sitemap {sitemap_location}: {e}")
            else:
                # Parse regular sitemap
                for loc in root.findall('.//sitemap:loc', namespaces):
                    url = loc.text.strip()
                    if url:
                        urls.append(url)
                        self.discovered_urls.append(url)

                self._log_info(f"Found {len(urls)} URLs in sitemap")

                # Check for sensitive URLs
                for url in urls:
                    if self._is_sensitive_url(url):
                        finding = self._create_finding(
                            severity="medium",
                            title="Sensitive URL Found in Sitemap",
                            description=(
                                f"A potentially sensitive URL was found in the sitemap: {url}"
                            ),
                            evidence=f"URL: {url}",
                            remediation=(
                                "Review whether this URL should be publicly accessible "
                                "or listed in the sitemap."
                            ),
                            confidence=0.8,
                            metadata={"url": url},
                        )
                        self._add_finding(finding)

                # Check number of URLs
                if len(urls) > 1000:
                    finding = self._create_finding(
                        severity="info",
                        title="Large Sitemap",
                        description=(
                            f"The sitemap contains {len(urls)} URLs. Large sites may "
                            "have more attack surface area."
                        ),
                        evidence=f"URL count: {len(urls)}",
                        remediation=(
                            "Consider breaking up large sitemaps into multiple smaller files."
                        ),
                        confidence=0.7,
                        metadata={"url_count": len(urls)},
                    )
                    self._add_finding(finding)

                # Check for file extensions that might indicate sensitive files
                sensitive_extensions = [
                    '.sql', '.dump', '.log', '.env', '.git', '.svn',
                    '.htaccess', '.htpasswd', '.conf', '.config',
                    '.bak', '.backup', '.old', '.orig', '.tmp',
                    '.pem', '.key', '.crt', '.cer', '.p12',
                    '.pfx', '.jks', '.keystore', '.truststore',
                    '.zip', '.tar', '.gz', '.rar', '.7z',
                    '.sql.gz', '.dump.gz',
                ]

                sensitive_extensions_found = []
                for url in urls:
                    parsed_url = urlparse(url)
                    path = parsed_url.path
                    for ext in sensitive_extensions:
                        if path.endswith(ext):
                            sensitive_extensions_found.append((url, ext))

                if sensitive_extensions_found:
                    # Deduplicate and report
                    unique_files = list(set([f[0] for f in sensitive_extensions_found]))
                    if len(unique_files) > 0:
                        finding = self._create_finding(
                            severity="high",
                            title="Sensitive File Extensions in Sitemap",
                            description=(
                                f"Found {len(unique_files)} URLs with sensitive file extensions "
                                "in the sitemap (e.g., .sql, .bak, .env)."
                            ),
                            evidence=f"Sample: {unique_files[:3]}",
                            remediation=(
                                "Remove sensitive files from the sitemap and ensure they are "
                                "not publicly accessible."
                            ),
                            confidence=0.9,
                            metadata={"sensitive_files": unique_files[:10]},
                        )
                        self._add_finding(finding)

                # Check for parameterized URLs (potential security issues)
                param_urls = [url for url in urls if '?' in url]
                if param_urls:
                    finding = self._create_finding(
                        severity="low",
                        title="Parameterized URLs in Sitemap",
                        description=(
                            f"Found {len(param_urls)} URLs with query parameters "
                            "in the sitemap. This may expose functionality or parameters."
                        ),
                        evidence=f"Sample: {param_urls[:3]}",
                        remediation=(
                            "Consider whether parameterized URLs should be included in "
                            "the sitemap."
                        ),
                        confidence=0.6,
                        metadata={"param_urls": param_urls[:10]},
                    )
                    self._add_finding(finding)

        except ET.ParseError as e:
            self._log_error(f"Failed to parse sitemap XML: {e}")
            finding = self._create_finding(
                severity="low",
                title="Invalid Sitemap XML",
                description="The sitemap contains malformed XML.",
                evidence=f"Parse error: {str(e)}",
                remediation="Fix the sitemap XML syntax.",
                confidence=1.0,
                metadata={"error": str(e)},
            )
            self._add_finding(finding)
        except Exception as e:
            self._log_error(f"Error analyzing sitemap: {e}")

    def _is_sensitive_url(self, url: str) -> bool:
        """
        Check if a URL is sensitive.

        Args:
            url: URL to check.

        Returns:
            bool: True if URL appears sensitive.
        """
        url_lower = url.lower()

        for pattern in self.SENSITIVE_URL_PATTERNS:
            if re.search(pattern, url_lower):
                return True

        return False

    def get_discovered_urls(self) -> List[str]:
        """
        Get URLs discovered from the sitemap.

        Returns:
            List[str]: List of discovered URLs.
        """
        return self.discovered_urls