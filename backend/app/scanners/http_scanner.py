"""
HTTP Scanner for Sentinel.

Performs basic HTTP checks on the target website:
- HTTP → HTTPS redirect
- HTTPS availability
- Response status codes
- Server header disclosure
- Security.txt presence
"""

import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from app.scanners.base import BaseScanner


class HTTPScanner(BaseScanner):
    """
    HTTP Scanner.

    Checks:
    - HTTP to HTTPS redirect
    - HTTPS availability
    - Response status codes
    - Server header disclosure
    - Security.txt presence
    """

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "http"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the HTTP scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting HTTP scan for {self.target_url}")
        self.findings = []

        # Normalize URL
        target = self._normalize_url(self.target_url)

        # Run checks
        await self._check_http_redirect(target)
        await self._check_https(target)
        await self._check_server_header(target)
        await self._check_response_status(target)
        await self._check_security_txt(target)

        self._log_info(f"HTTP scan completed. Found {len(self.findings)} findings.")
        return self.findings

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to include https:// if not present."""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url

    async def _check_http_redirect(self, url: str) -> None:
        """
        Check if HTTP redirects to HTTPS.

        Args:
            url: The target URL.
        """
        # Only check if URL is HTTPS
        if not url.startswith('https://'):
            return

        # Try HTTP version
        http_url = url.replace('https://', 'http://')

        try:
            client = await self._get_client()
            response = await client.get(http_url, follow_redirects=False)

            # Check if redirects to HTTPS
            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get('location', '')
                if location.startswith('https://'):
                    self._log_debug(f"HTTP redirects to HTTPS: {http_url} -> {location}")
                    return

            # If we got here, no proper HTTPS redirect
            finding = self._create_finding(
                severity="medium",
                title="HTTP to HTTPS Redirect Missing",
                description=(
                    f"The website does not properly redirect HTTP traffic to HTTPS. "
                    f"This can lead to man-in-the-middle attacks and downgrade attacks."
                ),
                evidence=(
                    f"HTTP request to {http_url} returned status {response.status_code} "
                    f"with Location: {response.headers.get('location', 'None')}"
                ),
                remediation=(
                    "Configure your web server to redirect all HTTP traffic to HTTPS "
                    "using a 301 (permanent) redirect."
                ),
                confidence=0.9,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                ],
                metadata={
                    "status_code": response.status_code,
                    "location": response.headers.get('location', ''),
                    "http_url": http_url,
                }
            )
            self._add_finding(finding)

        except httpx.RequestError as e:
            self._log_warning(f"Failed to check HTTP redirect: {e}")

    async def _check_https(self, url: str) -> None:
        """
        Check if HTTPS is available.

        Args:
            url: The target URL.
        """
        # Try HTTPS if not already
        if url.startswith('https://'):
            https_url = url
        else:
            https_url = url.replace('http://', 'https://')

        try:
            client = await self._get_client()
            response = await client.get(https_url, follow_redirects=False)

            if response.status_code < 400:
                self._log_debug(f"HTTPS is available: {https_url}")
            else:
                finding = self._create_finding(
                    severity="high",
                    title="HTTPS Not Available",
                    description=(
                        f"The website does not support HTTPS. All traffic is sent "
                        f"in plaintext, which is insecure."
                    ),
                    evidence=f"HTTPS request to {https_url} returned status {response.status_code}",
                    remediation=(
                        "Install an SSL/TLS certificate on your web server and "
                        "configure it to serve HTTPS traffic."
                    ),
                    confidence=0.95,
                    references=[
                        "https://letsencrypt.org/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade-Insecure-Requests",
                    ],
                    metadata={
                        "status_code": response.status_code,
                        "https_url": https_url,
                    }
                )
                self._add_finding(finding)

        except httpx.RequestError as e:
            finding = self._create_finding(
                severity="high",
                title="HTTPS Not Available",
                description=(
                    f"The website does not support HTTPS. Connection failed."
                ),
                evidence=f"Failed to connect to {https_url}: {str(e)}",
                remediation=(
                    "Install an SSL/TLS certificate on your web server."
                ),
                confidence=0.9,
                metadata={"error": str(e)}
            )
            self._add_finding(finding)

    async def _check_server_header(self, url: str) -> None:
        """
        Check server header for information disclosure.

        Args:
            url: The target URL.
        """
        try:
            client = await self._get_client()
            response = await client.get(url, follow_redirects=True)

            server_header = response.headers.get('server', '')

            if server_header:
                self._log_debug(f"Server header disclosed: {server_header}")

                # Info-level finding for server disclosure
                finding = self._create_finding(
                    severity="low",
                    title="Server Header Disclosed",
                    description=(
                        f"The web server is disclosing its identity via the "
                        f"`Server` header: `{server_header}`. This can help "
                        f"attackers identify known vulnerabilities."
                    ),
                    evidence=f"Server header: {server_header}",
                    remediation=(
                        "Remove or obfuscate the `Server` header in your "
                        "web server configuration."
                    ),
                    confidence=1.0,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
                    ],
                    metadata={"server_header": server_header}
                )
                self._add_finding(finding)

        except httpx.RequestError as e:
            self._log_warning(f"Failed to check server header: {e}")

    async def _check_response_status(self, url: str) -> None:
        """
        Check response status codes.

        Args:
            url: The target URL.
        """
        try:
            client = await self._get_client()
            response = await client.get(url, follow_redirects=True)

            if response.status_code >= 400:
                finding = self._create_finding(
                    severity="high" if response.status_code >= 500 else "medium",
                    title=f"HTTP Error {response.status_code}",
                    description=(
                        f"The website returned an error status code: "
                        f"{response.status_code}."
                    ),
                    evidence=f"GET {url} -> {response.status_code}",
                    remediation=(
                        "Investigate the error and fix the underlying issue."
                    ),
                    confidence=1.0,
                    metadata={"status_code": response.status_code}
                )
                self._add_finding(finding)

        except httpx.RequestError as e:
            finding = self._create_finding(
                severity="high",
                title="Website Unreachable",
                description=f"Failed to reach the website: {str(e)}",
                evidence=f"Request failed: {str(e)}",
                remediation=(
                    "Check if the website is online and accessible from the internet."
                ),
                confidence=0.9,
                metadata={"error": str(e)}
            )
            self._add_finding(finding)

    async def _check_security_txt(self, url: str) -> None:
        """
        Check for security.txt file presence.

        Args:
            url: The target URL.
        """
        try:
            # Parse domain
            parsed = urlparse(url)
            domain = parsed.netloc or url

            security_txt_url = f"https://{domain}/.well-known/security.txt"

            client = await self._get_client()
            response = await client.get(security_txt_url, follow_redirects=True)

            if response.status_code == 200:
                self._log_debug(f"security.txt found at {security_txt_url}")
                # Optional: Could parse security.txt content for better analysis
            else:
                finding = self._create_finding(
                    severity="info",
                    title="security.txt Not Found",
                    description=(
                        "The website does not have a security.txt file. "
                        "This file helps security researchers report vulnerabilities."
                    ),
                    evidence=f"GET {security_txt_url} -> {response.status_code}",
                    remediation=(
                        "Create a security.txt file at /.well-known/security.txt "
                        "with your security contact information."
                    ),
                    confidence=0.95,
                    references=[
                        "https://securitytxt.org/",
                        "https://www.rfc-editor.org/rfc/rfc9116.html",
                    ],
                    metadata={
                        "status_code": response.status_code,
                        "security_txt_url": security_txt_url,
                    }
                )
                self._add_finding(finding)

        except httpx.RequestError as e:
            self._log_warning(f"Failed to check security.txt: {e}")