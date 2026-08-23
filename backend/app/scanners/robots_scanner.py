"""
Robots Scanner for Sentinel.

Analyzes robots.txt file for:
- Presence and accessibility
- Disallowed paths
- Sitemap references
- Information disclosure
- Sensitive path exposure
"""

from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urljoin

from app.scanners.base import BaseScanner


class RobotsScanner(BaseScanner):
    """
    Robots.txt Scanner.

    Checks:
    - robots.txt presence
    - Disallowed paths
    - Sitemap references
    - Sensitive path exposure
    - Information disclosure
    """

    # Common sensitive paths to check for
    SENSITIVE_PATHS = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/wp-login",
        "/cms",
        "/dashboard",
        "/login",
        "/signin",
        "/auth",
        "/api",
        "/api/v1",
        "/graphql",
        "/dev",
        "/test",
        "/tests",
        "/staging",
        "/stage",
        "/internal",
        "/private",
        "/confidential",
        "/secret",
        "/backup",
        "/backups",
        "/tmp",
        "/temp",
        "/logs",
        "/debug",
        "/phpinfo",
        "/config",
        "/settings",
        "/console",
        "/webmail",
        "/mail",
        "/cgi-bin",
        "/phpmyadmin",
        "/pma",
        "/mysql",
        "/db",
        "/database",
        "/.env",
        "/.git",
        "/.svn",
        "/.hg",
        "/.aws",
        "/.ssh",
        "/.github",
        "/.vscode",
        "/.idea",
        "/.htaccess",
        "/.htpasswd",
        "/backup.sql",
        "/dump.sql",
        "/export",
        "/download",
    ]

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "robots"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the robots.txt scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting robots.txt scan for {self.target_url}")
        self.findings = []

        try:
            # Parse base domain
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            self.base_url = base_url

            # Check robots.txt
            robots_url = urljoin(base_url, "/robots.txt")

            client = await self._get_client()
            response = await client.get(robots_url, follow_redirects=True)

            if response.status_code == 200:
                self._log_info("robots.txt found and accessible")
                content = response.text
                await self._analyze_robots_txt(content)

            elif response.status_code in (404, 403):
                self._log_info("robots.txt not found (HTTP {response.status_code})")
                finding = self._create_finding(
                    severity="low",
                    title="robots.txt Not Found",
                    description=(
                        "The robots.txt file is missing. This is not a security issue, "
                        "but it may help search engines discover content."
                    ),
                    evidence=f"HTTP {response.status_code} for /robots.txt",
                    remediation=(
                        "Consider adding a robots.txt file to guide search engine crawlers."
                    ),
                    confidence=0.9,
                    references=[
                        "https://developers.google.com/search/docs/crawling-indexing/robots/create-robots-txt",
                    ],
                    metadata={"status_code": response.status_code},
                )
                self._add_finding(finding)
            else:
                self._log_warning(f"robots.txt returned status {response.status_code}")

        except Exception as e:
            self._log_error(f"robots.txt scan failed: {e}")

        self._log_info(f"robots.txt scan completed. Found {len(self.findings)} findings.")
        return self.findings

    async def _analyze_robots_txt(self, content: str) -> None:
        """
        Analyze robots.txt content for security issues.

        Args:
            content: robots.txt content.
        """
        lines = content.split("\n")
        disallowed_paths = []
        sitemaps = []
        user_agents = []

        # Parse robots.txt
        current_user_agent = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse directive
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "user-agent":
                    current_user_agent = value
                    user_agents.append(value)
                elif key == "disallow":
                    if value and value != "/":
                        # Don't flag "/" as it's usually not a sensitive path
                        disallowed_paths.append(value)
                elif key == "allow":
                    pass  # Allowed paths are not usually a security concern
                elif key == "sitemap":
                    sitemaps.append(value)
                elif key == "crawl-delay":
                    pass  # Crawl delay is not a security concern

        # Check for disallowed paths that might be sensitive
        if disallowed_paths:
            self._log_info(f"Found {len(disallowed_paths)} disallowed paths")

            # Check each disallowed path for sensitivity
            for path in disallowed_paths:
                if self._is_sensitive_path(path):
                    finding = self._create_finding(
                        severity="medium",
                        title="Sensitive Path Disallowed in robots.txt",
                        description=(
                            f"The path '{path}' is disallowed in robots.txt. "
                            "While this prevents search engine crawling, it also "
                            "exposes the existence of potentially sensitive directories."
                        ),
                        evidence=f"Disallow: {path}",
                        remediation=(
                            "If the path contains sensitive data, it should be "
                            "protected by authentication, not just robots.txt."
                        ),
                        confidence=0.8,
                        references=[
                            "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
                            "https://owasp.org/www-project-web-security-testing-guide/",
                        ],
                        metadata={"path": path},
                    )
                    self._add_finding(finding)

        # Check for sitemap references
        if sitemaps:
            self._log_info(f"Found {len(sitemaps)} sitemap references")
            # Sitemaps are not a security issue, but we'll note them
            for sitemap in sitemaps[:3]:
                self._log_debug(f"Sitemap: {sitemap}")

        # Check if any user agents are set
        if user_agents:
            self._log_debug(f"User agents: {', '.join(user_agents[:5])}")

    def _is_sensitive_path(self, path: str) -> bool:
        """
        Check if a path is sensitive.

        Args:
            path: Path to check.

        Returns:
            bool: True if path appears sensitive.
        """
        # Remove trailing wildcards
        path_clean = path.rstrip("*")
        path_clean = path_clean.rstrip("/")

        # Check against sensitive paths
        for sensitive in self.SENSITIVE_PATHS:
            if path_clean.startswith(sensitive) or path_clean == sensitive:
                return True

        # Check for file extensions that might be sensitive
        sensitive_extensions = [
            ".sql", ".dump", ".log", ".env", ".git", ".svn",
            ".htaccess", ".htpasswd", ".conf", ".config",
            ".bak", ".backup", ".old", ".orig", ".tmp",
            ".pem", ".key", ".crt", ".cer", ".p12",
            ".pfx", ".jks", ".keystore", ".truststore",
        ]

        for ext in sensitive_extensions:
            if path_clean.endswith(ext):
                return True

        return False

    async def _check_robots_txt_security(self) -> None:
        """
        Additional check for robots.txt security issues.
        This is a placeholder for future enhancement.
        """
        pass