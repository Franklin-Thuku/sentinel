"""
Cookie Scanner for Sentinel.

Analyzes cookie security configuration:
- Secure flag
- HttpOnly flag
- SameSite attribute
- Cookie expiration
- Session cookie usage
- Domain and path attributes
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import re

from app.scanners.base import BaseScanner


class CookieScanner(BaseScanner):
    """
    Cookie Scanner.

    Checks:
    - Secure flag
    - HttpOnly flag
    - SameSite attribute
    - Cookie expiration
    - Session cookie usage
    - Domain and path attributes
    """

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "cookies"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the cookie scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting cookie scan for {self.target_url}")
        self.findings = []

        try:
            client = await self._get_client()
            response = await client.get(self.target_url, follow_redirects=True)

            # Get cookies from response
            cookies = response.cookies

            if not cookies:
                self._log_info("No cookies found")
                # No cookies is not a finding, but we'll add an info note
                # Some sites may not need cookies
                return self.findings

            self._log_info(f"Found {len(cookies)} cookies")

            # Check each cookie
            for cookie in cookies:
                await self._analyze_cookie(cookie)

        except Exception as e:
            self._log_error(f"Cookie scan failed: {e}")
            finding = self._create_finding(
                severity="medium",
                title="Cookie Scan Failed",
                description=f"Failed to retrieve cookies: {str(e)}",
                evidence=f"Error: {str(e)}",
                remediation="Ensure the website is accessible and responding.",
                confidence=0.9,
            )
            self._add_finding(finding)

        self._log_info(f"Cookie scan completed. Found {len(self.findings)} findings.")
        return self.findings

    async def _analyze_cookie(self, cookie: Dict[str, Any]) -> None:
        """
        Analyze a single cookie for security issues.

        Args:
            cookie: Cookie object from httpx.
        """
        cookie_name = cookie.get("name", "unknown")
        cookie_value = cookie.get("value", "")
        secure = cookie.get("secure", False)
        httponly = cookie.get("httponly", False)
        samesite = cookie.get("samesite", "none")
        max_age = cookie.get("max-age")
        expires = cookie.get("expires")
        domain = cookie.get("domain", "")
        path = cookie.get("path", "")

        self._log_debug(f"Analyzing cookie: {cookie_name} (secure={secure}, httponly={httponly}, samesite={samesite})")

        # Check Secure flag
        if not secure:
            finding = self._create_finding(
                severity="medium",
                title="Cookie Missing Secure Flag",
                description=(
                    f"Cookie '{cookie_name}' is missing the Secure flag. "
                    "This means it can be sent over unencrypted HTTP connections, "
                    "making it vulnerable to interception."
                ),
                evidence=f"Cookie: {cookie_name}, Secure: {secure}",
                remediation=(
                    f"Add the `Secure` attribute to the '{cookie_name}' cookie: "
                    "`Set-Cookie: name=value; Secure; ...`"
                ),
                confidence=1.0,
                metadata={
                    "cookie_name": cookie_name,
                    "secure": secure,
                },
            )
            self._add_finding(finding)

        # Check HttpOnly flag
        if not httponly:
            finding = self._create_finding(
                severity="medium",
                title="Cookie Missing HttpOnly Flag",
                description=(
                    f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                    "This means it can be accessed by JavaScript, increasing "
                    "the risk of XSS attacks stealing the cookie."
                ),
                evidence=f"Cookie: {cookie_name}, HttpOnly: {httponly}",
                remediation=(
                    f"Add the `HttpOnly` attribute to the '{cookie_name}' cookie: "
                    "`Set-Cookie: name=value; HttpOnly; ...`"
                ),
                confidence=1.0,
                metadata={
                    "cookie_name": cookie_name,
                    "httponly": httponly,
                },
            )
            self._add_finding(finding)

        # Check SameSite attribute
        if not samesite or samesite.lower() == "none":
            # Check if it's a session cookie with sensitive data
            is_sensitive = self._is_sensitive_cookie(cookie_name, cookie_value)

            severity = "high" if is_sensitive else "medium"
            finding = self._create_finding(
                severity=severity,
                title="Cookie Missing SameSite Attribute",
                description=(
                    f"Cookie '{cookie_name}' has no SameSite attribute or is set to 'None'. "
                    "This makes it vulnerable to CSRF (Cross-Site Request Forgery) attacks."
                ),
                evidence=f"Cookie: {cookie_name}, SameSite: {samesite or 'not set'}",
                remediation=(
                    f"Add the `SameSite` attribute to the '{cookie_name}' cookie: "
                    "`SameSite=Lax` or `SameSite=Strict`."
                ),
                confidence=0.9,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/CSRF_Prevention_Cheat_Sheet.html",
                ],
                metadata={
                    "cookie_name": cookie_name,
                    "samesite": samesite,
                },
            )
            self._add_finding(finding)
        elif samesite.lower() == "lax":
            self._log_debug(f"Cookie {cookie_name} uses SameSite=Lax (acceptable)")
        elif samesite.lower() == "strict":
            self._log_debug(f"Cookie {cookie_name} uses SameSite=Strict (good)")

        # Check if cookie is a session cookie
        if max_age is None and expires is None:
            # Session cookie (expires when browser closes)
            # This is not necessarily bad, but worth noting
            self._log_debug(f"Cookie {cookie_name} is a session cookie")

            # Check if it's a session cookie with sensitive data
            if self._is_sensitive_cookie(cookie_name, cookie_value):
                finding = self._create_finding(
                    severity="low",
                    title="Session Cookie Used for Sensitive Data",
                    description=(
                        f"Cookie '{cookie_name}' appears to contain sensitive data "
                        "and is a session cookie. This is acceptable in most cases."
                    ),
                    evidence=f"Cookie: {cookie_name}, expires: session",
                    remediation=(
                        "No action required. Session cookies are acceptable for sensitive data."
                    ),
                    confidence=0.7,
                    metadata={
                        "cookie_name": cookie_name,
                        "is_session": True,
                    },
                )
                self._add_finding(finding)

        # Check if cookie expires soon
        if expires:
            try:
                # Parse expires date
                expires_dt = self._parse_cookie_date(expires)
                if expires_dt:
                    days_until_expiry = (expires_dt - datetime.utcnow()).days
                    if days_until_expiry < 7 and days_until_expiry > 0:
                        finding = self._create_finding(
                            severity="low",
                            title="Cookie Expiring Soon",
                            description=(
                                f"Cookie '{cookie_name}' will expire in {days_until_expiry} days. "
                                "This may cause users to be logged out unexpectedly."
                            ),
                            evidence=f"Cookie: {cookie_name}, expires: {expires}",
                            remediation="Consider increasing cookie expiration time.",
                            confidence=0.7,
                            metadata={
                                "cookie_name": cookie_name,
                                "days_until_expiry": days_until_expiry,
                            },
                        )
                        self._add_finding(finding)
            except Exception:
                pass

        # Check domain attribute
        if domain:
            if not domain.startswith(".") and domain != self._extract_domain():
                # Strict domain matching
                self._log_debug(f"Cookie {cookie_name} domain: {domain}")

        # Check path attribute
        if path and path != "/":
            self._log_debug(f"Cookie {cookie_name} path: {path}")

    def _is_sensitive_cookie(self, name: str, value: str) -> bool:
        """
        Check if a cookie might contain sensitive data.

        Args:
            name: Cookie name.
            value: Cookie value.

        Returns:
            bool: True if cookie appears sensitive.
        """
        sensitive_patterns = [
            "session",
            "auth",
            "token",
            "jwt",
            "login",
            "user",
            "id",
            "sid",
            "jsessionid",
            "phpsessid",
            "asp",
            "csrf",
            "xsrf",
            "x-csrf",
        ]

        name_lower = name.lower()

        # Check for session ID patterns
        session_patterns = [
            r'^[A-Fa-f0-9]{32}$',  # 32-char hex (like PHP session)
            r'^[A-Fa-f0-9]{40}$',  # 40-char hex
            r'^[A-Fa-f0-9]{64}$',  # 64-char hex
            r'^[A-Za-z0-9\-_]{16,}$',  # Longer base64-like
        ]

        # Check if name contains sensitive keywords
        for pattern in sensitive_patterns:
            if pattern in name_lower:
                return True

        # Check if value looks like a session token
        for pattern in session_patterns:
            if re.match(pattern, value):
                return True

        # Check if value is long and looks like a token
        if len(value) > 20 and re.match(r'^[A-Za-z0-9\-_]+$', value):
            return True

        return False

    def _parse_cookie_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse cookie expiration date.

        Args:
            date_str: Date string.

        Returns:
            Optional[datetime]: Parsed datetime or None.
        """
        # Common cookie date formats
        formats = [
            "%a, %d %b %Y %H:%M:%S %Z",  # Thu, 31 Dec 2025 23:59:59 GMT
            "%a, %d %b %Y %H:%M:%S",      # Thu, 31 Dec 2025 23:59:59
            "%d %b %Y %H:%M:%S %Z",       # 31 Dec 2025 23:59:59 GMT
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        # Try with timezone handling
        try:
            import email.utils
            parsed = email.utils.parsedate_to_datetime(date_str)
            if parsed:
                return parsed
        except Exception:
            pass

        return None

    def _extract_domain(self) -> str:
        """Extract domain from target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        domain = parsed.netloc or self.target_url
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain