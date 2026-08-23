"""
Security Headers Scanner for Sentinel.

Analyzes HTTP security headers and checks for proper configuration:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
"""

from typing import List, Dict, Any, Optional
import re

from app.scanners.base import BaseScanner


class SecurityHeadersScanner(BaseScanner):
    """
    Security Headers Scanner.

    Checks for proper security header configuration.
    """

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "security_headers"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the security headers scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting security headers scan for {self.target_url}")
        self.findings = []

        try:
            client = await self._get_client()
            response = await client.get(self.target_url, follow_redirects=True)
            headers = response.headers

            # Check each header
            await self._check_hsts(headers)
            await self._check_csp(headers)
            await self._check_x_content_type(headers)
            await self._check_x_frame_options(headers)
            await self._check_referrer_policy(headers)
            await self._check_permissions_policy(headers)
            await self._check_coep(headers)
            await self._check_coop(headers)
            await self._check_corp(headers)

        except Exception as e:
            self._log_error(f"Failed to fetch headers: {e}")
            finding = self._create_finding(
                severity="high",
                title="Failed to Retrieve Security Headers",
                description=f"Could not retrieve security headers: {str(e)}",
                evidence=f"Error: {str(e)}",
                remediation="Ensure the website is accessible and responding to requests.",
                confidence=0.9,
            )
            self._add_finding(finding)

        self._log_info(f"Security headers scan completed. Found {len(self.findings)} findings.")
        return self.findings

    # ================================================================
    # Individual Header Checks
    # ================================================================

    async def _check_hsts(self, headers: Dict[str, str]) -> None:
        """Check Strict-Transport-Security header."""
        hsts = headers.get("strict-transport-security", "")

        if not hsts:
            finding = self._create_finding(
                severity="medium",
                title="Strict-Transport-Security (HSTS) Header Missing",
                description=(
                    "The HSTS header is missing. This allows browsers to connect via HTTP, "
                    "which can lead to man-in-the-middle attacks and SSL stripping."
                ),
                evidence="No HSTS header found",
                remediation=(
                    "Add the HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`"
                ),
                confidence=1.0,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://hstspreload.org/",
                ],
            )
            self._add_finding(finding)
            return

        # Check max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                finding = self._create_finding(
                    severity="medium",
                    title="HSTS max-age Too Short",
                    description=f"HSTS max-age is set to {max_age} seconds. Recommended minimum is 31536000 (1 year).",
                    evidence=f"max-age={max_age}",
                    remediation="Set HSTS max-age to at least 31536000 seconds (1 year).",
                    confidence=0.95,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                    metadata={"max_age": max_age},
                )
                self._add_finding(finding)

        # Check includeSubDomains
        if "includesubdomains" not in hsts.lower():
            finding = self._create_finding(
                severity="low",
                title="HSTS includeSubDomains Missing",
                description="HSTS does not include the includeSubDomains directive.",
                evidence="No includeSubDomains directive found",
                remediation="Add `includeSubDomains` to the HSTS header.",
                confidence=0.9,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                metadata={"hsts": hsts},
            )
            self._add_finding(finding)

        # Check preload
        if "preload" not in hsts.lower():
            finding = self._create_finding(
                severity="low",
                title="HSTS Preload Not Enabled",
                description="HSTS does not include the preload directive.",
                evidence="No preload directive found",
                remediation="Add `preload` to the HSTS header and submit to hstspreload.org.",
                confidence=0.85,
                references=["https://hstspreload.org/"],
                metadata={"hsts": hsts},
            )
            self._add_finding(finding)

    async def _check_csp(self, headers: Dict[str, str]) -> None:
        """Check Content-Security-Policy header."""
        csp = headers.get("content-security-policy", "")
        csp_report_only = headers.get("content-security-policy-report-only", "")

        if not csp and not csp_report_only:
            finding = self._create_finding(
                severity="high",
                title="Content-Security-Policy (CSP) Header Missing",
                description=(
                    "The CSP header is missing. This allows XSS attacks and data injection "
                    "by not restricting which resources can be loaded."
                ),
                evidence="No CSP header found",
                remediation=(
                    "Add a Content-Security-Policy header to restrict resource loading. "
                    "Start with a restrictive policy: `default-src 'self'`."
                ),
                confidence=1.0,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                    "https://csp-evaluator.withgoogle.com/",
                ],
            )
            self._add_finding(finding)
            return

        # If report-only is used, that's better than nothing
        if csp_report_only and not csp:
            finding = self._create_finding(
                severity="medium",
                title="Content-Security-Policy (CSP) Report-Only Only",
                description=(
                    "CSP is in report-only mode, which does not block unsafe content. "
                    "This is good for testing but should be enforced in production."
                ),
                evidence="Content-Security-Policy-Report-Only header present",
                remediation="Switch to a full `Content-Security-Policy` header when ready.",
                confidence=0.9,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
            )
            self._add_finding(finding)

        # Check for unsafe-inline in script-src
        if csp and "script-src" in csp:
            if "unsafe-inline" in csp and "'unsafe-inline'" in csp:
                finding = self._create_finding(
                    severity="high",
                    title="CSP Contains 'unsafe-inline'",
                    description="CSP allows 'unsafe-inline' which defeats XSS protection.",
                    evidence="'unsafe-inline' found in script-src",
                    remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                    confidence=0.9,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src",
                    ],
                    metadata={"csp": csp},
                )
                self._add_finding(finding)

    async def _check_x_content_type(self, headers: Dict[str, str]) -> None:
        """Check X-Content-Type-Options header."""
        xcto = headers.get("x-content-type-options", "")

        if not xcto:
            finding = self._create_finding(
                severity="medium",
                title="X-Content-Type-Options Header Missing",
                description=(
                    "The X-Content-Type-Options header is missing. This allows MIME type "
                    "sniffing which can lead to XSS attacks."
                ),
                evidence="No X-Content-Type-Options header found",
                remediation="Add: `X-Content-Type-Options: nosniff`",
                confidence=1.0,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
            )
            self._add_finding(finding)
        elif xcto.lower() != "nosniff":
            finding = self._create_finding(
                severity="medium",
                title="X-Content-Type-Options Invalid Value",
                description=f"X-Content-Type-Options should be 'nosniff', got '{xcto}'.",
                evidence=f"X-Content-Type-Options: {xcto}",
                remediation="Set: `X-Content-Type-Options: nosniff`",
                confidence=1.0,
                metadata={"xcto": xcto},
            )
            self._add_finding(finding)

    async def _check_x_frame_options(self, headers: Dict[str, str]) -> None:
        """Check X-Frame-Options header."""
        xfo = headers.get("x-frame-options", "")

        if not xfo:
            finding = self._create_finding(
                severity="medium",
                title="X-Frame-Options Header Missing",
                description=(
                    "The X-Frame-Options header is missing. This allows clickjacking attacks."
                ),
                evidence="No X-Frame-Options header found",
                remediation="Add: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`",
                confidence=1.0,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
            )
            self._add_finding(finding)
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            finding = self._create_finding(
                severity="medium",
                title="X-Frame-Options Invalid Value",
                description=f"X-Frame-Options should be 'DENY' or 'SAMEORIGIN', got '{xfo}'.",
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Set: `X-Frame-Options: DENY`",
                confidence=1.0,
                metadata={"xfo": xfo},
            )
            self._add_finding(finding)

    async def _check_referrer_policy(self, headers: Dict[str, str]) -> None:
        """Check Referrer-Policy header."""
        referrer = headers.get("referrer-policy", "")

        if not referrer:
            finding = self._create_finding(
                severity="low",
                title="Referrer-Policy Header Missing",
                description=(
                    "The Referrer-Policy header is missing. This can leak information "
                    "about the user's browsing context."
                ),
                evidence="No Referrer-Policy header found",
                remediation=(
                    "Add: `Referrer-Policy: strict-origin-when-cross-origin` "
                    "or `Referrer-Policy: no-referrer`"
                ),
                confidence=0.9,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
            )
            self._add_finding(finding)

    async def _check_permissions_policy(self, headers: Dict[str, str]) -> None:
        """Check Permissions-Policy header."""
        pp = headers.get("permissions-policy", "")
        # Also check for the older Feature-Policy header
        fp = headers.get("feature-policy", "")

        if not pp and not fp:
            finding = self._create_finding(
                severity="info",
                title="Permissions-Policy Header Missing",
                description=(
                    "The Permissions-Policy header is missing. This controls which browser "
                    "features (camera, microphone, geolocation, etc.) can be used."
                ),
                evidence="No Permissions-Policy header found",
                remediation=(
                    "Add a Permissions-Policy header to restrict unnecessary features: "
                    "`Permissions-Policy: geolocation=(), microphone=(), camera=()`"
                ),
                confidence=0.8,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                ],
            )
            self._add_finding(finding)

    async def _check_coep(self, headers: Dict[str, str]) -> None:
        """Check Cross-Origin-Embedder-Policy header."""
        coep = headers.get("cross-origin-embedder-policy", "")

        if not coep:
            finding = self._create_finding(
                severity="info",
                title="Cross-Origin-Embedder-Policy (COEP) Header Missing",
                description=(
                    "COEP prevents cross-origin resource loading without permission. "
                    "This is important for Spectre/Meltdown mitigations."
                ),
                evidence="No COEP header found",
                remediation="Add: `Cross-Origin-Embedder-Policy: require-corp`",
                confidence=0.7,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                ],
            )
            self._add_finding(finding)

    async def _check_coop(self, headers: Dict[str, str]) -> None:
        """Check Cross-Origin-Opener-Policy header."""
        coop = headers.get("cross-origin-opener-policy", "")

        if not coop:
            finding = self._create_finding(
                severity="info",
                title="Cross-Origin-Opener-Policy (COOP) Header Missing",
                description=(
                    "COOP prevents cross-origin window sharing. This helps mitigate "
                    "cross-origin attacks and improves security."
                ),
                evidence="No COOP header found",
                remediation="Add: `Cross-Origin-Opener-Policy: same-origin`",
                confidence=0.7,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                ],
            )
            self._add_finding(finding)

    async def _check_corp(self, headers: Dict[str, str]) -> None:
        """Check Cross-Origin-Resource-Policy header."""
        corp = headers.get("cross-origin-resource-policy", "")

        if not corp:
            finding = self._create_finding(
                severity="info",
                title="Cross-Origin-Resource-Policy (CORP) Header Missing",
                description=(
                    "CORP prevents cross-origin resource loading without permission. "
                    "This is part of Spectre/Meltdown mitigations."
                ),
                evidence="No CORP header found",
                remediation="Add: `Cross-Origin-Resource-Policy: same-origin`",
                confidence=0.7,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
                ],
            )
            self._add_finding(finding)