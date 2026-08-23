"""
TLS/SSL Scanner for Sentinel.

Analyzes TLS/SSL certificate configuration and security:
- Certificate validity and expiration
- Hostname matching
- Protocol version support
- Cipher suite analysis
- Certificate chain verification
- Weak key detection
"""

import ssl
import socket
import asyncio
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

import httpx
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from app.scanners.base import BaseScanner
from app.config import settings


class TLSScanner(BaseScanner):
    """
    TLS/SSL Scanner.

    Checks:
    - Certificate validity and expiration
    - Hostname matching
    - Protocol version support
    - Weak cipher suites
    """

    def __init__(self, target_url: str, **kwargs):
        super().__init__(target_url, **kwargs)
        self._extract_domain()

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "tls"

    def _extract_domain(self) -> None:
        """Extract domain from target URL."""
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc or self.target_url
        # Remove port if present
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the TLS/SSL scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting TLS scan for {self.domain}")
        self.findings = []

        try:
            # Get certificate info
            cert_info = await self._get_certificate_info()

            if cert_info:
                await self._check_certificate_validity(cert_info)
                await self._check_hostname_match(cert_info)
                await self._check_key_strength(cert_info)
                await self._check_certificate_chain(cert_info)
                await self._check_protocol_versions()
                await self._check_cipher_suites()

        except Exception as e:
            self._log_error(f"TLS scan failed: {e}")
            finding = self._create_finding(
                severity="high",
                title="TLS/SSL Connection Failed",
                description=f"Failed to establish TLS connection: {str(e)}",
                evidence=f"Error: {str(e)}",
                remediation=(
                    "Check if the website supports HTTPS and has a valid certificate."
                ),
                confidence=0.9,
            )
            self._add_finding(finding)

        self._log_info(f"TLS scan completed. Found {len(self.findings)} findings.")
        return self.findings

    async def _get_certificate_info(self) -> Optional[Dict[str, Any]]:
        """
        Get certificate information via SSL connection.

        Returns:
            Optional[Dict[str, Any]]: Certificate information.
        """
        try:
            # Use asyncio to handle the synchronous SSL connection
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(None, self._get_cert_sync)
            return cert_info
        except Exception as e:
            self._log_warning(f"Failed to get certificate: {e}")
            return None

    def _get_cert_sync(self) -> Optional[Dict[str, Any]]:
        """
        Synchronous method to get certificate information.

        Returns:
            Optional[Dict[str, Any]]: Certificate information.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    # Get certificate
                    der_cert = ssock.getpeercert(True)
                    if not der_cert:
                        return None

                    # Load certificate
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Extract information
                    return self._extract_cert_info(cert)

        except socket.gaierror as e:
            self._log_error(f"DNS resolution failed: {e}")
            return None
        except ConnectionRefusedError:
            self._log_error("Connection refused on port 443")
            return None
        except ssl.SSLError as e:
            self._log_error(f"SSL error: {e}")
            return None
        except Exception as e:
            self._log_error(f"Error getting certificate: {e}")
            return None

    def _extract_cert_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Extract information from certificate.

        Args:
            cert: The X.509 certificate.

        Returns:
            Dict[str, Any]: Certificate information.
        """
        # Get subject and issuer
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value

        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value

        # Get SANs
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [san.value for san in ext.value]
        except x509.ExtensionNotFound:
            pass

        # Get validity
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        # Get key info
        public_key = cert.public_key()
        key_type = "unknown"
        key_size = 0

        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_size = public_key.curve.key_size

        # Get signature algorithm
        sig_algo = cert.signature_algorithm_oid._name

        return {
            "subject": subject,
            "issuer": issuer,
            "sans": sans,
            "not_valid_before": not_valid_before,
            "not_valid_after": not_valid_after,
            "key_type": key_type,
            "key_size": key_size,
            "signature_algorithm": sig_algo,
            "serial_number": str(cert.serial_number),
            "version": cert.version,
        }

    async def _check_certificate_validity(self, cert_info: Dict[str, Any]) -> None:
        """
        Check certificate validity and expiration.

        Args:
            cert_info: Certificate information.
        """
        not_valid_before = cert_info.get("not_valid_before")
        not_valid_after = cert_info.get("not_valid_after")

        if not not_valid_before or not not_valid_after:
            return

        now = datetime.utcnow()

        # Check if certificate is valid
        if now < not_valid_before:
            finding = self._create_finding(
                severity="critical",
                title="Certificate Not Yet Valid",
                description=f"Certificate is not valid until {not_valid_before}",
                evidence=f"Valid from: {not_valid_before}",
                remediation="Install a valid certificate.",
                confidence=1.0,
                metadata={
                    "not_valid_before": not_valid_before.isoformat(),
                },
            )
            self._add_finding(finding)

        # Check expiration
        days_until_expiry = (not_valid_after - now).days

        if days_until_expiry <= 0:
            finding = self._create_finding(
                severity="critical",
                title="Certificate Expired",
                description=f"Certificate expired on {not_valid_after}",
                evidence=f"Expired: {days_until_expiry} days ago",
                remediation="Renew the SSL/TLS certificate immediately.",
                confidence=1.0,
                metadata={
                    "not_valid_after": not_valid_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                },
            )
            self._add_finding(finding)
        elif days_until_expiry < 7:
            finding = self._create_finding(
                severity="high",
                title="Certificate Expiring Soon",
                description=f"Certificate will expire in {days_until_expiry} days on {not_valid_after}",
                evidence=f"Expires in {days_until_expiry} days",
                remediation="Renew the SSL/TLS certificate soon.",
                confidence=1.0,
                metadata={
                    "not_valid_after": not_valid_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                },
            )
            self._add_finding(finding)
        elif days_until_expiry < 30:
            finding = self._create_finding(
                severity="medium",
                title="Certificate Expiring Within 30 Days",
                description=f"Certificate will expire in {days_until_expiry} days on {not_valid_after}",
                evidence=f"Expires in {days_until_expiry} days",
                remediation="Renew the SSL/TLS certificate within the next 30 days.",
                confidence=1.0,
                metadata={
                    "not_valid_after": not_valid_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                },
            )
            self._add_finding(finding)

    async def _check_hostname_match(self, cert_info: Dict[str, Any]) -> None:
        """
        Check if certificate hostname matches the target domain.

        Args:
            cert_info: Certificate information.
        """
        subject = cert_info.get("subject", {})
        sans = cert_info.get("sans", [])

        # Get CN from subject
        common_name = subject.get("commonName", "")

        # Check if domain matches
        domain = self.domain.lower()

        # Check CN
        cn_match = common_name.lower() == domain or common_name.lower() == f"*.{domain}"

        # Check SANs
        san_match = any(
            san.lower() == domain or san.lower() == f"*.{domain}"
            for san in sans
            if isinstance(san, str)
        )

        if not cn_match and not san_match:
            finding = self._create_finding(
                severity="high",
                title="Certificate Hostname Mismatch",
                description=(
                    f"The certificate does not match the hostname '{domain}'. "
                    f"CN: {common_name}, SANs: {sans}"
                ),
                evidence=f"Certificate CN: {common_name}, SANs: {sans}",
                remediation=(
                    "Install a certificate that matches the domain name. "
                    "Use Let's Encrypt or your CA to generate a valid certificate."
                ),
                confidence=1.0,
                metadata={
                    "common_name": common_name,
                    "sans": sans,
                    "domain": domain,
                },
            )
            self._add_finding(finding)

    async def _check_key_strength(self, cert_info: Dict[str, Any]) -> None:
        """
        Check key strength.

        Args:
            cert_info: Certificate information.
        """
        key_type = cert_info.get("key_type", "")
        key_size = cert_info.get("key_size", 0)

        if key_type == "RSA":
            if key_size < 2048:
                finding = self._create_finding(
                    severity="high",
                    title="Weak RSA Key Size",
                    description=f"RSA key size is {key_size} bits. Recommended minimum is 2048 bits.",
                    evidence=f"Key size: {key_size} bits",
                    remediation="Generate a new certificate with a 2048-bit or stronger RSA key.",
                    confidence=1.0,
                    metadata={"key_size": key_size, "key_type": key_type},
                )
                self._add_finding(finding)
            elif key_size == 2048:
                self._log_info("RSA key size is 2048 bits (acceptable)")
            else:
                self._log_info(f"RSA key size is {key_size} bits (good)")

        elif key_type == "EC":
            if key_size < 256:
                finding = self._create_finding(
                    severity="high",
                    title="Weak EC Key Size",
                    description=f"EC key size is {key_size} bits. Recommended minimum is 256 bits.",
                    evidence=f"Key size: {key_size} bits",
                    remediation="Generate a new certificate with a 256-bit or stronger EC key.",
                    confidence=1.0,
                    metadata={"key_size": key_size, "key_type": key_type},
                )
                self._add_finding(finding)
            else:
                self._log_info(f"EC key size is {key_size} bits (good)")

    async def _check_certificate_chain(self, cert_info: Dict[str, Any]) -> None:
        """
        Check certificate chain completeness.

        Args:
            cert_info: Certificate information.
        """
        issuer = cert_info.get("issuer", {})
        subject = cert_info.get("subject", {})

        # Check if certificate is self-signed
        if issuer.get("commonName") == subject.get("commonName"):
            finding = self._create_finding(
                severity="high",
                title="Self-Signed Certificate",
                description="The certificate is self-signed and not trusted by browsers.",
                evidence=f"Issuer: {issuer.get('commonName')}",
                remediation=(
                    "Install a certificate signed by a trusted Certificate Authority (CA). "
                    "Use Let's Encrypt for a free trusted certificate."
                ),
                confidence=1.0,
                metadata={"issuer": issuer, "subject": subject},
            )
            self._add_finding(finding)

    async def _check_protocol_versions(self) -> None:
        """Check supported TLS protocol versions."""
        # This is a simplified check - in production, you'd use tools like sslyze
        # or test each protocol version explicitly
        supported_versions = await self._get_supported_protocols()

        if supported_versions:
            # Check if TLS 1.0 or 1.1 are supported (insecure)
            if "TLSv1.0" in supported_versions or "TLSv1.1" in supported_versions:
                finding = self._create_finding(
                    severity="high",
                    title="Outdated TLS Protocol Supported",
                    description="The server supports TLS 1.0 or 1.1, which are deprecated and insecure.",
                    evidence=f"Supported versions: {supported_versions}",
                    remediation="Disable TLS 1.0 and 1.1. Support only TLS 1.2 and 1.3.",
                    confidence=0.8,
                    references=[
                        "https://www.rfc-editor.org/rfc/rfc8996.html",
                    ],
                    metadata={"supported_versions": supported_versions},
                )
                self._add_finding(finding)

            # Check if TLS 1.3 is supported (good)
            if "TLSv1.3" in supported_versions:
                self._log_info("TLS 1.3 is supported (good)")

    async def _get_supported_protocols(self) -> List[str]:
        """
        Get supported TLS protocol versions.

        Returns:
            List[str]: List of supported protocol versions.
        """
        # This is a simplified check
        # In production, you'd use a more comprehensive test
        supported = []

        # Test each protocol version (simplified)
        protocols = [
            ("TLSv1.0", ssl.PROTOCOL_TLSv1),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
        ]

        # TLS 1.3 requires a different approach
        for name, proto in protocols:
            try:
                context = ssl.SSLContext(proto)
                with socket.create_connection((self.domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        supported.append(name)
            except (ssl.SSLError, socket.error, ConnectionRefusedError):
                pass

        # Check TLS 1.3 (use default context)
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    supported.append("TLSv1.3")
        except (ssl.SSLError, socket.error, ConnectionRefusedError):
            pass

        return supported

    async def _check_cipher_suites(self) -> None:
        """Check for weak cipher suites."""
        # This is a simplified check
        # In production, you'd use a comprehensive cipher suite test
        weak_ciphers = await self._get_weak_ciphers()

        if weak_ciphers:
            finding = self._create_finding(
                severity="medium",
                title="Weak Cipher Suites Supported",
                description="The server supports weak cipher suites that are vulnerable to attacks.",
                evidence=f"Weak ciphers: {weak_ciphers}",
                remediation="Configure the server to use only strong cipher suites.",
                confidence=0.7,
                references=[
                    "https://wiki.mozilla.org/Security/Server_Side_TLS",
                ],
                metadata={"weak_ciphers": weak_ciphers},
            )
            self._add_finding(finding)

    async def _get_weak_ciphers(self) -> List[str]:
        """
        Get weak cipher suites.

        Returns:
            List[str]: List of weak cipher suites.
        """
        # Simplified check - in production, use a proper cipher scan
        weak_patterns = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA1"]

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    # Get cipher
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for pattern in weak_patterns:
                            if pattern.upper() in cipher_name.upper():
                                return [cipher_name]
        except Exception:
            pass

        return []