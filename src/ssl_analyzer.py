#!/usr/bin/env python3
"""
SSL/TLS Certificate Analyzer
A comprehensive tool for analyzing SSL/TLS certificates and security configurations.

Author: Samuel Tan
License: Educational Use Only
"""

import ssl
import socket
import datetime
import json
import argparse
import sys
import re
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import OpenSSL
from typing import Dict, List, Optional, Tuple


class SSLAnalyzer:
    """Main SSL/TLS certificate analyzer class."""

    def __init__(self):
        self.results = {}
        self.vulnerabilities = []
        self.recommendations = []

    def analyze_domain(self, hostname: str, port: int = 443, timeout: int = 10) -> Dict:
        """
        Analyze SSL/TLS configuration for a given domain.

        Args:
            hostname: Target hostname to analyze
            port: SSL/TLS port (default: 443)
            timeout: Connection timeout in seconds

        Returns:
            Dictionary containing analysis results
        """
        print(f"[*] Analyzing SSL/TLS configuration for {hostname}:{port}")

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate info
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

            # Parse certificate with cryptography library
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Perform comprehensive analysis
            self.results = {
                "hostname": hostname,
                "port": port,
                "timestamp": datetime.datetime.now().isoformat(),
                "certificate": self._analyze_certificate(cert, cert_info),
                "cipher_suite": self._analyze_cipher_suite(cipher),
                "protocol_version": self._analyze_protocol_version(version),
                "vulnerabilities": [],
                "recommendations": [],
                "security_score": 0,
            }

            # Run security checks
            self._check_vulnerabilities(cert, cipher, version)
            self._generate_recommendations()
            self._calculate_security_score()

            self.results["vulnerabilities"] = self.vulnerabilities
            self.results["recommendations"] = self.recommendations

            return self.results

        except socket.timeout:
            raise Exception(f"Connection timeout to {hostname}:{port}")
        except socket.gaierror:
            raise Exception(f"DNS resolution failed for {hostname}")
        except ssl.SSLError as e:
            raise Exception(f"SSL/TLS error: {str(e)}")
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")

    def _analyze_certificate(self, cert: x509.Certificate, cert_info: Dict) -> Dict:
        """Analyze certificate details."""
        print("[*] Analyzing certificate details...")

        # Extract certificate information
        subject = cert.subject
        issuer = cert.issuer

        # Get subject and issuer details
        subject_dict = {}
        for attribute in subject:
            subject_dict[attribute.oid._name] = attribute.value

        issuer_dict = {}
        for attribute in issuer:
            issuer_dict[attribute.oid._name] = attribute.value

        # Certificate validity
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        days_until_expiry = (not_after - datetime.datetime.now()).days

        # Public key information
        public_key = cert.public_key()
        key_size = public_key.key_size if hasattr(public_key, "key_size") else "Unknown"

        # Extensions
        extensions = {}
        try:
            for ext in cert.extensions:
                extensions[ext.oid._name] = str(ext.value)
        except Exception:
            pass

        # Subject Alternative Names
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        return {
            "subject": subject_dict,
            "issuer": issuer_dict,
            "version": cert.version.name,
            "serial_number": str(cert.serial_number),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_algorithm": type(public_key).__name__,
            "key_size": key_size,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "is_expired": days_until_expiry < 0,
            "expires_soon": days_until_expiry < 30,
            "subject_alt_names": san_list,
            "extensions": extensions,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        }

    def _analyze_cipher_suite(self, cipher: Tuple) -> Dict:
        """Analyze cipher suite information."""
        print("[*] Analyzing cipher suite...")

        if not cipher:
            return {"error": "No cipher information available"}

        cipher_name, protocol_version, key_bits = cipher

        # Analyze cipher strength
        strength = "Unknown"
        if key_bits >= 256:
            strength = "Strong"
        elif key_bits >= 128:
            strength = "Adequate"
        elif key_bits >= 64:
            strength = "Weak"
        else:
            strength = "Very Weak"

        # Check for deprecated ciphers
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "SHA1"]
        is_deprecated = any(weak in cipher_name.upper() for weak in weak_ciphers)

        return {
            "name": cipher_name,
            "protocol_version": protocol_version,
            "key_bits": key_bits,
            "strength": strength,
            "is_deprecated": is_deprecated,
            "supports_forward_secrecy": "ECDHE" in cipher_name or "DHE" in cipher_name,
        }

    def _analyze_protocol_version(self, version: str) -> Dict:
        """Analyze SSL/TLS protocol version."""
        print("[*] Analyzing protocol version...")

        # Protocol security assessment
        secure_versions = ["TLSv1.2", "TLSv1.3"]
        deprecated_versions = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

        is_secure = version in secure_versions
        is_deprecated = version in deprecated_versions

        return {
            "version": version,
            "is_secure": is_secure,
            "is_deprecated": is_deprecated,
            "recommendation": "Secure" if is_secure else "Upgrade Required",
        }

    def _check_vulnerabilities(
        self, cert: x509.Certificate, cipher: Tuple, version: str
    ):
        """Check for common SSL/TLS vulnerabilities."""
        print("[*] Checking for vulnerabilities...")

        # Certificate expiry check
        days_until_expiry = (
            cert.not_valid_after_utc.replace(tzinfo=None) - datetime.datetime.now()
        ).days
        if days_until_expiry < 0:
            self.vulnerabilities.append(
                {
                    "type": "Certificate Expired",
                    "severity": "CRITICAL",
                    "description": f"Certificate expired {abs(days_until_expiry)} days ago",
                    "impact": "Users will see security warnings and may not be able to connect",
                }
            )
        elif days_until_expiry < 30:
            self.vulnerabilities.append(
                {
                    "type": "Certificate Expiring Soon",
                    "severity": "HIGH",
                    "description": f"Certificate expires in {days_until_expiry} days",
                    "impact": "Service disruption if not renewed soon",
                }
            )

        # Weak key size check
        public_key = cert.public_key()
        if hasattr(public_key, "key_size"):
            if public_key.key_size < 2048:
                self.vulnerabilities.append(
                    {
                        "type": "Weak Key Size",
                        "severity": "HIGH",
                        "description": f"RSA key size is {public_key.key_size} bits (minimum recommended: 2048)",
                        "impact": "Vulnerable to brute force attacks",
                    }
                )

        # Deprecated protocol version
        if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            self.vulnerabilities.append(
                {
                    "type": "Deprecated Protocol Version",
                    "severity": "HIGH" if version in ["SSLv2", "SSLv3"] else "MEDIUM",
                    "description": f"Using deprecated protocol version: {version}",
                    "impact": "Vulnerable to protocol-specific attacks",
                }
            )

        # Weak cipher suite
        if cipher:
            cipher_name = cipher[0]
            key_bits = cipher[2]

            if key_bits < 128:
                self.vulnerabilities.append(
                    {
                        "type": "Weak Cipher Suite",
                        "severity": "HIGH",
                        "description": f"Cipher {cipher_name} uses only {key_bits} bits",
                        "impact": "Encryption can be broken with sufficient resources",
                    }
                )

            # Check for specific weak ciphers
            weak_patterns = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
            for pattern in weak_patterns:
                if pattern in cipher_name.upper():
                    self.vulnerabilities.append(
                        {
                            "type": "Insecure Cipher Algorithm",
                            "severity": (
                                "CRITICAL" if pattern in ["NULL", "EXPORT"] else "HIGH"
                            ),
                            "description": f"Using insecure cipher algorithm: {pattern}",
                            "impact": "Encryption may be easily broken",
                        }
                    )

        # Check signature algorithm
        sig_alg = cert.signature_algorithm_oid._name
        if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
            self.vulnerabilities.append(
                {
                    "type": "Weak Signature Algorithm",
                    "severity": "MEDIUM",
                    "description": f"Certificate uses weak signature algorithm: {sig_alg}",
                    "impact": "Certificate authenticity may be compromised",
                }
            )

    def _generate_recommendations(self):
        """Generate security recommendations."""
        print("[*] Generating recommendations...")

        # Always recommend monitoring
        self.recommendations.append(
            {
                "category": "Monitoring",
                "recommendation": "Set up certificate expiration monitoring",
                "priority": "HIGH",
                "description": "Monitor certificate expiration dates and set up automated renewal",
            }
        )

        # Check if any critical vulnerabilities exist
        critical_vulns = [
            v for v in self.vulnerabilities if v["severity"] == "CRITICAL"
        ]
        if critical_vulns:
            self.recommendations.append(
                {
                    "category": "Security",
                    "recommendation": "Address critical vulnerabilities immediately",
                    "priority": "CRITICAL",
                    "description": "Critical security issues found that require immediate attention",
                }
            )

        # Protocol recommendations
        if "protocol_version" in self.results:
            if not self.results["protocol_version"]["is_secure"]:
                self.recommendations.append(
                    {
                        "category": "Protocol",
                        "recommendation": "Upgrade to TLS 1.2 or 1.3",
                        "priority": "HIGH",
                        "description": "Use only secure protocol versions (TLS 1.2 or 1.3)",
                    }
                )

        # Cipher suite recommendations
        if "cipher_suite" in self.results:
            if self.results["cipher_suite"].get("is_deprecated"):
                self.recommendations.append(
                    {
                        "category": "Encryption",
                        "recommendation": "Update cipher suite configuration",
                        "priority": "HIGH",
                        "description": "Remove deprecated cipher suites and use modern alternatives",
                    }
                )

            if not self.results["cipher_suite"].get("supports_forward_secrecy"):
                self.recommendations.append(
                    {
                        "category": "Encryption",
                        "recommendation": "Enable Perfect Forward Secrecy",
                        "priority": "MEDIUM",
                        "description": "Configure cipher suites that support Perfect Forward Secrecy (ECDHE/DHE)",
                    }
                )

    def _calculate_security_score(self):
        """Calculate overall security score (0-100)."""
        score = 100

        # Deduct points for vulnerabilities
        for vuln in self.vulnerabilities:
            if vuln["severity"] == "CRITICAL":
                score -= 30
            elif vuln["severity"] == "HIGH":
                score -= 20
            elif vuln["severity"] == "MEDIUM":
                score -= 10
            elif vuln["severity"] == "LOW":
                score -= 5

        # Ensure score doesn't go below 0
        self.results["security_score"] = max(0, score)

    def generate_report(self, format_type: str = "text") -> str:
        """Generate analysis report in specified format."""
        if format_type == "json":
            return json.dumps(self.results, indent=2, default=str)
        elif format_type == "html":
            return self._generate_html_report()
        else:
            return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """Generate human-readable text report."""
        if not self.results:
            return "No analysis results available."

        report = []
        report.append("=" * 60)
        report.append("SSL/TLS CERTIFICATE ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Target: {self.results['hostname']}:{self.results['port']}")
        report.append(f"Analysis Date: {self.results['timestamp']}")
        report.append(f"Security Score: {self.results['security_score']}/100")
        report.append("")

        # Certificate Information
        cert = self.results.get("certificate", {})
        if cert:
            report.append("CERTIFICATE INFORMATION")
            report.append("-" * 30)
            report.append(
                f"Subject: {cert.get('subject', {}).get('commonName', 'N/A')}"
            )
            report.append(
                f"Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}"
            )
            report.append(f"Valid From: {cert.get('not_before', 'N/A')}")
            report.append(f"Valid Until: {cert.get('not_after', 'N/A')}")
            report.append(f"Days Until Expiry: {cert.get('days_until_expiry', 'N/A')}")
            report.append(f"Key Size: {cert.get('key_size', 'N/A')} bits")
            report.append(
                f"Signature Algorithm: {cert.get('signature_algorithm', 'N/A')}"
            )

            if cert.get("subject_alt_names"):
                report.append(
                    f"Subject Alt Names: {', '.join(cert['subject_alt_names'])}"
                )
            report.append("")

        # Protocol and Cipher Information
        protocol = self.results.get("protocol_version", {})
        cipher = self.results.get("cipher_suite", {})

        if protocol or cipher:
            report.append("PROTOCOL & CIPHER INFORMATION")
            report.append("-" * 35)
            if protocol:
                report.append(f"Protocol Version: {protocol.get('version', 'N/A')}")
                report.append(
                    f"Protocol Status: {protocol.get('recommendation', 'N/A')}"
                )
            if cipher:
                report.append(f"Cipher Suite: {cipher.get('name', 'N/A')}")
                report.append(f"Cipher Strength: {cipher.get('strength', 'N/A')}")
                report.append(f"Key Bits: {cipher.get('key_bits', 'N/A')}")
                report.append(
                    f"Forward Secrecy: {'Yes' if cipher.get('supports_forward_secrecy') else 'No'}"
                )
            report.append("")

        # Vulnerabilities
        if self.vulnerabilities:
            report.append("SECURITY VULNERABILITIES")
            report.append("-" * 25)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"{i}. {vuln['type']} [{vuln['severity']}]")
                report.append(f"   Description: {vuln['description']}")
                report.append(f"   Impact: {vuln['impact']}")
                report.append("")
        else:
            report.append("No critical vulnerabilities detected.")
            report.append("")

        # Recommendations
        if self.recommendations:
            report.append("SECURITY RECOMMENDATIONS")
            report.append("-" * 27)
            for i, rec in enumerate(self.recommendations, 1):
                report.append(f"{i}. {rec['recommendation']} [{rec['priority']}]")
                report.append(f"   Category: {rec['category']}")
                report.append(f"   Description: {rec['description']}")
                report.append("")

        report.append("=" * 60)
        report.append("Analysis completed. Stay secure!")
        report.append("=" * 60)

        return "\n".join(report)

    def _generate_html_report(self) -> str:
        """Generate HTML report."""
        # Simplified HTML report - can be expanded
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SSL/TLS Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .vulnerability {{ background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }}
                .recommendation {{ background-color: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin: 10px 0; }}
                .score {{ font-size: 24px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SSL/TLS Analysis Report</h1>
                <p>Target: {self.results.get('hostname', 'N/A')}:{self.results.get('port', 'N/A')}</p>
                <p class="score">Security Score: {self.results.get('security_score', 0)}/100</p>
            </div>
            
            <div class="section">
                <h2>Certificate Information</h2>
                <pre>{json.dumps(self.results.get('certificate', {}), indent=2, default=str)}</pre>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {''.join([f'<div class="vulnerability"><strong>{v["type"]}</strong> [{v["severity"]}]<br>{v["description"]}</div>' for v in self.vulnerabilities]) if self.vulnerabilities else '<p>No vulnerabilities detected.</p>'}
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                {''.join([f'<div class="recommendation"><strong>{r["recommendation"]}</strong> [{r["priority"]}]<br>{r["description"]}</div>' for r in self.recommendations]) if self.recommendations else '<p>No specific recommendations.</p>'}
            </div>
        </body>
        </html>
        """
        return html


def parse_url(url: str) -> Tuple[str, int]:
    """Parse URL to extract hostname and port."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    return hostname, port


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SSL/TLS Certificate Analyzer - Comprehensive security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_analyzer.py google.com
  python ssl_analyzer.py https://example.com:8443
  python ssl_analyzer.py github.com --format json --output report.json
  python ssl_analyzer.py badssl.com --timeout 30
        """,
    )

    parser.add_argument("target", help="Target hostname or URL to analyze")
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Port number (default: 443)"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    args = parser.parse_args()

    try:
        # Parse target
        if "://" in args.target or ":" in args.target:
            hostname, port = parse_url(args.target)
        else:
            hostname, port = args.target, args.port

        # Initialize analyzer
        analyzer = SSLAnalyzer()

        # Perform analysis
        print(f"\n[*] Starting SSL/TLS analysis for {hostname}:{port}")
        print("=" * 50)

        results = analyzer.analyze_domain(hostname, port, args.timeout)

        # Generate report
        report = analyzer.generate_report(args.format)

        # Output results
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n[+] Report saved to: {args.output}")
        else:
            print("\n" + report)

        # Exit with appropriate code
        critical_vulns = [
            v for v in analyzer.vulnerabilities if v["severity"] == "CRITICAL"
        ]
        sys.exit(1 if critical_vulns else 0)

    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
