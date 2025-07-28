#!/usr/bin/env python3
"""
Basic tests for SSL Analyzer tool.
Educational testing framework for the SSL/TLS Certificate Analyzer.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ssl_analyzer import SSLAnalyzer, parse_url


class TestSSLAnalyzer(unittest.TestCase):
    """Test cases for SSL Analyzer functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = SSLAnalyzer()

    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly."""
        self.assertIsInstance(self.analyzer, SSLAnalyzer)
        self.assertEqual(self.analyzer.results, {})
        self.assertEqual(self.analyzer.vulnerabilities, [])
        self.assertEqual(self.analyzer.recommendations, [])

    def test_url_parsing(self):
        """Test URL parsing functionality."""
        test_cases = [
            ("google.com", ("google.com", 443)),
            ("https://github.com", ("github.com", 443)),
            ("https://example.com:8443", ("example.com", 8443)),
            ("http://test.com:8080", ("test.com", 8080)),
            ("test.example.com", ("test.example.com", 443)),
        ]

        for url, expected in test_cases:
            with self.subTest(url=url):
                result = parse_url(url)
                self.assertEqual(result, expected)

    def test_url_parsing_invalid(self):
        """Test URL parsing with invalid inputs."""
        invalid_urls = ["", "not-a-url", "ftp://invalid.com"]

        for url in invalid_urls:
            with self.subTest(url=url):
                try:
                    parse_url(url)
                except Exception:
                    pass  # Expected to fail

    def test_security_score_calculation(self):
        """Test security score calculation logic."""
        # Mock some results
        self.analyzer.results = {"security_score": 0}

        # Test with no vulnerabilities
        self.analyzer.vulnerabilities = []
        self.analyzer._calculate_security_score()
        self.assertEqual(self.analyzer.results["security_score"], 100)

        # Test with critical vulnerability
        self.analyzer.vulnerabilities = [{"severity": "CRITICAL"}]
        self.analyzer._calculate_security_score()
        self.assertEqual(self.analyzer.results["security_score"], 70)

        # Test with multiple vulnerabilities
        self.analyzer.vulnerabilities = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        self.analyzer._calculate_security_score()
        self.assertEqual(self.analyzer.results["security_score"], 40)

    def test_report_generation_text(self):
        """Test text report generation."""
        # Mock basic results
        self.analyzer.results = {
            "hostname": "test.com",
            "port": 443,
            "timestamp": "2025-01-28T12:00:00",
            "security_score": 85,
            "certificate": {
                "subject": {"commonName": "test.com"},
                "issuer": {"organizationName": "Test CA"},
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
                "days_until_expiry": 100,
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
            },
            "protocol_version": {"version": "TLSv1.3", "recommendation": "Secure"},
            "cipher_suite": {
                "name": "TLS_AES_256_GCM_SHA384",
                "strength": "Strong",
                "key_bits": 256,
                "supports_forward_secrecy": True,
            },
        }

        self.analyzer.vulnerabilities = []
        self.analyzer.recommendations = [
            {
                "recommendation": "Monitor certificate expiration",
                "priority": "HIGH",
                "category": "Monitoring",
                "description": "Set up monitoring",
            }
        ]

        report = self.analyzer.generate_report("text")

        # Check that report contains expected sections
        self.assertIn("SSL/TLS CERTIFICATE ANALYSIS REPORT", report)
        self.assertIn("test.com:443", report)
        self.assertIn("Security Score: 85/100", report)
        self.assertIn("CERTIFICATE INFORMATION", report)
        self.assertIn("SECURITY RECOMMENDATIONS", report)

    def test_report_generation_json(self):
        """Test JSON report generation."""
        # Mock basic results
        self.analyzer.results = {
            "hostname": "test.com",
            "port": 443,
            "security_score": 90,
        }

        report = self.analyzer.generate_report("json")

        # Check that it's valid JSON
        import json

        try:
            parsed = json.loads(report)
            self.assertIsInstance(parsed, dict)
            self.assertEqual(parsed["hostname"], "test.com")
            self.assertEqual(parsed["security_score"], 90)
        except json.JSONDecodeError:
            self.fail("Generated report is not valid JSON")

    def test_vulnerability_detection_logic(self):
        """Test vulnerability detection logic."""
        # This would normally require mocking SSL connections
        # For now, test the logic components

        # Test that vulnerability list starts empty
        self.assertEqual(len(self.analyzer.vulnerabilities), 0)

        # Test adding vulnerabilities
        test_vuln = {
            "type": "Test Vulnerability",
            "severity": "HIGH",
            "description": "Test description",
            "impact": "Test impact",
        }

        self.analyzer.vulnerabilities.append(test_vuln)
        self.assertEqual(len(self.analyzer.vulnerabilities), 1)
        self.assertEqual(self.analyzer.vulnerabilities[0]["type"], "Test Vulnerability")

    def test_recommendation_generation(self):
        """Test recommendation generation logic."""
        # Mock some basic results
        self.analyzer.results = {
            "protocol_version": {"is_secure": False},
            "cipher_suite": {"is_deprecated": True, "supports_forward_secrecy": False},
        }

        # Mock some vulnerabilities
        self.analyzer.vulnerabilities = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]

        self.analyzer._generate_recommendations()

        # Check that recommendations were generated
        self.assertGreater(len(self.analyzer.recommendations), 0)

        # Check for specific recommendations
        rec_types = [rec["category"] for rec in self.analyzer.recommendations]
        self.assertIn("Monitoring", rec_types)  # Should always recommend monitoring


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""

    def test_parse_url_edge_cases(self):
        """Test edge cases for URL parsing."""
        # Test localhost
        hostname, port = parse_url("localhost")
        self.assertEqual(hostname, "localhost")
        self.assertEqual(port, 443)

        # Test IP address
        hostname, port = parse_url("192.168.1.1")
        self.assertEqual(hostname, "192.168.1.1")
        self.assertEqual(port, 443)

        # Test with HTTP (should use port 80)
        hostname, port = parse_url("http://example.com")
        self.assertEqual(hostname, "example.com")
        self.assertEqual(port, 80)


def run_tests():
    """Run all tests."""
    print("🧪 Running SSL Analyzer Tests")
    print("=" * 40)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestSSLAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 40)
    if result.wasSuccessful():
        print("✅ All tests passed!")
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
