#!/usr/bin/env python3
"""
SSL Analyzer - Basic Usage Examples
Educational demonstration of the SSL/TLS Certificate Analyzer tool.
"""

import sys
import os

# Add the src directory to the path so we can import our module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ssl_analyzer import SSLAnalyzer, parse_url


def example_basic_analysis():
    """Example 1: Basic SSL certificate analysis."""
    print("Example 1: Basic SSL Certificate Analysis")
    print("=" * 50)

    analyzer = SSLAnalyzer()

    try:
        # Analyze a well-known secure site
        results = analyzer.analyze_domain("google.com", 443, timeout=10)

        print(f"✅ Analysis completed for google.com")
        print(f"Security Score: {results['security_score']}/100")
        print(
            f"Certificate expires in: {results['certificate']['days_until_expiry']} days"
        )
        print(f"Protocol Version: {results['protocol_version']['version']}")
        print(f"Cipher Suite: {results['cipher_suite']['name']}")

        if results["vulnerabilities"]:
            print(f"⚠️  Found {len(results['vulnerabilities'])} vulnerabilities")
        else:
            print("✅ No critical vulnerabilities detected")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")


def example_json_output():
    """Example 2: JSON output format."""
    print("\nExample 2: JSON Output Format")
    print("=" * 40)

    analyzer = SSLAnalyzer()

    try:
        # Analyze and get JSON output
        results = analyzer.analyze_domain("github.com", 443)
        json_report = analyzer.generate_report("json")

        print("JSON report generated (first 300 characters):")
        print(json_report[:300] + "...")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")


def example_vulnerability_detection():
    """Example 3: Testing with a site that has SSL issues."""
    print("\nExample 3: Vulnerability Detection")
    print("=" * 45)

    analyzer = SSLAnalyzer()

    # Note: badssl.com provides intentionally misconfigured SSL for testing
    test_domains = [
        ("expired.badssl.com", "Expired Certificate"),
        ("self-signed.badssl.com", "Self-Signed Certificate"),
        ("wrong.host.badssl.com", "Wrong Hostname"),
        ("untrusted-root.badssl.com", "Untrusted Root"),
    ]

    for domain, description in test_domains:
        try:
            print(f"\nTesting: {domain} ({description})")
            results = analyzer.analyze_domain(domain, 443, timeout=5)

            print(f"Security Score: {results['security_score']}/100")

            if results["vulnerabilities"]:
                print(f"Vulnerabilities found:")
                for vuln in results["vulnerabilities"][:2]:  # Show first 2
                    print(f"  - {vuln['type']}: {vuln['severity']}")
            else:
                print("No vulnerabilities detected")

        except Exception as e:
            print(f"Expected error for {domain}: {str(e)[:50]}...")


def example_batch_analysis():
    """Example 4: Batch analysis of multiple domains."""
    print("\nExample 4: Batch Analysis")
    print("=" * 35)

    domains = ["google.com", "github.com", "stackoverflow.com", "cloudflare.com"]
    results_summary = []

    for domain in domains:
        analyzer = SSLAnalyzer()
        try:
            results = analyzer.analyze_domain(domain, 443, timeout=8)
            results_summary.append(
                {
                    "domain": domain,
                    "score": results["security_score"],
                    "protocol": results["protocol_version"]["version"],
                    "expires_in": results["certificate"]["days_until_expiry"],
                    "vulnerabilities": len(results["vulnerabilities"]),
                }
            )

        except Exception as e:
            results_summary.append({"domain": domain, "error": str(e)[:30]})

    # Display summary table
    print(f"{'Domain':<20} {'Score':<6} {'Protocol':<10} {'Expires':<8} {'Vulns':<6}")
    print("-" * 60)

    for result in results_summary:
        if "error" in result:
            print(f"{result['domain']:<20} {'ERROR':<6} {result['error']:<10}")
        else:
            print(
                f"{result['domain']:<20} {result['score']:<6} {result['protocol']:<10} {result['expires_in']:<8} {result['vulnerabilities']:<6}"
            )


def example_url_parsing():
    """Example 5: URL parsing functionality."""
    print("\nExample 5: URL Parsing")
    print("=" * 30)

    test_urls = [
        "google.com",
        "https://github.com",
        "https://example.com:8443",
        "http://insecure.example.com:8080",
    ]

    print(f"{'URL':<35} {'Hostname':<20} {'Port':<6}")
    print("-" * 65)

    for url in test_urls:
        try:
            hostname, port = parse_url(url)
            print(f"{url:<35} {hostname:<20} {port:<6}")
        except Exception as e:
            print(f"{url:<35} {'ERROR':<20} {str(e):<6}")


def main():
    """Run all examples."""
    print("🔍 SSL/TLS Certificate Analyzer - Usage Examples")
    print("=" * 60)
    print("Educational demonstration of SSL analysis capabilities")
    print("⚠️  Only test domains you own or have permission to test!")
    print()

    try:
        # Run examples
        example_basic_analysis()
        example_json_output()
        example_url_parsing()
        example_batch_analysis()

        # Uncomment to test vulnerability detection (may take longer)
        # example_vulnerability_detection()

        print("\n" + "=" * 60)
        print("✅ Examples completed successfully!")
        print("💡 Try running the main script with different domains:")
        print("   python ssl_analyzer.py your-domain.com")

    except KeyboardInterrupt:
        print("\n⚠️  Examples interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")


if __name__ == "__main__":
    main()
