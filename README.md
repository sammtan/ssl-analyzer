# SSL/TLS Certificate Analyzer

An educational Python-based tool for analyzing SSL/TLS certificates and security configurations. This tool provides detailed insights into certificate details, cipher suites, protocol versions, and a basic set of common security issues.

## 🚀 Features

- **Certificate Analysis**: Detailed certificate information including validity, issuer, subject, SANs, extensions, and fingerprints
- **Protocol Version Analysis**: Identifies the negotiated TLS version and flags deprecated protocols
- **Cipher Suite Evaluation**: Analyzes encryption strength and forward secrecy support
- **Basic Vulnerability Checks**: Detects ~6 common SSL/TLS issues (see [What It Analyzes](#-what-it-analyzes))
- **Multiple Output Formats**: Supports text, JSON, and HTML report formats
- **Security Scoring**: Includes an overall security score and actionable recommendations
- **Web Interface**: Browser-based UI built with Flask
- **CLI & Batch Analysis**: Command-line interface with argparse; supports analyzing multiple domains

## 📋 Requirements

- Python 3.7+
- cryptography library
- pyOpenSSL library
- requests library

## 🛠️ Installation

1. Clone or download the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Web Interface (Recommended)

The SSL Analyzer includes a professional web interface for easy analysis:

```bash
# Install web dependencies
pip install -r web-requirements.txt

# Run the web interface
python web/app.py

# Or using Docker
docker-compose up ssl-analyzer

# Access at http://localhost:5000
```

**Web Features:**
- 🖥️ Professional dark theme interface
- 🔍 Single domain analysis with real-time results
- 📊 Batch analysis of up to 10 domains
- 📈 Security scoring and vulnerability visualization
- 📄 Export results in JSON, HTML, and text formats
- 📱 Responsive design for mobile devices
- 🚀 REST API endpoints for integration

### Command Line Usage

### Basic Usage

```bash
# Analyze a domain
python ssl_analyzer.py google.com

# Analyze with specific port
python ssl_analyzer.py example.com -p 8443

# Analyze with custom timeout
python ssl_analyzer.py github.com --timeout 30
```

### Advanced Usage

```bash
# Generate JSON report
python ssl_analyzer.py badssl.com --format json

# Save report to file
python ssl_analyzer.py mozilla.org --output report.txt

# Generate HTML report
python ssl_analyzer.py cloudflare.com --format html --output report.html

# Analyze URL with protocol
python ssl_analyzer.py https://www.example.com:8443
```

### Command Line Options

```
usage: ssl_analyzer.py [-h] [-p PORT] [-t TIMEOUT] [-f {text,json,html}] 
                       [-o OUTPUT] [--no-color] target

positional arguments:
  target                Target hostname or URL to analyze

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port number (default: 443)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 10)
  -f {text,json,html}, --format {text,json,html}
                        Output format (default: text)
  -o OUTPUT, --output OUTPUT
                        Output file path (default: stdout)
  --no-color            Disable colored output
```

## 📊 Sample Output

### Text Report
```
============================================================
SSL/TLS CERTIFICATE ANALYSIS REPORT
============================================================
Target: example.com:443
Analysis Date: 2025-01-28T10:30:45.123456
Security Score: 85/100

CERTIFICATE INFORMATION
------------------------------
Subject: example.com
Issuer: DigiCert Inc
Valid From: 2024-01-15T00:00:00
Valid Until: 2025-01-15T23:59:59
Days Until Expiry: 352
Key Size: 2048 bits
Signature Algorithm: sha256WithRSAEncryption

PROTOCOL & CIPHER INFORMATION
-----------------------------------
Protocol Version: TLSv1.3
Protocol Status: Secure
Cipher Suite: TLS_AES_256_GCM_SHA384
Cipher Strength: Strong
Key Bits: 256
Forward Secrecy: Yes

SECURITY RECOMMENDATIONS
---------------------------
1. Set up certificate expiration monitoring [HIGH]
   Category: Monitoring
   Description: Monitor certificate expiration dates and set up automated renewal
```

### JSON Output
```json
{
  "hostname": "example.com",
  "port": 443,
  "timestamp": "2025-01-28T10:30:45.123456",
  "certificate": {
    "subject": {"commonName": "example.com"},
    "issuer": {"organizationName": "DigiCert Inc"},
    "days_until_expiry": 352,
    "key_size": 2048,
    "is_expired": false
  },
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "strength": "Strong",
    "supports_forward_secrecy": true
  },
  "vulnerabilities": [],
  "security_score": 85
}
```

## 🔍 What It Analyzes

### Certificate Details
- **Validity Period**: Checks if certificate is expired or expiring soon
- **Key Size**: Checks key strength (RSA keys below 2048 bits flagged)
- **Signature Algorithm**: Identifies weak signature algorithms (MD5, SHA1)
- **Subject Alternative Names**: Lists all domains covered by the certificate
- **Issuer Information**: Certificate authority details
- **Extensions**: Critical certificate extensions and fingerprints

### Protocol Security
- **TLS Version**: Identifies the **negotiated** protocol version and flags deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- **Cipher Suite**: Analyzes the **negotiated** cipher's encryption strength and algorithms
- **Forward Secrecy**: Checks for Perfect Forward Secrecy support
- **Weak Ciphers**: Flags insecure cipher algorithms (RC4, DES, 3DES, NULL, EXPORT)

### Vulnerability Checks (~6 types)
1. **Certificate Expired** — certificate past its `not_valid_after` date
2. **Certificate Expiring Soon** — expires within 30 days
3. **Weak Key Size** — RSA key smaller than 2048 bits
4. **Deprecated Protocol Version** — SSLv2, SSLv3, TLSv1, or TLSv1.1 negotiated
5. **Weak Cipher Suite** — negotiated cipher uses fewer than 128-bit key
6. **Insecure Cipher Algorithm** — RC4, DES, 3DES, NULL, or EXPORT in cipher name
7. **Weak Signature Algorithm** — SHA1 or MD5 used in certificate signature

## 🛡️ Security Considerations

### Educational Use Only
This tool is designed for:
- Learning about SSL/TLS security
- Testing your own domains and services
- Security research and education
- Authorized penetration testing

### Legal Usage
- Only test domains you own or have explicit permission to test
- Respect rate limits and don't overload target servers
- Use responsibly and ethically
- Follow all applicable laws and regulations

### ⚠️ Limitations
This tool is a **basic, educational SSL/TLS analysis utility** — not a comprehensive security scanner:

- **No chain-of-trust validation**: Connects with `ssl.CERT_NONE`, so the certificate chain is *read and parsed*, not cryptographically verified
- **No HSTS checking**: Does not inspect HTTP Strict Transport Security headers
- **No OCSP stapling check**: Does not verify certificate revocation status
- **No Certificate Transparency log check**: Does not query CT logs
- **Negotiated connection only**: Reports only the cipher suite and protocol version actually negotiated — not all ciphers/protocols the server supports
- **~6–7 vulnerability types**: Does not cover the full range of known SSL/TLS weaknesses
- **Not a replacement** for professional tools such as [testssl.sh](https://testssl.sh/), [sslyze](https://github.com/nabla-c0d3/sslyze), or [SSL Labs](https://www.ssllabs.com/ssltest/)

## 🤝 Contributing

This project is part of an educational portfolio. Suggestions and improvements are welcome for learning purposes.

## 📄 License

Educational use only. This tool is provided for learning and authorized security testing purposes.

## 🔗 Related Tools

This SSL Analyzer is part of a comprehensive security toolkit including:
- Port Scanner Pro
- Hash Cracker
- DNS Resolver
- Packet Sniffer
- Log Parser
- Forensics Extractor

## 📞 Support

For educational purposes and portfolio demonstration. Use responsibly and ethically.

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and obtaining proper authorization before testing any systems they do not own.