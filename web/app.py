#!/usr/bin/env python3
"""
SSL Analyzer Web Interface
Professional web UI for the SSL/TLS Certificate Analyzer tool.
"""

import sys
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.exceptions import BadRequest
import asyncio
from concurrent.futures import ThreadPoolExecutor
import io

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from ssl_analyzer import SSLAnalyzer, parse_url

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssl-analyzer-demo-key-change-in-production'

# Thread pool for async analysis
executor = ThreadPoolExecutor(max_workers=4)

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_domain():
    """Analyze a domain and return results."""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'Domain is required'}), 400
        
        domain = data['domain'].strip()
        port = data.get('port', 443)
        timeout = data.get('timeout', 10)
        
        if not domain:
            return jsonify({'error': 'Domain cannot be empty'}), 400
        
        # Parse domain if it includes protocol/port
        try:
            hostname, parsed_port = parse_url(domain)
            if port == 443:  # Use parsed port if default wasn't changed
                port = parsed_port
        except Exception as e:
            return jsonify({'error': f'Invalid domain format: {str(e)}'}), 400
        
        # Perform analysis
        analyzer = SSLAnalyzer()
        results = analyzer.analyze_domain(hostname, port, timeout)
        
        # Add analysis metadata
        results['analysis_time'] = datetime.now().isoformat()
        results['web_interface'] = True
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Analyze multiple domains."""
    try:
        data = request.get_json()
        if not data or 'domains' not in data:
            return jsonify({'error': 'Domains list is required'}), 400
        
        domains = data['domains']
        if not isinstance(domains, list) or len(domains) == 0:
            return jsonify({'error': 'Domains must be a non-empty list'}), 400
        
        if len(domains) > 10:  # Limit batch size
            return jsonify({'error': 'Maximum 10 domains allowed per batch'}), 400
        
        timeout = data.get('timeout', 10)
        results = []
        
        for domain in domains:
            try:
                hostname, port = parse_url(domain.strip())
                analyzer = SSLAnalyzer()
                result = analyzer.analyze_domain(hostname, port, timeout)
                result['domain_input'] = domain
                results.append(result)
            except Exception as e:
                results.append({
                    'domain_input': domain,
                    'error': str(e),
                    'hostname': domain,
                    'analysis_failed': True
                })
        
        return jsonify({
            'success': True,
            'results': results,
            'total_analyzed': len(results),
            'analysis_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/export/<format>')
def export_results(format):
    """Export analysis results."""
    try:
        # Get results from session or request
        domain = request.args.get('domain', 'example.com')
        
        # Perform fresh analysis for export
        hostname, port = parse_url(domain)
        analyzer = SSLAnalyzer()
        results = analyzer.analyze_domain(hostname, port)
        
        if format == 'json':
            response_data = json.dumps(results, indent=2, default=str)
            filename = f"ssl_analysis_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        elif format == 'html':
            response_data = analyzer.generate_report('html')
            filename = f"ssl_report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        else:
            response_data = analyzer.generate_report('text')
            filename = f"ssl_report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Create in-memory file
        output = io.BytesIO()
        output.write(response_data.encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'SSL Analyzer Web Interface',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/stats')
def get_stats():
    """Get application statistics."""
    return jsonify({
        'supported_formats': ['text', 'json', 'html'],
        'max_batch_size': 10,
        'default_timeout': 10,
        'supported_ports': 'Any (default: 443)',
        'features': [
            'Certificate validation',
            'Vulnerability detection', 
            'Security scoring',
            'Protocol analysis',
            'Cipher suite evaluation',
            'Batch processing'
        ]
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

if __name__ == '__main__':
    # Development server
    app.run(debug=True, host='0.0.0.0', port=5000)