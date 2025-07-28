// SSL Analyzer Web Interface - JavaScript

class SSLAnalyzerApp {
    constructor() {
        this.currentResults = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupTabs();
        this.checkHealth();
    }

    setupEventListeners() {
        // Analysis buttons
        document.getElementById('analyzeBtn')?.addEventListener('click', () => this.analyzeSingle());
        document.getElementById('batchAnalyzeBtn')?.addEventListener('click', () => this.analyzeBatch());

        // Export buttons
        document.getElementById('exportJson')?.addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportHtml')?.addEventListener('click', () => this.exportResults('html'));
        document.getElementById('exportText')?.addEventListener('click', () => this.exportResults('text'));

        // Health check
        document.querySelector('.health-check')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.checkHealth(true);
        });

        // Enter key support
        document.getElementById('domain')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.analyzeSingle();
        });

        // Auto-parse domain input
        document.getElementById('domain')?.addEventListener('input', (e) => {
            this.autoParseDomain(e.target.value);
        });
    }

    setupTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');
                
                // Update active states
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                button.classList.add('active');
                document.getElementById(targetTab)?.classList.add('active');
            });
        });
    }

    autoParseDomain(input) {
        try {
            if (input.includes('://')) {
                const url = new URL(input);
                const portField = document.getElementById('port');
                if (portField && url.port) {
                    portField.value = url.port;
                } else if (portField) {
                    portField.value = url.protocol === 'https:' ? '443' : '80';
                }
            }
        } catch (e) {
            // Invalid URL, ignore
        }
    }

    async analyzeSingle() {
        const domain = document.getElementById('domain')?.value.trim();
        const port = parseInt(document.getElementById('port')?.value) || 443;
        const timeout = parseInt(document.getElementById('timeout')?.value) || 10;

        if (!domain) {
            this.showError('Please enter a domain name');
            return;
        }

        this.showLoading();
        this.setButtonState('analyzeBtn', true);

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domain, port, timeout })
            });

            const data = await response.json();

            if (data.success) {
                this.currentResults = [data.results];
                this.displayResults([data.results]);
            } else {
                this.showError(data.error || 'Analysis failed');
            }
        } catch (error) {
            this.showError(`Network error: ${error.message}`);
        } finally {
            this.hideLoading();
            this.setButtonState('analyzeBtn', false);
        }
    }

    async analyzeBatch() {
        const domainsText = document.getElementById('domains')?.value.trim();
        
        if (!domainsText) {
            this.showError('Please enter at least one domain');
            return;
        }

        const domains = domainsText.split('\n')
            .map(d => d.trim())
            .filter(d => d.length > 0);

        if (domains.length === 0) {
            this.showError('Please enter valid domains');
            return;
        }

        if (domains.length > 10) {
            this.showError('Maximum 10 domains allowed per batch');
            return;
        }

        this.showLoading();
        this.setButtonState('batchAnalyzeBtn', true);

        try {
            const response = await fetch('/batch', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domains, timeout: 10 })
            });

            const data = await response.json();

            if (data.success) {
                this.currentResults = data.results;
                this.displayBatchResults(data.results, data.total_analyzed);
            } else {
                this.showError(data.error || 'Batch analysis failed');
            }
        } catch (error) {
            this.showError(`Network error: ${error.message}`);
        } finally {
            this.hideLoading();
            this.setButtonState('batchAnalyzeBtn', false);
        }
    }

    displayResults(results) {
        const resultsDiv = document.getElementById('results');
        const contentDiv = document.getElementById('resultsContent');

        if (!resultsDiv || !contentDiv) return;

        let html = '';

        results.forEach(result => {
            if (result.analysis_failed) {
                html += this.renderErrorResult(result);
            } else {
                html += this.renderResult(result);
            }
        });

        contentDiv.innerHTML = html;
        resultsDiv.classList.remove('hidden');
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }

    displayBatchResults(results, totalAnalyzed) {
        const resultsDiv = document.getElementById('results');
        const contentDiv = document.getElementById('resultsContent');

        if (!resultsDiv || !contentDiv) return;

        // Calculate statistics
        const successful = results.filter(r => !r.analysis_failed).length;
        const failed = results.filter(r => r.analysis_failed).length;
        const avgScore = successful > 0 ? 
            Math.round(results.filter(r => !r.analysis_failed)
                .reduce((sum, r) => sum + (r.security_score || 0), 0) / successful) : 0;

        let html = `
            <div class="batch-summary">
                <h4>Batch Analysis Summary</h4>
                <div class="batch-stats">
                    <div class="batch-stat">
                        <div class="batch-stat-value">${totalAnalyzed}</div>
                        <div class="batch-stat-label">Total Analyzed</div>
                    </div>
                    <div class="batch-stat">
                        <div class="batch-stat-value">${successful}</div>
                        <div class="batch-stat-label">Successful</div>
                    </div>
                    <div class="batch-stat">
                        <div class="batch-stat-value">${failed}</div>
                        <div class="batch-stat-label">Failed</div>
                    </div>
                    <div class="batch-stat">
                        <div class="batch-stat-value">${avgScore}</div>
                        <div class="batch-stat-label">Avg Score</div>
                    </div>
                </div>
            </div>
        `;

        results.forEach(result => {
            if (result.analysis_failed) {
                html += this.renderErrorResult(result);
            } else {
                html += this.renderResult(result);
            }
        });

        contentDiv.innerHTML = html;
        resultsDiv.classList.remove('hidden');
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }

    renderResult(result) {
        const scoreClass = this.getScoreClass(result.security_score);
        const cert = result.certificate || {};
        const cipher = result.cipher_suite || {};
        const protocol = result.protocol_version || {};

        let html = `
            <div class="result-card">
                <div class="result-header">
                    <div class="domain-title">${result.hostname}:${result.port}</div>
                    <div class="security-score ${scoreClass}">${result.security_score}/100</div>
                </div>
                
                <div class="result-grid">
                    <div class="result-section">
                        <h4><i class="fas fa-certificate"></i> Certificate Info</h4>
                        <div class="result-item">
                            <span class="result-label">Subject:</span>
                            <span class="result-value">${cert.subject?.commonName || 'N/A'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Issuer:</span>
                            <span class="result-value">${cert.issuer?.organizationName || 'N/A'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Valid Until:</span>
                            <span class="result-value">${new Date(cert.not_after).toLocaleDateString()}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Days Until Expiry:</span>
                            <span class="result-value ${cert.expires_soon ? 'text-warning' : ''}">${cert.days_until_expiry}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Key Size:</span>
                            <span class="result-value">${cert.key_size} bits</span>
                        </div>
                    </div>
                    
                    <div class="result-section">
                        <h4><i class="fas fa-shield-alt"></i> Security Info</h4>
                        <div class="result-item">
                            <span class="result-label">Protocol:</span>
                            <span class="result-value">${protocol.version || 'N/A'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Cipher Suite:</span>
                            <span class="result-value">${cipher.name || 'N/A'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Cipher Strength:</span>
                            <span class="result-value">${cipher.strength || 'N/A'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Forward Secrecy:</span>
                            <span class="result-value">${cipher.supports_forward_secrecy ? 'Yes' : 'No'}</span>
                        </div>
                        <div class="result-item">
                            <span class="result-label">Signature Algorithm:</span>
                            <span class="result-value">${cert.signature_algorithm || 'N/A'}</span>
                        </div>
                    </div>
                </div>
        `;

        // Add vulnerabilities if any
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            html += `
                <div class="result-section">
                    <h4><i class="fas fa-exclamation-triangle"></i> Vulnerabilities (${result.vulnerabilities.length})</h4>
            `;
            
            result.vulnerabilities.forEach(vuln => {
                html += `
                    <div class="vulnerability">
                        <div class="vulnerability-header">
                            <span class="vulnerability-type">${vuln.type}</span>
                            <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        </div>
                        <div class="vulnerability-description">${vuln.description}</div>
                        <div class="vulnerability-impact">Impact: ${vuln.impact}</div>
                    </div>
                `;
            });
            
            html += '</div>';
        }

        // Add subject alternative names if available
        if (cert.subject_alt_names && cert.subject_alt_names.length > 0) {
            html += `
                <div class="result-section">
                    <h4><i class="fas fa-list"></i> Subject Alternative Names</h4>
                    <div class="result-value" style="word-break: break-all;">
                        ${cert.subject_alt_names.slice(0, 10).join(', ')}
                        ${cert.subject_alt_names.length > 10 ? ` (+${cert.subject_alt_names.length - 10} more)` : ''}
                    </div>
                </div>
            `;
        }

        html += '</div>';
        return html;
    }

    renderErrorResult(result) {
        return `
            <div class="result-card">
                <div class="result-header">
                    <div class="domain-title">${result.domain_input || result.hostname}</div>
                    <div class="security-score score-danger">ERROR</div>
                </div>
                <div class="vulnerability">
                    <div class="vulnerability-header">
                        <span class="vulnerability-type">Analysis Failed</span>
                        <span class="severity-badge severity-critical">ERROR</span>
                    </div>
                    <div class="vulnerability-description">${result.error}</div>
                </div>
            </div>
        `;
    }

    getScoreClass(score) {
        if (score >= 90) return 'score-excellent';
        if (score >= 75) return 'score-good';
        if (score >= 50) return 'score-warning';
        return 'score-danger';
    }

    async exportResults(format) {
        if (!this.currentResults || this.currentResults.length === 0) {
            this.showError('No results to export');
            return;
        }

        try {
            // For single domain, use the first result's hostname
            const domain = this.currentResults[0].hostname || 'batch-analysis';
            const url = `/export/${format}?domain=${encodeURIComponent(domain)}`;
            
            // Create download link
            const link = document.createElement('a');
            link.href = url;
            link.download = `ssl_analysis_${domain}_${new Date().toISOString().slice(0, 10)}.${format}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
        } catch (error) {
            this.showError(`Export failed: ${error.message}`);
        }
    }

    async checkHealth(showResult = false) {
        try {
            const response = await fetch('/api/health');
            const data = await response.json();
            
            if (showResult) {
                this.showSuccess(`Service is ${data.status} - Version ${data.version}`);
            }
        } catch (error) {
            if (showResult) {
                this.showError('Health check failed');
            }
        }
    }

    showLoading() {
        document.getElementById('loading')?.classList.remove('hidden');
        document.getElementById('results')?.classList.add('hidden');
    }

    hideLoading() {
        document.getElementById('loading')?.classList.add('hidden');
    }

    setButtonState(buttonId, disabled) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.disabled = disabled;
            if (disabled) {
                button.style.opacity = '0.6';
                button.style.cursor = 'not-allowed';
            } else {
                button.style.opacity = '1';
                button.style.cursor = 'pointer';
            }
        }
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showNotification(message, type = 'info') {
        // Create notification
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'check-circle'}"></i>
            <span>${message}</span>
            <button class="notification-close"><i class="fas fa-times"></i></button>
        `;

        // Add styles if not already added
        if (!document.getElementById('notification-styles')) {
            const style = document.createElement('style');
            style.id = 'notification-styles';
            style.textContent = `
                .notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--dark-surface);
                    border: 1px solid var(--dark-border);
                    color: var(--text-primary);
                    padding: 1rem;
                    border-radius: 0.5rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    z-index: 1000;
                    min-width: 300px;
                    animation: slideIn 0.3s ease;
                }
                .notification-error {
                    border-left: 4px solid var(--danger-color);
                }
                .notification-success {
                    border-left: 4px solid var(--success-color);
                }
                .notification-close {
                    background: none;
                    border: none;
                    color: var(--text-secondary);
                    cursor: pointer;
                    margin-left: auto;
                }
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        }

        // Add to page
        document.body.appendChild(notification);

        // Close button
        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.remove();
        });

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SSLAnalyzerApp();
});