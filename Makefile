# SSL/TLS Certificate Analyzer - Makefile
# Provides convenient commands for development and testing

.PHONY: help install test run example clean build upload lint

# Default target
help:
	@echo "SSL/TLS Certificate Analyzer - Available Commands:"
	@echo "=================================================="
	@echo "install     - Install dependencies"
	@echo "test        - Run tests"
	@echo "run         - Run analyzer with example domain"
	@echo "example     - Run usage examples"
	@echo "lint        - Run code linting"
	@echo "clean       - Clean build artifacts"
	@echo "build       - Build distribution packages"
	@echo "docs        - Generate documentation"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make install"
	@echo "  make test"
	@echo "  make run TARGET=google.com"
	@echo "  make example"

# Install dependencies
install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	pip install -e .

# Install development dependencies
install-dev: install
	@echo "Installing development dependencies..."
	pip install pytest pytest-cov flake8 black mypy

# Run tests
test:
	@echo "Running tests..."
	python -m pytest tests/ -v
	@echo "Running basic unit tests..."
	python tests/test_ssl_analyzer.py

# Run analyzer with specified target (default: google.com)
TARGET ?= google.com
run:
	@echo "Running SSL Analyzer on $(TARGET)..."
	python src/ssl_analyzer.py $(TARGET)

# Run examples
example:
	@echo "Running usage examples..."
	python examples/basic_usage.py

# Run linting
lint:
	@echo "Running code linting..."
	flake8 src/ tests/ examples/ --max-line-length=100 --ignore=E501,W503
	@echo "Checking code formatting..."
	black --check src/ tests/ examples/

# Format code
format:
	@echo "Formatting code..."
	black src/ tests/ examples/

# Type checking
typecheck:
	@echo "Running type checking..."
	mypy src/ssl_analyzer.py

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete

# Build distribution packages
build: clean
	@echo "Building distribution packages..."
	python setup.py sdist bdist_wheel

# Generate documentation
docs:
	@echo "Documentation available in README.md"
	@echo "For detailed usage, see examples/ directory"

# Security scan
security:
	@echo "Running security scan..."
	bandit -r src/

# Performance test
perf:
	@echo "Running performance test..."
	@echo "Testing analysis speed on multiple domains..."
	@time python -c "from src.ssl_analyzer import SSLAnalyzer; \
	domains = ['google.com', 'github.com', 'stackoverflow.com']; \
	[SSLAnalyzer().analyze_domain(d) for d in domains]; \
	print('Performance test completed')"

# Demo run with comprehensive output
demo:
	@echo "Running comprehensive demo..."
	python src/ssl_analyzer.py google.com --format text
	@echo ""
	@echo "JSON output example:"
	python src/ssl_analyzer.py github.com --format json | head -20

# Quick test on local development
dev-test:
	@echo "Running quick development tests..."
	python -m pytest tests/test_ssl_analyzer.py -v
	python examples/basic_usage.py

# Install and run everything
all: install test example
	@echo "SSL Analyzer setup and testing completed!"

# Show tool version and system info
info:
	@echo "SSL Analyzer Tool Information"
	@echo "============================"
	@echo "Python version: $(shell python --version)"
	@echo "Dependencies:"
	@cat requirements.txt
	@echo ""
	@echo "Tool capabilities:"
	@echo "- SSL/TLS certificate analysis"
	@echo "- Security vulnerability detection"
	@echo "- Multiple output formats (text, JSON, HTML)"
	@echo "- Batch domain analysis"
	@echo "- Comprehensive security scoring"