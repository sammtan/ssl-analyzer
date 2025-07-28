#!/usr/bin/env python3
"""
Setup script for SSL/TLS Certificate Analyzer
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='ssl-analyzer',
    version='1.0.0',
    description='Comprehensive SSL/TLS Certificate Analyzer for security assessment',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Samuel Tan',
    author_email='samuel@sammtan.com',
    url='https://github.com/sammtan/ssl-analyzer',
    license='MIT',
    
    packages=find_packages('src'),
    package_dir={'': 'src'},
    
    install_requires=read_requirements(),
    
    entry_points={
        'console_scripts': [
            'ssl-analyzer=ssl_analyzer:main',
        ],
    },
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Utilities',
    ],
    
    keywords='ssl tls certificate security analysis encryption vulnerability',
    
    python_requires='>=3.7',
    
    include_package_data=True,
    zip_safe=False,
    
    project_urls={
        'Bug Reports': 'https://github.com/sammtan/ssl-analyzer/issues',
        'Source': 'https://github.com/sammtan/ssl-analyzer',
        'Documentation': 'https://github.com/sammtan/ssl-analyzer/blob/main/README.md',
    },
)