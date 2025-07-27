#!/usr/bin/env python3
"""
Setup script for DMV scam analysis project.
"""

from setuptools import setup, find_packages
import os

# Read version from file
version_file = os.path.join(os.path.dirname(__file__), 'VERSION')
with open(version_file) as f:
    version = f.read().strip()

# Read long description from README
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='dmv-scam-analysis',
    version=version,
    description='Analysis toolkit for DMV-related scam messages',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/dmv_scam_analysis',
    packages=find_packages(where='src', exclude=['tests*', 'docs*']),
    package_dir={'': 'src'},
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'pytest-mock>=3.7.0',
            'pytest-asyncio>=0.16.0',
            'flake8>=4.0.0',
            'black>=22.0.0',
            'isort>=5.10.0',
            'mypy>=0.930',
            'sphinx>=4.4.0',
            'sphinx-rtd-theme>=1.0.0',
        ],
        'test': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'pytest-mock>=3.7.0',
            'pytest-asyncio>=0.16.0',
        ],
        'docs': [
            'sphinx>=4.4.0',
            'sphinx-rtd-theme>=1.0.0',
            'nbsphinx>=0.8.0',
            'jupyter>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'dmv-analyze=dmv_scam_analysis.cli.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Security',
    ],
    python_requires='>=3.9',
    include_package_data=True,
    zip_safe=False,
    platforms='any',
)
