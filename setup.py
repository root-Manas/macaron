"""
Security Reconnaissance Platform
A modular, automated security reconnaissance and asset discovery platform
"""

__version__ = "2.1.0"
__author__ = "Security Recon Team"
__license__ = "MIT"

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip() 
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="security-recon-platform",
    version=__version__,
    author=__author__,
    author_email="security@example.com",
    description="Automated security reconnaissance and asset discovery platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/root-Manas/macaron",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "scripts"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "recon=recon:main",
            "macaron=recon:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.txt", "*.md"],
        "config": ["*.yaml", "*.yml", "*.txt"],
    },
    zip_safe=False,
    keywords="security reconnaissance pentesting osint recon scanning",
    project_urls={
        "Bug Reports": "https://github.com/root-Manas/macaron/issues",
        "Source": "https://github.com/root-Manas/macaron",
        "Documentation": "https://github.com/root-Manas/macaron/blob/main/README.md",
    },
)
