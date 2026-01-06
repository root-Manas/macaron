"""
Macaron - Security Reconnaissance Platform
A CLI-based automated security reconnaissance and asset discovery tool
"""

__version__ = "2.4.0"
__author__ = "root-Manas"
__license__ = "MIT"

from setuptools import setup
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
    name="macaron",
    version=__version__,
    author=__author__,
    author_email="",
    description="CLI-based security reconnaissance platform for bug bounty hunters",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/root-Manas/macaron",
    py_modules=[],
    scripts=["macaron"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    include_package_data=True,
    zip_safe=False,
    keywords="security reconnaissance pentesting bugbounty recon scanning",
    project_urls={
        "Bug Reports": "https://github.com/root-Manas/macaron/issues",
        "Source": "https://github.com/root-Manas/macaron",
    },
)
