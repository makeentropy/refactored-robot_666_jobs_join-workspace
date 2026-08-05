"""Setup.py for TOOLSCHAIN BOX — optional editable install:
    pip install -e .

After install, the `toolschain` console-script is on PATH.
"""

from setuptools import setup, find_packages

setup(
    name="toolschain-box",
    version="1.0.0",
    description="Toolschain Box: Security · Finance · Data Toolkit (UTF-8 CLI + Web)",
    long_description=open("README.md", encoding="utf-8").read()
    if __import__("os").path.exists("README.md") else "",
    author="Toolschain Box",
    license="BSD-3-Clause",
    packages=find_packages(include=["toolschain", "toolschain.*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        "Flask>=3.0.0",
        "Pillow>=10.0.0",
        "tabulate>=0.9.0",
        "pydantic>=2.0.0",
        "python-gnupg>=0.5.1",
    ],
    extras_require={
        "evm": ["web3>=6.0.0"],
    },
    entry_points={
        "console_scripts": [
            "toolschain=toolschain.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: Chinese (Simplified)",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business :: Financial",
    ],
)
