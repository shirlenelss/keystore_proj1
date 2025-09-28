from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="keystore-manager",
    version="1.0.0",
    author="Keystore Practice Project",
    author_email="practice@example.com",
    description="A practice project for keystore management, certificates, and secOps",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shirlenelss/keystore_proj1",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "click>=8.1.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "bandit>=1.7.0",
            "safety>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "keystore-manager=keystore_manager.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "keystore_manager": ["config/*.yml"],
    },
)