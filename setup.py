from setuptools import setup, find_packages
import os

# Read version from environment or default to development version
VERSION = os.environ.get("VERSION", "1.3.0.dev0")

# Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Define requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="4Chat",
    version=VERSION,
    author="4INSEC",
    author_email="mwaijegakelvin@gmail.com",
    description="Secure end-to-end encrypted chat application",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/4insec/4Chat",
    project_urls={
        "Bug Tracker": "https://github.com/4insec/4Chat/issues",
        "Documentation": "https://github.com/4insec/4Chat/wiki",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",
    ],
    package_dir={"": "4chat"},
    packages=find_packages(where="4chat"),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "4Chat=client.client:main",
            "4Chat-server=server.main:main",
        ],
    },
)