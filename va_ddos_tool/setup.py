from setuptools import setup, find_packages

setup(
    name="va-ddos-tool",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "scapy"
    ],
    entry_points={
        "console_scripts": [
            "va-ddos=main:main"
        ]
    },
)
