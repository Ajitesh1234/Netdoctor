
from setuptools import setup, find_packages

setup(
    name="netdoctor",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "netdoctor=netdoctor.main:main"
        ]
    },
    python_requires=">=3.7",
)
