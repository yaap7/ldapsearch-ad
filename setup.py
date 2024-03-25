from setuptools import setup, find_packages

setup(
    name="ldapsearch-ad",
    version="2022.8.24",
    packages=find_packages(),
    scripts=["ldapsearch-ad.py"],
    install_requires=["ldap3", "pycryptodome"],
    description="Python3 script to quickly get various information from a domain controller through his LDAP service.",
    url="https://github.com/yaap7ldapsearch-ad",
    license="GPLv3",
)
