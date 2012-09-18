from distutils.core import setup

setup(
    name = "PyNFSe",
    packages = ["pysped_nfse"],
    version = "0.0.1",
    description = "Library for SPED NFS-e specification",
    author = "Daniel Hartmann",
    author_email = "daniel@proge.com.br",
    url = "https://github.com/proge/PySPED-NFe",
    download_url = "https://nodeload.github.com/proge/PySPED-NFSe/tarball/v0.0.1",
    keywords = ["sped", "brazil", "brasil", "nfse"],
    requires=['PySPED-Tools (>=0.0.1)'],
    install_requires=['PySPED-Tools'],
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries",
        ],
    long_description = """\
PyNFSe
------

NFS-e is part of the Brazilian public system of digital bookkeeping (SPED).

This module handles XML file generation, validation and submission of NFS-e
version 1.0. The signature is made using pysped_tools module.
"""
)