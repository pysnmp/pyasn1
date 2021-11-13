#!/usr/bin/env python
#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import os
import sys
import unittest

classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
Intended Audience :: Education
Intended Audience :: Information Technology
Intended Audience :: System Administrators
Intended Audience :: Telecommunications Industry
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 3.7
Programming Language :: Python :: 3.8
Topic :: Communications
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_setuptools():
    print(
        """
   Error: You need setuptools Python package!

   It's very easy to install it, just type:

   wget https://bootstrap.pypa.io/ez_setup.py
   python ez_setup.py

   Then you could make eggs from this package.
"""
    )


try:
    from setuptools import Command, setup

    params = {"zip_safe": True}

except ImportError:
    for arg in sys.argv:
        if "egg" in arg:
            howto_install_setuptools()
            sys.exit(1)
    from distutils.core import Command, setup

    params = {}

params.update(
    {
        "name": "pyasn1",
        "version": open(os.path.join("pyasn1", "__init__.py")).read().split("'")[1],
        "description": "ASN.1 types and codecs",
        "long_description": "Pure-Python implementation of ASN.1 types and DER/BER/CER codecs (X.208)",
        "maintainer": "Splunk <rfaircloth@splunk.com>",
        "author": "Ilya Etingof",
        "author_email": "etingof@gmail.com",
        "url": "https://github.com/pysnmp/pyasn1",
        "platforms": ["any"],
        "classifiers": [x for x in classifiers.split("\n") if x],
        "license": "BSD",
        "packages": [
            "pyasn1",
            "pyasn1.type",
            "pyasn1.compat",
            "pyasn1.codec",
            "pyasn1.codec.ber",
            "pyasn1.codec.cer",
            "pyasn1.codec.der",
            "pyasn1.codec.native",
        ],
        "python_requires": ">=3.7",
    }
)


class PyTest(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        suite = unittest.TestLoader().loadTestsFromNames(["tests.__main__.suite"])

        unittest.TextTestRunner(verbosity=2).run(suite)


params["cmdclass"] = {
    "test": PyTest,
    "tests": PyTest,
}

setup(**params)
