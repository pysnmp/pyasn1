#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
"""Native codec benchmarks.

The native codec is the bridge between ASN.1 values and plain Python
objects, so it is what anything dumping a decoded structure to JSON or
feeding one from a dict goes through.
"""

import pytest

from benchmarks.schemas import Certificate, Message, buildCertificate, buildMessage
from pyasn1.codec.native.decoder import decode
from pyasn1.codec.native.encoder import encode


@pytest.fixture(scope="module")
def message():
    """Return an SNMP-like message with 32 variable bindings."""
    return buildMessage()


@pytest.fixture(scope="module")
def certificate():
    """Return a certificate-like value with nested SET OFs."""
    return buildCertificate()


def test_native_encode_message(benchmark, message):
    """Turn a nested message into plain Python objects."""
    benchmark(encode, message)


def test_native_encode_certificate(benchmark, certificate):
    """Turn a certificate-like value into plain Python objects."""
    benchmark(encode, certificate)


def test_native_decode_message(benchmark, message):
    """Rebuild a message from a dict, against its schema."""
    payload = encode(message)
    spec = Message()
    benchmark(decode, payload, asn1Spec=spec)


def test_native_decode_certificate(benchmark, certificate):
    """Rebuild a certificate-like value from plain Python objects."""
    payload = encode(certificate)
    spec = Certificate()
    benchmark(decode, payload, asn1Spec=spec)
