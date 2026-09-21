#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
"""DER and CER benchmarks.

The distinguished and canonical rules are what signing and comparing
structures rely on, so their extra work is worth watching separately
from BER: DER sorts SET OF components before encoding them, and CER
chops long strings into 1000-octet chunks under an indefinite length.
"""

import pytest

from benchmarks.schemas import Certificate, Message, buildCertificate, buildMessage
from pyasn1.codec.cer.decoder import decode as cerDecode
from pyasn1.codec.cer.encoder import encode as cerEncode
from pyasn1.codec.der.decoder import decode as derDecode
from pyasn1.codec.der.encoder import encode as derEncode
from pyasn1.type import univ

LONG_OCTETS = bytes(range(256)) * 32


@pytest.fixture(scope="module")
def certificate():
    """Return a certificate-like value: nested SET OFs, times, BIT STRING."""
    return buildCertificate()


@pytest.fixture(scope="module")
def message():
    """Return an SNMP-like message with 32 variable bindings."""
    return buildMessage()


def test_der_encode_certificate(benchmark, certificate):
    """Encode a certificate-like value, sorting every SET OF."""
    benchmark(derEncode, certificate)


def test_der_encode_message(benchmark, message):
    """Encode a nested message under the distinguished rules."""
    benchmark(derEncode, message)


def test_der_encode_set_of(benchmark):
    """Encode a SET OF whose components have to be sorted first."""
    setOf = univ.SetOf(componentType=univ.OctetString())
    for index in range(64):
        setOf[index] = b"component-%03d" % ((index * 37) % 64)
    benchmark(derEncode, setOf)


def test_der_decode_certificate(benchmark, certificate):
    """Decode a certificate-like value against its schema."""
    substrate = derEncode(certificate)
    spec = Certificate()
    benchmark(derDecode, substrate, asn1Spec=spec)


def test_der_decode_certificate_open_types(benchmark, certificate):
    """Decode the same value, resolving the ANY components by OID."""
    substrate = derEncode(certificate)
    spec = Certificate()
    benchmark(derDecode, substrate, asn1Spec=spec, decodeOpenTypes=True)


def test_der_decode_message(benchmark, message):
    """Decode a nested message under the distinguished rules."""
    substrate = derEncode(message)
    spec = Message()
    benchmark(derDecode, substrate, asn1Spec=spec)


def test_cer_encode_certificate(benchmark, certificate):
    """Encode a certificate-like value under the canonical rules."""
    benchmark(cerEncode, certificate)


def test_cer_encode_long_octet_string(benchmark):
    """Encode an 8 KiB OCTET STRING, which CER splits into chunks."""
    benchmark(cerEncode, univ.OctetString(LONG_OCTETS))


def test_cer_decode_long_octet_string(benchmark):
    """Reassemble a chunked OCTET STRING from its constructed form."""
    substrate = cerEncode(univ.OctetString(LONG_OCTETS))
    benchmark(cerDecode, substrate, asn1Spec=univ.OctetString())


def test_cer_decode_certificate(benchmark, certificate):
    """Decode a certificate-like value encoded with canonical rules."""
    substrate = cerEncode(certificate)
    spec = Certificate()
    benchmark(cerDecode, substrate, asn1Spec=spec)
