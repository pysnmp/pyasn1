#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
"""BER encoder and decoder benchmarks.

BER is the codec everything else in pyasn1 is built on: CER and DER
subclass it, and every protocol using this library goes through these
two functions. Both the definite and the indefinite length forms are
measured, and decoding is measured both against a schema and without
one, because the schema-less path takes a different route through the
decoder.
"""

import pytest

from benchmarks.schemas import Message, buildMessage, buildRecord, buildSequenceOf
from pyasn1.codec.ber.decoder import decode
from pyasn1.codec.ber.encoder import encode
from pyasn1.type import univ

LARGE_INTEGER = 2**607 - 1
OCTETS = bytes(range(256)) * 16
OID = "1.3.6.1.4.1.9.9.42.1.2.9.1.6.4294967295"


@pytest.fixture(scope="module")
def message():
    """Return an SNMP-like message with 32 variable bindings."""
    return buildMessage()


@pytest.fixture(scope="module")
def sequenceOf():
    """Return a SEQUENCE OF 256 integers."""
    return buildSequenceOf()


@pytest.fixture(scope="module")
def record():
    """Return the README record, with an optional and a defaulted component."""
    return buildRecord()


def test_encode_integer_small(benchmark):
    """Encode a small INTEGER, the most common value there is."""
    benchmark(encode, univ.Integer(12345))


def test_encode_integer_large(benchmark):
    """Encode a 607-bit INTEGER, where the octet loop dominates."""
    benchmark(encode, univ.Integer(LARGE_INTEGER))


def test_encode_octet_string(benchmark):
    """Encode a 4 KiB OCTET STRING in the definite length form."""
    benchmark(encode, univ.OctetString(OCTETS))


def test_encode_object_identifier(benchmark):
    """Encode an OID whose last arc needs five subidentifier octets."""
    benchmark(encode, univ.ObjectIdentifier(OID))


def test_encode_bit_string(benchmark):
    """Encode a BIT STRING built from a hex value."""
    benchmark(encode, univ.BitString(hexValue="deadbeef" * 32))


def test_encode_record(benchmark, record):
    """Encode a small SEQUENCE with an implicit tag and a default."""
    benchmark(encode, record)


def test_encode_message(benchmark, message):
    """Encode a nested message, definite length."""
    benchmark(encode, message)


def test_encode_message_indefinite(benchmark, message):
    """Encode the same message with indefinite lengths and EOO markers."""
    benchmark(encode, message, defMode=False)


def test_encode_sequence_of_integers(benchmark, sequenceOf):
    """Encode 256 integers under one SEQUENCE OF."""
    benchmark(encode, sequenceOf)


def test_decode_integer(benchmark):
    """Decode a 607-bit INTEGER."""
    substrate = encode(univ.Integer(LARGE_INTEGER))
    benchmark(decode, substrate, asn1Spec=univ.Integer())


def test_decode_octet_string(benchmark):
    """Decode a 4 KiB OCTET STRING."""
    substrate = encode(univ.OctetString(OCTETS))
    benchmark(decode, substrate, asn1Spec=univ.OctetString())


def test_decode_object_identifier(benchmark):
    """Decode an OID with a multi-octet arc."""
    substrate = encode(univ.ObjectIdentifier(OID))
    benchmark(decode, substrate, asn1Spec=univ.ObjectIdentifier())


def test_decode_message_with_spec(benchmark, message):
    """Decode a nested message against its schema."""
    substrate = encode(message)
    spec = Message()
    benchmark(decode, substrate, asn1Spec=spec)


def test_decode_message_without_spec(benchmark, message):
    """Decode the same message with no schema, by tag alone."""
    substrate = encode(message)
    benchmark(decode, substrate)


def test_decode_message_indefinite(benchmark, message):
    """Decode a message serialised with indefinite lengths."""
    substrate = encode(message, defMode=False)
    spec = Message()
    benchmark(decode, substrate, asn1Spec=spec)


def test_decode_sequence_of_integers(benchmark, sequenceOf):
    """Decode 256 integers out of one SEQUENCE OF."""
    substrate = encode(sequenceOf)
    spec = univ.SequenceOf(componentType=univ.Integer())
    benchmark(decode, substrate, asn1Spec=spec)
