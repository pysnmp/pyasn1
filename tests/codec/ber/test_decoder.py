#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import itertools
import sys
import timeit
import unittest

import pytest

from pyasn1.codec.ber import decoder, encoder, eoo
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, constraint, namedtype, opentype, tag, univ
from pyasn1.type.error import ValueConstraintError
from tests.base import BaseTestCase


def _str2octs(s):
    return s.encode("iso-8859-1")


_null = b""


class LargeTagDecoderTestCase(BaseTestCase):
    def testLargeTag(self):
        assert decoder.decode(bytes((127, 141, 245, 182, 253, 47, 3, 2, 1, 1))) == (
            1,
            _null,
        )

    def testLongTag(self):
        assert decoder.decode(bytes((0x1F, 2, 1, 0)))[0].tagSet == univ.Integer.tagSet

    def testPaddedTagNumberRejected(self):
        # X.690 8.1.2.4.2 c): bits 7 to 1 of the first subsequent octet shall
        # not all be zero. Tag 0 therefore has no high tag number form at all,
        # padded or otherwise, and 8.1.2.2 gives it the single octet 0x80.
        # Both spellings below used to decode, silently aliasing that tag.
        integer = univ.Integer(2).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, 0, 0)
        )

        for substrate in (
            bytes((0x9F, 0x80, 0x00, 0x02, 0x01, 0x02)),
            bytes((0x9F, 0x00, 0x02, 0x01, 0x02)),
        ):
            self.assertRaises(PyAsn1Error, decoder.decode, substrate, asn1Spec=integer)

        assert decoder.decode(bytes((0x80, 0x01, 0x02)), asn1Spec=integer) == (
            2,
            _null,
        )


class DecoderCacheTestCase(BaseTestCase):
    def testCache(self):
        assert decoder.decode(bytes((0x1F, 2, 1, 0))) == decoder.decode(
            bytes((0x1F, 2, 1, 0))
        )


class IntegerDecoderTestCase(BaseTestCase):
    def testPosInt(self):
        assert decoder.decode(bytes((2, 1, 12))) == (12, _null)

    def testNegInt(self):
        assert decoder.decode(bytes((2, 1, 244))) == (-12, _null)

    def testZeroLengthRejected(self):
        # X.690 8.3.1: the contents octets shall consist of one or more
        # octets, so zero is not a spelling of INTEGER 0.
        try:
            decoder.decode(bytes((2, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "zero-length INTEGER accepted"

    def testZeroLong(self):
        assert decoder.decode(bytes((2, 1, 0))) == (0, _null)

    def testMinusOne(self):
        assert decoder.decode(bytes((2, 1, 255))) == (-1, _null)

    def testPosLong(self):
        assert decoder.decode(
            bytes((2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255))
        ) == (0xFFFFFFFFFFFFFFFF, _null)

    def testNegLong(self):
        assert decoder.decode(bytes((2, 9, 255, 0, 0, 0, 0, 0, 0, 0, 1))) == (
            -0xFFFFFFFFFFFFFFFF,
            _null,
        )

    def testSpec(self):
        try:
            decoder.decode(bytes((2, 1, 12)), asn1Spec=univ.Null()) == (12, _null)
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong asn1Spec worked out"
        assert decoder.decode(bytes((2, 1, 12)), asn1Spec=univ.Integer()) == (
            12,
            _null,
        )

    def testTagFormat(self):
        try:
            decoder.decode(bytes((34, 1, 12)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"


class BooleanDecoderTestCase(BaseTestCase):
    def testTrue(self):
        assert decoder.decode(bytes((1, 1, 1))) == (1, _null)

    def testTrueNeg(self):
        assert decoder.decode(bytes((1, 1, 255))) == (1, _null)

    def testExtraTrue(self):
        assert decoder.decode(bytes((1, 1, 1, 0, 120, 50, 50))) == (
            1,
            bytes((0, 120, 50, 50)),
        )

    def testFalse(self):
        assert decoder.decode(bytes((1, 1, 0))) == (0, _null)

    def testTagFormat(self):
        try:
            decoder.decode(bytes((33, 1, 1)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"


class BitStringDecoderTestCase(BaseTestCase):
    def testDefMode(self):
        assert decoder.decode(bytes((3, 3, 1, 169, 138))) == (
            (1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1),
            _null,
        )

    def testIndefMode(self):
        assert decoder.decode(bytes((3, 3, 1, 169, 138))) == (
            (1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1),
            _null,
        )

    def testDefModeChunked(self):
        assert decoder.decode(bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138))) == (
            (1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1),
            _null,
        )

    def testIndefModeChunked(self):
        assert decoder.decode(bytes((35, 128, 3, 2, 0, 169, 3, 2, 1, 138, 0, 0))) == (
            (1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1),
            _null,
        )

    def testDefModeChunkedSubst(self):
        assert decoder.decode(
            bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138)),
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (bytes((3, 2, 0, 169, 3, 2, 1, 138)), _str2octs(""))

    def testIndefModeChunkedSubst(self):
        assert decoder.decode(
            bytes((35, 128, 3, 2, 0, 169, 3, 2, 1, 138, 0, 0)),
            substrateFun=lambda a, b, c: (b, _str2octs("")),
        ) == (bytes((3, 2, 0, 169, 3, 2, 1, 138, 0, 0)), _str2octs(""))

    def testTypeChecking(self):
        try:
            decoder.decode(bytes((35, 4, 2, 2, 42, 42)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "accepted mis-encoded bit-string constructed out of an integer"


class OctetStringDecoderTestCase(BaseTestCase):
    def testDefMode(self):
        assert decoder.decode(
            bytes(
                (
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                )
            )
        ) == (_str2octs("Quick brown fox"), _null)

    def testIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    36,
                    128,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                    0,
                    0,
                )
            )
        ) == (_str2octs("Quick brown fox"), _null)

    def testDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    36,
                    23,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                )
            )
        ) == (_str2octs("Quick brown fox"), _null)

    def testIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    36,
                    128,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                    0,
                    0,
                )
            )
        ) == (_str2octs("Quick brown fox"), _null)

    def testDefModeChunkedSubst(self):
        assert decoder.decode(
            bytes(
                (
                    36,
                    23,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                )
            ),
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (
            bytes(
                (
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                )
            ),
            _str2octs(""),
        )

    def testIndefModeChunkedSubst(self):
        assert decoder.decode(
            bytes(
                (
                    36,
                    128,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                    0,
                    0,
                )
            ),
            substrateFun=lambda a, b, c: (b, _str2octs("")),
        ) == (
            bytes(
                (
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                    0,
                    0,
                )
            ),
            _str2octs(""),
        )


class ExpTaggedOctetStringDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.o = univ.OctetString(
            "Quick brown fox",
            tagSet=univ.OctetString.tagSet.tagExplicitly(
                tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 5)
            ),
        )

    def testDefMode(self):
        o, r = decoder.decode(
            bytes(
                (
                    101,
                    17,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                )
            )
        )
        assert not r
        assert self.o == o
        assert self.o.tagSet == o.tagSet
        assert self.o.isSameTypeWith(o)

    def testIndefMode(self):
        o, r = decoder.decode(
            bytes(
                (
                    101,
                    128,
                    36,
                    128,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                    0,
                    0,
                    0,
                    0,
                )
            )
        )
        assert not r
        assert self.o == o
        assert self.o.tagSet == o.tagSet
        assert self.o.isSameTypeWith(o)

    def testDefModeChunked(self):
        o, r = decoder.decode(
            bytes(
                (
                    101,
                    25,
                    36,
                    23,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                )
            )
        )
        assert not r
        assert self.o == o
        assert self.o.tagSet == o.tagSet
        assert self.o.isSameTypeWith(o)

    def testIndefModeChunked(self):
        o, r = decoder.decode(
            bytes(
                (
                    101,
                    128,
                    36,
                    128,
                    4,
                    4,
                    81,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    4,
                    111,
                    119,
                    110,
                    32,
                    4,
                    3,
                    102,
                    111,
                    120,
                    0,
                    0,
                    0,
                    0,
                )
            )
        )
        assert not r
        assert self.o == o
        assert self.o.tagSet == o.tagSet
        assert self.o.isSameTypeWith(o)

    def testDefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    101,
                    17,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                )
            ),
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (
            bytes(
                (
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                )
            ),
            _str2octs(""),
        )

    def testIndefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    101,
                    128,
                    36,
                    128,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            substrateFun=lambda a, b, c: (b, _str2octs("")),
        ) == (
            bytes(
                (
                    36,
                    128,
                    4,
                    15,
                    81,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    32,
                    102,
                    111,
                    120,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            _str2octs(""),
        )


class NullDecoderTestCase(BaseTestCase):
    def testNull(self):
        assert decoder.decode(bytes((5, 0))) == (_null, _null)

    def testTagFormat(self):
        try:
            decoder.decode(bytes((37, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"


# Useful analysis of OID encoding issues could be found here:
# https://misc.daniel-marschall.de/asn.1/oid_facts.html
class ObjectIdentifierDecoderTestCase(BaseTestCase):
    def testOne(self):
        assert decoder.decode(bytes((6, 6, 43, 6, 0, 191, 255, 126))) == (
            (1, 3, 6, 0, 0xFFFFE),
            _null,
        )

    def testEdge1(self):
        assert decoder.decode(bytes((6, 1, 39))) == ((0, 39), _null)

    def testEdge2(self):
        assert decoder.decode(bytes((6, 1, 79))) == ((1, 39), _null)

    def testEdge3(self):
        assert decoder.decode(bytes((6, 1, 120))) == ((2, 40), _null)

    def testEdge4(self):
        assert decoder.decode(bytes((6, 5, 0x90, 0x80, 0x80, 0x80, 0x4F))) == (
            (2, 0xFFFFFFFF),
            _null,
        )

    def testEdge5(self):
        assert decoder.decode(bytes((6, 1, 0x7F))) == ((2, 47), _null)

    def testEdge6(self):
        assert decoder.decode(bytes((6, 2, 0x81, 0x00))) == ((2, 48), _null)

    def testEdge7(self):
        assert decoder.decode(bytes((6, 3, 0x81, 0x34, 0x03))) == (
            (2, 100, 3),
            _null,
        )

    def testEdge8(self):
        assert decoder.decode(bytes((6, 2, 133, 0))) == ((2, 560), _null)

    def testEdge9(self):
        assert decoder.decode(bytes((6, 4, 0x88, 0x84, 0x87, 0x02))) == (
            (2, 16843570),
            _null,
        )

    def testNonLeading0x80(self):
        assert decoder.decode(
            bytes((6, 5, 85, 4, 129, 128, 0)),
        ) == ((2, 5, 4, 16384), _null)

    def testLeading0x80Case1(self):
        try:
            decoder.decode(bytes((6, 5, 85, 4, 128, 129, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Leading 0x80 tolerated"

    def testLeading0x80Case2(self):
        try:
            decoder.decode(bytes((6, 7, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Leading 0x80 tolerated"

    def testLeading0x80Case3(self):
        try:
            decoder.decode(bytes((6, 2, 0x80, 1)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Leading 0x80 tolerated"

    def testLeading0x80Case4(self):
        try:
            decoder.decode(bytes((6, 2, 0x80, 0x7F)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Leading 0x80 tolerated"

    def testTagFormat(self):
        try:
            decoder.decode(bytes((38, 1, 239)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"

    def testZeroLength(self):
        try:
            decoder.decode(bytes((6, 0, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "zero length tolerated"

    def testIndefiniteLength(self):
        try:
            decoder.decode(bytes((6, 128, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "indefinite length tolerated"

    def testReservedLength(self):
        try:
            decoder.decode(bytes((6, 255, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "reserved length tolerated"

    def testLarge1(self):
        assert decoder.decode(
            bytes(
                (
                    0x06,
                    0x11,
                    0x83,
                    0xC6,
                    0xDF,
                    0xD4,
                    0xCC,
                    0xB3,
                    0xFF,
                    0xFF,
                    0xFE,
                    0xF0,
                    0xB8,
                    0xD6,
                    0xB8,
                    0xCB,
                    0xE2,
                    0xB7,
                    0x17,
                )
            )
        ) == ((2, 18446744073709551535184467440737095), _null)

    def testLarge2(self):
        assert decoder.decode(
            bytes(
                (
                    0x06,
                    0x13,
                    0x88,
                    0x37,
                    0x83,
                    0xC6,
                    0xDF,
                    0xD4,
                    0xCC,
                    0xB3,
                    0xFF,
                    0xFF,
                    0xFE,
                    0xF0,
                    0xB8,
                    0xD6,
                    0xB8,
                    0xCB,
                    0xE2,
                    0xB6,
                    0x47,
                )
            )
        ) == ((2, 999, 18446744073709551535184467440737095), _null)


class RealDecoderTestCase(BaseTestCase):
    def testChar(self):
        # "123.E11". X.690 8.5.8 has the sender name the ISO 6093 form and
        # then encode according to it, and NR3 requires the decimal mark.
        assert decoder.decode(bytes((9, 8, 3, 49, 50, 51, 46, 69, 49, 49))) == (
            univ.Real((123, 10, 11)),
            _null,
        )

    def testCharWithoutDecimalMark(self):
        # "123E11" under an NR3 selector: NR2-shaped octets declaring NR3.
        self.assertRaises(
            PyAsn1Error,
            decoder.decode,
            bytes((9, 7, 3, 49, 50, 51, 69, 49, 49)),
        )

    def testBin1(self):  # check base = 2
        assert decoder.decode(  # (0.5, 2, 0) encoded with base = 2
            bytes((9, 3, 128, 255, 1))
        ) == (univ.Real((1, 2, -1)), _null)

    def testBin2(self):  # check base = 2 and scale factor
        assert decoder.decode(  # (3.25, 2, 0) encoded with base = 8
            bytes((9, 3, 148, 255, 13))
        ) == (univ.Real((26, 2, -3)), _null)

    def testBin3(self):  # check base = 16
        assert decoder.decode(  # (0.00390625, 2, 0) encoded with base = 16
            bytes((9, 3, 160, 254, 1))
        ) == (univ.Real((1, 2, -8)), _null)

    def testBin4(self):  # check exponent = 0
        assert decoder.decode(  # (1, 2, 0) encoded with base = 2
            bytes((9, 3, 128, 0, 1))
        ) == (univ.Real((1, 2, 0)), _null)

    def testBin5(self):  # case of 2 octs for exponent and negative exponent
        assert decoder.decode(  # (3, 2, -1020) encoded with base = 16
            bytes((9, 4, 161, 255, 1, 3))
        ) == (univ.Real((3, 2, -1020)), _null)

    # TODO: this requires Real type comparison fix

    #    def testBin6(self):
    #        assert decoder.decode(
    #            bytes((9, 5, 162, 0, 255, 255, 1))
    #        ) == (univ.Real((1, 2, 262140)), _null)

    #    def testBin7(self):
    #        assert decoder.decode(
    #            bytes((9, 7, 227, 4, 1, 35, 69, 103, 1))
    #        ) == (univ.Real((-1, 2, 76354972)), _null)

    def testPlusInf(self):
        assert decoder.decode(bytes((9, 1, 64))) == (univ.Real("inf"), _null)

    def testMinusInf(self):
        assert decoder.decode(bytes((9, 1, 65))) == (univ.Real("-inf"), _null)

    def testEmpty(self):
        assert decoder.decode(bytes((9, 0))) == (univ.Real(0.0), _null)

    def testTagFormat(self):
        try:
            decoder.decode(bytes((41, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"

    def testShortEncoding(self):
        try:
            decoder.decode(bytes((9, 1, 131)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "accepted too-short real"


class RealRoundTripTestCase(BaseTestCase):
    @staticmethod
    def _roundTrip(value):
        decoded, rest = decoder.decode(encoder.encode(value), asn1Spec=univ.Real())
        assert rest == _null
        return decoded

    def testSupportedBinaryBases(self):
        cases = (
            (univ.Real((0.5, 2, 0)), (1, 2, -1), 2),
            (univ.Real((3.25, 2, 0)), (26, 2, -3), 8),
            (univ.Real((0.00390625, 2, 0)), (1, 2, -8), 16),
        )

        for value, expected, encbase in cases:
            value.binEncBase = encbase
            assert tuple(self._roundTrip(value)) == expected

    def testSubnormalAndLargeExponentValues(self):
        cases = (
            ((1, 2, -1074), (1, 2, -1074)),
            ((1, 2, 262140), (1, 2, 262140)),
            ((-1, 2, 76354972), (-1, 2, 76354972)),
        )

        for value, expected in cases:
            assert tuple(self._roundTrip(univ.Real(value))) == expected

    def testInfinityValues(self):
        assert self._roundTrip(univ.Real("inf")).isPlusInf
        assert self._roundTrip(univ.Real("-inf")).isMinusInf


class UniversalStringDecoderTestCase(BaseTestCase):
    def testDecoder(self):
        assert decoder.decode(
            bytes((28, 12, 0, 0, 0, 97, 0, 0, 0, 98, 0, 0, 0, 99))
        ) == (char.UniversalString("abc"), _null)


class BMPStringDecoderTestCase(BaseTestCase):
    def testDecoder(self):
        assert decoder.decode(bytes((30, 6, 0, 97, 0, 98, 0, 99))) == (
            char.BMPString("abc"),
            _null,
        )


class UTF8StringDecoderTestCase(BaseTestCase):
    def testDecoder(self):
        assert decoder.decode(bytes((12, 3, 97, 98, 99))) == (
            char.UTF8String("abc"),
            _null,
        )


class SequenceOfDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.s = univ.SequenceOf(componentType=univ.OctetString())
        self.s.setComponentByPosition(0, univ.OctetString("quick brown"))

    def testDefMode(self):
        assert decoder.decode(
            bytes((48, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110))
        ) == (self.s, _null)

    def testIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    19,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            )
        ) == (self.s, _null)

    def testIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testSchemalessDecoder(self):
        assert decoder.decode(
            bytes((48, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)),
            asn1Spec=univ.SequenceOf(),
        ) == (self.s, _null)


class ExpTaggedSequenceOfDecoderTestCase(BaseTestCase):
    def testWithSchema(self):
        s = univ.SequenceOf().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )
        s2, r = decoder.decode(
            bytes(
                (
                    163,
                    15,
                    48,
                    13,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=s,
        )
        assert not r
        assert s2 == [_str2octs("quick brown")]
        assert s.tagSet == s2.tagSet

    def testWithoutSchema(self):
        s = univ.SequenceOf().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )
        s2, r = decoder.decode(
            bytes(
                (
                    163,
                    15,
                    48,
                    13,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            )
        )
        assert not r
        assert s2 == [_str2octs("quick brown")]
        assert s.tagSet == s2.tagSet


class SequenceOfDecoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SequenceOf(componentType=univ.OctetString())
        self.s.setComponentByPosition(0, univ.OctetString("quick brown"))

    def testDefMode(self):
        assert decoder.decode(
            bytes((48, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    19,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)


class SetOfDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SetOf(componentType=univ.OctetString())
        self.s.setComponentByPosition(0, univ.OctetString("quick brown"))

    def testDefMode(self):
        assert decoder.decode(
            bytes((49, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110))
        ) == (self.s, _null)

    def testIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    19,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            )
        ) == (self.s, _null)

    def testIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testSchemalessDecoder(self):
        assert decoder.decode(
            bytes((49, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)),
            asn1Spec=univ.SetOf(),
        ) == (self.s, _null)


class SetOfDecoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SetOf(componentType=univ.OctetString())
        self.s.setComponentByPosition(0, univ.OctetString("quick brown"))

    def testDefMode(self):
        assert decoder.decode(
            bytes((49, 13, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    19,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)


class SequenceDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.NamedType("first-name", univ.OctetString(_null)),
                namedtype.NamedType("age", univ.Integer(33)),
            )
        )
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testWithOptionalAndDefaultedDefMode(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    24,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (
            bytes(
                (
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            _str2octs(""),
        )

    def testWithOptionalAndDefaultedIndefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            substrateFun=lambda a, b, c: (b, _str2octs("")),
        ) == (
            bytes(
                (
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            _str2octs(""),
        )

    def testTagFormat(self):
        try:
            decoder.decode(
                bytes(
                    (
                        16,
                        18,
                        5,
                        0,
                        4,
                        11,
                        113,
                        117,
                        105,
                        99,
                        107,
                        32,
                        98,
                        114,
                        111,
                        119,
                        110,
                        2,
                        1,
                        1,
                    )
                )
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"


class SequenceDecoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

    def __init(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))

    def __initWithOptional(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))

    def __initWithDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def __initWithOptionalAndDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testDefMode(self):
        self.__init()
        assert decoder.decode(bytes((48, 2, 5, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testIndefMode(self):
        self.__init()
        assert decoder.decode(bytes((48, 128, 5, 0, 0, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testDefModeChunked(self):
        self.__init()
        assert decoder.decode(bytes((48, 2, 5, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testIndefModeChunked(self):
        self.__init()
        assert decoder.decode(bytes((48, 128, 5, 0, 0, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithOptionalDefMode(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    48,
                    15,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionaIndefMode(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalDefModeChunked(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    48,
                    21,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalIndefModeChunked(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithDefaultedDefMode(self):
        self.__initWithDefaulted()
        assert decoder.decode(bytes((48, 5, 5, 0, 2, 1, 1)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithDefaultedIndefMode(self):
        self.__initWithDefaulted()
        assert decoder.decode(
            bytes((48, 128, 5, 0, 2, 1, 1, 0, 0)), asn1Spec=self.s
        ) == (self.s, _null)

    def testWithDefaultedDefModeChunked(self):
        self.__initWithDefaulted()
        assert decoder.decode(bytes((48, 5, 5, 0, 2, 1, 1)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithDefaultedIndefModeChunked(self):
        self.__initWithDefaulted()
        assert decoder.decode(
            bytes((48, 128, 5, 0, 2, 1, 1, 0, 0)), asn1Spec=self.s
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    48,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeChunked(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    48,
                    24,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefModeChunked(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    48,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)


class SequenceDecoderWithUntaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType("blob", univ.Any(), openType=openType),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes(
                (
                    48,
                    16,
                    2,
                    1,
                    2,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 2
        assert s[1] == univ.OctetString("quick brown")

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)),
                asn1Spec=self.s,
                decodeOpenTypes=True,
            )

        except PyAsn1Error:
            pass

        else:
            assert False, "unknown open type tolerated"

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 3, 6, 1, 39)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue="060127")

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s)
        assert not r
        assert s[0] == 1
        assert s[1] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes(
                (
                    48,
                    16,
                    2,
                    1,
                    2,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        )
        assert not r
        assert s[0] == 2
        assert s[1] == bytes(
            (4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)
        )


class SequenceDecoderOpenTypeLiveMapTestCase(BaseTestCase):
    """OpenType retains the caller's typeMap by reference, so types registered
    on the original mapping after the spec is built are honoured at decode
    time (regression test for by-reference storage)."""

    def setUp(self):
        # Start with only one governing value mapped.
        self.typeMap = {1: univ.Integer()}
        openType = opentype.OpenType("id", self.typeMap)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType("blob", univ.Any(), openType=openType),
            )
        )

    def testDecodeOpenTypeAddedAfterConstruction(self):
        # Register the second governing value *after* the spec was built.
        self.typeMap[2] = univ.OctetString()

        s, r = decoder.decode(
            bytes(
                (
                    48,
                    16,
                    2,
                    1,
                    2,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 2
        assert s[1] == univ.OctetString("quick brown")


class SequenceDecoderWithImplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.Any().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                    ),
                    openType=openType,
                ),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue="02010C")


class SequenceDecoderWithExplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.Any().subtype(
                        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                    ),
                    openType=openType,
                ),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 163, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 163, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue="02010C")


class SequenceDecoderWithUnaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob", univ.SetOf(componentType=univ.Any()), openType=openType
                ),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes(
                (
                    48,
                    18,
                    2,
                    1,
                    2,
                    49,
                    13,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == univ.OctetString("quick brown")

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)),
                asn1Spec=self.s,
                decodeOpenTypes=True,
            )

        except PyAsn1Error:
            pass

        else:
            assert False, "unknown open type tolerated"

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 49, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue="02010c")

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s)
        assert not r
        assert s[0] == 1
        assert s[1][0] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes(
                (
                    48,
                    18,
                    2,
                    1,
                    2,
                    49,
                    13,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == bytes(
            (4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)
        )


class SequenceDecoderWithImplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.SetOf(
                        componentType=univ.Any().subtype(
                            implicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3
                            )
                        )
                    ),
                    openType=openType,
                ),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue="02010C")


class SequenceDecoderWithExplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.SetOf(
                        componentType=univ.Any().subtype(
                            explicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3
                            )
                        )
                    ),
                    openType=openType,
                ),
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s,
            decodeOpenTypes=True,
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue="02010C")


class SetDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.NamedType("first-name", univ.OctetString(_null)),
                namedtype.NamedType("age", univ.Integer(33)),
            )
        )
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testWithOptionalAndDefaultedDefMode(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefMode(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    24,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefModeChunked(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            )
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (
            bytes(
                (
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            _str2octs(""),
        )

    def testWithOptionalAndDefaultedIndefModeSubst(self):
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            substrateFun=lambda a, b, c: (b, _str2octs("")),
        ) == (
            bytes(
                (
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            _str2octs(""),
        )

    def testTagFormat(self):
        try:
            decoder.decode(
                bytes(
                    (
                        16,
                        18,
                        5,
                        0,
                        4,
                        11,
                        113,
                        117,
                        105,
                        99,
                        107,
                        32,
                        98,
                        114,
                        111,
                        119,
                        110,
                        2,
                        1,
                        1,
                    )
                )
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, "wrong tagFormat worked out"


class SetDecoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

    def __init(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))

    def __initWithOptional(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))

    def __initWithDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def __initWithOptionalAndDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testDefMode(self):
        self.__init()
        assert decoder.decode(bytes((49, 128, 5, 0, 0, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testIndefMode(self):
        self.__init()
        assert decoder.decode(bytes((49, 128, 5, 0, 0, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testDefModeChunked(self):
        self.__init()
        assert decoder.decode(bytes((49, 2, 5, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testIndefModeChunked(self):
        self.__init()
        assert decoder.decode(bytes((49, 128, 5, 0, 0, 0)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithOptionalDefMode(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    49,
                    15,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalIndefMode(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalDefModeChunked(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    49,
                    21,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalIndefModeChunked(self):
        self.__initWithOptional()
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithDefaultedDefMode(self):
        self.__initWithDefaulted()
        assert decoder.decode(bytes((49, 5, 5, 0, 2, 1, 1)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithDefaultedIndefMode(self):
        self.__initWithDefaulted()
        assert decoder.decode(
            bytes((49, 128, 5, 0, 2, 1, 1, 0, 0)), asn1Spec=self.s
        ) == (self.s, _null)

    def testWithDefaultedDefModeChunked(self):
        self.__initWithDefaulted()
        assert decoder.decode(bytes((49, 5, 5, 0, 2, 1, 1)), asn1Spec=self.s) == (
            self.s,
            _null,
        )

    def testWithDefaultedIndefModeChunked(self):
        self.__initWithDefaulted()
        assert decoder.decode(
            bytes((49, 128, 5, 0, 2, 1, 1, 0, 0)), asn1Spec=self.s
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    18,
                    5,
                    0,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeReordered(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    18,
                    2,
                    1,
                    1,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    5,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefModeReordered(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    2,
                    1,
                    1,
                    5,
                    0,
                    36,
                    128,
                    4,
                    11,
                    113,
                    117,
                    105,
                    99,
                    107,
                    32,
                    98,
                    114,
                    111,
                    119,
                    110,
                    0,
                    0,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedDefModeChunked(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    24,
                    5,
                    0,
                    36,
                    17,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    2,
                    1,
                    1,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testWithOptionalAndDefaultedIndefModeChunked(self):
        self.__initWithOptionalAndDefaulted()
        assert decoder.decode(
            bytes(
                (
                    49,
                    128,
                    5,
                    0,
                    36,
                    128,
                    4,
                    4,
                    113,
                    117,
                    105,
                    99,
                    4,
                    4,
                    107,
                    32,
                    98,
                    114,
                    4,
                    3,
                    111,
                    119,
                    110,
                    0,
                    0,
                    2,
                    1,
                    1,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)


class SequenceOfWithExpTaggedOctetStringDecoder(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SequenceOf(
            componentType=univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
        self.s.setComponentByPosition(0, "q")
        self.s2 = univ.SequenceOf()

    def testDefModeSchema(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)), asn1Spec=self.s)
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeSchema(self):
        s, r = decoder.decode(
            bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)), asn1Spec=self.s
        )
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testDefModeNoComponent(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)), asn1Spec=self.s2)
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeNoComponent(self):
        s, r = decoder.decode(
            bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)), asn1Spec=self.s2
        )
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testDefModeSchemaless(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)))
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeSchemaless(self):
        s, r = decoder.decode(bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)))
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet


class SequenceWithExpTaggedOctetStringDecoder(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType(
                    "x",
                    univ.OctetString().subtype(
                        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                    ),
                )
            )
        )
        self.s.setComponentByPosition(0, "q")
        self.s2 = univ.Sequence()

    def testDefModeSchema(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)), asn1Spec=self.s)
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeSchema(self):
        s, r = decoder.decode(
            bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)), asn1Spec=self.s
        )
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testDefModeNoComponent(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)), asn1Spec=self.s2)
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeNoComponent(self):
        s, r = decoder.decode(
            bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)), asn1Spec=self.s2
        )
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testDefModeSchemaless(self):
        s, r = decoder.decode(bytes((48, 5, 163, 3, 4, 1, 113)))
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet

    def testIndefModeSchemaless(self):
        s, r = decoder.decode(bytes((48, 128, 163, 128, 4, 1, 113, 0, 0, 0, 0)))
        assert not r
        assert s == self.s
        assert s.tagSet == self.s.tagSet


class ChoiceDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.NamedType("number", univ.Integer(0)),
                namedtype.NamedType("string", univ.OctetString()),
            )
        )

    def testBySpec(self):
        self.s.setComponentByPosition(0, univ.Null(_null))
        assert decoder.decode(bytes((5, 0)), asn1Spec=self.s) == (self.s, _null)

    def testWithoutSpec(self):
        self.s.setComponentByPosition(0, univ.Null(_null))
        assert decoder.decode(bytes((5, 0))) == (self.s, _null)
        assert decoder.decode(bytes((5, 0))) == (univ.Null(_null), _null)

    def testUndefLength(self):
        self.s.setComponentByPosition(2, univ.OctetString("abcdefgh"))
        assert decoder.decode(
            bytes(
                (
                    36,
                    128,
                    4,
                    3,
                    97,
                    98,
                    99,
                    4,
                    3,
                    100,
                    101,
                    102,
                    4,
                    2,
                    103,
                    104,
                    0,
                    0,
                )
            ),
            asn1Spec=self.s,
        ) == (self.s, _null)

    def testExplicitTag(self):
        s = self.s.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )
        s.setComponentByPosition(0, univ.Null(_null))
        assert decoder.decode(bytes((164, 2, 5, 0)), asn1Spec=s) == (s, _null)

    def testExplicitTagUndefLength(self):
        s = self.s.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )
        s.setComponentByPosition(0, univ.Null(_null))
        assert decoder.decode(bytes((164, 128, 5, 0, 0, 0)), asn1Spec=s) == (
            s,
            _null,
        )


class AnyDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Any()

    def testByUntagged(self):
        assert decoder.decode(bytes((4, 3, 102, 111, 120)), asn1Spec=self.s) == (
            univ.Any("\004\003fox"),
            _null,
        )

    def testTaggedEx(self):
        s = univ.Any("\004\003fox").subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )
        assert decoder.decode(bytes((164, 5, 4, 3, 102, 111, 120)), asn1Spec=s) == (
            s,
            _null,
        )

    def testTaggedIm(self):
        s = univ.Any("\004\003fox").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )
        assert decoder.decode(bytes((132, 5, 4, 3, 102, 111, 120)), asn1Spec=s) == (
            s,
            _null,
        )

    def testByUntaggedIndefMode(self):
        assert decoder.decode(bytes((4, 3, 102, 111, 120)), asn1Spec=self.s) == (
            univ.Any("\004\003fox"),
            _null,
        )

    def testTaggedExIndefMode(self):
        s = univ.Any("\004\003fox").subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )
        assert decoder.decode(
            bytes((164, 128, 4, 3, 102, 111, 120, 0, 0)), asn1Spec=s
        ) == (s, _null)

    def testTaggedImIndefMode(self):
        s = univ.Any("\004\003fox").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )
        assert decoder.decode(
            bytes((164, 128, 4, 3, 102, 111, 120, 0, 0)), asn1Spec=s
        ) == (s, _null)

    def testByUntaggedSubst(self):
        assert decoder.decode(
            bytes((4, 3, 102, 111, 120)),
            asn1Spec=self.s,
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (bytes((4, 3, 102, 111, 120)), _str2octs(""))

    def testTaggedExSubst(self):
        assert decoder.decode(
            bytes((164, 5, 4, 3, 102, 111, 120)),
            asn1Spec=self.s,
            substrateFun=lambda a, b, c: (b, b[c:]),
        ) == (bytes((164, 5, 4, 3, 102, 111, 120)), _str2octs(""))


class EndOfOctetsTestCase(BaseTestCase):
    def testUnexpectedEoo(self):
        try:
            decoder.decode(bytes((0, 0)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "end-of-contents octets accepted at top level"

    def testExpectedEoo(self):
        result, remainder = decoder.decode(bytes((0, 0)), allowEoo=True)
        assert (
            eoo.endOfOctets.isSameTypeWith(result)
            and result == eoo.endOfOctets
            and result is eoo.endOfOctets
        )
        assert remainder == _null

    def testDefiniteNoEoo(self):
        try:
            decoder.decode(bytes((0x23, 0x02, 0x00, 0x00)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "end-of-contents octets accepted inside definite-length encoding"

    def testIndefiniteEoo(self):
        result, remainder = decoder.decode(bytes((0x23, 0x80, 0x00, 0x00)))
        assert result == () and remainder == _null, (
            "incorrect decoding of indefinite length end-of-octets"
        )

    def testNoLongFormEoo(self):
        try:
            decoder.decode(bytes((0x23, 0x80, 0x00, 0x81, 0x00)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "end-of-contents octets accepted with invalid long-form length"

    def testNoConstructedEoo(self):
        try:
            decoder.decode(bytes((0x23, 0x80, 0x20, 0x00)))
        except PyAsn1Error:
            pass
        else:
            assert 0, (
                "end-of-contents octets accepted with invalid constructed encoding"
            )

    def testNoEooData(self):
        try:
            decoder.decode(bytes((0x23, 0x80, 0x00, 0x01, 0x00)))
        except PyAsn1Error:
            pass
        else:
            assert 0, "end-of-contents octets accepted with unexpected data"


class NonStringDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null(_null)),
                namedtype.NamedType("first-name", univ.OctetString(_null)),
                namedtype.NamedType("age", univ.Integer(33)),
            )
        )
        self.s.setComponentByPosition(0, univ.Null(_null))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

        self.substrate = bytes(
            [
                48,
                18,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
            ]
        )

    def testOctetString(self):
        s, _ = decoder.decode(univ.OctetString(self.substrate), asn1Spec=self.s)
        assert self.s == s

    def testAny(self):
        s, _ = decoder.decode(univ.Any(self.substrate), asn1Spec=self.s)
        assert self.s == s


class BoundedInteger(univ.Integer):
    subtypeSpec = constraint.ConstraintsIntersection(
        constraint.ValueRangeConstraint(1, 9)
    )


class ConstructedValueConstraintDecoderTestCase(BaseTestCase):
    class RequiredIdSequence(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType("id", univ.Integer()),
            namedtype.OptionalNamedType("name", univ.OctetString()),
        )
        subtypeSpec = constraint.ConstraintsIntersection(
            constraint.WithComponentsConstraint(
                ("id", constraint.ComponentPresentConstraint()),
                ("name", constraint.ComponentAbsentConstraint()),
            )
        )

    class NoIdSet(univ.Set):
        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType("id", univ.Integer())
        )
        subtypeSpec = constraint.ConstraintsIntersection(
            constraint.WithComponentsConstraint(
                ("id", constraint.ComponentAbsentConstraint()),
            )
        )

    class SubtypedSequence(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("number", BoundedInteger())
        )

    class DefaultedSequence(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.DefaultedNamedType("count", univ.Integer(5))
        )

    def testDefiniteLengthRequiredComponentIsValidated(self):
        with self.assertRaises(ValueConstraintError):
            decoder.decode(b"0\x00", asn1Spec=self.RequiredIdSequence())

    def testIndefiniteLengthRequiredComponentIsValidated(self):
        with self.assertRaises(ValueConstraintError):
            decoder.decode(b"0\x80\x00\x00", asn1Spec=self.RequiredIdSequence())

    def testAbsentComponentConstraintIsValidated(self):
        with self.assertRaises(ValueConstraintError):
            decoder.decode(b"1\x03\x02\x01\x01", asn1Spec=self.NoIdSet())

    def testPresentSubtypeIsMaterializedAsAValue(self):
        value, rest = decoder.decode(
            b"0\x03\x02\x01\x01", asn1Spec=self.SubtypedSequence()
        )

        component = value["number"]
        assert rest == _null
        assert isinstance(component, BoundedInteger)
        assert component.isValue
        assert component == 1

    def testOmittedDefaultRemainsAbsentUntilAccessed(self):
        value, rest = decoder.decode(b"0\x00", asn1Spec=self.DefaultedSequence())

        assert rest == _null
        assert (
            value.getComponentByName("count", default=None, instantiate=False) is None
        )
        assert value["count"] == 5


class ErrorOnDecodingTestCase(BaseTestCase):
    def testErrorCondition(self):
        decode = decoder.Decoder(decoder.tagMap, decoder.typeMap)

        try:
            asn1Object, rest = decode(_str2octs("abc"))

        except PyAsn1Error:
            exc = sys.exc_info()[1]
            assert isinstance(exc, PyAsn1Error), f"Unexpected exception raised {exc!r}"

        else:
            assert False, f"Unexpected decoder result {asn1Object!r}"

    def testRawDump(self):
        decode = decoder.Decoder(decoder.tagMap, decoder.typeMap)

        decode.defaultErrorState = decoder.stDumpRawValue

        asn1Object, rest = decode(bytes((31, 8, 2, 1, 1, 131, 3, 2, 1, 12)))

        assert isinstance(asn1Object, univ.Any), (
            f"Unexpected raw dump type {asn1Object!r}"
        )
        assert asn1Object.asNumbers() == (
            31,
            8,
            2,
            1,
            1,
        ), f"Unexpected raw dump value {asn1Object!r}"
        assert rest == bytes((131, 3, 2, 1, 12)), (
            f"Unexpected rest of substrate after raw dump {rest!r}"
        )


class ResourceExhaustionGuardTestCase(BaseTestCase):
    """Bounds on unbounded-by-spec BER constructs (see issue #110)."""

    #: Arc counts differ by this factor across the scaling checks below.
    SCALING_SPAN = 32

    #: Growth allowed across that span. Linear work lands near 32x and
    #: quadratic work near 1000x; 150 sits far enough from both that host
    #: noise cannot reach it while a regression cannot hide under it.
    SCALING_LIMIT = 150

    @staticmethod
    def _oidSubstrate(continuationOctets):
        # 06 <len> 2b <0x81 * n> 01 -- arc 1.3 followed by one arc encoded
        # across `continuationOctets` continuation octets plus a final octet.
        payload = b"\x2b" + b"\x81" * continuationOctets + b"\x01"
        return b"\x06" + bytes((len(payload),)) + payload

    def testOidArcAtContinuationLimitDecodes(self):
        limit = decoder.MAX_OID_ARC_CONTINUATION_OCTETS

        asn1Object, rest = decoder.decode(self._oidSubstrate(limit))

        assert rest == _null
        assert len(asn1Object) == 3, f"Unexpected OID {asn1Object!r}"

    def testOidArcBeyondContinuationLimitRejected(self):
        limit = decoder.MAX_OID_ARC_CONTINUATION_OCTETS

        try:
            decoder.decode(self._oidSubstrate(limit + 1))

        except PyAsn1Error as exc:
            assert exc.context["limit"] == limit

        else:
            assert False, "Over-long OID arc accepted"

    def testLongOidDecodesInLinearTime(self):
        # Repeated tuple concatenation made this quadratic in the arc count.
        #
        # Comparing two adjacent doublings cannot tell linear from quadratic
        # reliably: at a few milliseconds per sample the measurement noise on
        # a shared runner is larger than the 2x-versus-4x signal. Spanning a
        # 32x range instead puts linear near 32x and quadratic near 1000x, so
        # a threshold between them holds regardless of how noisy the host is.
        def elapsed(arcs, repeat):
            payload = b"\x2b" + b"\x01" * arcs
            substrate = b"\x06\x83" + len(payload).to_bytes(3, "big") + payload
            return min(
                timeit.repeat(
                    lambda: decoder.decode(substrate), repeat=repeat, number=1
                )
            )

        # The large sample is timed once: against a 150x threshold a single
        # reading is ample, and it keeps a regression failing in seconds
        # rather than grinding through repeats of quadratic work.
        small = elapsed(1 << 12, repeat=3)
        large = elapsed(1 << 17, repeat=1)

        assert large < small * self.SCALING_LIMIT, (
            f"OID decoding scales worse than linearly over a "
            f"{self.SCALING_SPAN}x range: {small:.4f}s -> {large:.4f}s "
            f"(ratio {large / small:.1f}, limit {self.SCALING_LIMIT})"
        )

    def testLongFormTagBeyondOctetLimitRejected(self):
        limit = decoder.MAX_TAG_OCTETS

        # 0x1f selects the high-tag-number form of X.690 8.1.2.4.
        substrate = b"\x1f" + b"\xff" * (limit + 1) + b"\x01\x00"

        try:
            decoder.decode(substrate)

        except PyAsn1Error as exc:
            assert exc.context.get("limit") == limit, f"Unexpected error {exc!r}"

        else:
            assert False, "Over-long tag number accepted"

    def testLongFormTagAtOctetLimitIsNotRejectedForLength(self):
        limit = decoder.MAX_TAG_OCTETS

        substrate = b"\x1f" + b"\xff" * (limit - 1) + b"\x01\x00"

        # The tag itself is within bounds; decoding fails later, if at all,
        # for reasons unrelated to the octet cap.
        try:
            decoder.decode(substrate)

        except PyAsn1Error as exc:
            assert exc.context.get("limit") != limit, f"Tag wrongly capped: {exc!r}"

    def testLengthBeyondOctetLimitRejected(self):
        limit = decoder.MAX_LENGTH_OCTETS

        # INTEGER with a long-form length claiming `limit + 1` length octets.
        substrate = b"\x02" + bytes((0x80 | (limit + 1),)) + b"\x01" * (limit + 1)

        try:
            decoder.decode(substrate)

        except PyAsn1Error as exc:
            assert exc.context["limit"] == limit, f"Unexpected error {exc!r}"

        else:
            assert False, "Over-long length field accepted"


class LateBoundComponentTypeDecoderTestCase(BaseTestCase):
    """Recursive schemas bind componentType after the fact (see issue #111)."""

    @staticmethod
    def _ldapFilterSpec():
        # Modelled on RFC 4511 Filter, the canonical recursive schema: And
        # holds Filters, so its componentType can only be assigned once every
        # participating class exists.
        class AttributeValueAssertion(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("attributeDesc", univ.OctetString()),
                namedtype.NamedType("assertionValue", univ.OctetString()),
            )

        class EqualityMatch(AttributeValueAssertion):
            tagSet = AttributeValueAssertion.tagSet.tagImplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
            )

        class And(univ.SetOf):
            tagSet = univ.SetOf.tagSet.tagImplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )

        class NestedFilter(univ.Choice):
            pass

        class Filter(univ.Choice):
            pass

        Filter.componentType = namedtype.NamedTypes(namedtype.NamedType("and", And()))
        NestedFilter.componentType = namedtype.NamedTypes(
            namedtype.NamedType("equalityMatch", EqualityMatch())
        )
        And.componentType = NestedFilter()

        return Filter

    def testDefMode(self):
        asn1Object, rest = decoder.decode(
            bytes.fromhex("a00ea30c040375696404057573657231"),
            asn1Spec=self._ldapFilterSpec()(),
        )

        assert rest == _null
        # Before the fix the nested components were silently dropped: the
        # decode succeeded but yielded only the first OCTET STRING.
        equalityMatch = asn1Object["and"][0]["equalityMatch"]
        assert equalityMatch["attributeDesc"] == _str2octs("uid")
        assert equalityMatch["assertionValue"] == _str2octs("user1")

    def testIndefMode(self):
        asn1Object, rest = decoder.decode(
            bytes.fromhex("a080a38004037569640405757365723100000000"),
            asn1Spec=self._ldapFilterSpec()(),
        )

        assert rest == _null
        equalityMatch = asn1Object["and"][0]["equalityMatch"]
        assert equalityMatch["attributeDesc"] == _str2octs("uid")
        assert equalityMatch["assertionValue"] == _str2octs("user1")


class SchemalessTaggedConstructedDecoderTestCase(BaseTestCase):
    """A refuted explicit-tag guess must not drop components (issue #116)."""

    # [0] IMPLICIT holding two SEQUENCEs:
    #   a0 13  30 07 16 05 "first"  30 08 16 06 "second"
    twoComponents = bytes.fromhex("a013300716056669727374300816067365636f6e64")
    twoComponentsIndef = bytes.fromhex("a080300716056669727374300816067365636f6e640000")
    # The same tag holding a single SEQUENCE stays an explicit-tag reading.
    oneComponent = bytes.fromhex("a009300716056669727374")
    oneComponentIndef = bytes.fromhex("a0803007160566697273740000")

    def testDefModeKeepsAllComponents(self):
        asn1Object, rest = decoder.decode(self.twoComponents)

        assert rest == _null
        assert len(asn1Object) == 2, f"Components dropped: {asn1Object!r}"
        assert asn1Object[0][0] == char.IA5String("first")
        assert asn1Object[1][0] == char.IA5String("second")

    def testIndefModeKeepsAllComponents(self):
        asn1Object, rest = decoder.decode(self.twoComponentsIndef)

        assert rest == _null
        assert len(asn1Object) == 2, f"Components dropped: {asn1Object!r}"
        assert asn1Object[0][0] == char.IA5String("first")
        assert asn1Object[1][0] == char.IA5String("second")

    def testDefModeSingleComponentUnwrapsAsExplicitTag(self):
        # One inner encoding is consistent with X.690 8.14.2, so the explicit
        # tag reading stands and the tag is unwrapped as before.
        asn1Object, rest = decoder.decode(self.oneComponent)

        assert rest == _null
        assert len(asn1Object) == 1
        assert asn1Object[0] == char.IA5String("first")

    def testIndefModeSingleComponentUnwrapsAsExplicitTag(self):
        asn1Object, rest = decoder.decode(self.oneComponentIndef)

        assert rest == _null
        assert len(asn1Object) == 1
        assert asn1Object[0] == char.IA5String("first")

    def testNestedInSequenceKeepsAllComponents(self):
        # The originally reported shape: the tagged value sits inside an
        # outer SEQUENCE, so the loss showed up with rest == b''.
        substrate = bytes((0x30, len(self.twoComponents))) + self.twoComponents

        asn1Object, rest = decoder.decode(substrate)

        assert rest == _null
        assert len(asn1Object[0]) == 2, f"Components dropped: {asn1Object!r}"

    def testRoundTripsThroughEncoder(self):
        asn1Object, _ = decoder.decode(self.twoComponents)

        assert encoder.encode(asn1Object) == self.twoComponents


class ExplicitTagSubstrateFunDecoderTestCase(BaseTestCase):
    """substrateFun over a guessed explicit tag stays in PyAsn1Error (issue #140)."""

    # [0] EXPLICIT SEQUENCE { INTEGER 1 }, definite and indefinite length.
    substrate = bytes.fromhex("a0053003020101")
    substrateIndef = bytes.fromhex("a08030030201010000")

    constructedSpecs = (
        univ.Sequence(),
        univ.SequenceOf(componentType=univ.Integer()),
        univ.Set(),
        univ.Choice(),
    )

    @staticmethod
    def _capture(asn1Object, substrate, length):
        return asn1Object, substrate[:length]

    def testDefModeConstructedSpecIsNotCoerced(self):
        for asn1Spec in self.constructedSpecs:
            asn1Object, _ = decoder.decode(
                self.substrate, asn1Spec=asn1Spec, substrateFun=self._capture
            )

            assert asn1Object is asn1Spec, f"Spec replaced: {asn1Object!r}"

    def testIndefModeConstructedSpecIsNotCoerced(self):
        for asn1Spec in self.constructedSpecs:
            asn1Object, _ = decoder.decode(
                self.substrateIndef, asn1Spec=asn1Spec, substrateFun=self._capture
            )

            assert asn1Object is asn1Spec, f"Spec replaced: {asn1Object!r}"

    def testSimpleSpecIsNotCoerced(self):
        # A simple spec used to be cloned with an empty string, which the
        # Integer constraint rejected as a PyAsn1Error of its own.
        asn1Spec = univ.Integer()

        asn1Object, _ = decoder.decode(
            self.substrate, asn1Spec=asn1Spec, substrateFun=self._capture
        )

        assert asn1Object is asn1Spec

    def testSchemalessDecodeStillYieldsAny(self):
        asn1Object, _ = decoder.decode(self.substrate, substrateFun=self._capture)

        assert isinstance(asn1Object, univ.Any)
        assert asn1Object.tagSet[-1] == tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0
        )

    def testSubstrateReachesTheCallback(self):
        _, captured = decoder.decode(
            self.substrate, asn1Spec=univ.Sequence(), substrateFun=self._capture
        )

        assert captured == self.substrate[2:]

    def testDebugLoggingSurvivesAValuelessResult(self):
        # The decoder's own debug record used to call prettyPrint() on the
        # schema object handed back by substrateFun. The suite runs with
        # debug records enabled, so any spec reaches that line.
        asn1Spec = univ.OctetString()

        asn1Object, captured = decoder.decode(
            bytes.fromhex("0403616263"),
            asn1Spec=asn1Spec,
            substrateFun=self._capture,
        )

        assert asn1Object is asn1Spec
        assert captured == bytes.fromhex("616263")


# Decodes in bulk; see the no_debug_records marker in tests/conftest.py.
@pytest.mark.no_debug_records
class MalformedBitStringDecoderTestCase(BaseTestCase):
    """Malformed BIT STRING input stays inside PyAsn1Error (issue #121)."""

    def testEmptySegmentIndefiniteLength(self):
        # The reported substrate: an indefinite-length BIT STRING whose only
        # segment carries no contents octets at all.
        try:
            decoder.decode(bytes.fromhex("0380600000"))

        except PyAsn1Error:
            pass

        else:
            assert False, "Empty BIT STRING segment accepted"

    def testEmptySegmentDefiniteLength(self):
        try:
            decoder.decode(bytes.fromhex("23026000"))

        except PyAsn1Error:
            pass

        else:
            assert False, "Empty BIT STRING segment accepted"

    def testWellFormedBitStringStillDecodes(self):
        asn1Object, rest = decoder.decode(bytes.fromhex("030200ff"))

        assert rest == _null
        assert asn1Object == univ.BitString(hexValue="ff")

    def testEmptyBitStringStillDecodes(self):
        # X.690 8.6.2.3: an empty bitstring is a single zero initial octet.
        asn1Object, rest = decoder.decode(bytes.fromhex("030100"))

        assert rest == _null
        assert asn1Object == univ.BitString(())

    def testMalformedSubstratesRaisePyAsn1Error(self):
        # Every decoder failure on untrusted input must be a PyAsn1Error
        # subclass, so a caller wrapping decode() the documented way cannot be
        # surprised by IndexError, ValueError or TypeError.
        alphabet = (0x00, 0x01, 0x02, 0x07, 0x08, 0x23, 0x60, 0x80, 0x03, 0xFF)

        escapes = []

        for size in range(5):
            for body in itertools.product(alphabet, repeat=size):
                for tagOctet in (0x03, 0x23):
                    substrate = bytes((tagOctet, *body))

                    try:
                        decoder.decode(substrate)

                    except PyAsn1Error:
                        pass

                    except Exception as exc:  # noqa: BLE001
                        escapes.append((substrate.hex(), type(exc).__name__))

        assert not escapes, f"Non-PyAsn1Error escapes: {escapes[:10]}"


class IndefiniteLengthAnyCaptureTestCase(BaseTestCase):
    """An untagged ANY keeps the EOO closing what it captures (issue #114)."""

    def setUp(self):
        BaseTestCase.setUp(self)

        class Inner(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("x", univ.OctetString())
            )

        class Outer(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.Any(),
                    openType=opentype.OpenType("id", {1: Inner()}),
                ),
            )

        self.Inner = Inner
        self.Outer = Outer

        inner = Inner()
        inner["x"] = "abc"

        value = Outer()
        value["id"] = 1
        value["blob"] = univ.Any(encoder.encode(inner, defMode=False))

        self.substrate = encoder.encode(value, defMode=False)

    def testCapturedAnyIsAWellFormedEncoding(self):
        asn1Object, rest = decoder.decode(self.substrate, asn1Spec=self.Outer())

        assert rest == _null
        # 30 80 04 03 "abc" 00 00 -- the trailing EOO closes the indefinite
        # length header the capture starts with.
        assert bytes(asn1Object["blob"]) == bytes.fromhex("308004036162630000")

    def testCapturedAnyDecodesOnItsOwn(self):
        asn1Object, _ = decoder.decode(self.substrate, asn1Spec=self.Outer())

        inner, rest = decoder.decode(bytes(asn1Object["blob"]), asn1Spec=self.Inner())

        assert rest == _null
        assert inner["x"] == _str2octs("abc")

    def testOpenTypeDecodingSucceeds(self):
        asn1Object, rest = decoder.decode(
            self.substrate, asn1Spec=self.Outer(), decodeOpenTypes=True
        )

        assert rest == _null
        assert asn1Object["blob"]["x"] == _str2octs("abc")

    def testRoundTripsThroughEncoder(self):
        asn1Object, _ = decoder.decode(self.substrate, asn1Spec=self.Outer())

        assert encoder.encode(asn1Object, defMode=False) == self.substrate

    def testTaggedAnyStillHoldsContentsOnly(self):
        # A tagged ANY holds the contents octets of its own tag, and the EOO
        # closes that tag rather than anything inside it, so it stays out.
        s = univ.Any("\004\003fox").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )

        assert decoder.decode(
            bytes((164, 128, 4, 3, 102, 111, 120, 0, 0)), asn1Spec=s
        ) == (s, _null)


class OptionalBeforeConstructedDecoderTestCase(BaseTestCase):
    """OPTIONAL followed by a constructed component (see issue #120)."""

    @staticmethod
    def _legalSpec():
        # X.680 25.6: the tags of an OPTIONAL component and of everything that
        # may follow it must be distinct. [2] against [3]/[4] satisfies that.
        class Lists(univ.Choice):
            pass

        Lists.componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "first",
                univ.SequenceOf(componentType=univ.Integer()).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                ),
            ),
            namedtype.NamedType(
                "second",
                univ.SequenceOf(componentType=univ.Integer()).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
                ),
            ),
        )

        class Obj(univ.Sequence):
            pass

        Obj.componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "counter",
                univ.Integer().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                ),
            ),
            namedtype.OptionalNamedType(
                "opt",
                univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
                ),
            ),
            namedtype.NamedType("lists", Lists()),
        )

        return Obj

    def testOptionalPresentBeforeConstructed(self):
        # 30 0c 81 01 02 82 02 "xy" a3 03 02 01 01
        substrate = bytes.fromhex("300c81010282027879a303020101")

        asn1Object, rest = decoder.decode(substrate, asn1Spec=self._legalSpec()())

        assert rest == _null
        assert asn1Object["counter"] == 2
        assert asn1Object["opt"] == _str2octs("xy")
        assert asn1Object["lists"]["first"][0] == 1
        assert asn1Object.prettyPrint()

    def testOptionalAbsentBeforeConstructed(self):
        substrate = bytes.fromhex("3008810102a303020101")

        asn1Object, rest = decoder.decode(substrate, asn1Spec=self._legalSpec()())

        assert rest == _null
        assert asn1Object["counter"] == 2
        assert asn1Object["lists"]["first"][0] == 1
        assert asn1Object.prettyPrint()

    def testAmbiguousSchemaIsReportedAsSuch(self):
        # The reported schema: the OPTIONAL component carries [2] and so does
        # one alternative of the mandatory Choice that follows it, which X.680
        # 25.6 forbids. The decoder must name that rather than failing further
        # in with a message about the tag format of whichever component it
        # happened to pick.
        class Lists(univ.Choice):
            pass

        Lists.componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "clashing",
                univ.SequenceOf(componentType=univ.Integer()).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
                ),
            ),
        )

        class Obj(univ.Sequence):
            pass

        Obj.componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "counter",
                univ.Integer().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                ),
            ),
            namedtype.OptionalNamedType(
                "opt",
                univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
                ),
            ),
            namedtype.NamedType("lists", Lists()),
        )

        substrate = bytes.fromhex("3008810102820278790000")[:10]

        try:
            decoder.decode(substrate, asn1Spec=Obj())

        except PyAsn1Error as exc:
            assert "Duplicate component tag" in str(exc), f"Unexpected error {exc!r}"
            assert exc.context["tagSet"] == tag.TagSet(
                tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2),
                tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2),
            )

        else:
            assert False, "Ambiguous schema accepted"


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
