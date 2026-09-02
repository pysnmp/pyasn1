#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""X.690 conformance checks.

The bulk of the codec suite is round-trip: encode a value, decode it back,
assert the value survived. That proves the codecs agree with each other, not
that either agrees with X.690. The cases here assert against the octets and
the restrictions the specification names, so a self-consistent pair of bugs
cannot satisfy them.

Each test cites the X.690 clause it enforces.
"""

import sys
import unittest

from pyasn1 import error
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.ber.decoder import MAX_NESTING_DEPTH
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import constraint, namedtype, univ
from tests.base import BaseTestCase


class CerStringSegmentationTestCase(BaseTestCase):
    """X.690 9.2: under CER a string of more than 1000 content octets is
    encoded as a constructed value using the indefinite length form, and every
    segment but the last carries exactly 1000 octets."""

    def testPrimitiveAtBoundary(self):
        substrate = cer_encoder.encode(univ.OctetString(b"x" * 1000))

        assert substrate[0] == 0x04, "1000 octets must stay primitive"
        assert substrate == bytes((0x04, 0x82, 0x03, 0xE8)) + b"x" * 1000

    def testConstructedPastBoundary(self):
        substrate = cer_encoder.encode(univ.OctetString(b"x" * 1001))

        assert substrate[:2] == bytes((0x24, 0x80)), "expected constructed, indefinite"
        assert substrate[2:6] == bytes((0x04, 0x82, 0x03, 0xE8))
        assert substrate[1006:] == bytes((0x04, 0x01)) + b"x" + bytes((0x00, 0x00))

    def testSegmentsAreExactlyOneThousandOctets(self):
        substrate = cer_encoder.encode(univ.OctetString(b"x" * 2500))
        segments = []
        offset = 2

        while substrate[offset : offset + 2] != bytes((0x00, 0x00)):
            assert substrate[offset] == 0x04, "segment must be a primitive OCTET STRING"
            if substrate[offset + 1] & 0x80:
                sizeOctets = substrate[offset + 1] & 0x7F
                size = int.from_bytes(
                    substrate[offset + 2 : offset + 2 + sizeOctets], "big"
                )
                offset += 2 + sizeOctets
            else:
                size = substrate[offset + 1]
                offset += 2

            segments.append(size)
            offset += size

        assert segments == [1000, 1000, 500]

    def testBitStringSegmentedOnContentOctets(self):
        # A BIT STRING segment carries the unused-bits octet plus 999 octets of
        # bits, so the first content octet count is 1000 like every other type.
        substrate = cer_encoder.encode(univ.BitString(hexValue="00" * 1500))

        assert substrate[:2] == bytes((0x23, 0x80)), "expected constructed, indefinite"
        assert substrate[2:6] == bytes((0x03, 0x82, 0x03, 0xE9))


class DerSetOfOrderingTestCase(BaseTestCase):
    """X.690 11.6: the encodings of the components of a SET OF are sorted into
    ascending order, regardless of the order they were added in."""

    def testSortedByEncodingNotInsertion(self):
        class SetOfOctetString(univ.SetOf):
            componentType = univ.OctetString()

        setOf = SetOfOctetString()
        setOf.extend(
            [
                univ.OctetString(b"\xff"),
                univ.OctetString(b"\x01"),
                univ.OctetString(b"\x7f"),
            ]
        )

        assert der_encoder.encode(setOf) == bytes(
            (0x31, 0x09, 0x04, 0x01, 0x01, 0x04, 0x01, 0x7F, 0x04, 0x01, 0xFF)
        )

    def testShorterEncodingSortsFirstOnCommonPrefix(self):
        # X.690 11.6 sorts the full encodings as octet strings, so a shorter
        # encoding that is a prefix of a longer one comes first.
        class SetOfOctetString(univ.SetOf):
            componentType = univ.OctetString()

        setOf = SetOfOctetString()
        setOf.extend([univ.OctetString(b"AB"), univ.OctetString(b"A")])

        assert der_encoder.encode(setOf) == bytes(
            (0x31, 0x07, 0x04, 0x01, 0x41, 0x04, 0x02, 0x41, 0x42)
        )


class DerSetOrderingTestCase(BaseTestCase):
    """X.690 11.3: the components of a SET are encoded in ascending order of
    their tags."""

    def testSortedByTag(self):
        class Set(univ.Set):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("boolean", univ.Boolean()),
                namedtype.NamedType("integer", univ.Integer()),
            )

        value = Set()
        value["integer"] = 1
        value["boolean"] = True

        # BOOLEAN is UNIVERSAL 1, INTEGER is UNIVERSAL 2, so BOOLEAN leads
        # even though INTEGER was assigned first.
        assert der_encoder.encode(value) == bytes(
            (0x31, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01)
        )


class DerDefaultOmissionTestCase(BaseTestCase):
    """X.690 11.5: a component whose value equals its DEFAULT is not encoded."""

    class Sequence(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.DefaultedNamedType("version", univ.Integer(1)),
            namedtype.NamedType("serial", univ.Integer()),
        )

    def testDefaultValuedComponentOmitted(self):
        value = self.Sequence()
        value["version"] = 1
        value["serial"] = 7

        assert der_encoder.encode(value) == bytes((0x30, 0x03, 0x02, 0x01, 0x07))

    def testNonDefaultValuedComponentEncoded(self):
        value = self.Sequence()
        value["version"] = 2
        value["serial"] = 7

        assert der_encoder.encode(value) == bytes(
            (0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x07)
        )

    def testBerAlsoOmitsDefaultValuedComponent(self):
        # 11.5 makes omission mandatory only for CER/DER. BER is free either
        # way and pyasn1 omits there too, so all three codecs agree.
        value = self.Sequence()
        value["version"] = 1
        value["serial"] = 7

        assert ber_encoder.encode(value) == bytes((0x30, 0x03, 0x02, 0x01, 0x07))


class ObjectIdentifierTestCase(BaseTestCase):
    """X.690 8.19."""

    def testFirstTwoArcsPackedIntoOneSubidentifier(self):
        # 8.19.4: the first subidentifier is 40 * arc1 + arc2.
        value, _ = der_decoder.decode(bytes((0x06, 0x01, 0x2A)))

        assert value == univ.ObjectIdentifier("1.2")

    def testLargeSecondArcUnderJointIsoItu(self):
        # 8.19.4 places no ceiling on arc2 when arc1 is 2, so 2.999 must
        # round-trip through the 40 * arc1 + arc2 packing.
        substrate = bytes((0x06, 0x03, 0x88, 0x37, 0x01))
        value, _ = der_decoder.decode(substrate)

        assert value == univ.ObjectIdentifier("2.999.1")
        assert der_encoder.encode(univ.ObjectIdentifier("2.999.1")) == substrate

    def testNonMinimalSubidentifierRejected(self):
        # 8.19.2: leading 0x80 octets pad a subidentifier and are prohibited.
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x06, 0x03, 0x2A, 0x80, 0x01)),
        )

    def testUnterminatedSubidentifierRejected(self):
        # 8.19.2: bit 8 of the last octet of a subidentifier is zero.
        self.assertRaises(
            error.PyAsn1Error, der_decoder.decode, bytes((0x06, 0x02, 0x2A, 0x81))
        )

    def testEmptyValueRejected(self):
        # 8.19.1: the contents octets are one or more subidentifiers.
        self.assertRaises(error.PyAsn1Error, der_decoder.decode, bytes((0x06, 0x00)))

    def testFirstArcAboveTwoRejected(self):
        # 8.19.4 constrains arc1 to 0, 1 or 2.
        self.assertRaises(
            error.PyAsn1Error, der_encoder.encode, univ.ObjectIdentifier("3.1.1")
        )

    def testSecondArcAboveThirtyNineRejected(self):
        # 8.19.4: when arc1 is 0 or 1, arc2 is at most 39.
        self.assertRaises(
            error.PyAsn1Error, der_encoder.encode, univ.ObjectIdentifier("1.40.1")
        )

    def testSingleArcRejected(self):
        # 8.19.4 needs two arcs to form the first subidentifier.
        self.assertRaises(
            error.PyAsn1Error, der_encoder.encode, univ.ObjectIdentifier("1")
        )

    def testNegativeArcRejected(self):
        # Rejected when the value is built, ahead of any encoding.
        self.assertRaises(error.PyAsn1Error, univ.ObjectIdentifier, (1, 2, -3))


class BooleanStrictnessTestCase(BaseTestCase):
    """X.690 8.2.2 against 11.1: BER reads any non-zero octet as TRUE, while
    CER and DER accept only 0xFF."""

    def testBerAcceptsAnyNonZeroOctet(self):
        for octet in (0x01, 0x7F, 0xFE):
            value, _ = ber_decoder.decode(bytes((0x01, 0x01, octet)))
            assert value == univ.Boolean(True), f"{octet:#04x} should read as TRUE"

    def testCerAndDerRejectNonCanonicalTrue(self):
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, bytes((0x01, 0x01, 0x01)))

    def testCerAndDerAcceptCanonicalOctets(self):
        for decode in (cer_decoder.decode, der_decoder.decode):
            assert decode(bytes((0x01, 0x01, 0xFF)))[0] == univ.Boolean(True)
            assert decode(bytes((0x01, 0x01, 0x00)))[0] == univ.Boolean(False)

    def testCerAndDerEncodeTrueAsAllOnes(self):
        # 11.1 fixes TRUE at 0xFF.
        for encode in (cer_encoder.encode, der_encoder.encode):
            assert encode(univ.Boolean(True)) == bytes((0x01, 0x01, 0xFF))
            assert encode(univ.Boolean(False)) == bytes((0x01, 0x01, 0x00))

    def testBerEncodesTrueAsAnyNonZeroOctet(self):
        # 8.2.2 lets BER pick any non-zero octet; pyasn1 picks 0x01.
        substrate = ber_encoder.encode(univ.Boolean(True))

        assert substrate[:2] == bytes((0x01, 0x01))
        assert substrate[2] != 0x00
        assert ber_encoder.encode(univ.Boolean(False)) == bytes((0x01, 0x01, 0x00))

    def testMultiOctetPayloadRejected(self):
        # 8.2.1: the contents octets are a single octet.
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(
                error.PyAsn1Error, decode, bytes((0x01, 0x02, 0xFF, 0xFF))
            )
            self.assertRaises(error.PyAsn1Error, decode, bytes((0x01, 0x00)))


class NullTestCase(BaseTestCase):
    """X.690 8.8.2: the contents octets of a NULL are empty."""

    def testEmptyContentsRequired(self):
        self.assertRaises(
            error.PyAsn1Error, der_decoder.decode, bytes((0x05, 0x01, 0x00))
        )

    def testCanonicalEncoding(self):
        assert der_encoder.encode(univ.Null("")) == bytes((0x05, 0x00))


class SpecialRealValueTestCase(BaseTestCase):
    """X.690 8.5.9: when a SpecialRealValue or minus zero is encoded, there
    shall be only one contents octet, with values as follows::

        01000000    Value is PLUS-INFINITY
        01000001    Value is MINUS-INFINITY
        01000010    Value is NOT-A-NUMBER
        01000011    Value is minus zero

    "All other values having bits 8 and 7 equal to 0 and 1 respectively are
    reserved."

    NOT-A-NUMBER and minus zero were added after the 07/2002 edition that
    parts of this source still cite, where only the two infinities were
    defined and the remaining bit patterns were reserved.
    """

    def testPlusInfinity(self):
        assert der_encoder.encode(univ.Real(float("inf"))) == bytes((0x09, 0x01, 0x40))

    def testMinusInfinity(self):
        assert der_encoder.encode(univ.Real(float("-inf"))) == bytes((0x09, 0x01, 0x41))

    def testNotANumberEncodesToItsOwnOctet(self):
        assert der_encoder.encode(univ.Real(float("nan"))) == bytes((0x09, 0x01, 0x42))

    def testMinusZeroEncodesToItsOwnOctet(self):
        # Distinct from the empty-contents encoding of positive zero that
        # 8.5.2 requires, even though the two compare equal as floats.
        assert der_encoder.encode(univ.Real(-0.0)) == bytes((0x09, 0x01, 0x43))
        assert der_encoder.encode(univ.Real(0.0)) == bytes((0x09, 0x00))

    def testNotANumberDecodes(self):
        value, _ = der_decoder.decode(bytes((0x09, 0x01, 0x42)))

        assert value.isNaN, "0x42 is NOT-A-NUMBER, not an infinity"
        assert not value.isInf

    def testMinusZeroDecodes(self):
        value, _ = der_decoder.decode(bytes((0x09, 0x01, 0x43)))

        assert value.isMinusZero, "0x43 is minus zero, not an infinity"
        assert not value.isInf
        assert float(value) == 0.0

    def testInfinitiesAreNotConfusedWithTheOthers(self):
        plusInf, _ = der_decoder.decode(bytes((0x09, 0x01, 0x40)))
        minusInf, _ = der_decoder.decode(bytes((0x09, 0x01, 0x41)))

        assert plusInf.isPlusInf and not plusInf.isNaN and not plusInf.isMinusZero
        assert minusInf.isMinusInf and not minusInf.isNaN and not minusInf.isMinusZero

    def testReservedValuesRejected(self):
        # Bits 8 to 7 of 01 with any other pattern is reserved for addenda.
        for firstOctet in (0x44, 0x45, 0x50, 0x60, 0x7F):
            self.assertRaises(
                error.PyAsn1Error,
                ber_decoder.decode,
                bytes((0x09, 0x01, firstOctet)),
            )

    def testSingleContentsOctetRequired(self):
        self.assertRaises(
            error.PyAsn1Error,
            ber_decoder.decode,
            bytes((0x09, 0x02, 0x40, 0x00)),
        )

    def testSpecialValuesSurviveTheRoundTrip(self):
        nan, _ = der_decoder.decode(der_encoder.encode(univ.Real(float("nan"))))
        minusZero, _ = der_decoder.decode(der_encoder.encode(univ.Real(-0.0)))

        assert nan.isNaN
        assert minusZero.isMinusZero


class IntegerMinimalEncodingTestCase(BaseTestCase):
    """X.690 8.3.2: given more than one contents octet, the bits of the first
    octet and bit 8 of the second shall not all be ones, nor all be zero.

    The note to 8.3.2 states the intent: "These rules ensure that an integer
    value is always encoded in the smallest possible number of octets." The
    all-ones half is the one that bites, because ``int.bit_length`` ignores
    the sign: -128 needs exactly one octet, but a naive sizing pads it to
    ``ff 80`` -- nine leading one-bits, which 8.3.2 a) forbids outright.
    """

    @staticmethod
    def minimalOctetCount(value):
        count = 1
        while not -(1 << (8 * count - 1)) <= value <= (1 << (8 * count - 1)) - 1:
            count += 1
        return count

    def testNegativePowersOfTwoUseOneOctetLess(self):
        for value, expected in (
            (-128, bytes((0x02, 0x01, 0x80))),
            (-32768, bytes((0x02, 0x02, 0x80, 0x00))),
            (-8388608, bytes((0x02, 0x03, 0x80, 0x00, 0x00))),
        ):
            for encode in (ber_encoder.encode, cer_encoder.encode, der_encoder.encode):
                assert encode(univ.Integer(value)) == expected, value

    def testFirstNineBitsAreNeverAllOnesOrAllZero(self):
        for value in range(-70000, 70000):
            octets = der_encoder.encode(univ.Integer(value))[2:]
            if len(octets) < 2:
                continue

            leading = (octets[0] << 1) | (octets[1] >> 7)
            assert leading != 0x1FF, f"{value} encodes with nine leading ones"
            assert leading != 0x000, f"{value} encodes with nine leading zeros"

    def testEveryValueUsesTheSmallestPossibleNumberOfOctets(self):
        for value in range(-70000, 70000):
            octets = der_encoder.encode(univ.Integer(value))[2:]
            assert len(octets) == self.minimalOctetCount(value), value

    def testBoundariesRoundTrip(self):
        for value in (-8388608, -32769, -32768, -129, -128, -1, 0, 127, 128, 32767):
            assert (
                der_decoder.decode(der_encoder.encode(univ.Integer(value)))[0] == value
            )


class BitStringTestCase(BaseTestCase):
    """X.690 8.6."""

    def testUnusedBitCountAboveSevenRejected(self):
        # 8.6.2.2: the initial octet counts 0 to 7 unused bits.
        self.assertRaises(
            error.PyAsn1Error, der_decoder.decode, bytes((0x03, 0x02, 0x09, 0x00))
        )

    def testEmptyContentsRejected(self):
        # 8.6.2: the initial octet is always present.
        self.assertRaises(error.PyAsn1Error, der_decoder.decode, bytes((0x03, 0x00)))

    def testDerRejectsConstructedForm(self):
        # 10.2: under DER a bitstring is encoded in the primitive form.
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x23, 0x04, 0x03, 0x02, 0x00, 0x00)),
        )


class OctetStringTestCase(BaseTestCase):
    def testDerRejectsConstructedForm(self):
        # 10.2: under DER an octetstring is encoded in the primitive form.
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x24, 0x06, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42)),
        )

    def testBerAcceptsConstructedForm(self):
        # 8.21.6 permits the constructed form under BER.
        value, _ = ber_decoder.decode(
            bytes((0x24, 0x06, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42))
        )

        assert value == univ.OctetString(b"AB")


class IndefiniteLengthTestCase(BaseTestCase):
    """X.690 10.1: DER uses the definite length form throughout."""

    def testDerRejectsIndefiniteLength(self):
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00)),
        )

    def testBerAcceptsIndefiniteLength(self):
        value, remainder = ber_decoder.decode(
            bytes((0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00))
        )

        assert remainder == b""
        assert len(value) == 1
        assert value[0] == univ.Integer(1)


class DecodeTimeConstraintTestCase(BaseTestCase):
    """A subtype's constraints are applied to the value the decoder recovers,
    not only to values built in Python."""

    def testValueSizeConstraintEnforced(self):
        class Sized(univ.OctetString):
            subtypeSpec = constraint.ValueSizeConstraint(1, 2)

        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x04, 0x05)) + b"hello",
            asn1Spec=Sized(),
        )

        value, _ = der_decoder.decode(bytes((0x04, 0x02)) + b"hi", asn1Spec=Sized())
        assert value == univ.OctetString(b"hi")

    def testValueRangeConstraintEnforced(self):
        class Ranged(univ.Integer):
            subtypeSpec = constraint.ValueRangeConstraint(0, 10)

        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x02, 0x01, 0x63)),
            asn1Spec=Ranged(),
        )

        value, _ = der_decoder.decode(bytes((0x02, 0x01, 0x05)), asn1Spec=Ranged())
        assert value == univ.Integer(5)


class NestingDepthTestCase(BaseTestCase):
    """Decoders are pointed at hostile octets, so a deeply nested substrate has
    to be refused rather than exhaust the interpreter stack."""

    def testIndefiniteLengthDepthBombRejected(self):
        substrate = (
            bytes((0x30, 0x80)) * (MAX_NESTING_DEPTH + 50)
            + bytes((0x05, 0x00))
            + bytes((0x00, 0x00)) * (MAX_NESTING_DEPTH + 50)
        )

        self.assertRaises(error.PyAsn1Error, ber_decoder.decode, substrate)

    def testNestingUpToTheLimitStillDecodes(self):
        depth = MAX_NESTING_DEPTH - 2
        substrate = (
            bytes((0x30, 0x80)) * depth
            + bytes((0x05, 0x00))
            + bytes((0x00, 0x00)) * depth
        )

        ber_decoder.decode(substrate)


class SequenceComponentTestCase(BaseTestCase):
    """X.690 8.9.2: the components of a SEQUENCE appear in the order the type
    definition gives them."""

    class Sequence(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("first", univ.Integer()),
            namedtype.NamedType("second", univ.Boolean()),
        )

    def testOutOfOrderComponentsRejected(self):
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01)),
            asn1Spec=self.Sequence(),
        )

    def testMissingMandatoryComponentRejected(self):
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes((0x30, 0x03, 0x02, 0x01, 0x01)),
            asn1Spec=self.Sequence(),
        )

    def testWellFormedSequenceDecodes(self):
        value, _ = der_decoder.decode(
            bytes((0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF)),
            asn1Spec=self.Sequence(),
        )

        assert value["first"] == 1
        assert value["second"] == True


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
