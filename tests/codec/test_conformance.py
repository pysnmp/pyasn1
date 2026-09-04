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
from pyasn1.codec.native import encoder as native_encoder
from pyasn1.type import char, constraint, namedtype, opentype, tag, univ, useful
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
        # 8.6.2.2 spends the first content octet of a BIT STRING on the unused
        # bit count, so a 1000-octet segment carries 999 octets of bits.
        substrate = cer_encoder.encode(univ.BitString(hexValue="00" * 1500))

        assert substrate[:2] == bytes((0x23, 0x80)), "expected constructed, indefinite"
        assert substrate[2:6] == bytes((0x03, 0x82, 0x03, 0xE8))
        assert substrate[6] == 0x00, "leading segment is octet aligned"

        # 999 octets of bits leave 501 octets, plus the unused bits octet.
        assert substrate[1006:1010] == bytes((0x03, 0x82, 0x01, 0xF6))
        assert substrate[-2:] == bytes((0x00, 0x00))

    def testBitStringPrimitiveAtBoundary(self):
        # 7992 bits fill 999 octets, which the unused bits octet brings to the
        # 1000 content octets 9.2 still admits as primitive.
        substrate = cer_encoder.encode(univ.BitString(binValue="1" * 7992))

        assert substrate[:4] == bytes((0x03, 0x82, 0x03, 0xE8))
        assert len(substrate) == 1004

        substrate = cer_encoder.encode(univ.BitString(binValue="1" * 7993))

        assert substrate[:2] == bytes((0x23, 0x80)), "one bit more must segment"


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


class SchemaGuidedStrictnessTestCase(BaseTestCase):
    """A restriction must hold whether or not the caller supplies a schema.

    The decoders reach their per-type handlers two ways: by tag when the
    substrate is decoded blind, and by ``typeId`` when an ``asn1Spec`` guides
    them. CER and DER install their stricter handlers in both maps, and a
    restriction that binds on one path but not the other is a bug -- the
    schema-guided path is the one that parses X.509 and SNMP in practice.
    """

    def assertRejectedBothWays(self, decode, substrate, asn1Spec):
        self.assertRaises(error.PyAsn1Error, decode, substrate)
        self.assertRaises(error.PyAsn1Error, decode, substrate, asn1Spec=asn1Spec)

    def assertAcceptedBothWays(self, decode, substrate, asn1Spec, expected):
        byTag, _ = decode(substrate)
        bySpec, _ = decode(substrate, asn1Spec=asn1Spec)

        assert byTag == expected
        assert bySpec == expected

    def testBooleanCanonicalTrue(self):
        # 11.1: TRUE has all eight bits set. The tag-driven path has enforced
        # this for a long time; the schema-guided path used to fall through
        # to the BER decoder and accept any non-zero octet.
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRejectedBothWays(
                decode, bytes((0x01, 0x01, 0x01)), univ.Boolean()
            )
            self.assertRejectedBothWays(
                decode, bytes((0x01, 0x01, 0x7F)), univ.Boolean()
            )

    def testBooleanCanonicalValuesAccepted(self):
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertAcceptedBothWays(
                decode, bytes((0x01, 0x01, 0xFF)), univ.Boolean(), univ.Boolean(1)
            )
            self.assertAcceptedBothWays(
                decode, bytes((0x01, 0x01, 0x00)), univ.Boolean(), univ.Boolean(0)
            )

    def testBerToleratesOnBothPaths(self):
        # The mirror of the above: BER is lax either way round.
        for kwargs in ({}, {"asn1Spec": univ.Boolean()}):
            value, _ = ber_decoder.decode(bytes((0x01, 0x01, 0x01)), **kwargs)

            assert value == univ.Boolean(1)

    def testDerConstructedStringRejectedBothWays(self):
        # 10.2: the constructed form is prohibited under DER.
        self.assertRejectedBothWays(
            der_decoder.decode,
            bytes((0x24, 0x04, 0x04, 0x02, 0x41, 0x42)),
            univ.OctetString(),
        )

    def testStrictDecodersReachableByTypeId(self):
        # The structural claim behind the cases above, asserted directly:
        # the map keyed by typeId must carry the codec's own decoder, not the
        # one inherited from the codec it derives from.
        for module in (cer_decoder, der_decoder):
            byTag = module.tagMap[univ.Boolean.tagSet]
            byTypeId = module.typeMap[univ.Boolean.typeId]

            assert type(byTag) is type(byTypeId), (
                f"{module.__name__} resolves Boolean to different decoders "
                f"by tag ({type(byTag).__name__}) and by typeId "
                f"({type(byTypeId).__name__})"
            )

    def testDecoderUsesItsOwnTypeMap(self):
        # cer.decode was constructed with the BER typeMap, discarding the one
        # assembled directly above it in the module.
        for module in (cer_decoder, der_decoder):
            assert module.decode._Decoder__typeMap is module.typeMap, (
                f"{module.__name__}.decode is not using the module typeMap"
            )


def _time(tag, text):
    return bytes((tag, len(text))) + text.encode("ascii")


class StringEncodingFormTestCase(BaseTestCase):
    """X.690 9.1, 9.2 and 10.2 on the form a string encoding may take.

    BER lets a sender split a string wherever it likes, or not at all. CER
    admits exactly one split, DER admits none, and both refuse the forms the
    other codecs allow.
    """

    # 9.2 and 10.2 name bitstring, octetstring and the restricted character
    # string types. Each entry is the type's universal tag number and a value
    # long enough to force segmentation under CER.
    STRING_TYPES = (
        (univ.OctetString, 0x04),
        (char.UTF8String, 0x0C),
        (char.NumericString, 0x12),
        (char.PrintableString, 0x13),
        (char.TeletexString, 0x14),
        (char.VideotexString, 0x15),
        (char.IA5String, 0x16),
        (char.GraphicString, 0x19),
        (char.VisibleString, 0x1A),
        (char.GeneralString, 0x1B),
        (char.UniversalString, 0x1C),
        (char.BMPString, 0x1E),
        (useful.ObjectDescriptor, 0x07),
    )

    @staticmethod
    def _constructed(tagNumber, fragments, definite):
        """Splice fragments into a constructed encoding of the given type.

        8.7.3.2 gives every fragment the universal OCTET STRING tag, whatever
        the tag of the string they belong to.
        """
        body = b""
        for fragment in fragments:
            if len(fragment) < 128:
                body += bytes((0x04, len(fragment)))
            else:
                body += bytes((0x04, 0x82)) + len(fragment).to_bytes(2, "big")
            body += fragment

        identifier = bytes((tagNumber | 0x20,))

        if definite:
            return identifier + bytes((0x82,)) + len(body).to_bytes(2, "big") + body

        return identifier + b"\x80" + body + b"\x00\x00"

    def testEveryStringTypeRefusesConstructedUnderDer(self):
        # 10.2: "For bitstring, octetstring and restricted character string
        # types, the constructed form of encoding shall not be used."
        for asn1Type, tagNumber in self.STRING_TYPES:
            substrate = self._constructed(tagNumber, [b"A", b"B"], definite=True)

            for decoder in (der_decoder, cer_decoder):
                try:
                    decoder.decode(substrate)
                except error.PyAsn1Error:
                    continue
                raise AssertionError(
                    f"{asn1Type.__name__} constructed accepted by {decoder.__name__}"
                )

    def testBerStillAcceptsConstructed(self):
        # 8.7.2 leaves the form to the sender under BER, and 7.3 requires a
        # receiver to handle every permitted one, so the restriction above
        # belongs to CER and DER alone.
        for asn1Type, tagNumber in ((univ.OctetString, 0x04), (char.IA5String, 0x16)):
            for definite in (True, False):
                substrate = self._constructed(
                    tagNumber, [b"A", b"B"], definite=definite
                )

                assert ber_decoder.decode(substrate)[0] == asn1Type("AB")

    def testEveryStringTypeRefusesConstructedUnderDerWithSchema(self):
        # The schema-guided path dispatches on type ID rather than on tag, so
        # it has to reach the same decoder.
        for asn1Type, tagNumber in self.STRING_TYPES:
            substrate = self._constructed(tagNumber, [b"A", b"B"], definite=True)

            for decoder in (der_decoder, cer_decoder):
                try:
                    decoder.decode(substrate, asn1Spec=asn1Type())
                except error.PyAsn1Error:
                    continue
                raise AssertionError(
                    f"{asn1Type.__name__} constructed accepted by {decoder.__name__}"
                )

    def testCerRefusesDefiniteLengthConstructed(self):
        # 9.1: "If the encoding is constructed, it shall employ the indefinite
        # length form."
        fragments = [b"x" * 1000, b"y"]
        substrate = self._constructed(0x04, fragments, definite=True)

        with self.assertRaises(error.PyAsn1Error):
            cer_decoder.decode(substrate)

        # The same fragments under the indefinite form are what CER admits.
        substrate = self._constructed(0x04, fragments, definite=False)

        assert cer_decoder.decode(substrate)[0] == univ.OctetString(b"x" * 1000 + b"y")

    def testCerRefusesShortConstructed(self):
        # 9.2: a value of no more than 1000 contents octets "shall be encoded
        # with a primitive encoding", so a split that short has no conforming
        # spelling however its fragments are sized.
        for fragments in ([b"A", b"B"], [b"x" * 999, b"y"], [b"x" * 1000]):
            substrate = self._constructed(0x04, fragments, definite=False)

            with self.assertRaises(error.PyAsn1Error):
                cer_decoder.decode(substrate)

    def testCerRefusesUndersizedLeadingFragment(self):
        # 9.2: "The encoding of each fragment, except possibly the last, shall
        # have 1000 contents octets."
        for leading in (999, 1001):
            fragments = [b"x" * leading, b"x" * 1000, b"y"]
            substrate = self._constructed(0x04, fragments, definite=False)

            with self.assertRaises(error.PyAsn1Error):
                cer_decoder.decode(substrate)

    def testCerRefusesEmptyLastFragment(self):
        # 9.2: "The last fragment shall have at least one, and no more than
        # 1000, contents octets."
        substrate = self._constructed(0x04, [b"x" * 1000, b""], definite=False)

        with self.assertRaises(error.PyAsn1Error):
            cer_decoder.decode(substrate)

    def testCerRefusesConstructedFragment(self):
        # 9.2: "The string fragments contained in the constructed encoding
        # shall be encoded with a primitive encoding."
        inner = self._constructed(0x04, [b"x" * 1000, b"y"], definite=False)
        substrate = b"\x24\x80" + inner + b"\x04\x01z" + b"\x00\x00"

        with self.assertRaises(error.PyAsn1Error):
            cer_decoder.decode(substrate)

    def testCerAcceptsConformingSegmentation(self):
        substrate = self._constructed(
            0x04, [b"x" * 1000, b"y" * 1000, b"z" * 500], definite=False
        )

        decoded, remainder = cer_decoder.decode(substrate)

        assert remainder == b""
        assert decoded == univ.OctetString(b"x" * 1000 + b"y" * 1000 + b"z" * 500)


class SegmentedStringRoundTripTestCase(BaseTestCase):
    """Every string type survives its own segmented encoding.

    8.23.3 encodes a character string as if it were `[UNIVERSAL x] IMPLICIT
    OCTET STRING`, and 8.7.3.2 gives its fragments the universal OCTET STRING
    tag. A codec that segments on characters rather than octets, or that
    expects the outer tag back on a fragment, fails here and nowhere else in
    the suite: the value is unchanged either way, only the octets differ.
    """

    VALUES = (
        univ.OctetString(b"x" * 2500),
        char.PrintableString("x" * 3000),
        char.UTF8String("é" * 600),
        char.BMPString("x" * 1500),
        char.UniversalString("x" * 1500),
        useful.ObjectDescriptor("x" * 1200),
        # Two fragments' worth of bits, kept under the ~14285 that #98 makes
        # unprintable: the suite renders every debug record it emits.
        univ.BitString(binValue="1" * 12000),
    )

    def testRoundTripThroughEveryCodec(self):
        codecs = (
            (ber_encoder, ber_decoder),
            (cer_encoder, cer_decoder),
            (der_encoder, der_decoder),
        )

        for value in self.VALUES:
            for encoder, decoder in codecs:
                decoded, remainder = decoder.decode(encoder.encode(value))

                assert remainder == b"", (type(value).__name__, encoder.__name__)
                assert decoded == value, (type(value).__name__, encoder.__name__)

    def testCerSegmentsOnContentsOctets(self):
        for value in self.VALUES:
            substrate = cer_encoder.encode(value)

            assert substrate[0] & 0x20, type(value).__name__
            assert substrate[1] == 0x80, type(value).__name__

            # 8.6.4.1 tags bitstring fragments universal 3, 8.7.3.2 tags every
            # other string's fragments universal 4.
            expectedTag = 0x03 if isinstance(value, univ.BitString) else 0x04

            offset = 2
            sizes = []

            while substrate[offset : offset + 2] != b"\x00\x00":
                assert substrate[offset] == expectedTag, type(value).__name__

                offset += 1
                size = substrate[offset]

                if size & 0x80:
                    sizeOctets = size & 0x7F
                    size = int.from_bytes(
                        substrate[offset + 1 : offset + 1 + sizeOctets], "big"
                    )
                    offset += 1 + sizeOctets
                else:
                    offset += 1

                sizes.append(size)
                offset += size

            assert all(size == 1000 for size in sizes[:-1]), (
                type(value).__name__,
                sizes,
            )
            assert 1 <= sizes[-1] <= 1000, (type(value).__name__, sizes)

    def testMultiOctetCharactersTerminate(self):
        # Segmenting a BMPString or UniversalString on characters leaves every
        # chunk over the octet budget, so the encoder recurses without bound.
        for value in (char.BMPString("x" * 1500), char.UniversalString("x" * 1500)):
            depth = sys.getrecursionlimit()
            sys.setrecursionlimit(200)
            try:
                cer_encoder.encode(value)
            finally:
                sys.setrecursionlimit(depth)


class CanonicalTimeTestCase(BaseTestCase):
    """X.690 11.7 and 11.8 reduce the BER spellings of an instant to one.

    The invalid representations below are the specification's own examples.
    """

    GENERALIZED = 0x18
    UTC = 0x17

    def testGeneralizedTimeInvalidRepresentations(self):
        # 11.7: the examples given as invalid, plus the two forms 11.7.1 and
        # 11.7.2 rule out.
        for text in (
            "19920520240000Z",  # midnight represented incorrectly (11.7.5)
            "19920622123421.0Z",  # spurious trailing zeros (11.7.3)
            "19920722132100.30Z",  # spurious trailing zeros (11.7.3)
            "199206221234Z",  # seconds omitted (11.7.2)
            "19920622123421",  # no "Z" (11.7.1)
            "19920622123421+0200",  # not UTC (11.7.1)
            "19920622123421,5Z",  # comma for the point (11.7.4)
        ):
            for decode in (cer_decoder.decode, der_decoder.decode):
                self.assertRaises(
                    error.PyAsn1Error, decode, _time(self.GENERALIZED, text)
                )

    def testGeneralizedTimeValidRepresentations(self):
        for text in ("19920521000000Z", "19920622123421Z", "19920722132100.3Z"):
            value, _ = der_decoder.decode(_time(self.GENERALIZED, text))

            assert str(value) == text

    def testUtcTimeInvalidRepresentations(self):
        for text in (
            "920520240000Z",  # midnight represented incorrectly (11.8.3)
            "9207221321Z",  # seconds of "00" omitted (11.8.2)
            "920622123421",  # no "Z" (11.8.1)
            "920622123421.5Z",  # UTCTime carries no fractional seconds
        ):
            for decode in (cer_decoder.decode, der_decoder.decode):
                self.assertRaises(error.PyAsn1Error, decode, _time(self.UTC, text))

    def testUtcTimeValidRepresentations(self):
        for text in ("920521000000Z", "920622123421Z", "920722132100Z"):
            value, _ = der_decoder.decode(_time(self.UTC, text))

            assert str(value) == text

    def testBerRemainsTolerant(self):
        # Clause 11 binds CER and DER only, so BER keeps reading the lot.
        for text in ("199206221234Z", "19920520240000Z", "19920622123421.0Z"):
            value, _ = ber_decoder.decode(_time(self.GENERALIZED, text))

            assert str(value) == text

    def testEncoderNormalisesFractionalSeconds(self):
        # 11.7.3 gives these two conversions as examples: a seconds element
        # of "26.000" is represented as "26", and "26.5200" as "26.52".
        assert der_encoder.encode(
            useful.GeneralizedTime("19920622123426.000Z")
        ) == _time(self.GENERALIZED, "19920622123426Z")

        assert der_encoder.encode(
            useful.GeneralizedTime("19920622123426.5200Z")
        ) == _time(self.GENERALIZED, "19920622123426.52Z")

    def testEncoderRejectsMissingSeconds(self):
        self.assertRaises(
            error.PyAsn1Error,
            der_encoder.encode,
            useful.GeneralizedTime("199206221234Z"),
        )
        self.assertRaises(
            error.PyAsn1Error, der_encoder.encode, useful.UTCTime("9207221321Z")
        )

    def testEncoderRejectsHourTwentyFour(self):
        # 11.7.5 and 11.8.3: midnight is the zero hour of the following day.
        self.assertRaises(
            error.PyAsn1Error,
            der_encoder.encode,
            useful.GeneralizedTime("19920520240000Z"),
        )
        self.assertRaises(
            error.PyAsn1Error, der_encoder.encode, useful.UTCTime("920520240000Z")
        )

    def testMidnightAsZeroHourAccepted(self):
        assert der_encoder.encode(useful.GeneralizedTime("19920521000000Z")) == _time(
            self.GENERALIZED, "19920521000000Z"
        )


class IntegerMinimalOctetsTestCase(BaseTestCase):
    """X.690 8.3.2: given more than one contents octet, the bits of the first
    octet and bit 8 of the second shall not all be ones, nor all be zero.

    The note to 8.3.2 gives the intent: "These rules ensure that an integer
    value is always encoded in the smallest possible number of octets."

    8.3.2 sits in clause 8, so it binds BER too. pyasn1 enforces it only under
    CER and DER: rejecting padded integers in BER would break callers parsing
    output from encoders that pad, and the padded form decodes to an
    unambiguous value. The encoder never emits one under any codec.
    """

    #: (label, contents octets, value) -- each is the shortest encoding.
    MINIMAL = (
        ("zero", bytes((0x00,)), 0),
        ("one", bytes((0x01,)), 1),
        ("minus one", bytes((0xFF,)), -1),
        ("minus 128", bytes((0x80,)), -128),
        # 255 needs the leading zero: bit 8 of ff is set, so without it the
        # value would read as -1. 8.3.2 permits it because the two octets are
        # not all zero taken together with bit 8 of the second.
        ("255", bytes((0x00, 0xFF)), 255),
        ("minus 129", bytes((0xFF, 0x7F)), -129),
    )

    #: (label, contents octets) -- each pads a shorter encoding.
    NON_MINIMAL = (
        ("leading zero on 1", bytes((0x00, 0x01))),
        ("leading zero on 0", bytes((0x00, 0x00))),
        ("leading sign on -1", bytes((0xFF, 0xFF))),
        ("leading sign on -128", bytes((0xFF, 0x80))),
        ("two leading zeros", bytes((0x00, 0x00, 0x01))),
    )

    def testMinimalEncodingsAccepted(self):
        for label, contents, expected in self.MINIMAL:
            substrate = bytes((0x02, len(contents))) + contents

            for decode in (
                ber_decoder.decode,
                cer_decoder.decode,
                der_decoder.decode,
            ):
                value, _ = decode(substrate)
                assert value == expected, label

    def testNonMinimalRejectedUnderCerAndDer(self):
        for label, contents in self.NON_MINIMAL:
            substrate = bytes((0x02, len(contents))) + contents

            for decode in (cer_decoder.decode, der_decoder.decode):
                self.assertRaises(error.PyAsn1Error, decode, substrate)
                self.assertRaises(
                    error.PyAsn1Error,
                    decode,
                    substrate,
                    asn1Spec=univ.Integer(),
                )

    def testNonMinimalToleratedUnderBer(self):
        # The padded form is unambiguous, so BER keeps decoding it.
        for label, contents in self.NON_MINIMAL:
            substrate = bytes((0x02, len(contents))) + contents

            value, _ = ber_decoder.decode(substrate)
            assert value == int.from_bytes(contents, "big", signed=True), label

    def testEnumeratedFollowsIntegerRules(self):
        # 8.4: "The encoding of an enumerated value shall be that of the
        # integer value with which it is associated."
        substrate = bytes((0x0A, 0x02, 0x00, 0x01))

        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, substrate)
            self.assertRaises(
                error.PyAsn1Error, decode, substrate, asn1Spec=univ.Enumerated()
            )

        value, _ = ber_decoder.decode(substrate)
        assert value == 1

    def testEncoderNeverEmitsNonMinimal(self):
        # Every codec must produce the shortest form, so a value that
        # round-trips through DER survives its own strictness.
        for value in (0, 1, -1, 127, -128, 128, -129, 255, -256, 65535, -65536):
            for encode, decode in (
                (ber_encoder.encode, ber_decoder.decode),
                (cer_encoder.encode, cer_decoder.decode),
                (der_encoder.encode, der_decoder.decode),
            ):
                substrate = encode(univ.Integer(value))
                # der_decoder is the strict reader; feed every encoding to it.
                recovered, _ = der_decoder.decode(substrate)

                assert recovered == value, (value, substrate.hex())


class RealCanonicalFormTestCase(BaseTestCase):
    """X.690 11.3 admits one encoding per real value.

    11.3.1 fixes the binary form: base 2, a zero scaling factor, a mantissa
    that is zero or odd, and the fewest octets for M and E. 11.3.2 fixes the
    decimal form as ISO 6093 NR3 with a further six restrictions on its
    spelling.
    """

    #: (label, contents octets) -- binary forms 11.3.1 rules out.
    NON_CANONICAL_BINARY = (
        # 11.3.1: M shall be odd. 6 * 2^0 is 3 * 2^1 written wastefully.
        ("even mantissa", bytes((0x80, 0x00, 0x06))),
        # 11.3.1: "the binary scaling factor F shall be zero" (bits 4 to 3).
        ("non-zero scaling factor", bytes((0x84, 0x00, 0x03))),
        # 11.3.1: base 2 only. 8.5.7.2 spells base 8 as bits 6-5 = 01.
        ("base 8", bytes((0x90, 0x00, 0x03))),
        ("base 16", bytes((0xA0, 0x00, 0x03))),
        # 11.3.1: "M and E shall each be represented in the fewest octets."
        ("padded exponent", bytes((0x81, 0x00, 0x01, 0x03))),
        ("padded mantissa", bytes((0x80, 0x00, 0x00, 0x03))),
    )

    #: (label, contents octets) -- canonical, and must stay accepted.
    CANONICAL_BINARY = (
        ("three", bytes((0x80, 0x00, 0x03)), 3.0),
        ("six as 3 x 2^1", bytes((0x80, 0x01, 0x03)), 6.0),
        ("negative three", bytes((0xC0, 0x00, 0x03)), -3.0),
    )

    def testNonCanonicalBinaryRejectedUnderCerAndDer(self):
        for label, contents in self.NON_CANONICAL_BINARY:
            substrate = bytes((0x09, len(contents))) + contents

            for decode in (cer_decoder.decode, der_decoder.decode):
                self.assertRaises(error.PyAsn1Error, decode, substrate)
                self.assertRaises(
                    error.PyAsn1Error, decode, substrate, asn1Spec=univ.Real()
                )

            # BER is free to accept them, and does.
            ber_decoder.decode(substrate)

    def testCanonicalBinaryAccepted(self):
        for label, contents, expected in self.CANONICAL_BINARY:
            substrate = bytes((0x09, len(contents))) + contents

            for decode in (
                ber_decoder.decode,
                cer_decoder.decode,
                der_decoder.decode,
            ):
                value, _ = decode(substrate)
                assert float(value) == expected, label

    def testOnlyNr3AcceptedUnderCerAndDer(self):
        # 11.3.2.1: "The ISO 6093 NR3 form shall be used". 8.5.8 spells the
        # form in bits 6 to 1 of the first contents octet.
        nr1 = bytes((0x09, 0x04, 0x01)) + b"123"
        nr2 = bytes((0x09, 0x06, 0x02)) + b"1.234"

        for substrate in (nr1, nr2):
            for decode in (cer_decoder.decode, der_decoder.decode):
                self.assertRaises(error.PyAsn1Error, decode, substrate)
                self.assertRaises(
                    error.PyAsn1Error, decode, substrate, asn1Spec=univ.Real()
                )

            # BER accepts all three ISO 6093 forms.
            ber_decoder.decode(substrate)

        nr3 = bytes((0x09, 0x07, 0x03)) + b"15.E-1"
        for decode in (
            ber_decoder.decode,
            cer_decoder.decode,
            der_decoder.decode,
        ):
            value, _ = decode(nr3)
            assert float(value) == 1.5

    def testDecimalEncodingSpelling(self):
        # 11.3.2.5: the last mantissa digit is immediately followed by FULL
        # STOP, then the exponent-mark. 11.3.2.6: a zero exponent is written
        # "+0", and PLUS SIGN is not used otherwise.
        expected = {
            1.5: b"15.E-1",
            -0.75: b"-75.E-2",
            1.0: b"1.E+0",
            -1.0: b"-1.E+0",
        }

        for value, contents in expected.items():
            substrate = der_encoder.encode(univ.Real(value))

            assert substrate == bytes((0x09, len(contents) + 1, 0x03)) + contents, (
                value,
                substrate.hex(),
            )

    def testMantissaTrailingZeroMovedIntoExponent(self):
        # 11.3.2.4: "Neither the first nor the last digit of the mantissa may
        # be a 0."
        for value in (10.0, 100.0, 1e10):
            substrate = der_encoder.encode(univ.Real(value))
            mantissa = substrate[3:].split(b".")[0].lstrip(b"-")

            assert not mantissa.endswith(b"0"), substrate
            assert not mantissa.startswith(b"0"), substrate

            recovered, _ = der_decoder.decode(substrate)
            assert float(recovered) == value

    def testEncoderOutputSurvivesStrictReader(self):
        for value in (0.0, 1.0, -1.0, 1.5, -0.75, 3.0, 10.0, 1e10, 1e-10):
            for encode in (cer_encoder.encode, der_encoder.encode):
                substrate = encode(univ.Real(value))
                recovered, _ = der_decoder.decode(substrate)

                assert float(recovered) == value, (value, substrate.hex())

    def testSpecialValuesUnaffected(self):
        # 8.5.9 encodings are a single octet and carry no canonical variants.
        for octet, expected in ((0x40, "inf"), (0x41, "-inf")):
            substrate = bytes((0x09, 0x01, octet))
            value, _ = der_decoder.decode(substrate)

            assert str(float(value)) == expected


class RealRoundTripTestCase(BaseTestCase):
    """A REAL must survive a trip through every codec unchanged.

    X.690 8.5.8 writes a base 10 value as an ISO 6093 field, which is a
    string of digits, so the mantissa has to stay an integer. It used to be
    divided down with true division, which made it a float, and a float whose
    repr uses exponent notation rendered as a nested exponent: 1e300 encoded
    as "1e+299E1", which no decoder can read back.

    The decomposition was also lossy. Multiplying by ten until the value came
    out whole accumulated binary rounding error, and near the bottom of the
    double range it lost the value outright.
    """

    # Named so a failure says which magnitude broke.
    VALUES = (
        ("zero", 0.0),
        ("one", 1.0),
        ("half", 0.5),
        ("negative", -1.5),
        ("hundred", 100.0),
        ("recurring", 1 / 3),
        ("negative recurring", -4.1),
        # Large exponents, where a float mantissa starts rendering as "1e+299".
        ("large", 1e300),
        ("largest double", 1.7976931348623157e308),
        ("small", 1e-300),
        # Subnormals: below the smallest normal double, where 10 ** exponent
        # has already underflowed to zero.
        ("smallest normal", 2.2250738585072014e-308),
        ("subnormal", 1e-320),
        ("smallest subnormal", 5e-324),
    )

    CODECS = (
        ("ber", ber_encoder, ber_decoder),
        ("cer", cer_encoder, cer_decoder),
        ("der", der_encoder, der_decoder),
    )

    def testRoundTrip(self):
        for name, value in self.VALUES:
            for codec, encode, decode in self.CODECS:
                with self.subTest(name, codec=codec, value=value):
                    substrate = encode.encode(univ.Real(value))
                    decoded, rest = decode.decode(substrate, asn1Spec=univ.Real())

                    self.assertEqual(rest, b"")
                    self.assertEqual(float(decoded), value)

    def testFloatParity(self):
        # Real duck-types float, so the value it holds must be the value
        # float() would hold, not one rounded on the way in.
        for name, value in self.VALUES:
            with self.subTest(name, value=value):
                self.assertEqual(float(univ.Real(value)), value)

    def testMantissaStaysAnInteger(self):
        for name, value in self.VALUES:
            with self.subTest(name, value=value):
                mantissa, base, exponent = tuple(univ.Real(value))

                self.assertIsInstance(mantissa, int)
                self.assertIsInstance(exponent, int)
                self.assertEqual(base, 10)

    def testCharacterFormIsWellFormed(self):
        # X.690 8.5.8: the contents octets after the first form an ISO 6093
        # field. "1e+299E1" is not one.
        for name, value in self.VALUES:
            if not value:
                continue

            with self.subTest(name, value=value):
                substrate = ber_encoder.encode(univ.Real(value))
                firstOctet = substrate[2]

                # Bits 8 to 7 zero selects the decimal encoding.
                self.assertEqual(firstOctet & 0xC0, 0)

                field = substrate[3:].decode("ascii")
                mantissa, _, exponent = field.partition("E")

                self.assertNotIn("e", field)
                self.assertNotIn(" ", field)
                float(field)
                int(mantissa.replace(".", "") or "0")
                int(exponent)

    def testReservedNumberFormRejected(self):
        # X.690 8.5.8: bits 6 to 1 choose the ISO 6093 form, and every value
        # other than 1, 2 and 3 is "reserved for further editions". Only the
        # low two bits used to be looked at, so 000101 read as NR1.
        substrate = bytes((0x09, 0x04, 0x05)) + b"1E0"

        self.assertRaises(
            error.PyAsn1Error,
            ber_decoder.decode,
            substrate,
            asn1Spec=univ.Real(),
        )

    def testNumberFormGrammarEnforced(self):
        # X.690 8.5.8 has the sender name the ISO 6093 form in bits 6 to 1 and
        # then encode "according to ISO 6093", so the octets are held to the
        # form they declare. Decimal on its own reads all of these.
        rejected = (
            # NR1 is an integer: no decimal mark, no exponent.
            (0x01, b"1.5"),
            (0x01, b"1E2"),
            # Python's own int() reads "1_0" as 10. ISO 6093 does not.
            (0x01, b"1_0"),
            # NR2 carries a decimal mark but no exponent.
            (0x02, b"1E2"),
            (0x02, b"15"),
            # NR3 requires both.
            (0x03, b"15E-1"),
            (0x03, b"1.5"),
            # None of the three has a spelling for a special value, which
            # 8.5.9 gives a single contents octet of its own.
            (0x02, b"NaN"),
            (0x03, b"Infinity"),
            (0x01, b"-Infinity"),
            # Padding is SPACE; a tab or a newline is not an ISO 6093 field.
            (0x01, b"\t15"),
            (0x03, b"1.5E1\n"),
        )

        for numberForm, field in rejected:
            with self.subTest(numberForm=numberForm, field=field):
                substrate = bytes((0x09, len(field) + 1, numberForm)) + field

                self.assertRaises(
                    error.PyAsn1Error,
                    ber_decoder.decode,
                    substrate,
                    asn1Spec=univ.Real(),
                )

    def testNumberFormGrammarAccepts(self):
        accepted = (
            (0x01, b"15", (15, 10, 0)),
            (0x01, b"-15", (-15, 10, 0)),
            # 8.5.8 NOTE 1 leaves a digit left of the mark optional.
            (0x02, b".5", (5, 10, -1)),
            (0x02, b"15.", (15, 10, 0)),
            (0x03, b"15.E-1", (15, 10, -1)),
            (0x03, b"1.5E1", (15, 10, 0)),
            # ISO 6093 fields are padded to a width the sender chooses.
            (0x01, b"  15  ", (15, 10, 0)),
        )

        for numberForm, field, expected in accepted:
            with self.subTest(numberForm=numberForm, field=field):
                substrate = bytes((0x09, len(field) + 1, numberForm)) + field
                decoded, _ = ber_decoder.decode(substrate, asn1Spec=univ.Real())

                self.assertEqual(tuple(decoded), expected)

    def testCommaDecimalMark(self):
        # ISO 6093 admits either a comma or a full stop as the decimal mark.
        substrate = bytes((0x09, 0x06, 0x03)) + b"1,5E0"

        decoded, _ = ber_decoder.decode(substrate, asn1Spec=univ.Real())

        self.assertEqual(float(decoded), 1.5)

    def testExponentBeyondDoubleRange(self):
        # A value built from a tuple need not be a representable double. It
        # still has to survive the codecs, and its mantissa still has to be
        # written as digits.
        value = univ.Real((1, 10, 5000))

        for codec, encode, decode in self.CODECS:
            with self.subTest(codec=codec):
                decoded, rest = decode.decode(
                    encode.encode(value), asn1Spec=univ.Real()
                )

                self.assertEqual(rest, b"")
                self.assertEqual(tuple(decoded), (1, 10, 5000))


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


class TaggedIntegerMinimalEncodingTestCase(BaseTestCase):
    """X.690 8.3.2 binds the contents octets, which an IMPLICIT tag does not touch.

    X.690 8.14.3: implicit tagging replaces the tag octets and leaves the
    contents octets alone. So a tagged INTEGER must carry exactly the contents
    of the untagged one -- including the leading zero octet that keeps a
    positive value with bit 8 set from reading as negative.

    Reported (pyasn1/pyasn1#87) as a spurious leading ``00`` on a 32-octet
    positive value, with ``82 20 ff...ff`` given as the expected encoding.
    That encoding denotes -1: 8.3.2 requires the ``00``, and dropping it would
    change the value rather than shorten it.
    """

    class TaggedInteger(univ.Integer):
        tagSet = univ.Integer.tagSet.tagImplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x02)
        )

    def testContentsOctetsMatchTheUntaggedEncoding(self):
        # The untagged encoding is already pinned as minimal over this range by
        # IntegerMinimalEncodingTestCase, so equality here carries minimality
        # onto the tagged path without re-deriving it.
        values = list(range(-70000, 70000, 13))
        values += [0, 1, 127, 128, 255, 256, 65535, -1, -128, -129, -32768]
        values += [0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 1 << 256, -(1 << 256)]

        for value in values:
            for encode in (ber_encoder.encode, cer_encoder.encode, der_encoder.encode):
                # Strip the identifier octet from each; the length and contents
                # octets that follow must be identical.
                tagged = encode(self.TaggedInteger(value))[1:]
                untagged = encode(univ.Integer(value))[1:]

                assert tagged == untagged, (
                    f"{value}: tagged {tagged.hex()} != untagged {untagged.hex()}"
                )

    def testPositiveValueWithBitEightSetKeepsItsLeadingZero(self):
        # The reported case. 82 21 00 ff... , not 82 20 ff... .
        value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        substrate = der_encoder.encode(self.TaggedInteger(value))

        assert substrate == bytes.fromhex("822100" + "ff" * 32)

    def testTheReportedExpectationDenotesMinusOne(self):
        # 82 20 ff...ff does not shorten the value, it changes it. Under BER,
        # which tolerates non-minimal contents, it reads as -1.
        substrate = bytes.fromhex("8220" + "ff" * 32)

        decoded, rest = ber_decoder.decode(substrate, asn1Spec=self.TaggedInteger())

        assert rest == b""
        assert decoded == -1

    def testTheReportedExpectationIsRejectedUnderDer(self):
        # And under DER it is not even well formed: 32 octets of ff is a
        # non-minimal encoding of -1, which 8.3.2 a) forbids outright.
        self.assertRaises(
            error.PyAsn1Error,
            der_decoder.decode,
            bytes.fromhex("8220" + "ff" * 32),
            asn1Spec=self.TaggedInteger(),
        )

    def testTaggedValuesRoundTrip(self):
        for value in (-32769, -129, -128, -1, 0, 127, 128, 255, 32767, 1 << 256):
            substrate = der_encoder.encode(self.TaggedInteger(value))

            assert (
                der_decoder.decode(substrate, asn1Spec=self.TaggedInteger())[0] == value
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

    def testEmptyBitStringMustHaveZeroInitialOctet(self):
        # 8.6.2.3: "If the bitstring is empty, there shall be no subsequent
        # octets, and the initial octet shall be zero." A non-zero count with
        # no octets to take the bits from is unsatisfiable.
        for unusedBits in range(1, 8):
            self.assertRaises(
                error.PyAsn1Error,
                ber_decoder.decode,
                bytes((0x03, 0x01, unusedBits)),
            )

    def testEmptyBitStringWithZeroInitialOctetAccepted(self):
        value, _ = ber_decoder.decode(bytes((0x03, 0x01, 0x00)))

        assert value == univ.BitString(())

    def testEmptySegmentInConstructedFormRejected(self):
        # Each fragment of a constructed bitstring is itself a primitive
        # bitstring, so 8.6.2.3 binds the fragments too.
        self.assertRaises(
            error.PyAsn1Error,
            ber_decoder.decode,
            bytes((0x23, 0x03, 0x03, 0x01, 0x03)),
        )


class MalformedPrimitiveTestCase(BaseTestCase):
    """Encodings clause 8 makes structurally impossible.

    These are rejected in BER as well as CER and DER: the restriction is in
    the base encoding rules, and no tolerant reading of the octets exists.
    """

    def testZeroLengthIntegerRejected(self):
        # 8.3.1: "The contents octets shall consist of one or more octets."
        self.assertRaises(error.PyAsn1Error, ber_decoder.decode, bytes((0x02, 0x00)))

    def testZeroLengthEnumeratedRejected(self):
        # 8.4: an enumerated value is encoded as the integer value, so 8.3.1
        # carries over.
        self.assertRaises(error.PyAsn1Error, ber_decoder.decode, bytes((0x0A, 0x00)))

    def testSingleOctetIntegerZeroAccepted(self):
        value, _ = ber_decoder.decode(bytes((0x02, 0x01, 0x00)))

        assert value == univ.Integer(0)

    def testZeroLengthBooleanRejected(self):
        # 8.2.1: "The contents octets shall consist of a single octet."
        self.assertRaises(error.PyAsn1Error, ber_decoder.decode, bytes((0x01, 0x00)))

    def testMultiOctetBooleanRejected(self):
        self.assertRaises(
            error.PyAsn1Error, ber_decoder.decode, bytes((0x01, 0x02, 0xFF, 0xFF))
        )

    def testSingleOctetBooleanAccepted(self):
        # 8.2.2 leaves the non-zero octet to the sender, so BER takes any of
        # them as TRUE.
        for octet in (0x01, 0x7F, 0xFF):
            value, _ = ber_decoder.decode(bytes((0x01, 0x01, octet)))
            assert value == univ.Boolean(1)

        value, _ = ber_decoder.decode(bytes((0x01, 0x01, 0x00)))
        assert value == univ.Boolean(0)

    def testZeroLengthRealIsZero(self):
        # 8.5.2 is the exception that proves the rule: a real value of zero
        # is the one primitive with no contents octets at all.
        value, _ = ber_decoder.decode(bytes((0x09, 0x00)))

        assert value == univ.Real(0.0)


class BitStringUnusedBitsTestCase(BaseTestCase):
    """X.690 11.2.1: "Each unused bit in the final octet of the encoding of a
    bit string value shall be set to zero."

    BER leaves those bits to the sender (8.6.2 says nothing about them), so
    the same abstract value has several BER spellings. CER and DER admit one.
    """

    def testNonZeroUnusedBitsRejected(self):
        # 05 unused bits, final octet a1: bit 1 is set inside the padding.
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(
                error.PyAsn1Error, decode, bytes((0x03, 0x02, 0x05, 0xA1))
            )

    def testAllPaddingBitsChecked(self):
        # One unused bit, and it is the only thing wrong with the octet.
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(
                error.PyAsn1Error, decode, bytes((0x03, 0x02, 0x01, 0xFF))
            )

    def testZeroUnusedBitsAccepted(self):
        value, _ = der_decoder.decode(bytes((0x03, 0x02, 0x05, 0xA0)))

        assert value == univ.BitString(binValue="101")

    def testBerStillTolerant(self):
        # The restriction is in clause 11, so BER keeps accepting both
        # spellings and reads the same value from each.
        lax, _ = ber_decoder.decode(bytes((0x03, 0x02, 0x05, 0xA1)))
        canonical, _ = ber_decoder.decode(bytes((0x03, 0x02, 0x05, 0xA0)))

        assert lax == canonical == univ.BitString(binValue="101")

    def testEncoderEmitsZeroPadding(self):
        # The encoder is already canonical; this pins it so the decoder
        # restriction cannot be satisfied by accident.
        assert der_encoder.encode(univ.BitString(binValue="101")) == bytes(
            (0x03, 0x02, 0x05, 0xA0)
        )
        assert der_encoder.encode(univ.BitString(binValue="1")) == bytes(
            (0x03, 0x02, 0x07, 0x80)
        )

    def testFullFinalOctetHasNoPadding(self):
        # Nothing to check when the count is zero, whatever the octet holds.
        value, _ = der_decoder.decode(bytes((0x03, 0x02, 0x00, 0xFF)))

        assert value == univ.BitString(binValue="11111111")


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


class LengthFormTestCase(BaseTestCase):
    """X.690 10.1: DER uses the definite length form in the minimum number of
    octets. 9.1: CER uses the fewest length octets for a primitive encoding
    and the indefinite form for a constructed one. BER leaves the octet count
    to the sender per the note to 8.1.3.5."""

    # INTEGER 5 with the length spelled three ways.
    minimal = bytes((0x02, 0x01, 0x05))
    longForm = bytes((0x02, 0x81, 0x01, 0x05))
    paddedLongForm = bytes((0x02, 0x82, 0x00, 0x01, 0x05))

    def testMinimalFormAcceptedEverywhere(self):
        for decode in (ber_decoder.decode, cer_decoder.decode, der_decoder.decode):
            value, _ = decode(self.minimal)
            assert value == 5

    def testLongFormForSmallLengthRejectedUnderCerAndDer(self):
        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, self.longForm)
            self.assertRaises(error.PyAsn1Error, decode, self.paddedLongForm)

    def testLongFormToleratedUnderBer(self):
        # The note to 8.1.3.5 makes the octet count a sender's option, so
        # neither spelling is an error under BER.
        for substrate in (self.longForm, self.paddedLongForm):
            value, _ = ber_decoder.decode(substrate)
            assert value == 5

    def testPaddedLongFormRejectedAtEveryWidth(self):
        # 201 octets of contents needs exactly one length octet, so the
        # two-octet spelling is non-minimal even though the short form is
        # unavailable.
        contents = b"\x00" * 201
        minimal = bytes((0x04, 0x81, 0xC9)) + contents
        padded = bytes((0x04, 0x82, 0x00, 0xC9)) + contents

        value, _ = der_decoder.decode(minimal)
        assert value == univ.OctetString(contents)

        self.assertRaises(error.PyAsn1Error, der_decoder.decode, padded)

    def testReservedLengthOctetRejected(self):
        # 8.1.3.5 c): the value 11111111 shall not be used. This holds under
        # BER too, since no sender's option covers it.
        for decode in (ber_decoder.decode, cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, bytes((0x02, 0xFF, 0x01)))

    def testCerRequiresIndefiniteFormForConstructed(self):
        definite = bytes((0x30, 0x03, 0x02, 0x01, 0x05))
        indefinite = bytes((0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00))

        self.assertRaises(error.PyAsn1Error, cer_decoder.decode, definite)

        value, _ = cer_decoder.decode(indefinite)
        assert value[0] == 5

    def testDerRequiresDefiniteFormForConstructed(self):
        definite = bytes((0x30, 0x03, 0x02, 0x01, 0x05))
        indefinite = bytes((0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00))

        value, _ = der_decoder.decode(definite)
        assert value[0] == 5

        self.assertRaises(error.PyAsn1Error, der_decoder.decode, indefinite)

    def testEncodersEmitMinimalLengths(self):
        # 127 contents octets is the last length the short form reaches.
        for size in (0, 1, 127, 128, 255, 256):
            substrate = der_encoder.encode(univ.OctetString(b"x" * size))

            if size < 128:
                assert substrate[1] == size, f"{size} should use the short form"
            else:
                sizeOctets = substrate[1] & 0x7F
                assert substrate[1] & 0x80, f"{size} should use the long form"
                assert sizeOctets == (size.bit_length() + 7) // 8


class TagFormTestCase(BaseTestCase):
    """X.690 8.1.2.2: tags from 0 to 30 occupy a single identifier octet.
    8.1.2.4.2 c): bits 7 to 1 of the first subsequent octet of a high tag
    number shall not all be zero."""

    def testLowTagNumberFormAcceptedEverywhere(self):
        for decode in (ber_decoder.decode, cer_decoder.decode, der_decoder.decode):
            value, _ = decode(bytes((0x02, 0x01, 0x05)))
            assert value == 5

    def testHighTagNumberFormForSmallTagRejectedUnderCerAndDer(self):
        # Tag 2 spelled the long way. It decodes to the same tag as 0x02, so
        # accepting it admits two encodings of one value.
        substrate = bytes((0x1F, 0x02, 0x01, 0x05))

        for decode in (cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, substrate)

    def testHighTagNumberFormForSmallTagToleratedUnderBer(self):
        value, _ = ber_decoder.decode(bytes((0x1F, 0x02, 0x01, 0x05)))
        assert value == 5

    def testPaddedTagNumberRejectedEverywhere(self):
        # 8.1.2.4.2 c) admits no sender's option, so the padding is invalid
        # under BER as well.
        substrate = bytes((0x1F, 0x80, 0x02, 0x01, 0x05))

        for decode in (ber_decoder.decode, cer_decoder.decode, der_decoder.decode):
            self.assertRaises(error.PyAsn1Error, decode, substrate)

    def testHighTagNumberFormAcceptedForLargeTag(self):
        # Tag 31 is the smallest that needs the high tag number form.
        largeTag = univ.Integer(5).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 31)
        )
        substrate = der_encoder.encode(largeTag)

        assert substrate == bytes((0x9F, 0x1F, 0x01, 0x05))

        value, _ = der_decoder.decode(substrate, asn1Spec=largeTag)
        assert value == 5

    def testEncodersNeverEmitHighTagNumberFormForSmallTag(self):
        for tagId in range(31):
            asn1Object = univ.Integer(5).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagId)
            )
            substrate = der_encoder.encode(asn1Object)

            assert substrate[0] & 0x1F != 0x1F, f"tag {tagId} took the long form"


class EncoderPurityTestCase(BaseTestCase):
    """Encoding must not alter the object being encoded (see issue #112).

    X.690 11.5 requires DER and CER to omit a component equal to its DEFAULT
    value, and BER permits it, so an absent DEFAULT component contributes
    nothing to the octets either way. Materialising one while encoding is
    therefore pure side effect: it changes which components the caller's
    object reports as present, and does so silently.
    """

    def setUp(self):
        BaseTestCase.setUp(self)

        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
                namedtype.OptionalNamedType("nick", univ.OctetString()),
            )
        )

    def _value(self):
        value = self.s.clone()
        value["name"] = "abc"
        return value

    @staticmethod
    def _presence(value):
        return [
            value.getComponentByPosition(idx, instantiate=False) is not univ.noValue
            for idx in range(3)
        ]

    def testBerEncodeLeavesComponentsAbsent(self):
        value = self._value()

        ber_encoder.encode(value)

        assert self._presence(value) == [True, False, False]

    def testCerEncodeLeavesComponentsAbsent(self):
        value = self._value()

        cer_encoder.encode(value)

        assert self._presence(value) == [True, False, False]

    def testDerEncodeLeavesComponentsAbsent(self):
        value = self._value()

        der_encoder.encode(value)

        assert self._presence(value) == [True, False, False]

    def testNativeEncodeLeavesComponentsAbsent(self):
        value = self._value()

        native_encoder.encode(value)

        assert self._presence(value) == [True, False, False]

    def testEncodingIsUnchanged(self):
        # X.690 11.5: the absent DEFAULT component is omitted, as before.
        assert ber_encoder.encode(self._value()) == bytes.fromhex("30050403616263")
        assert der_encoder.encode(self._value()) == bytes.fromhex("30050403616263")

    def testRepeatedEncodingIsStable(self):
        value = self._value()

        for encode in (ber_encoder.encode, cer_encoder.encode, der_encoder.encode):
            assert encode(value) == encode(value)

    def testNativeEncodingCarriesDefaultValue(self):
        # The native codec produces a Python mapping rather than octets, so a
        # DEFAULT component belongs in the output even when absent.
        assert native_encoder.encode(self._value()) == {"name": b"abc", "age": 33}

    def testExplicitlySetDefaultValueStillOmitted(self):
        # X.690 11.5 applies to the value, not to how it was set.
        value = self._value()
        value["age"] = 33

        assert der_encoder.encode(value) == bytes.fromhex("30050403616263")

    def testNonDefaultValueIsEncoded(self):
        value = self._value()
        value["age"] = 34

        assert der_encoder.encode(value) == bytes.fromhex("30080403616263020122")

    def testChoiceEncodesOnlyTheSetAlternative(self):
        c = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("number", univ.Integer()),
                namedtype.NamedType("string", univ.OctetString()),
            )
        )
        value = c.clone()
        value["number"] = 7

        assert native_encoder.encode(value) == {"number": 7}
        assert der_encoder.encode(value) == bytes.fromhex("020107")


class PresentButEmptyOptionalTestCase(BaseTestCase):
    """A present OPTIONAL component is encoded even if empty (see issue #119).

    X.690 11.5 restricts DER and CER to omitting a component whose value
    equals its DEFAULT value. Nothing licenses omitting an OPTIONAL component
    that is present, and 'present with empty contents' is a different abstract
    value from 'absent' -- a SEQUENCE all of whose components are DEFAULT and
    equal to their defaults encodes as ``30 00``, which is a value, not a
    space.
    """

    @staticmethod
    def _innerType():
        return univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.DefaultedNamedType("m", univ.Integer(1))
            )
        )

    def _sequenceValue(self):
        inner = self._innerType()

        outer = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.OptionalNamedType("opt", inner),
            )
        )

        value = outer.clone()
        value["id"] = 7
        value["opt"] = inner.clone()
        value["opt"]["m"] = 1  # equals the default, so the inner encodes 30 00

        return outer, value

    def testSequenceKeepsAPresentEmptyOptional(self):
        _, value = self._sequenceValue()

        for encode in (ber_encoder.encode, der_encoder.encode):
            assert encode(value) == bytes.fromhex("30050201073000"), encode

    def testSetKeepsAPresentEmptyOptional(self):
        inner = self._innerType()

        outer = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.OptionalNamedType("opt", inner),
            )
        )

        value = outer.clone()
        value["id"] = 7
        value["opt"] = inner.clone()
        value["opt"]["m"] = 1

        for encode in (ber_encoder.encode, der_encoder.encode):
            assert encode(value) == bytes.fromhex("31050201073000"), encode

    def testAbsentOptionalIsStillOmitted(self):
        outer, _ = self._sequenceValue()

        value = outer.clone()
        value["id"] = 7

        for encode in (ber_encoder.encode, der_encoder.encode):
            assert encode(value) == bytes.fromhex("3003020107"), encode

        # X.690 9.1: CER uses the indefinite length form for constructed types.
        assert cer_encoder.encode(value) == bytes.fromhex("30800201070000")

    def testDefaultEqualToItsDefaultIsStillOmitted(self):
        # X.690 11.5, the rule that does apply here.
        inner = self._innerType()

        value = inner.clone()
        value["m"] = 1

        assert der_encoder.encode(value) == bytes.fromhex("3000")

    def testOpenTypeRoundTripPreservesTheEmptySequence(self):
        # The reported case: the empty SEQUENCE is the open-type value of an
        # OPTIONAL ANY, and re-encoding after decodeOpenTypes dropped it.
        oid = univ.ObjectIdentifier((1, 2, 410, 200046, 1, 2))

        inner = self._innerType()

        algorithmIdentifier = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
                namedtype.OptionalNamedType(
                    "parameters",
                    univ.Any(),
                    openType=opentype.OpenType("algorithm", {oid: inner}),
                ),
            )
        )

        parameters = inner.clone()
        parameters["m"] = 1

        value = algorithmIdentifier.clone()
        value["algorithm"] = oid
        value["parameters"] = univ.Any(der_encoder.encode(parameters))

        substrate = der_encoder.encode(value)

        assert substrate == bytes.fromhex("300c06082a831a8c9a6e01023000")

        decoded, rest = der_decoder.decode(
            substrate, asn1Spec=algorithmIdentifier.clone(), decodeOpenTypes=True
        )

        assert rest == b""
        assert der_encoder.encode(decoded) == substrate


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
