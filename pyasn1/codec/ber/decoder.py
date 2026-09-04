#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""BER decoder for ASN.1 types."""

import decimal
import logging
import re
from typing import Any, Final, cast

from pyasn1 import debug, error
from pyasn1.codec.ber import eoo
from pyasn1.type import base, char, tag, tagmap, univ, useful

__all__ = ["decode"]

LOG = logging.getLogger(__name__)
noValue: Final = base.noValue
# Maximum recursion depth for nested SEQUENCE/SET structures.
# Prevents unbounded recursion DoS (same fix as CVE-2026-30922 /
# GHSA-jr27-m4p2-rc6r in mainline pyasn1, ported here).
MAX_NESTING_DEPTH: Final = 100

# X.690 8.19.2 does not bound the number of octets making up a single OBJECT
# IDENTIFIER subidentifier, so a short substrate can encode an arc with an
# arbitrary number of bits. 20 continuation octets carry 140 bits of arc,
# which no registered OID comes close to using.
# (CVE-2026-23490 / GHSA-x5q7-9jj9-jw8m in mainline pyasn1, ported here.)
MAX_OID_ARC_CONTINUATION_OCTETS: Final = 20

# X.690 8.1.2.4.2 likewise leaves the high-tag-number form unbounded. The same
# 140-bit ceiling applies; real tag numbers are orders of magnitude smaller.
# (CVE-2026-59884 / GHSA-9j8v-p6qm-c2xq in mainline pyasn1, ported here.)
MAX_TAG_OCTETS: Final = 20

# X.690 8.1.3.5 permits up to 126 subsequent length octets. 8 octets already
# describe a 2**64-octet value, which no substrate can satisfy, so longer
# length fields are rejected rather than accumulated into a huge integer.
MAX_LENGTH_OCTETS: Final = 8


class AbstractDecoder:
    protoComponent: Any = None

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        raise error.PyAsn1Error("Decoder not implemented", tagSet=tagSet)

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        raise error.PyAsn1Error(
            "Indefinite length mode decoder not implemented", tagSet=tagSet
        )


class AbstractSimpleDecoder(AbstractDecoder):
    @staticmethod
    def substrateCollector(asn1Object: Any, substrate: bytes, length: int) -> Any:
        return substrate[:length], substrate[length:]

    def _createComponent(
        self, asn1Spec: Any, tagSet: Any, value: Any, **options: Any
    ) -> Any:
        if options.get("native"):
            return value
        elif asn1Spec is None:
            return self.protoComponent.clone(value, tagSet=tagSet)
        elif value is noValue:
            return asn1Spec
        else:
            return asn1Spec.clone(value)


class ExplicitTagDecoder(AbstractSimpleDecoder):
    """Decode a non-universal constructed tag guessed to be an explicit tag.

    Nothing on the wire distinguishes IMPLICIT from EXPLICIT tagging, so
    without an `asn1Spec` the decoder has to guess. The guess is refutable
    though: X.690 8.14.2 makes the contents octets of an explicitly tagged
    value the complete encoding of exactly one value, so content holding
    more than one encoding can only be an implicit tag over a constructed
    type. Both entry points fall back to that reading rather than dropping
    the components that do not fit.
    """

    protoComponent = univ.Any("")

    @staticmethod
    def _decodeAsConstructed(
        substrate: bytes, tagSet: Any, decodeFun: Any, **options: Any
    ) -> tuple[Any, bytes]:
        """Decode *substrate* as the content of an implicitly tagged type."""
        # Reuses the universal constructed decoder so the container type is
        # guessed exactly as it would be for an untagged SEQUENCE.
        constructedDecoder = cast(
            "UniversalConstructedTypeDecoder", tagMap[univ.Sequence.tagSet]
        )

        return constructedDecoder._decodeComponents(
            substrate, tagSet=tagSet, decodeFun=decodeFun, **options
        )

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, "", **options),
                substrate,
                length,
            )

        head, tail = substrate[:length], substrate[length:]

        value, trailing = decodeFun(head, asn1Spec, tagSet, length, **options)

        if trailing:
            # X.690 8.14.2: the contents octets of an explicitly tagged value
            # are the complete encoding of exactly one value. Anything left
            # over refutes the explicit-tag guess this codec was chosen on,
            # so read the content as an implicit tag over a constructed type
            # rather than discarding the remaining components.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "explicit tag guess refuted by trailing payload, "
                    "decoding as an implicitly tagged constructed value",
                    extra={"trailing": trailing},
                )

            asn1Object, _ = self._decodeAsConstructed(
                head, tagSet, decodeFun, **options
            )

            return asn1Object, tail

        return value, tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, "", **options),
                substrate,
                length,
            )

        originalSubstrate = substrate

        value, substrate = decodeFun(substrate, asn1Spec, tagSet, length, **options)

        eooMarker, substrate = decodeFun(substrate, allowEoo=True, **options)

        if eooMarker is eoo.endOfOctets:
            return value, substrate

        # Content beyond the first value refutes the explicit-tag guess
        # (X.690 8.14.2); read it as an implicitly tagged constructed value.
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "explicit tag guess refuted by a missing end-of-octets "
                "terminator, decoding as an implicitly tagged constructed value"
            )

        # allowEoo lets _decodeComponents recognise the terminator that closes
        # this indefinite-length container rather than choking on it.
        return self._decodeAsConstructed(
            originalSubstrate, tagSet, decodeFun, **dict(options, allowEoo=True)
        )


explicitTagDecoder: Final = ExplicitTagDecoder()


class IntegerDecoder(AbstractSimpleDecoder):
    protoComponent = univ.Integer(0)

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error("Simple tag format expected")

        head, tail = substrate[:length], substrate[length:]

        if not head:
            raise error.PyAsn1Error(
                "INTEGER contents octets shall consist of one or more octets",
                tagSet=tagSet,
            )

        value = int.from_bytes(head, "big", signed=True)

        return self._createComponent(asn1Spec, tagSet, value, **options), tail


class BooleanDecoder(IntegerDecoder):
    protoComponent = univ.Boolean(0)

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        # X.690 8.2.1: the contents octets of a boolean shall consist of a
        # single octet. Any other count is not a tolerable BOOLEAN.
        if length != 1:
            raise error.PyAsn1Error(
                "BOOLEAN contents octets shall consist of a single octet",
                length=length,
            )

        return IntegerDecoder.valueDecoder(
            self,
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    def _createComponent(
        self, asn1Spec: Any, tagSet: Any, value: Any, **options: Any
    ) -> Any:
        return IntegerDecoder._createComponent(
            self, asn1Spec, tagSet, int(bool(value)), **options
        )


class BitStringDecoder(AbstractSimpleDecoder):
    protoComponent = univ.BitString(())
    supportConstructedForm = True

    # 8.6.4.1: "the tags in the contents octets are always universal class,
    # number 3", which is the prototype's own tag.
    fragmentComponent = univ.BitString(())

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        head, tail = substrate[:length], substrate[length:]

        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, noValue, **options),
                substrate,
                length,
            )

        if not head:
            raise error.PyAsn1Error("Empty BIT STRING substrate")

        if tagSet[0].tagFormat == tag.tagFormatSimple:  # XXX what tag to check?
            trailingBits = head[0]
            if trailingBits > 7:
                raise error.PyAsn1Error(
                    "Trailing bits overflow", trailingBits=trailingBits
                )

            # X.690 8.6.2.3: an empty bitstring has no subsequent octets and a
            # zero initial octet, so a non-zero count with nothing to take the
            # bits from cannot be satisfied.
            if len(head) == 1 and trailingBits:
                raise error.PyAsn1Error(
                    "Empty BIT STRING must carry a zero initial octet",
                    trailingBits=trailingBits,
                )

            value = self.protoComponent.fromOctetString(
                head[1:], internalFormat=True, padding=trailingBits
            )

            return self._createComponent(asn1Spec, tagSet, value, **options), tail

        if not self.supportConstructedForm:
            raise error.PyAsn1Error(
                "Constructed encoding form prohibited",
                decoder=self.__class__.__name__,
            )

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("assembling constructed serialization")

        # All inner fragments are of the same type, treat them as octet string
        substrateFun = self.substrateCollector

        bitString = self.protoComponent.fromOctetString(b"", internalFormat=True)

        while head:
            component, head = decodeFun(
                head, self.protoComponent, substrateFun=substrateFun, **options
            )

            trailingBits = component[0]
            if trailingBits > 7:
                raise error.PyAsn1Error(
                    "Trailing bits overflow", trailingBits=trailingBits
                )

            if len(component) == 1 and trailingBits:
                raise error.PyAsn1Error(
                    "Empty BIT STRING segment must carry a zero initial octet",
                    trailingBits=trailingBits,
                )

            bitString = self.protoComponent.fromOctetString(
                component[1:],
                internalFormat=True,
                prepend=bitString,
                padding=trailingBits,
            )

        return self._createComponent(asn1Spec, tagSet, bitString, **options), tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, noValue, **options),
                substrate,
                length,
            )

        # All inner fragments are of the same type, treat them as octet string
        substrateFun = self.substrateCollector

        bitString = self.protoComponent.fromOctetString(b"", internalFormat=True)

        while substrate:
            component, substrate = decodeFun(
                substrate,
                self.protoComponent,
                substrateFun=substrateFun,
                allowEoo=True,
                **options,
            )
            if component is eoo.endOfOctets:
                break

            trailingBits = component[0]
            if trailingBits > 7:
                raise error.PyAsn1Error(
                    "Trailing bits overflow", trailingBits=trailingBits
                )

            if len(component) == 1 and trailingBits:
                raise error.PyAsn1Error(
                    "Empty BIT STRING segment must carry a zero initial octet",
                    trailingBits=trailingBits,
                )

            bitString = self.protoComponent.fromOctetString(
                component[1:],
                internalFormat=True,
                prepend=bitString,
                padding=trailingBits,
            )

        else:
            raise error.SubstrateUnderrunError("No EOO seen before substrate ends")

        return self._createComponent(asn1Spec, tagSet, bitString, **options), substrate


class OctetStringDecoder(AbstractSimpleDecoder):
    protoComponent = univ.OctetString("")
    supportConstructedForm = True

    # 8.7.3.2: "the tags in the contents octets are always universal class,
    # number 4". A restricted character string is encoded as if it were
    # [UNIVERSAL x] IMPLICIT OCTET STRING (8.23.3), so the outer tag belongs to
    # the string type while its fragments stay plain octetstrings.
    fragmentComponent = univ.OctetString("")

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        head, tail = substrate[:length], substrate[length:]

        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, noValue, **options),
                substrate,
                length,
            )

        if tagSet[0].tagFormat == tag.tagFormatSimple:  # XXX what tag to check?
            return self._createComponent(asn1Spec, tagSet, head, **options), tail

        if not self.supportConstructedForm:
            raise error.PyAsn1Error(
                "Constructed encoding form prohibited",
                decoder=self.__class__.__name__,
            )

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("assembling constructed serialization")

        # All inner fragments are of the same type, treat them as octet string
        substrateFun = self.substrateCollector

        header = b""

        while head:
            component, head = decodeFun(
                head, self.fragmentComponent, substrateFun=substrateFun, **options
            )
            header += component

        return self._createComponent(asn1Spec, tagSet, header, **options), tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if substrateFun and substrateFun is not self.substrateCollector:
            asn1Object = self._createComponent(asn1Spec, tagSet, noValue, **options)
            return substrateFun(asn1Object, substrate, length)

        # All inner fragments are of the same type, treat them as octet string
        substrateFun = self.substrateCollector

        header = b""

        while substrate:
            component, substrate = decodeFun(
                substrate,
                self.fragmentComponent,
                substrateFun=substrateFun,
                allowEoo=True,
                **options,
            )
            if component is eoo.endOfOctets:
                break

            header += component

        else:
            raise error.SubstrateUnderrunError("No EOO seen before substrate ends")

        return self._createComponent(asn1Spec, tagSet, header, **options), substrate


class NullDecoder(AbstractSimpleDecoder):
    protoComponent = univ.Null("")

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error("Simple tag format expected")

        head, tail = substrate[:length], substrate[length:]

        component = self._createComponent(asn1Spec, tagSet, "", **options)

        if head:
            raise error.PyAsn1Error("Unexpected substrate for Null", length=length)

        return component, tail


class ObjectIdentifierDecoder(AbstractSimpleDecoder):
    protoComponent = univ.ObjectIdentifier(())

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error("Simple tag format expected")

        head, tail = substrate[:length], substrate[length:]
        if not head:
            raise error.PyAsn1Error("Empty substrate")

        # Accumulated in a list: repeated tuple concatenation is quadratic in
        # the arc count, which turns a large OID into a CPU exhaustion vector.
        oid: list[int] = []
        index = 0
        substrateLen = len(head)
        while index < substrateLen:
            subId = head[index]
            index += 1
            if subId < 128:
                oid.append(subId)
            elif subId > 128:
                # Construct subid from a number of octets
                nextSubId = subId
                subId = 0
                continuationOctets = 0
                while nextSubId >= 128:
                    continuationOctets += 1
                    if continuationOctets > MAX_OID_ARC_CONTINUATION_OCTETS:
                        raise error.PyAsn1Error(
                            "OID arc exceeds maximum continuation octets",
                            limit=MAX_OID_ARC_CONTINUATION_OCTETS,
                            position=index,
                        )
                    subId = (subId << 7) + (nextSubId & 0x7F)
                    if index >= substrateLen:
                        raise error.SubstrateUnderrunError(
                            "Short substrate for sub-OID", oid=tuple(oid)
                        )
                    nextSubId = head[index]
                    index += 1
                oid.append((subId << 7) + nextSubId)
            elif subId == 128:
                # ASN.1 spec forbids leading zeros (0x80) in OID
                # encoding, tolerating it opens a vulnerability. See
                # https://www.esat.kuleuven.be/cosic/publications/article-1432.pdf
                # page 7
                raise error.PyAsn1Error("Invalid octet 0x80 in OID encoding")

        # Decode two leading arcs
        if 0 <= oid[0] <= 39:
            oid.insert(0, 0)
        elif 40 <= oid[0] <= 79:
            oid[0] -= 40
            oid.insert(0, 1)
        elif oid[0] >= 80:
            oid[0] -= 80
            oid.insert(0, 2)
        else:
            raise error.PyAsn1Error("Malformed first OID octet", octet=head[0])

        return self._createComponent(asn1Spec, tagSet, tuple(oid), **options), tail


#: The four values X.690 8.5.9 encodes as a single contents octet with
#: bits 8 to 7 set to 01. Every other value in that range is reserved.
_SPECIAL_REAL_VALUES = {
    0x40: float("inf"),  # PLUS-INFINITY
    0x41: float("-inf"),  # MINUS-INFINITY
    0x42: float("nan"),  # NOT-A-NUMBER
    0x43: -0.0,  # minus zero
}

#: The ISO 6093 number representations X.690 8.5.8 selects with bits 6 to 1 of
#: the first contents octet. NR1 is an integer, NR2 adds a decimal mark, and
#: NR3 adds an exponent; the mark is required in both of the latter. 8.5.8
#: NOTE 1 makes a digit to the left of the mark a recommendation rather than a
#: requirement, so ".5" is admitted, and 11.3.2.5 writes the canonical NR3
#: mantissa with nothing to the right of it, as "15.E-1".
_ISO6093_FORMS: Final = {
    0x01: re.compile(r"[+-]?\d+\Z"),
    0x02: re.compile(r"[+-]?(?:\d+[.,]\d*|\d*[.,]\d+)\Z"),
    0x03: re.compile(r"[+-]?(?:\d+[.,]\d*|\d*[.,]\d+)[Ee][+-]?\d+\Z"),
}


class RealDecoder(AbstractSimpleDecoder):
    protoComponent = univ.Real()

    @staticmethod
    def _decodeBinary(firstOctet: int, payload: bytes) -> tuple[int, int, int]:
        if not payload:
            raise error.PyAsn1Error("Incomplete floating-point value")

        exponentLength = (firstOctet & 0x03) + 1
        if exponentLength == 4:
            exponentLength = payload[0]
            payload = payload[1:]

        exponentOctets, mantissaOctets = (
            payload[:exponentLength],
            payload[exponentLength:],
        )
        if not exponentOctets or not mantissaOctets:
            raise error.PyAsn1Error("Real exponent screwed")

        exponent = int.from_bytes(exponentOctets, "big", signed=True)
        baseBits = firstOctet >> 4 & 0x03
        if baseBits > 2:
            raise error.PyAsn1Error("Illegal Real base")
        if baseBits == 1:
            exponent *= 3
        elif baseBits == 2:
            exponent *= 4

        mantissa = int.from_bytes(mantissaOctets, "big")
        if firstOctet & 0x40:
            mantissa = -mantissa
        mantissa *= 2 ** (firstOctet >> 2 & 0x03)

        return mantissa, 2, exponent

    @staticmethod
    def _decodeCharacter(firstOctet: int, payload: bytes) -> Any:
        """Decode the decimal form of X.690 8.5.8.

        Bits 6 to 1 of the first contents octet choose the ISO 6093 number
        representation. Every other value of those bits is reserved for a
        further edition of X.690, so it is rejected rather than ignored.
        """
        if not payload:
            raise error.PyAsn1Error("Incomplete floating-point value")

        numberForm = firstOctet & 0x3F

        try:
            grammar = _ISO6093_FORMS[numberForm]

        except KeyError:
            raise error.SubstrateUnderrunError("Unknown NR", tag=firstOctet) from None

        try:
            # ISO 6093 fields are padded to a width the sender chooses, which
            # is why 8.5.8 calls the contents octets a field, so SPACE around
            # the number is expected. Nothing else is: a tab or a newline
            # would have to survive the grammar below.
            text = payload.decode("ascii").strip(" ")

        except UnicodeDecodeError as exc:
            raise error.SubstrateUnderrunError("Bad character Real syntax") from exc

        # 8.5.8 has the sender name the ISO 6093 form and then encode
        # according to it, so the octets are held to the form they declare.
        # Decimal alone would read an exponent under an NR2 selector, take
        # Python's own "1_0" as an NR1 integer, and accept "NaN" and
        # "Infinity" under any of the three.
        if not grammar.match(text):
            raise error.SubstrateUnderrunError(
                "Bad character Real syntax", numberForm=numberForm
            )

        if numberForm == 0x01:
            return int(text), 10, 0

        try:
            # ISO 6093 admits either a comma or a full stop as the decimal
            # mark; Decimal only knows the full stop.
            sign, digits, exponent = decimal.Decimal(text.replace(",", ".")).as_tuple()

        except decimal.InvalidOperation as exc:
            raise error.SubstrateUnderrunError("Bad character Real syntax") from exc

        # The grammar admits only a finite decimal, so as_tuple() cannot have
        # spelled the exponent with the letter it uses for a NaN or infinity.
        assert isinstance(exponent, int)

        mantissa = int("".join(str(digit) for digit in digits))

        # Kept exact rather than passed through float(): 8.5.8 puts no ceiling
        # on the exponent, and float("1E5000") is infinity, which would turn a
        # finite value into a SpecialRealValue.
        return -mantissa if sign else mantissa, 10, exponent

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error("Simple tag format expected")

        head, tail = substrate[:length], substrate[length:]

        if not head:
            return self._createComponent(asn1Spec, tagSet, 0.0, **options), tail

        firstOctet = head[0]
        payload = head[1:]
        if firstOctet & 0x80:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding binary encoded REAL")

            value: Any = self._decodeBinary(firstOctet, payload)

        elif firstOctet & 0x40:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding SpecialRealValue")

            if payload:
                raise error.PyAsn1Error(
                    "SpecialRealValue must occupy a single contents octet",
                    length=len(head),
                )

            try:
                value = _SPECIAL_REAL_VALUES[firstOctet]

            except KeyError:
                raise error.PyAsn1Error(
                    "Reserved SpecialRealValue encoding", tag=firstOctet
                ) from None

        elif firstOctet & 0xC0 == 0:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding character encoded REAL")

            value = self._decodeCharacter(firstOctet, payload)

        else:
            raise error.SubstrateUnderrunError("Unknown encoding", tag=firstOctet)

        return self._createComponent(asn1Spec, tagSet, value, **options), tail


class AbstractConstructedDecoder(AbstractDecoder):
    protoComponent: Any = None


class UniversalConstructedTypeDecoder(AbstractConstructedDecoder):
    protoRecordComponent: Any = None
    protoSequenceComponent: Any = None

    @staticmethod
    def _validateConstructedValue(asn1Object: Any) -> None:
        """Raise an ASN.1 constraint error for an inconsistent decoded value."""
        inconsistency = asn1Object.isInconsistent
        if inconsistency:
            raise error.inconsistencyError(inconsistency, asn1Object)

    def _getComponentTagMap(self, asn1Object: Any, idx: int) -> Any:
        raise NotImplementedError

    def _getComponentPositionByType(
        self, asn1Object: Any, tagSet: Any, idx: int
    ) -> Any:
        raise NotImplementedError

    def _decodeComponents(
        self,
        substrate: bytes,
        tagSet: Any = None,
        decodeFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        components = []
        componentTypes = set()

        while substrate:
            component, substrate = decodeFun(substrate, **options)
            if component is eoo.endOfOctets:
                break

            components.append(component)
            componentTypes.add(component.tagSet)

        # Now we have to guess is it SEQUENCE/SET or SEQUENCE OF/SET OF
        # The heuristics is:
        # * 1+ components of different types -> likely SEQUENCE/SET
        # * otherwise -> likely SEQUENCE OF/SET OF
        if len(componentTypes) > 1:
            protoComponent = self.protoRecordComponent

        else:
            protoComponent = self.protoSequenceComponent

        asn1Object = protoComponent.clone(
            # construct tagSet from base tag from prototype ASN.1 object
            # and additional tags recovered from the substrate
            tagSet=tag.TagSet(protoComponent.tagSet.baseTag, *tagSet.superTags)
        )

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "guessed container type (pass `asn1Spec` to guide the decoder)",
                extra={"asn1Object": asn1Object},
            )

        for idx, component in enumerate(components):
            asn1Object.setComponentByPosition(
                idx,
                component,
                verifyConstraints=False,
                matchTags=False,
                matchConstraints=False,
            )

        return asn1Object, substrate

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatConstructed:
            raise error.PyAsn1Error("Constructed tag format expected")

        head, tail = substrate[:length], substrate[length:]

        if substrateFun is not None:
            if asn1Spec is not None:
                asn1Object = asn1Spec.clone()

            elif self.protoComponent is not None:
                asn1Object = self.protoComponent.clone(tagSet=tagSet)

            else:
                asn1Object = self.protoRecordComponent, self.protoSequenceComponent

            return substrateFun(asn1Object, substrate, length)

        if asn1Spec is None:
            asn1Object, trailing = self._decodeComponents(
                head, tagSet=tagSet, decodeFun=decodeFun, **options
            )

            if trailing:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "unused trailing octets encountered",
                        extra={"trailing": trailing},
                    )

            return asn1Object, tail

        asn1Object = asn1Spec.clone()
        asn1Object.clear()

        if asn1Spec.typeId in (univ.Sequence.typeId, univ.Set.typeId):
            # Read the schema off the clone, not the spec: a recursively
            # defined componentType is re-resolved by clone().
            namedTypes = asn1Object.componentType

            isSetType = asn1Spec.typeId == univ.Set.typeId
            isDeterministic = not isSetType and not namedTypes.hasOptionalOrDefault

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "decoding type chosen by type ID",
                    extra={
                        "deterministic": isDeterministic,
                        "isSet": isSetType,
                        "asn1Spec": asn1Spec,
                    },
                )

            seenIndices = set()
            idx = 0
            while head:
                if not namedTypes:
                    componentType = None

                elif isSetType:
                    componentType = namedTypes.tagMapUnique

                else:
                    try:
                        if isDeterministic:
                            componentType = namedTypes[idx].asn1Object

                        elif namedTypes[idx].isOptional or namedTypes[idx].isDefaulted:
                            componentType = namedTypes.getTagMapNearPosition(idx)

                        else:
                            componentType = namedTypes[idx].asn1Object

                    except IndexError as exc:
                        raise error.PyAsn1Error(
                            "Excessive components decoded", asn1Spec=asn1Spec
                        ) from exc

                component, head = decodeFun(head, componentType, **options)

                if not isDeterministic and namedTypes:
                    if isSetType:
                        idx = namedTypes.getPositionByType(component.effectiveTagSet)

                    elif namedTypes[idx].isOptional or namedTypes[idx].isDefaulted:
                        idx = namedTypes.getPositionNearType(
                            component.effectiveTagSet, idx
                        )

                asn1Object.setComponentByPosition(
                    idx,
                    component,
                    verifyConstraints=False,
                    matchTags=False,
                    matchConstraints=False,
                )

                seenIndices.add(idx)
                idx += 1

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("seen component indices", extra={"seenIndices": seenIndices})

            if namedTypes:
                if not namedTypes.requiredComponents.issubset(seenIndices):
                    raise error.PyAsn1Error(
                        "ASN.1 object has uninitialized components",
                        asn1Type=asn1Object.__class__.__name__,
                    )

                if namedTypes.hasOpenTypes:
                    openTypes = options.get("openTypes", {})

                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "user-specified open types map",
                            extra={"openTypes": openTypes},
                        )

                    if openTypes or options.get("decodeOpenTypes", False):
                        for idx, namedType in enumerate(namedTypes.namedTypes):
                            if not namedType.openType:
                                continue

                            if (
                                namedType.isOptional
                                and not asn1Object.getComponentByPosition(idx).isValue
                            ):
                                continue

                            governingValue = asn1Object.getComponentByName(
                                namedType.openType.name
                            )

                            try:
                                openType = openTypes[governingValue]

                            except KeyError:
                                if LOG.isEnabledFor(logging.DEBUG):
                                    LOG.debug(
                                        "no user-specified open type; falling back "
                                        "to default open types map",
                                        extra={
                                            "asn1Object": asn1Object.__class__.__name__,
                                            "component": namedType.name,
                                            "governingComponent": namedType.openType.name,
                                            "openTypes": namedType.openType,
                                        },
                                    )

                                try:
                                    openType = namedType.openType[governingValue]

                                except KeyError:
                                    if LOG.isEnabledFor(logging.DEBUG):
                                        LOG.debug(
                                            "failed to resolve open type by "
                                            "governing value",
                                            extra={"governingValue": governingValue},
                                        )
                                    continue

                            if LOG.isEnabledFor(logging.DEBUG):
                                LOG.debug(
                                    "resolved open type by governing value",
                                    extra={
                                        "openType": openType,
                                        "governingValue": governingValue,
                                    },
                                )

                            containerValue = asn1Object.getComponentByPosition(idx)

                            if containerValue.typeId in (
                                univ.SetOf.typeId,
                                univ.SequenceOf.typeId,
                            ):
                                for pos, containerElement in enumerate(containerValue):
                                    component, rest = decodeFun(
                                        containerElement.asOctets(),
                                        asn1Spec=openType,
                                        **options,
                                    )

                                    containerValue[pos] = component

                            else:
                                component, rest = decodeFun(
                                    asn1Object.getComponentByPosition(idx).asOctets(),
                                    asn1Spec=openType,
                                    **options,
                                )

                                asn1Object.setComponentByPosition(idx, component)

        else:
            asn1Object = asn1Spec.clone()
            asn1Object.clear()

            # Read the schema off the clone, not the spec: a recursively
            # defined componentType is re-resolved by clone().
            componentType = asn1Object.componentType

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "decoding type chosen by given `asn1Spec`",
                    extra={"componentType": componentType},
                )

            idx = 0

            while head:
                component, head = decodeFun(head, componentType, **options)
                asn1Object.setComponentByPosition(
                    idx,
                    component,
                    verifyConstraints=False,
                    matchTags=False,
                    matchConstraints=False,
                )

                idx += 1

        self._validateConstructedValue(asn1Object)

        return asn1Object, tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if tagSet[0].tagFormat != tag.tagFormatConstructed:
            raise error.PyAsn1Error("Constructed tag format expected")

        if substrateFun is not None:
            if asn1Spec is not None:
                asn1Object = asn1Spec.clone()

            elif self.protoComponent is not None:
                asn1Object = self.protoComponent.clone(tagSet=tagSet)

            else:
                asn1Object = self.protoRecordComponent, self.protoSequenceComponent

            return substrateFun(asn1Object, substrate, length)

        if asn1Spec is None:
            return self._decodeComponents(
                substrate,
                tagSet=tagSet,
                decodeFun=decodeFun,
                **dict(options, allowEoo=True),
            )

        asn1Object = asn1Spec.clone()
        asn1Object.clear()

        if asn1Spec.typeId in (univ.Sequence.typeId, univ.Set.typeId):
            namedTypes = asn1Object.componentType

            isSetType = asn1Object.typeId == univ.Set.typeId
            isDeterministic = not isSetType and not namedTypes.hasOptionalOrDefault

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "decoding type chosen by type ID",
                    extra={
                        "deterministic": isDeterministic,
                        "isSet": isSetType,
                        "asn1Spec": asn1Spec,
                    },
                )

            seenIndices = set()
            idx = 0
            while substrate:
                if len(namedTypes) <= idx:
                    asn1Spec = None

                elif isSetType:
                    asn1Spec = namedTypes.tagMapUnique

                else:
                    try:
                        if isDeterministic:
                            asn1Spec = namedTypes[idx].asn1Object

                        elif namedTypes[idx].isOptional or namedTypes[idx].isDefaulted:
                            asn1Spec = namedTypes.getTagMapNearPosition(idx)

                        else:
                            asn1Spec = namedTypes[idx].asn1Object

                    except IndexError as exc:
                        raise error.PyAsn1Error(
                            "Excessive components decoded", asn1Object=asn1Object
                        ) from exc

                component, substrate = decodeFun(
                    substrate, asn1Spec, allowEoo=True, **options
                )
                if component is eoo.endOfOctets:
                    break

                if not isDeterministic and namedTypes:
                    if isSetType:
                        idx = namedTypes.getPositionByType(component.effectiveTagSet)
                    elif namedTypes[idx].isOptional or namedTypes[idx].isDefaulted:
                        idx = namedTypes.getPositionNearType(
                            component.effectiveTagSet, idx
                        )

                asn1Object.setComponentByPosition(
                    idx,
                    component,
                    verifyConstraints=False,
                    matchTags=False,
                    matchConstraints=False,
                )

                seenIndices.add(idx)
                idx += 1

            else:
                raise error.SubstrateUnderrunError("No EOO seen before substrate ends")

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("seen component indices", extra={"seenIndices": seenIndices})

            if namedTypes:
                if not namedTypes.requiredComponents.issubset(seenIndices):
                    raise error.PyAsn1Error(
                        "ASN.1 object has uninitialized components",
                        asn1Type=asn1Object.__class__.__name__,
                    )

                if namedTypes.hasOpenTypes:
                    openTypes = options.get("openTypes", {})

                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "user-specified open types map",
                            extra={"openTypes": openTypes},
                        )

                    if openTypes or options.get("decodeOpenTypes", False):
                        for idx, namedType in enumerate(namedTypes.namedTypes):
                            if not namedType.openType:
                                continue

                            if (
                                namedType.isOptional
                                and not asn1Object.getComponentByPosition(idx).isValue
                            ):
                                continue

                            governingValue = asn1Object.getComponentByName(
                                namedType.openType.name
                            )

                            try:
                                openType = openTypes[governingValue]

                            except KeyError:
                                if LOG.isEnabledFor(logging.DEBUG):
                                    LOG.debug(
                                        "no user-specified open type; falling back "
                                        "to default open types map",
                                        extra={
                                            "asn1Object": asn1Object.__class__.__name__,
                                            "component": namedType.name,
                                            "governingComponent": namedType.openType.name,
                                            "openTypes": namedType.openType,
                                        },
                                    )

                                try:
                                    openType = namedType.openType[governingValue]

                                except KeyError:
                                    if LOG.isEnabledFor(logging.DEBUG):
                                        LOG.debug(
                                            "failed to resolve open type by "
                                            "governing value",
                                            extra={"governingValue": governingValue},
                                        )
                                    continue

                            if LOG.isEnabledFor(logging.DEBUG):
                                LOG.debug(
                                    "resolved open type by governing value",
                                    extra={
                                        "openType": openType,
                                        "governingValue": governingValue,
                                    },
                                )

                            containerValue = asn1Object.getComponentByPosition(idx)

                            if containerValue.typeId in (
                                univ.SetOf.typeId,
                                univ.SequenceOf.typeId,
                            ):
                                for pos, containerElement in enumerate(containerValue):
                                    component, rest = decodeFun(
                                        containerElement.asOctets(),
                                        asn1Spec=openType,
                                        **dict(options, allowEoo=True),
                                    )

                                    containerValue[pos] = component

                            else:
                                component, rest = decodeFun(
                                    asn1Object.getComponentByPosition(idx).asOctets(),
                                    asn1Spec=openType,
                                    **dict(options, allowEoo=True),
                                )

                                if component is not eoo.endOfOctets:
                                    asn1Object.setComponentByPosition(idx, component)

        else:
            asn1Object = asn1Spec.clone()
            asn1Object.clear()

            # Read the schema off the clone, not the spec: a recursively
            # defined componentType is re-resolved by clone().
            componentType = asn1Object.componentType

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "decoding type chosen by given `asn1Spec`",
                    extra={"componentType": componentType},
                )

            idx = 0

            while substrate:
                component, substrate = decodeFun(
                    substrate, componentType, allowEoo=True, **options
                )

                if component is eoo.endOfOctets:
                    break

                asn1Object.setComponentByPosition(
                    idx,
                    component,
                    verifyConstraints=False,
                    matchTags=False,
                    matchConstraints=False,
                )

                idx += 1

            else:
                raise error.SubstrateUnderrunError("No EOO seen before substrate ends")

        self._validateConstructedValue(asn1Object)

        return asn1Object, substrate


class SequenceOrSequenceOfDecoder(UniversalConstructedTypeDecoder):
    protoRecordComponent = univ.Sequence()
    protoSequenceComponent = univ.SequenceOf()


class SequenceDecoder(SequenceOrSequenceOfDecoder):
    protoComponent = univ.Sequence()


class SequenceOfDecoder(SequenceOrSequenceOfDecoder):
    protoComponent = univ.SequenceOf()


class SetOrSetOfDecoder(UniversalConstructedTypeDecoder):
    protoRecordComponent = univ.Set()
    protoSequenceComponent = univ.SetOf()


class SetDecoder(SetOrSetOfDecoder):
    protoComponent = univ.Set()


class SetOfDecoder(SetOrSetOfDecoder):
    protoComponent = univ.SetOf()


class ChoiceDecoder(AbstractConstructedDecoder):
    protoComponent = univ.Choice()

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        head, tail = substrate[:length], substrate[length:]

        if asn1Spec is None:
            asn1Object = self.protoComponent.clone(tagSet=tagSet)

        else:
            asn1Object = asn1Spec.clone()

        if substrateFun:
            return substrateFun(asn1Object, substrate, length)

        if asn1Object.tagSet == tagSet:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding explicitly tagged CHOICE", extra={"tagSet": tagSet})

            component, head = decodeFun(head, asn1Object.componentTagMap, **options)

        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding untagged CHOICE", extra={"tagSet": tagSet})

            component, head = decodeFun(
                head, asn1Object.componentTagMap, tagSet, length, state, **options
            )

        effectiveTagSet = component.effectiveTagSet

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "decoded component",
                extra={"component": component, "effectiveTagSet": effectiveTagSet},
            )

        asn1Object.setComponentByType(
            effectiveTagSet,
            component,
            verifyConstraints=False,
            matchTags=False,
            matchConstraints=False,
            innerFlag=False,
        )

        return asn1Object, tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if asn1Spec is None:
            asn1Object = self.protoComponent.clone(tagSet=tagSet)
        else:
            asn1Object = asn1Spec.clone()

        if substrateFun:
            return substrateFun(asn1Object, substrate, length)

        if asn1Object.tagSet == tagSet:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding explicitly tagged CHOICE", extra={"tagSet": tagSet})

            component, substrate = decodeFun(
                substrate, asn1Object.componentType.tagMapUnique, **options
            )

            # eat up EOO marker
            eooMarker, substrate = decodeFun(substrate, allowEoo=True, **options)

            if eooMarker is not eoo.endOfOctets:
                raise error.PyAsn1Error("No EOO seen before substrate ends")

        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding untagged CHOICE", extra={"tagSet": tagSet})

            component, substrate = decodeFun(
                substrate,
                asn1Object.componentType.tagMapUnique,
                tagSet,
                length,
                state,
                **options,
            )

        effectiveTagSet = component.effectiveTagSet

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "decoded component",
                extra={"component": component, "effectiveTagSet": effectiveTagSet},
            )

        asn1Object.setComponentByType(
            effectiveTagSet,
            component,
            verifyConstraints=False,
            matchTags=False,
            matchConstraints=False,
            innerFlag=False,
        )

        return asn1Object, substrate


class AnyDecoder(AbstractSimpleDecoder):
    protoComponent = univ.Any()

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if asn1Spec is None:
            isUntagged = True

        elif asn1Spec.__class__ is tagmap.TagMap:
            isUntagged = tagSet not in asn1Spec

        else:
            isUntagged = tagSet != asn1Spec.tagSet

        if isUntagged:
            fullSubstrate = options["fullSubstrate"]

            # untagged Any container, recover inner header substrate
            length += len(fullSubstrate) - len(substrate)
            substrate = fullSubstrate

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding as untagged ANY", extra={"substrate": substrate})

        if substrateFun:
            return substrateFun(
                self._createComponent(asn1Spec, tagSet, noValue, **options),
                substrate,
                length,
            )

        head, tail = substrate[:length], substrate[length:]

        return self._createComponent(asn1Spec, tagSet, head, **options), tail

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: Any = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if asn1Spec is None:
            isTagged = False

        elif asn1Spec.__class__ is tagmap.TagMap:
            isTagged = tagSet in asn1Spec

        else:
            isTagged = tagSet == asn1Spec.tagSet

        if isTagged:
            # tagged Any type -- consume header substrate
            header = b""

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("decoding as tagged ANY")

        else:
            fullSubstrate = options["fullSubstrate"]

            # untagged Any, recover header substrate
            header = fullSubstrate[: -len(substrate)]

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "decoding as untagged ANY, consuming header substrate",
                    extra={"header": header},
                )

        # Any components do not inherit initial tag
        asn1Spec = self.protoComponent

        if substrateFun and substrateFun is not self.substrateCollector:
            asn1Object = self._createComponent(asn1Spec, tagSet, noValue, **options)
            return substrateFun(asn1Object, header + substrate, length + len(header))

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("assembling constructed serialization")

        # All inner fragments are of the same type, treat them as octet string
        substrateFun = self.substrateCollector

        while substrate:
            component, substrate = decodeFun(
                substrate, asn1Spec, substrateFun=substrateFun, allowEoo=True, **options
            )
            if component is eoo.endOfOctets:
                break

            header += component

        else:
            raise error.SubstrateUnderrunError("No EOO seen before substrate ends")

        if substrateFun:
            return header, substrate

        else:
            return self._createComponent(asn1Spec, tagSet, header, **options), substrate


# character string types
class UTF8StringDecoder(OctetStringDecoder):
    protoComponent = char.UTF8String()


class NumericStringDecoder(OctetStringDecoder):
    protoComponent = char.NumericString()


class PrintableStringDecoder(OctetStringDecoder):
    protoComponent = char.PrintableString()


class TeletexStringDecoder(OctetStringDecoder):
    protoComponent = char.TeletexString()


class VideotexStringDecoder(OctetStringDecoder):
    protoComponent = char.VideotexString()


class IA5StringDecoder(OctetStringDecoder):
    protoComponent = char.IA5String()


class GraphicStringDecoder(OctetStringDecoder):
    protoComponent = char.GraphicString()


class VisibleStringDecoder(OctetStringDecoder):
    protoComponent = char.VisibleString()


class GeneralStringDecoder(OctetStringDecoder):
    protoComponent = char.GeneralString()


class UniversalStringDecoder(OctetStringDecoder):
    protoComponent = char.UniversalString()


class BMPStringDecoder(OctetStringDecoder):
    protoComponent = char.BMPString()


# "useful" types
class ObjectDescriptorDecoder(OctetStringDecoder):
    protoComponent = useful.ObjectDescriptor()


class GeneralizedTimeDecoder(OctetStringDecoder):
    protoComponent = useful.GeneralizedTime()


class UTCTimeDecoder(OctetStringDecoder):
    protoComponent = useful.UTCTime()


tagMap: Final[dict[tag.TagSet, AbstractDecoder]] = {
    univ.Integer.tagSet: IntegerDecoder(),
    univ.Boolean.tagSet: BooleanDecoder(),
    univ.BitString.tagSet: BitStringDecoder(),
    univ.OctetString.tagSet: OctetStringDecoder(),
    univ.Null.tagSet: NullDecoder(),
    univ.ObjectIdentifier.tagSet: ObjectIdentifierDecoder(),
    univ.Enumerated.tagSet: IntegerDecoder(),
    univ.Real.tagSet: RealDecoder(),
    univ.Sequence.tagSet: SequenceOrSequenceOfDecoder(),  # conflicts with SequenceOf
    univ.Set.tagSet: SetOrSetOfDecoder(),  # conflicts with SetOf
    univ.Choice.tagSet: ChoiceDecoder(),  # conflicts with Any
    # character string types
    char.UTF8String.tagSet: UTF8StringDecoder(),
    char.NumericString.tagSet: NumericStringDecoder(),
    char.PrintableString.tagSet: PrintableStringDecoder(),
    char.TeletexString.tagSet: TeletexStringDecoder(),
    char.VideotexString.tagSet: VideotexStringDecoder(),
    char.IA5String.tagSet: IA5StringDecoder(),
    char.GraphicString.tagSet: GraphicStringDecoder(),
    char.VisibleString.tagSet: VisibleStringDecoder(),
    char.GeneralString.tagSet: GeneralStringDecoder(),
    char.UniversalString.tagSet: UniversalStringDecoder(),
    char.BMPString.tagSet: BMPStringDecoder(),
    # useful types
    useful.ObjectDescriptor.tagSet: ObjectDescriptorDecoder(),
    useful.GeneralizedTime.tagSet: GeneralizedTimeDecoder(),
    useful.UTCTime.tagSet: UTCTimeDecoder(),
}

# Type-to-codec map for ambiguous ASN.1 types
typeMap: Final[dict[int, AbstractDecoder]] = {
    univ.Set.typeId: SetDecoder(),
    univ.SetOf.typeId: SetOfDecoder(),
    univ.Sequence.typeId: SequenceDecoder(),
    univ.SequenceOf.typeId: SequenceOfDecoder(),
    univ.Choice.typeId: ChoiceDecoder(),
    univ.Any.typeId: AnyDecoder(),
}

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in tagMap.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in typeMap:
            typeMap[typeId] = typeDecoder


(
    stDecodeTag,
    stDecodeLength,
    stGetValueDecoder,
    stGetValueDecoderByAsn1Spec,
    stGetValueDecoderByTag,
    stTryAsExplicitTag,
    stDecodeValue,
    stDumpRawValue,
    stErrorCondition,
    stStop,
) = (x for x in range(10))


class Decoder:
    defaultErrorState = stErrorCondition
    # defaultErrorState = stDumpRawValue
    defaultRawDecoder = AnyDecoder()
    supportIndefLength = True

    # X.690 10.1 (DER) and 9.1 (CER) both require the definite length to be
    # encoded in the fewest octets. BER leaves it open: 8.1.3.5 note 2 makes
    # the octet count a sender's option, so this stays off for the base codec.
    requireMinimalLength = False

    # X.690 9.1: under CER a constructed encoding uses the indefinite form.
    requireIndefLengthForConstructed = False

    # X.690 8.1.2.2 reserves the single-octet identifier for tags up to 30.
    # Clause 8 states it unconditionally, but a high tag number carrying a
    # small tag still decodes unambiguously, so BER keeps accepting it and
    # the canonical codecs do not.
    requireLowTagNumberForm = False

    def __init__(
        self,
        tagMap: dict[tag.TagSet, AbstractDecoder],
        typeMap: dict[int, AbstractDecoder] | None = None,
    ) -> None:
        self.__tagMap = tagMap
        self.__typeMap = typeMap if typeMap is not None else {}
        # Tag & TagSet objects caches
        self.__tagCache: dict[int, tag.Tag] = {}
        self.__tagSetCache: dict[int, tag.TagSet] = {}
        self.__eooSentinel = bytes((0, 0))

    @staticmethod
    def _checkMinimalLength(length: int, sizeOctets: int, tagSet: Any) -> None:
        """Reject a long form that could have been written in fewer octets.

        X.690 10.1 and 9.1 both demand the fewest length octets. A length
        below 128 has a short form available, and above it the count of
        subsequent octets is fixed by the magnitude of the length.
        """
        if length < 128:
            raise error.PyAsn1Error(
                "Long length form used where the short form suffices",
                length=length,
                tagSet=tagSet,
            )

        minimalSize = (length.bit_length() + 7) // 8

        if sizeOctets != minimalSize:
            raise error.PyAsn1Error(
                "Non-minimal length encoding",
                length=length,
                expectedSize=minimalSize,
                actualSize=sizeOctets,
                tagSet=tagSet,
            )

    def __call__(
        self,
        substrate: bytes,
        asn1Spec: Any = None,
        tagSet: Any = None,
        length: Any = None,
        state: int = stDecodeTag,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        _nestingLevel = options.get("_nestingLevel", 0)
        if _nestingLevel > MAX_NESTING_DEPTH:
            raise error.PyAsn1Error(
                "ASN.1 structure nesting depth exceeds limit",
                limit=MAX_NESTING_DEPTH,
            )
        options["_nestingLevel"] = _nestingLevel + 1

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "decoder called, working with substrate",
                extra={
                    "scope": str(debug.scope),
                    "state": state,
                    "substrate": substrate,
                },
            )

        allowEoo = options.pop("allowEoo", False)

        # Look for end-of-octets sentinel
        if allowEoo and self.supportIndefLength:
            if substrate[:2] == self.__eooSentinel:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("end-of-octets sentinel found")
                return eoo.endOfOctets, substrate[2:]

        value = noValue

        tagMap = self.__tagMap
        typeMap = self.__typeMap
        tagCache = self.__tagCache
        tagSetCache = self.__tagSetCache

        fullSubstrate = substrate

        concreteDecoder: Any

        while state is not stStop:
            if state is stDecodeTag:
                if not substrate:
                    raise error.SubstrateUnderrunError(
                        "Short octet stream on tag decoding"
                    )

                # Decode tag
                isShortTag = True
                firstOctet = substrate[0]
                substrate = substrate[1:]

                try:
                    lastTag = tagCache[firstOctet]

                except KeyError:
                    integerTag = firstOctet
                    tagClass = integerTag & 0xC0
                    tagFormat = integerTag & 0x20
                    tagId = integerTag & 0x1F

                    if tagId == 0x1F:
                        isShortTag = False
                        lengthOctetIdx = 0
                        tagId = 0

                        try:
                            while True:
                                integerTag = substrate[lengthOctetIdx]
                                if lengthOctetIdx == 0 and not integerTag & 0x7F:
                                    # 8.1.2.4.2 c): bits 7 to 1 of the first
                                    # subsequent octet shall not all be zero,
                                    # which rules out padding the tag number.
                                    raise error.PyAsn1Error(
                                        "Non-minimal tag number encoding"
                                    )
                                lengthOctetIdx += 1
                                if lengthOctetIdx > MAX_TAG_OCTETS:
                                    raise error.PyAsn1Error(
                                        "Tag number exceeds maximum octets",
                                        limit=MAX_TAG_OCTETS,
                                    )
                                tagId <<= 7
                                tagId |= integerTag & 0x7F
                                if not integerTag & 0x80:
                                    break

                            substrate = substrate[lengthOctetIdx:]

                        except IndexError as exc:
                            raise error.SubstrateUnderrunError(
                                "Short octet stream on long tag decoding"
                            ) from exc

                    lastTag = tag.Tag(
                        tagClass=tagClass, tagFormat=tagFormat, tagId=tagId
                    )

                    if isShortTag:
                        # cache short tags
                        tagCache[firstOctet] = lastTag

                if (
                    self.requireLowTagNumberForm
                    and not isShortTag
                    and lastTag.tagId < 0x1F
                ):
                    # 8.1.2.2 reserves the single octet for these tags. Short
                    # tags are the only ones cached, so a cache hit leaves
                    # isShortTag set and skips the check.
                    raise error.PyAsn1Error(
                        "High tag number form used where the low tag number "
                        "form suffices",
                        tagId=lastTag.tagId,
                    )

                if tagSet is None:
                    if isShortTag:
                        try:
                            tagSet = tagSetCache[firstOctet]

                        except KeyError:
                            # base tag not recovered
                            tagSet = tag.TagSet((), lastTag)
                            tagSetCache[firstOctet] = tagSet
                    else:
                        tagSet = tag.TagSet((), lastTag)

                else:
                    tagSet = lastTag + tagSet

                state = stDecodeLength

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("tag decoded, decoding length", extra={"tagSet": tagSet})

            if state is stDecodeLength:
                # Decode length
                if not substrate:
                    raise error.SubstrateUnderrunError(
                        "Short octet stream on length decoding"
                    )

                firstOctet = substrate[0]

                if firstOctet < 128:
                    size = 1
                    length = firstOctet

                elif firstOctet > 128:
                    if firstOctet == 0xFF:
                        # 8.1.3.5 c): reserved for a future extension. Caught
                        # here so it does not read as a 127-octet length that
                        # merely ran off the end of the substrate.
                        raise error.PyAsn1Error(
                            "Length octet 0xff is reserved by X.690 8.1.3.5",
                            tagSet=tagSet,
                        )

                    size = firstOctet & 0x7F
                    if size > MAX_LENGTH_OCTETS:
                        # X.690 8.1.3.5 allows up to 126 length octets, but a
                        # value longer than 2**64 octets can never be supplied.
                        # Reject rather than accumulate an unbounded integer.
                        raise error.PyAsn1Error(
                            "Length field exceeds maximum octets",
                            limit=MAX_LENGTH_OCTETS,
                            actualSize=size,
                            tagSet=tagSet,
                        )
                    # encoded in size bytes
                    encodedLength = substrate[1 : size + 1]
                    if len(encodedLength) != size:
                        raise error.SubstrateUnderrunError(
                            "Short substrate for length octets",
                            expectedSize=size,
                            actualSize=len(encodedLength),
                            tagSet=tagSet,
                        )

                    length = 0
                    for lengthOctet in encodedLength:
                        length <<= 8
                        length |= lengthOctet

                    if self.requireMinimalLength:
                        self._checkMinimalLength(length, size, tagSet)

                    size += 1

                else:
                    size = 1
                    length = -1

                substrate = substrate[size:]

                if length == -1:
                    if not self.supportIndefLength:
                        raise error.PyAsn1Error(
                            "Indefinite length encoding not supported by this codec"
                        )

                elif (
                    self.requireIndefLengthForConstructed
                    and lastTag.tagFormat == tag.tagFormatConstructed
                ):
                    raise error.PyAsn1Error(
                        "Definite length form used for a constructed encoding",
                        tagSet=tagSet,
                    )

                elif len(substrate) < length:
                    raise error.SubstrateUnderrunError(
                        "Short substrate",
                        shortBy=length - len(substrate),
                        length=length,
                        available=len(substrate),
                    )

                state = stGetValueDecoder

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "value length decoded, decoding payload",
                        extra={
                            "length": length,
                            "payload": substrate
                            if length == -1
                            else substrate[:length],
                        },
                    )

            if state is stGetValueDecoder:
                if asn1Spec is None:
                    state = stGetValueDecoderByTag

                else:
                    state = stGetValueDecoderByAsn1Spec
            #
            # There're two ways of creating subtypes in ASN.1 what influences
            # decoder operation. These methods are:
            # 1) Either base types used in or no IMPLICIT tagging has been
            #    applied on subtyping.
            # 2) Subtype syntax drops base type information (by means of
            #    IMPLICIT tagging.
            # The first case allows for complete tag recovery from substrate
            # while the second one requires original ASN.1 type spec for
            # decoding.
            #
            # In either case a set of tags (tagSet) is coming from substrate
            # in an incremental, tag-by-tag fashion (this is the case of
            # EXPLICIT tag which is most basic). Outermost tag comes first
            # from the wire.
            #
            if state is stGetValueDecoderByTag:
                try:
                    concreteDecoder = tagMap[tagSet]

                except KeyError:
                    concreteDecoder = None

                if concreteDecoder:
                    state = stDecodeValue

                else:
                    try:
                        concreteDecoder = tagMap[tagSet[:1]]

                    except KeyError:
                        concreteDecoder = None

                    if concreteDecoder:
                        state = stDecodeValue
                    else:
                        state = stTryAsExplicitTag

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "codec chosen by a built-in type",
                        extra={
                            "codec": type(concreteDecoder).__name__
                            if concreteDecoder
                            else None,
                            "decodingValue": state is stDecodeValue,
                        },
                    )
                    debug.scope.push(
                        concreteDecoder is None
                        and "?"
                        or concreteDecoder.protoComponent.__class__.__name__
                    )

            if state is stGetValueDecoderByAsn1Spec:
                if asn1Spec.__class__ is tagmap.TagMap:
                    try:
                        chosenSpec = asn1Spec[tagSet]

                    except KeyError:
                        chosenSpec = None

                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "candidate ASN.1 spec is a map of",
                            extra={"presentTypes": asn1Spec.presentTypes},
                        )

                        if asn1Spec.skipTypes:
                            LOG.debug(
                                "candidate ASN.1 spec excludes",
                                extra={"skipTypes": asn1Spec.skipTypes},
                            )

                        LOG.debug(
                            "new candidate ASN.1 spec chosen by tag set",
                            extra={
                                "chosenSpec": None
                                if chosenSpec is None
                                else chosenSpec.prettyPrintType(),
                                "tagSet": tagSet,
                            },
                        )

                elif tagSet == asn1Spec.tagSet or tagSet in asn1Spec.tagMap:
                    chosenSpec = asn1Spec
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "candidate ASN.1 spec found",
                            extra={"asn1Spec": asn1Spec.__class__.__name__},
                        )

                else:
                    chosenSpec = None

                if chosenSpec is not None:
                    try:
                        # ambiguous type or just faster codec lookup
                        concreteDecoder = typeMap[chosenSpec.typeId]

                        if LOG.isEnabledFor(logging.DEBUG):
                            LOG.debug(
                                "value decoder chosen for an ambiguous type by type ID",
                                extra={"typeId": chosenSpec.typeId},
                            )

                    except KeyError:
                        # use base type for codec lookup to recover untagged types
                        baseTagSet = tag.TagSet(
                            chosenSpec.tagSet.baseTag, chosenSpec.tagSet.baseTag
                        )
                        try:
                            # base type or tagged subtype
                            concreteDecoder = tagMap[baseTagSet]

                            if LOG.isEnabledFor(logging.DEBUG):
                                LOG.debug(
                                    "value decoder chosen by base tag set",
                                    extra={"baseTagSet": baseTagSet},
                                )

                        except KeyError:
                            concreteDecoder = None

                    if concreteDecoder:
                        asn1Spec = chosenSpec
                        state = stDecodeValue

                    else:
                        state = stTryAsExplicitTag

                else:
                    concreteDecoder = None
                    state = stTryAsExplicitTag

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "codec chosen by ASN.1 spec",
                        extra={
                            "codec": concreteDecoder.__class__.__name__
                            if state is stDecodeValue
                            else None,
                            "decodingValue": state is stDecodeValue,
                        },
                    )
                    debug.scope.push(
                        "?" if chosenSpec is None else chosenSpec.__class__.__name__
                    )

            if state is stDecodeValue:
                if (
                    not options.get("recursiveFlag", True) and not substrateFun
                ):  # deprecate this
                    substrateFun = lambda a, b, c: (a, b[:c])

                options.update(fullSubstrate=fullSubstrate)

                if length == -1:  # indef length
                    value, substrate = concreteDecoder.indefLenValueDecoder(
                        substrate,
                        asn1Spec,
                        tagSet,
                        length,
                        stGetValueDecoder,
                        self,
                        substrateFun,
                        **options,
                    )

                else:
                    value, substrate = concreteDecoder.valueDecoder(
                        substrate,
                        asn1Spec,
                        tagSet,
                        length,
                        stGetValueDecoder,
                        self,
                        substrateFun,
                        **options,
                    )

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "codec yielded value, decoding remaining substrate",
                        extra={
                            "codec": concreteDecoder.__class__.__name__,
                            "valueType": value.__class__.__name__,
                            "value": value.prettyPrint()
                            if isinstance(value, base.Asn1Type)
                            else value,
                            "substrate": substrate,
                        },
                    )

                state = stStop
                break

            if state is stTryAsExplicitTag:
                if (
                    tagSet
                    and tagSet[0].tagFormat == tag.tagFormatConstructed
                    and tagSet[0].tagClass != tag.tagClassUniversal
                ):
                    # Assume explicit tagging
                    concreteDecoder = explicitTagDecoder
                    state = stDecodeValue

                else:
                    concreteDecoder = None
                    state = self.defaultErrorState

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "codec chosen",
                        extra={
                            "codec": type(concreteDecoder).__name__
                            if concreteDecoder
                            else None,
                            "decodingValue": state is stDecodeValue,
                        },
                    )

            if state is stDumpRawValue:
                concreteDecoder = self.defaultRawDecoder

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "codec chosen, decoding value",
                        extra={"codec": concreteDecoder.__class__.__name__},
                    )

                state = stDecodeValue

            if state is stErrorCondition:
                raise error.PyAsn1Error(
                    "TagSet not in asn1Spec", tagSet=tagSet, asn1Spec=asn1Spec
                )

        if LOG.isEnabledFor(logging.DEBUG):
            debug.scope.pop()
            LOG.debug(
                "decoder left scope, call completed", extra={"scope": str(debug.scope)}
            )

        return value, substrate


#: Turns BER octet stream into an ASN.1 object.
#:
#: Takes BER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes` (Python 3) or :py:class:`str` (Python 2)
#:     BER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from BER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty).
#:     Omitted DEFAULT components remain absent until normal component access
#:     resolves their schema default.
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode BER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode BER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode: Final = Decoder(tagMap, typeMap)

# XXX
# non-recursive decoding; return position rather than substrate
