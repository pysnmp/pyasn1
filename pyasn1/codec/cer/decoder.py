#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""CER decoder for ASN.1 types."""

from typing import Any, Final

from pyasn1 import error
from pyasn1.codec.ber import decoder, eoo
from pyasn1.type import char, tag, univ, useful

__all__ = ["decode"]


class IntegerDecoder(decoder.IntegerDecoder):
    """INTEGER decoder enforcing X.690 8.3.2.

    A redundant leading 00 or ff octet leaves the value unchanged, so BER
    accepts it and one integer has unboundedly many spellings. 8.3.2 forbids
    it: given more than one contents octet, the bits of the first octet and
    bit 8 of the second shall not all be ones, nor all be zero.
    """

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        self._verifyMinimalEncoding(substrate[:length])

        return super().valueDecoder(
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    @staticmethod
    def _verifyMinimalEncoding(head: bytes) -> None:
        # A single contents octet is always minimal, and an empty one is the
        # base decoder's to reject under 8.3.1.
        if len(head) < 2:
            return

        if head[0] == 0x00 and not head[1] & 0x80:
            raise error.PyAsn1Error(
                "Non-minimal INTEGER encoding: redundant leading zero octet",
                payload=head[:2],
            )

        if head[0] == 0xFF and head[1] & 0x80:
            raise error.PyAsn1Error(
                "Non-minimal INTEGER encoding: redundant leading sign octet",
                payload=head[:2],
            )


class RealDecoder(decoder.RealDecoder):
    """REAL decoder enforcing X.690 11.3.

    BER offers three bases, a scaling factor and three ISO 6093 forms, so one
    real value has many encodings. 11.3 admits one of each: base 2 with a zero
    scaling factor and an odd mantissa for binary, NR3 for decimal.
    """

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        self._verifyCanonicalForm(substrate[:length])

        return super().valueDecoder(
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    @classmethod
    def _verifyCanonicalForm(cls, head: bytes) -> None:
        # No contents octets is the value zero (8.5.2) and a SpecialRealValue
        # occupies a single octet (8.5.9); neither admits a variant spelling.
        if len(head) < 2:
            return

        firstOctet = head[0]

        if firstOctet & 0x80:
            cls._verifyBinaryForm(head)

        elif not firstOctet & 0x40:
            # 11.3.2.1: "The ISO 6093 NR3 form shall be used". 8.5.8 puts the
            # form in bits 6 to 1, with NR3 spelled 00 0011.
            if firstOctet & 0x3F != 0x03:
                raise error.PyAsn1Error(
                    "Decimal REAL must use the ISO 6093 NR3 form",
                    firstOctet=firstOctet,
                )

    @staticmethod
    def _verifyBinaryForm(head: bytes) -> None:
        firstOctet = head[0]

        # 11.3.1: "binary encoding employing base 2 shall be used". 8.5.7.2
        # puts the base in bits 6 to 5, with base 2 spelled 00.
        if firstOctet & 0x30:
            raise error.PyAsn1Error(
                "Binary REAL must use base 2", firstOctet=firstOctet
            )

        # 11.3.1: "the binary scaling factor F shall be zero" (bits 4 to 3).
        if firstOctet & 0x0C:
            raise error.PyAsn1Error(
                "Binary REAL scaling factor must be zero", firstOctet=firstOctet
            )

        exponentFormat = firstOctet & 0x03

        if exponentFormat == 0x03:
            exponentLength = head[1]
            mantissaStart = 2 + exponentLength
            exponentOctets = head[2:mantissaStart]
        else:
            exponentLength = exponentFormat + 1
            mantissaStart = 1 + exponentLength
            exponentOctets = head[1:mantissaStart]

        mantissaOctets = head[mantissaStart:]

        if not exponentOctets or not mantissaOctets:
            # Malformed rather than non-canonical; the base decoder says so.
            return

        # 11.3.1: "M and E shall each be represented in the fewest octets
        # necessary." E is two's complement, so 8.3.2 sizes it; M is an
        # unsigned integer, so a leading zero octet is simply redundant.
        if len(exponentOctets) > 1:
            if exponentOctets[0] == 0x00 and not exponentOctets[1] & 0x80:
                raise error.PyAsn1Error("Non-minimal REAL exponent encoding")
            if exponentOctets[0] == 0xFF and exponentOctets[1] & 0x80:
                raise error.PyAsn1Error("Non-minimal REAL exponent encoding")

        if len(mantissaOctets) > 1 and mantissaOctets[0] == 0x00:
            raise error.PyAsn1Error("Non-minimal REAL mantissa encoding")

        # 11.3.1: "the mantissa M and exponent E are chosen so that M is
        # either 0 or is odd."
        mantissa = int.from_bytes(mantissaOctets, "big")
        if mantissa and not mantissa & 0x01:
            raise error.PyAsn1Error(
                "Binary REAL mantissa must be zero or odd", mantissa=mantissa
            )


class BooleanDecoder(decoder.AbstractSimpleDecoder):
    protoComponent = univ.Boolean(0)

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        head, tail = substrate[:length], substrate[length:]
        if not head or length != 1:
            raise error.PyAsn1Error("Not single-octet Boolean payload")
        byte = head[0]
        # CER/DER specifies encoding of TRUE as 0xFF and FALSE as 0x0, while
        # BER allows any non-zero value as TRUE; cf. sections 8.2.2. and 11.1
        # in https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
        if byte == 0xFF:
            value = 1
        elif byte == 0x00:
            value = 0
        else:
            raise error.PyAsn1Error("Unexpected Boolean payload", payload=byte)
        return self._createComponent(asn1Spec, tagSet, value, **options), tail


class CanonicalStringDecoderMixIn:
    """Reject string encoding forms X.690 9.1 and 9.2 do not admit.

    BER lets a sender split a string wherever it likes, or not at all, so one
    value has many spellings. CER admits one: primitive up to 1000 contents
    octets, and past that a constructed encoding of primitive fragments, all
    but the last of them exactly 1000 contents octets long. 9.1 pins the
    length form of the constructed encoding to the indefinite one.
    """

    fragmentSize = 1000

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        # This is the definite length path, so a constructed encoding reaching
        # it already contradicts 9.1 whatever its fragments turn out to hold.
        # A decoder that bars the constructed form outright, as DER does under
        # 10.2, has a more specific complaint to make, so defer to it.
        if (
            getattr(self, "supportConstructedForm", True)
            and not substrateFun
            and tagSet
            and tagSet[0].tagFormat != tag.tagFormatSimple
        ):
            raise error.PyAsn1Error(
                "Constructed string encoding must use the indefinite length form",
                decoder=self.__class__.__name__,
            )

        return super().valueDecoder(  # type: ignore[misc]
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    def indefLenValueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        # A caller collecting raw substrate is assembling an outer value and
        # never sees the fragments as such, so leave those to their own decode.
        if not substrateFun and decodeFun:
            self._verifyFragments(substrate, decodeFun, options)

        return super().indefLenValueDecoder(  # type: ignore[misc]
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    def _verifyFragments(
        self, substrate: bytes, decodeFun: Any, options: dict[str, Any]
    ) -> None:
        sizes = []

        while substrate:
            # 9.2 admits primitive fragments only, so a constructed identifier
            # octet is wrong however well formed the encoding beneath it is.
            if substrate[0] & 0x20:
                raise error.PyAsn1Error(
                    "String fragment must use the primitive encoding form",
                    decoder=self.__class__.__name__,
                )

            component, substrate = decodeFun(
                substrate,
                self.fragmentComponent,  # type: ignore[attr-defined]
                substrateFun=self.substrateCollector,  # type: ignore[attr-defined]
                allowEoo=True,
                **options,
            )

            if component is eoo.endOfOctets:
                break

            sizes.append(len(component))

        else:
            # Nothing closed the encoding; the base decoder reports that.
            return

        # One fragment carries no more than 1000 octets, which 9.2 requires to
        # have been sent primitively. Two is the shortest conforming split.
        if len(sizes) < 2:
            raise error.PyAsn1Error(
                "String of no more than 1000 octets must use the primitive "
                "encoding form",
                fragments=len(sizes),
                decoder=self.__class__.__name__,
            )

        for size in sizes[:-1]:
            if size != self.fragmentSize:
                raise error.PyAsn1Error(
                    "String fragment before the last carries the wrong "
                    "number of contents octets",
                    fragmentSize=size,
                    expectedSize=self.fragmentSize,
                    decoder=self.__class__.__name__,
                )

        if not 1 <= sizes[-1] <= self.fragmentSize:
            raise error.PyAsn1Error(
                "Last string fragment carries the wrong number of contents octets",
                fragmentSize=sizes[-1],
                maxSize=self.fragmentSize,
                decoder=self.__class__.__name__,
            )


class BitStringDecoder(decoder.BitStringDecoder):
    """BIT STRING decoder enforcing X.690 11.2.1.

    BER leaves the unused bits in the final octet to the sender, so two
    encodings of the same value can differ in bits nobody reads. CER and DER
    close that off: "Each unused bit in the final octet of the encoding of a
    bit string value shall be set to zero."
    """

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        if not substrateFun and tagSet and tagSet[0].tagFormat == tag.tagFormatSimple:
            self._verifyUnusedBitsAreZero(substrate[:length])

        return super().valueDecoder(
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

    @staticmethod
    def _verifyUnusedBitsAreZero(head: bytes) -> None:
        # An initial octet on its own carries no bits to pad, and a count
        # above seven is the base decoder's to reject.
        if len(head) < 2:
            return

        unusedBits = head[0]
        if unusedBits and unusedBits < 8 and head[-1] & ((1 << unusedBits) - 1):
            raise error.PyAsn1Error(
                "Unused bits in the final octet of a BIT STRING must be zero",
                unusedBits=unusedBits,
                finalOctet=head[-1],
            )


class CanonicalTimeDecoderMixIn:
    """Reject time values X.690 11.7 and 11.8 do not admit.

    BER accepts local time, an omitted seconds element, hour 24 for midnight
    and fractional seconds padded with zeros, so one instant has many
    spellings. CER and DER admit one, and the type knows how to check it.
    """

    def valueDecoder(
        self,
        substrate: bytes,
        asn1Spec: Any,
        tagSet: Any = None,
        length: int | None = None,
        state: Any = None,
        decodeFun: Any = None,
        substrateFun: Any = None,
        **options: Any,
    ) -> tuple[Any, bytes]:
        component, tail = super().valueDecoder(  # type: ignore[misc]
            substrate,
            asn1Spec,
            tagSet,
            length,
            state,
            decodeFun,
            substrateFun,
            **options,
        )

        if isinstance(component, useful.TimeMixIn):
            component.verifyCanonicalForm()

        return component, tail


class GeneralizedTimeDecoder(
    CanonicalStringDecoderMixIn,
    CanonicalTimeDecoderMixIn,
    decoder.GeneralizedTimeDecoder,
):
    pass


class UTCTimeDecoder(
    CanonicalStringDecoderMixIn, CanonicalTimeDecoderMixIn, decoder.UTCTimeDecoder
):
    pass


class OctetStringDecoder(CanonicalStringDecoderMixIn, decoder.OctetStringDecoder):
    pass


# 9.2 names bitstring, octetstring and the restricted character string types.
# The parent codec derives all of these from its own OctetStringDecoder, so
# each needs its own subclass here for the restriction to reach it.
class UTF8StringDecoder(CanonicalStringDecoderMixIn, decoder.UTF8StringDecoder):
    pass


class NumericStringDecoder(CanonicalStringDecoderMixIn, decoder.NumericStringDecoder):
    pass


class PrintableStringDecoder(
    CanonicalStringDecoderMixIn, decoder.PrintableStringDecoder
):
    pass


class TeletexStringDecoder(CanonicalStringDecoderMixIn, decoder.TeletexStringDecoder):
    pass


class VideotexStringDecoder(CanonicalStringDecoderMixIn, decoder.VideotexStringDecoder):
    pass


class IA5StringDecoder(CanonicalStringDecoderMixIn, decoder.IA5StringDecoder):
    pass


class GraphicStringDecoder(CanonicalStringDecoderMixIn, decoder.GraphicStringDecoder):
    pass


class VisibleStringDecoder(CanonicalStringDecoderMixIn, decoder.VisibleStringDecoder):
    pass


class GeneralStringDecoder(CanonicalStringDecoderMixIn, decoder.GeneralStringDecoder):
    pass


class UniversalStringDecoder(
    CanonicalStringDecoderMixIn, decoder.UniversalStringDecoder
):
    pass


class BMPStringDecoder(CanonicalStringDecoderMixIn, decoder.BMPStringDecoder):
    pass


class ObjectDescriptorDecoder(
    CanonicalStringDecoderMixIn, decoder.ObjectDescriptorDecoder
):
    pass


tagMap: Final = decoder.tagMap.copy()
tagMap.update(
    {
        univ.Integer.tagSet: IntegerDecoder(),
        univ.Enumerated.tagSet: IntegerDecoder(),
        univ.Boolean.tagSet: BooleanDecoder(),
        univ.BitString.tagSet: BitStringDecoder(),
        univ.OctetString.tagSet: OctetStringDecoder(),
        univ.Real.tagSet: RealDecoder(),
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
        useful.ObjectDescriptor.tagSet: ObjectDescriptorDecoder(),
        useful.GeneralizedTime.tagSet: GeneralizedTimeDecoder(),
        useful.UTCTime.tagSet: UTCTimeDecoder(),
    }
)

typeMap: Final = decoder.typeMap.copy()

# Put in non-ambiguous types for faster codec lookup.
# This map starts as a copy of the parent codec's, so an entry already
# exists for every type overridden above. The override has to win: guarding
# on absence would leave the parent's laxer decoder in place.
for typeDecoder in tagMap.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None:
            typeMap[typeId] = typeDecoder


class Decoder(decoder.Decoder):
    # X.690 9.1: a constructed encoding takes the indefinite form, and a
    # primitive one the fewest length octets.
    requireMinimalLength = True
    requireIndefLengthForConstructed = True
    requireLowTagNumberForm = True


#: Turns CER octet stream into an ASN.1 object.
#:
#: Takes CER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes` (Python 3) or :py:class:`str` (Python 2)
#:     CER octet-stream
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
#:     A tuple of pyasn1 object recovered from CER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode CER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode CER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode: Final = Decoder(tagMap, typeMap)
