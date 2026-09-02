#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""CER decoder for ASN.1 types."""

from typing import Any, Final

from pyasn1 import error
from pyasn1.codec.ber import decoder
from pyasn1.type import tag, univ, useful

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


class GeneralizedTimeDecoder(CanonicalTimeDecoderMixIn, decoder.GeneralizedTimeDecoder):
    pass


class UTCTimeDecoder(CanonicalTimeDecoderMixIn, decoder.UTCTimeDecoder):
    pass


# TODO: prohibit non-canonical encoding
OctetStringDecoder = decoder.OctetStringDecoder
RealDecoder = decoder.RealDecoder

tagMap: Final = decoder.tagMap.copy()
tagMap.update(
    {
        univ.Integer.tagSet: IntegerDecoder(),
        univ.Enumerated.tagSet: IntegerDecoder(),
        univ.Boolean.tagSet: BooleanDecoder(),
        univ.BitString.tagSet: BitStringDecoder(),
        univ.OctetString.tagSet: OctetStringDecoder(),
        univ.Real.tagSet: RealDecoder(),
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
    pass


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
