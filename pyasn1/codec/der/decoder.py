#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""DER decoder for ASN.1 types."""

from typing import Final

from pyasn1.codec.cer import decoder
from pyasn1.type import char, univ, useful

__all__ = ["decode"]


# X.690 10.2: "For bitstring, octetstring and restricted character string
# types, the constructed form of encoding shall not be used." The parent codec
# derives every restricted character string decoder from its own
# OctetStringDecoder, so each needs its own subclass here to be covered.
class BitStringDecoder(decoder.BitStringDecoder):
    supportConstructedForm = False


class OctetStringDecoder(decoder.OctetStringDecoder):
    supportConstructedForm = False


class UTF8StringDecoder(decoder.UTF8StringDecoder):
    supportConstructedForm = False


class NumericStringDecoder(decoder.NumericStringDecoder):
    supportConstructedForm = False


class PrintableStringDecoder(decoder.PrintableStringDecoder):
    supportConstructedForm = False


class TeletexStringDecoder(decoder.TeletexStringDecoder):
    supportConstructedForm = False


class VideotexStringDecoder(decoder.VideotexStringDecoder):
    supportConstructedForm = False


class IA5StringDecoder(decoder.IA5StringDecoder):
    supportConstructedForm = False


class GraphicStringDecoder(decoder.GraphicStringDecoder):
    supportConstructedForm = False


class VisibleStringDecoder(decoder.VisibleStringDecoder):
    supportConstructedForm = False


class GeneralStringDecoder(decoder.GeneralStringDecoder):
    supportConstructedForm = False


class UniversalStringDecoder(decoder.UniversalStringDecoder):
    supportConstructedForm = False


class BMPStringDecoder(decoder.BMPStringDecoder):
    supportConstructedForm = False


class ObjectDescriptorDecoder(decoder.ObjectDescriptorDecoder):
    supportConstructedForm = False


class GeneralizedTimeDecoder(decoder.GeneralizedTimeDecoder):
    supportConstructedForm = False


class UTCTimeDecoder(decoder.UTCTimeDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealDecoder = decoder.RealDecoder

tagMap: Final = decoder.tagMap.copy()
tagMap.update(
    {
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
    supportIndefLength = False

    # X.690 10.1: the definite form throughout, so the CER rule that pushes
    # constructed encodings onto the indefinite form does not carry over.
    requireIndefLengthForConstructed = False


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes` (Python 3) or :py:class:`str` (Python 2)
#:     DER octet-stream
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
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
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
