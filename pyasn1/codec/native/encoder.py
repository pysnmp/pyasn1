#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import logging
from collections.abc import Callable
from typing import Any, Final

from pyasn1 import debug, error
from pyasn1.type import base, char, tag, univ, useful

__all__ = ["encode"]

LOG = logging.getLogger(__name__)


class AbstractItemEncoder:
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        raise error.PyAsn1Error("Not implemented")


class BooleanEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return bool(value)


class IntegerEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return int(value)


class BitStringEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return str(value)


class OctetStringEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return value.asOctets()


class TextStringEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return str(value)


class NullEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return None


class ObjectIdentifierEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return str(value)


class RealEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return float(value)


class SetEncoder(AbstractItemEncoder):
    protoDict = dict

    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        inconsistency = value.isInconsistent
        if inconsistency:
            raise inconsistency

        namedTypes = value.componentType
        substrate = self.protoDict()

        for idx, (key, subValue) in enumerate(value.items()):
            if namedTypes and namedTypes[idx].isOptional and not value[idx].isValue:
                continue
            substrate[key] = encodeFun(subValue, **options)
        return substrate


class SequenceEncoder(SetEncoder):
    protoDict = dict


class SequenceOfEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        inconsistency = value.isInconsistent
        if inconsistency:
            raise inconsistency
        return [encodeFun(x, **options) for x in value]


class ChoiceEncoder(SequenceEncoder):
    pass


class AnyEncoder(AbstractItemEncoder):
    def encode(self, value: Any, encodeFun: Callable[..., Any], **options: Any) -> Any:
        return value.asOctets()


tagMap: Final[dict[tag.TagSet, AbstractItemEncoder]] = {
    univ.Boolean.tagSet: BooleanEncoder(),
    univ.Integer.tagSet: IntegerEncoder(),
    univ.BitString.tagSet: BitStringEncoder(),
    univ.OctetString.tagSet: OctetStringEncoder(),
    univ.Null.tagSet: NullEncoder(),
    univ.ObjectIdentifier.tagSet: ObjectIdentifierEncoder(),
    univ.Enumerated.tagSet: IntegerEncoder(),
    univ.Real.tagSet: RealEncoder(),
    # Sequence & Set have same tags as SequenceOf & SetOf
    univ.SequenceOf.tagSet: SequenceOfEncoder(),
    univ.SetOf.tagSet: SequenceOfEncoder(),
    univ.Choice.tagSet: ChoiceEncoder(),
    # character string types
    char.UTF8String.tagSet: TextStringEncoder(),
    char.NumericString.tagSet: TextStringEncoder(),
    char.PrintableString.tagSet: TextStringEncoder(),
    char.TeletexString.tagSet: TextStringEncoder(),
    char.VideotexString.tagSet: TextStringEncoder(),
    char.IA5String.tagSet: TextStringEncoder(),
    char.GraphicString.tagSet: TextStringEncoder(),
    char.VisibleString.tagSet: TextStringEncoder(),
    char.GeneralString.tagSet: TextStringEncoder(),
    char.UniversalString.tagSet: TextStringEncoder(),
    char.BMPString.tagSet: TextStringEncoder(),
    # useful types
    useful.ObjectDescriptor.tagSet: OctetStringEncoder(),
    useful.GeneralizedTime.tagSet: OctetStringEncoder(),
    useful.UTCTime.tagSet: OctetStringEncoder(),
}


# Put in ambiguous & non-ambiguous types for faster codec lookup
typeMap: Final[dict[int, AbstractItemEncoder]] = {
    univ.Boolean.typeId: BooleanEncoder(),
    univ.Integer.typeId: IntegerEncoder(),
    univ.BitString.typeId: BitStringEncoder(),
    univ.OctetString.typeId: OctetStringEncoder(),
    univ.Null.typeId: NullEncoder(),
    univ.ObjectIdentifier.typeId: ObjectIdentifierEncoder(),
    univ.Enumerated.typeId: IntegerEncoder(),
    univ.Real.typeId: RealEncoder(),
    # Sequence & Set have same tags as SequenceOf & SetOf
    univ.Set.typeId: SetEncoder(),
    univ.SetOf.typeId: SequenceOfEncoder(),
    univ.Sequence.typeId: SequenceEncoder(),
    univ.SequenceOf.typeId: SequenceOfEncoder(),
    univ.Choice.typeId: ChoiceEncoder(),
    univ.Any.typeId: AnyEncoder(),
    # character string types
    char.UTF8String.typeId: OctetStringEncoder(),
    char.NumericString.typeId: OctetStringEncoder(),
    char.PrintableString.typeId: OctetStringEncoder(),
    char.TeletexString.typeId: OctetStringEncoder(),
    char.VideotexString.typeId: OctetStringEncoder(),
    char.IA5String.typeId: OctetStringEncoder(),
    char.GraphicString.typeId: OctetStringEncoder(),
    char.VisibleString.typeId: OctetStringEncoder(),
    char.GeneralString.typeId: OctetStringEncoder(),
    char.UniversalString.typeId: OctetStringEncoder(),
    char.BMPString.typeId: OctetStringEncoder(),
    # useful types
    useful.ObjectDescriptor.typeId: OctetStringEncoder(),
    useful.GeneralizedTime.typeId: OctetStringEncoder(),
    useful.UTCTime.typeId: OctetStringEncoder(),
}


class Encoder:
    def __init__(
        self,
        tagMap: dict[tag.TagSet, AbstractItemEncoder],
        typeMap: dict[int, AbstractItemEncoder] | None = None,
    ) -> None:
        self.__tagMap = tagMap
        self.__typeMap = typeMap if typeMap is not None else {}

    def __call__(self, value: base.Asn1Type, **options: Any) -> Any:
        if not isinstance(value, base.Asn1Item):
            raise error.PyAsn1Error(
                "value is not valid (should be an instance of an ASN.1 Item)"
            )

        if LOG.isEnabledFor(logging.DEBUG):
            debug.scope.push(type(value).__name__)
            LOG.debug(
                "encoder called",
                extra={"valueType": type(value).__name__, "value": value.prettyPrint()},
            )

        tagSet = value.tagSet

        try:
            concreteEncoder = self.__typeMap[value.typeId]

        except KeyError:
            # use base type for codec lookup to recover untagged types
            baseTagSet = tag.TagSet(value.tagSet.baseTag, value.tagSet.baseTag)

            try:
                concreteEncoder = self.__tagMap[baseTagSet]

            except KeyError as exc:
                raise error.PyAsn1Error("No encoder for %s" % (value,)) from exc

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "using value codec chosen by tagSet",
                extra={
                    "codec": concreteEncoder.__class__.__name__,
                    "tagSet": tagSet,
                },
            )

        pyObject = concreteEncoder.encode(value, self, **options)

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "encoder produced value",
                extra={"codec": type(concreteEncoder).__name__, "pyObject": pyObject},
            )
            debug.scope.pop()

        return pyObject


#: Turns ASN.1 object into a Python built-in type object(s).
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a Python built-in type or a tree
#: of those.
#:
#: One exception is that :py:class:`dict` preserves ordering of the components
#: in ASN.1 SEQUENCE (since Python 3.7+).
#:
#: Parameters
#: ----------
#  asn1Value: any pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     pyasn1 object to encode (or a tree of them)
#:
#: Returns
#: -------
#: : :py:class:`object`
#:     Python built-in type instance (or a tree of them)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode ASN.1 value object into native Python types
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    [1, 2, 3]
#:
encode: Final = Encoder(tagMap, typeMap)
