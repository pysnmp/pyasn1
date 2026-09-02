#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Character-string ASN.1 types."""

from collections.abc import Iterator
from typing import Any, Final

from pyasn1 import error
from pyasn1.type import tag, univ

__all__ = [
    "BMPString",
    "GeneralString",
    "GraphicString",
    "IA5String",
    "ISO646String",
    "NumericString",
    "PrintableString",
    "T61String",
    "TeletexString",
    "UTF8String",
    "UniversalString",
    "VideotexString",
    "VisibleString",
]

NoValue = univ.NoValue
noValue: Final = univ.noValue


class AbstractCharacterString(univ.OctetString):
    """Creates |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`,
    its objects are immutable and duck-type Python :class:`bytes`.
    When used in octet-stream context, |ASN.1| type assumes
    "|encoding|" encoding.

    Keyword Args
    ------------
    value: :class:`str`, :class:`bytes` or |ASN.1| object
        :class:`str` or :class:`bytes`
        representing octet-stream of serialised unicode string
        (note `encoding` parameter) or |ASN.1| class instance.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    encoding: :py:class:`str`
        Unicode codec ID to encode/decode :class:`str`
        the payload when |ASN.1| object is used
        in octet-stream context.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.
    """

    def __str__(self) -> str:
        return str(self._value)

    def __bytes__(self) -> bytes:
        try:
            return self._value.encode(self.encoding)
        except UnicodeEncodeError as exc:
            raise error.PyAsn1UnicodeEncodeError(
                "Can't encode string with codec",
                exc,
                value=self._value,
                codec=self.encoding,
            ) from exc

    def prettyIn(self, value: Any) -> str:
        try:
            if isinstance(value, str):
                return value
            elif isinstance(value, bytes):
                return value.decode(self.encoding)
            elif isinstance(value, tuple | list):
                return self.prettyIn(bytes(value))
            elif isinstance(value, univ.OctetString):
                return value.asOctets().decode(self.encoding)
            else:
                return str(value)

        except (UnicodeDecodeError, LookupError) as exc:
            raise error.PyAsn1UnicodeDecodeError(
                "Can't decode string with codec",
                exc,
                value=value,
                codec=self.encoding,
            ) from exc

    def asOctets(self, padding: bool = True) -> bytes:
        return bytes(self)

    def asNumbers(self, padding: bool = True) -> tuple[int, ...]:
        return tuple(bytes(self))

    #
    # See OctetString.prettyPrint() for the explanation
    #

    def prettyOut(self, value: Any) -> Any:
        return value

    def prettyPrint(self, scope: int = 0) -> str:
        # first see if subclass has its own .prettyOut()
        value = self.prettyOut(self._value)

        if value is not self._value:
            return value

        return AbstractCharacterString.__str__(self)

    def __reversed__(self) -> Iterator[str]:
        return reversed(self._value)


class NumericString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 18)
    )
    encoding = "us-ascii"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class PrintableString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 19)
    )
    encoding = "us-ascii"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class TeletexString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 20)
    )
    encoding = "iso-8859-1"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class T61String(TeletexString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = TeletexString.__doc__

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class VideotexString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 21)
    )
    encoding = "iso-8859-1"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class IA5String(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 22)
    )
    encoding = "us-ascii"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class GraphicString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 25)
    )
    encoding = "iso-8859-1"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class VisibleString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 26)
    )
    encoding = "us-ascii"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class ISO646String(VisibleString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = VisibleString.__doc__

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class GeneralString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 27)
    )
    encoding = "iso-8859-1"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class UniversalString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 28)
    )
    encoding = "utf-32-be"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class BMPString(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 30)
    )
    encoding = "utf-16-be"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()


class UTF8String(AbstractCharacterString):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = AbstractCharacterString.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = AbstractCharacterString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 12)
    )
    encoding = "utf-8"

    # Optimization for faster codec lookup
    typeId = AbstractCharacterString.getTypeId()
