#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""ASN.1 universal types: Integer, OctetString, Sequence, Choice and friends."""

import math
import typing
import warnings
from collections.abc import Iterator
from typing import Final

from pyasn1 import error
from pyasn1.codec.ber import eoo
from pyasn1.type import base, constraint, namedtype, namedval, tag, tagmap


def _int_to_bytes(value: int, signed: bool = False, length: int = 0) -> bytes:
    """Convert an integer to bytes with the same logic as the former compat.integer.to_bytes."""
    length = max(value.bit_length(), length)
    if signed and length % 8 == 0:
        length += 1
    return value.to_bytes((length + 7) // 8, "big", signed=signed)


NoValue = base.NoValue
noValue: Final = NoValue()

__all__ = [
    "Any",
    "BitString",
    "Boolean",
    "Choice",
    "Enumerated",
    "Integer",
    "NoValue",
    "Null",
    "ObjectIdentifier",
    "OctetString",
    "Real",
    "Sequence",
    "SequenceAndSetBase",
    "SequenceOf",
    "SequenceOfAndSetOfBase",
    "Set",
    "SetOf",
    "noValue",
]

# "Simple" ASN.1 types (yet incomplete)


class Integer(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`int` objects.

    Keyword Args
    ------------
    value: :class:`int`, :class:`str` or |ASN.1| object
        Python :class:`int` or :class:`str` literal or |ASN.1| class
        instance. If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    namedValues: :py:class:`~pyasn1.type.namedval.NamedValues`
        Object representing non-default symbolic aliases for numbers

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------

    .. code-block:: python

        class ErrorCode(Integer):
            '''
            ASN.1 specification:

            ErrorCode ::=
                INTEGER { disk-full(1), no-disk(-1),
                          disk-not-formatted(2) }

            error ErrorCode ::= disk-full
            '''
            namedValues = NamedValues(
                ('disk-full', 1), ('no-disk', -1),
                ('disk-not-formatted', 2)
            )

        error = ErrorCode('disk-full')
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    #: Default :py:class:`~pyasn1.type.namedval.NamedValues` object
    #: representing symbolic aliases for numbers
    namedValues = namedval.NamedValues()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    def __init__(self, value: typing.Any = noValue, **kwargs: typing.Any) -> None:
        if "namedValues" not in kwargs:
            kwargs["namedValues"] = self.namedValues

        base.SimpleAsn1Type.__init__(self, value, **kwargs)

    def __and__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value & value)

    def __rand__(self, value: typing.Any) -> typing.Any:
        return self.clone(value & self._value)

    def __or__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value | value)

    def __ror__(self, value: typing.Any) -> typing.Any:
        return self.clone(value | self._value)

    def __xor__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value ^ value)

    def __rxor__(self, value: typing.Any) -> typing.Any:
        return self.clone(value ^ self._value)

    def __lshift__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value << value)

    def __rshift__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value >> value)

    def __add__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value + value)

    def __radd__(self, value: typing.Any) -> typing.Any:
        return self.clone(value + self._value)

    def __sub__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value - value)

    def __rsub__(self, value: typing.Any) -> typing.Any:
        return self.clone(value - self._value)

    def __mul__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value * value)

    def __rmul__(self, value: typing.Any) -> typing.Any:
        return self.clone(value * self._value)

    def __mod__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value % value)

    def __rmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(value % self._value)

    def __pow__(self, value: typing.Any, modulo: typing.Any = None) -> typing.Any:
        return self.clone(pow(self._value, value, modulo))

    def __rpow__(self, value: typing.Any) -> typing.Any:
        return self.clone(pow(value, self._value))

    def __floordiv__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value // value)

    def __rfloordiv__(self, value: typing.Any) -> typing.Any:
        return self.clone(value // self._value)

    def __truediv__(self, value: typing.Any) -> typing.Any:
        return Real(self._value / value)

    def __rtruediv__(self, value: typing.Any) -> typing.Any:
        return Real(value / self._value)

    def __divmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(divmod(self._value, value))

    def __rdivmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(divmod(value, self._value))

    __hash__ = base.SimpleAsn1Type.__hash__

    def __int__(self) -> int:
        return int(self._value)

    def __float__(self) -> float:
        return float(self._value)

    def __abs__(self) -> typing.Any:
        return self.clone(abs(self._value))

    def __index__(self) -> int:
        return int(self._value)

    def __pos__(self) -> typing.Any:
        return self.clone(+self._value)

    def __neg__(self) -> typing.Any:
        return self.clone(-self._value)

    def __invert__(self) -> typing.Any:
        return self.clone(~self._value)

    def __round__(self, n: int = 0) -> typing.Any:
        r = round(self._value, n)
        if n:
            return self.clone(r)
        else:
            return r

    def __floor__(self) -> int:
        return math.floor(self._value)

    def __ceil__(self) -> int:
        return math.ceil(self._value)

    def __trunc__(self) -> int:
        return self.clone(math.trunc(self._value))

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into a plain :class:`int`.

        Parameters
        ----------
        value: :class:`int`, :class:`str` or |ASN.1| object
            Value to coerce. A :class:`str` is first looked up among
            `namedValues` if it cannot be parsed as an integer.

        Returns
        -------
        : :class:`int`
            The coerced integer value.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If `value` can be coerced to neither an :class:`int` nor a
            known named value.
        """
        try:
            return int(value)

        except ValueError:
            try:
                return self.namedValues[value]

            except KeyError as exc:
                raise error.PyAsn1Error(
                    f"Can't coerce {value!r} into integer: {exc}"
                ) from exc

    def prettyOut(self, value: typing.Any) -> typing.Any:
        """Return the human-friendly text representation of `value`.

        Parameters
        ----------
        value: :class:`int`
            Value to render, looked up among `namedValues` first.

        Returns
        -------
        : :class:`str`
            The named value alias if one is defined, otherwise `str(value)`.
        """
        try:
            return str(self.namedValues[value])

        except KeyError:
            return str(value)


class Boolean(Integer):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`int` objects.

    Keyword Args
    ------------
    value: :class:`int`, :class:`str` or |ASN.1| object
        Python :class:`int` or :class:`str` literal or |ASN.1| class
        instance. If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s).Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    namedValues: :py:class:`~pyasn1.type.namedval.NamedValues`
        Object representing non-default symbolic aliases for numbers

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class RoundResult(Boolean):
            '''
            ASN.1 specification:

            RoundResult ::= BOOLEAN

            ok RoundResult ::= TRUE
            ko RoundResult ::= FALSE
            '''
        ok = RoundResult(True)
        ko = RoundResult(False)
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x01),
    )

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = Integer.subtypeSpec + constraint.SingleValueConstraint(0, 1)

    #: Default :py:class:`~pyasn1.type.namedval.NamedValues` object
    #: representing symbolic aliases for numbers
    namedValues = namedval.NamedValues(("False", 0), ("True", 1))

    # Optimization for faster codec lookup
    typeId = Integer.getTypeId()


SizedIntegerBase = int


class SizedInteger(SizedIntegerBase):
    bitLength = leadingZeroBits = None

    def setBitLength(self, bitLength: int) -> typing.Any:
        self.bitLength = bitLength
        self.leadingZeroBits = max(bitLength - self.bit_length(), 0)
        return self

    def __len__(self) -> int:
        if self.bitLength is None:
            self.setBitLength(self.bit_length())

        return typing.cast(int, self.bitLength)


class BitString(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type both Python :class:`tuple` (as a tuple
    of bits) and :class:`int` objects.

    Keyword Args
    ------------
    value: :class:`int`, :class:`str` or |ASN.1| object
        Python :class:`int` or :class:`str` literal representing binary
        or hexadecimal number or sequence of integer bits or |ASN.1| object.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    namedValues: :py:class:`~pyasn1.type.namedval.NamedValues`
        Object representing non-default symbolic aliases for numbers

    binValue: :py:class:`str`
        Binary string initializer to use instead of the *value*.
        Example: '10110011'.

    hexValue: :py:class:`str`
        Hexadecimal string initializer to use instead of the *value*.
        Example: 'DEADBEEF'.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class Rights(BitString):
            '''
            ASN.1 specification:

            Rights ::= BIT STRING { user-read(0), user-write(1),
                                    group-read(2), group-write(3),
                                    other-read(4), other-write(5) }

            group1 Rights ::= { group-read, group-write }
            group2 Rights ::= '0011'B
            group3 Rights ::= '3'H
            '''
            namedValues = NamedValues(
                ('user-read', 0), ('user-write', 1),
                ('group-read', 2), ('group-write', 3),
                ('other-read', 4), ('other-write', 5)
            )

        group1 = Rights(('group-read', 'group-write'))
        group2 = Rights('0011')
        group3 = Rights(0x3)
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x03))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    #: Default :py:class:`~pyasn1.type.namedval.NamedValues` object
    #: representing symbolic aliases for numbers
    namedValues = namedval.NamedValues()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    defaultBinValue = defaultHexValue = noValue

    def __init__(self, value: typing.Any = noValue, **kwargs: typing.Any) -> None:
        if value is noValue:
            if kwargs:
                try:
                    value = self.fromBinaryString(
                        kwargs.pop("binValue"), internalFormat=True
                    )

                except KeyError:
                    pass

                try:
                    value = self.fromHexString(
                        kwargs.pop("hexValue"), internalFormat=True
                    )

                except KeyError:
                    pass

        if value is noValue:
            if self.defaultBinValue is not noValue:
                value = self.fromBinaryString(self.defaultBinValue, internalFormat=True)

            elif self.defaultHexValue is not noValue:
                value = self.fromHexString(self.defaultHexValue, internalFormat=True)

        if "namedValues" not in kwargs:
            kwargs["namedValues"] = self.namedValues

        base.SimpleAsn1Type.__init__(self, value, **kwargs)

    def __str__(self) -> str:
        return self.asBinary()

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        value = self._cmpValue("__eq__")
        otherValue = self.prettyIn(other)
        return value == otherValue and len(value) == len(otherValue)

    def __ne__(self, other: object) -> bool:
        if self is other:
            return False

        value = self._cmpValue("__ne__")
        otherValue = self.prettyIn(other)
        return value != otherValue or len(value) != len(otherValue)

    def __lt__(self, other: typing.Any) -> bool:
        value = self._cmpValue("__lt__")
        other = self.prettyIn(other)
        return len(value) < len(other) or len(value) == len(other) and value < other

    def __le__(self, other: typing.Any) -> bool:
        value = self._cmpValue("__le__")
        other = self.prettyIn(other)
        return len(value) <= len(other) or len(value) == len(other) and value <= other

    def __gt__(self, other: typing.Any) -> bool:
        value = self._cmpValue("__gt__")
        other = self.prettyIn(other)
        return len(value) > len(other) or len(value) == len(other) and value > other

    def __ge__(self, other: typing.Any) -> bool:
        value = self._cmpValue("__ge__")
        other = self.prettyIn(other)
        return len(value) >= len(other) or len(value) == len(other) and value >= other

    # Immutable sequence object protocol

    def __len__(self) -> int:
        return len(self._value)

    def __getitem__(self, i: typing.Any) -> typing.Any:
        if i.__class__ is slice:
            return self.clone([self[x] for x in range(*i.indices(len(self)))])
        else:
            length = len(self._value) - 1
            if i > length or i < 0:
                raise IndexError("bit index out of range")
            return (self._value >> (length - i)) & 1

    def __iter__(self) -> Iterator[typing.Any]:
        length = len(self._value)
        while length:
            length -= 1
            yield (self._value >> length) & 1

    def __reversed__(self) -> Iterator[typing.Any]:
        return reversed(tuple(self))

    # arithmetic operators

    def __add__(self, value: typing.Any) -> typing.Any:
        value = self.prettyIn(value)
        return self.clone(
            SizedInteger(self._value << len(value) | value).setBitLength(
                len(self._value) + len(value)
            )
        )

    def __radd__(self, value: typing.Any) -> typing.Any:
        value = self.prettyIn(value)
        return self.clone(
            SizedInteger(value << len(self._value) | self._value).setBitLength(
                len(self._value) + len(value)
            )
        )

    def __mul__(self, value: typing.Any) -> typing.Any:
        bitString = self._value
        while value > 1:
            bitString <<= len(self._value)
            bitString |= self._value
            value -= 1
        return self.clone(bitString)

    def __rmul__(self, value: typing.Any) -> typing.Any:
        return self * value

    def __lshift__(self, count: typing.Any) -> typing.Any:
        return self.clone(
            SizedInteger(self._value << count).setBitLength(len(self._value) + count)
        )

    def __rshift__(self, count: typing.Any) -> typing.Any:
        return self.clone(
            SizedInteger(self._value >> count).setBitLength(
                max(0, len(self._value) - count)
            )
        )

    def __int__(self) -> int:
        return int(self._cmpValue("__int__"))

    def __float__(self) -> float:
        return float(self._cmpValue("__float__"))

    def asNumbers(self) -> tuple[int, ...]:
        """Get |ASN.1| value as a sequence of 8-bit integers.

        If |ASN.1| object length is not a multiple of 8, result
        will be left-padded with zeros.
        """
        return tuple(self.asOctets())

    def asOctets(self) -> bytes:
        """Get |ASN.1| value as a sequence of octets.

        If |ASN.1| object length is not a multiple of 8, result
        will be left-padded with zeros.
        """
        return _int_to_bytes(self._value, length=len(self))

    def asInteger(self) -> int:
        """Get |ASN.1| value as a single integer value."""
        return self._value

    def asBinary(self) -> str:
        """Get |ASN.1| value as a text string of bits."""
        binString = bin(self._value)[2:]
        return "0" * (len(self._value) - len(binString)) + binString

    @classmethod
    def fromHexString(
        cls, value: typing.Any, internalFormat: bool = False, prepend: typing.Any = None
    ) -> typing.Any:
        """Create a |ASN.1| object initialized from the hex string.

        Parameters
        ----------
        value: :class:`str`
            Text string like 'DEADBEEF'
        """
        try:
            value = SizedInteger(value, 16).setBitLength(len(value) * 4)

        except ValueError as exc:
            raise error.PyAsn1Error(
                f"{cls.__name__}.fromHexString() error: {exc}"
            ) from exc

        if prepend is not None:
            value = SizedInteger(
                (SizedInteger(prepend) << len(value)) | value
            ).setBitLength(len(prepend) + len(value))

        if not internalFormat:
            value = cls(value)

        return value

    @classmethod
    def fromBinaryString(
        cls, value: typing.Any, internalFormat: bool = False, prepend: typing.Any = None
    ) -> typing.Any:
        """Create a |ASN.1| object initialized from a string of '0' and '1'.

        Parameters
        ----------
        value: :class:`str`
            Text string like '1010111'
        """
        try:
            value = SizedInteger(value or "0", 2).setBitLength(len(value))

        except ValueError as exc:
            raise error.PyAsn1Error(
                f"{cls.__name__}.fromBinaryString() error: {exc}"
            ) from exc

        if prepend is not None:
            value = SizedInteger(
                (SizedInteger(prepend) << len(value)) | value
            ).setBitLength(len(prepend) + len(value))

        if not internalFormat:
            value = cls(value)

        return value

    @classmethod
    def fromOctetString(
        cls,
        value: bytes,
        internalFormat: bool = False,
        prepend: typing.Any = None,
        padding: int = 0,
    ) -> typing.Any:
        r"""Create a |ASN.1| object initialized from a string.

        Parameters
        ----------
        value: :class:`str` (Py2) or :class:`bytes` (Py3)
            Text string like '\\\\x01\\\\xff' (Py2) or b'\\\\x01\\\\xff' (Py3)
        """
        bits = SizedInteger(int.from_bytes(value, "big") >> padding).setBitLength(
            len(value) * 8 - padding
        )

        if prepend is not None:
            bits = SizedInteger(
                (SizedInteger(prepend) << len(bits)) | bits
            ).setBitLength(len(prepend) + len(bits))

        if not internalFormat:
            return cls(bits)

        return bits

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into an internal :class:`SizedInteger`.

        Parameters
        ----------
        value: :class:`SizedInteger`, :class:`str`, :class:`tuple`,
        :class:`list`, |ASN.1| object or :class:`int`
            Value to coerce: a bit-position tuple/list, a binary/hex
            string (optionally prefixed with '0b'/'0x'), a comma-separated
            string of named bits, or another |ASN.1| BitString/int value.

        Returns
        -------
        : :class:`SizedInteger`
            The coerced bit string value.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If `value` is of an unsupported type or references unknown
            named bits.
        """
        if isinstance(value, SizedInteger):
            return value
        elif isinstance(value, str):
            if not value:
                return SizedInteger(0).setBitLength(0)

            elif (
                self.namedValues and not value.isdigit()
            ):  # named bits like 'Urgent, Active'
                names = [x.strip() for x in value.split(",")]

                try:
                    bitPositions = [self.namedValues[name] for name in names]

                except KeyError as exc:
                    raise error.PyAsn1Error(
                        f"unknown bit name(s) in {names!r}"
                    ) from exc

                rightmostPosition = max(bitPositions)

                number = 0
                for bitPosition in bitPositions:
                    number |= 1 << (rightmostPosition - bitPosition)

                return SizedInteger(number).setBitLength(rightmostPosition + 1)

            elif value.startswith("0x"):
                return self.fromHexString(value[2:], internalFormat=True)

            elif value.startswith("0b"):
                return self.fromBinaryString(value[2:], internalFormat=True)

            else:  # assume plain binary string like '1011'
                return self.fromBinaryString(value, internalFormat=True)

        elif isinstance(value, tuple | list):
            return self.fromBinaryString(
                "".join(["1" if b else "0" for b in value]), internalFormat=True
            )

        elif isinstance(value, BitString):
            return SizedInteger(value).setBitLength(len(value))

        elif isinstance(value, intTypes):
            return SizedInteger(value)

        else:
            raise error.PyAsn1Error(f"Bad BitString initializer type '{value}'")


class OctetString(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`bytes`.
    When used in Unicode context, |ASN.1| type
    assumes "|encoding|" serialisation.

    Keyword Args
    ------------
    value: :class:`str`, :class:`bytes` or |ASN.1| object
        :class:`bytes` representing character string to be serialised into octets
        (note `encoding` parameter) or |ASN.1| object.
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
        in text string context.

    binValue: :py:class:`str`
        Binary string initializer to use instead of the *value*.
        Example: '10110011'.

    hexValue: :py:class:`str`
        Hexadecimal string initializer to use instead of the *value*.
        Example: 'DEADBEEF'.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class Icon(OctetString):
            '''
            ASN.1 specification:

            Icon ::= OCTET STRING

            icon1 Icon ::= '001100010011001000110011'B
            icon2 Icon ::= '313233'H
            '''
        icon1 = Icon.fromBinaryString('001100010011001000110011')
        icon2 = Icon.fromHexString('313233')
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x04))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    defaultBinValue = defaultHexValue = noValue
    encoding = "iso-8859-1"

    def __init__(self, value: typing.Any = noValue, **kwargs: typing.Any) -> None:
        if kwargs:
            if value is noValue:
                try:
                    value = self.fromBinaryString(kwargs.pop("binValue"))

                except KeyError:
                    pass

                try:
                    value = self.fromHexString(kwargs.pop("hexValue"))

                except KeyError:
                    pass

        if value is noValue:
            if self.defaultBinValue is not noValue:
                value = self.fromBinaryString(self.defaultBinValue)

            elif self.defaultHexValue is not noValue:
                value = self.fromHexString(self.defaultHexValue)

        if "encoding" not in kwargs:
            kwargs["encoding"] = self.encoding

        base.SimpleAsn1Type.__init__(self, value, **kwargs)

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into plain :class:`bytes`.

        Parameters
        ----------
        value: :class:`bytes`, :class:`str`, :class:`tuple`, :class:`list`
        or |ASN.1| object
            Value to coerce. A :class:`str` is encoded with `self.encoding`.

        Returns
        -------
        : :class:`bytes`
            The coerced octet string value.

        Raises
        ------
        ~pyasn1.error.PyAsn1UnicodeEncodeError
            If `value` is a :class:`str` that cannot be encoded with
            `self.encoding`.
        """
        if isinstance(value, bytes):
            return value

        elif isinstance(value, str):
            try:
                return value.encode(self.encoding)

            except UnicodeEncodeError as exc:
                raise error.PyAsn1UnicodeEncodeError(
                    f"Can't encode string '{value}' with '{self.encoding}' codec",
                    exc,
                ) from exc
        elif isinstance(
            value, OctetString
        ):  # a shortcut, bytes() would work the same way
            return value.asOctets()

        elif isinstance(
            value, base.SimpleAsn1Type
        ):  # this mostly targets Integer objects
            return self.prettyIn(str(value))

        elif isinstance(value, tuple | list):
            return self.prettyIn(bytes(value))

        else:
            return bytes(value)

    def _asText(self) -> str:
        try:
            return self._value.decode(self.encoding)

        except UnicodeDecodeError as exc:
            raise error.PyAsn1UnicodeDecodeError(
                f"Can't decode string '{self._value}' with '{self.encoding}' codec at "
                f"'{self.__class__.__name__}'",
                exc,
            ) from exc

    def __str__(self) -> str:
        warnings.warn(
            f"str() on {self.__class__.__name__} decodes the payload as text using the '{self.encoding}' codec. "
            "A future release will return the hexadecimal representation "
            "instead -- an ASN.1 OCTET STRING is not text. Use .asOctets() "
            "for the octet stream, or .asOctets().decode(encoding) for text.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._asText()

    def __bytes__(self) -> bytes:
        return bytes(self._value)

    def asOctets(self) -> bytes:
        """Get |ASN.1| value as a sequence of octets."""
        return bytes(self._value)

    def asNumbers(self) -> tuple[int, ...]:
        """Get |ASN.1| value as a sequence of 8-bit integers."""
        return tuple(self._value)

    #
    # Normally, `.prettyPrint()` is called from `__str__()`. Historically,
    # OctetString.prettyPrint() used to return hexified payload
    # representation in cases when non-printable content is present. At the
    # same time `str()` used to produce either octet-stream (Py2) or
    # text (Py3) representations.
    #
    # Therefore `OctetString.__str__()` -> `.prettyPrint()` call chain is
    # reversed to preserve the original behaviour.
    #
    # `__str__()` now emits a DeprecationWarning: a future major release will
    # have it produce the hexified representation, leaving text and
    # octet-stream representations to be requested explicitly via
    # `.asOctets()`. Internal callers go through `._asText()` so that they do
    # not trip the warning.
    #
    # Note: ASN.1 OCTET STRING is never mean to contain text!
    #

    def prettyOut(self, value: typing.Any) -> typing.Any:
        """Return `value` unchanged.

        Parameters
        ----------
        value: :class:`bytes`
            Internal octet string value.

        Returns
        -------
        : :class:`bytes`
            The `value` argument, unchanged.
        """
        return value

    def prettyPrint(self, scope: int = 0) -> str:
        """Return a human-friendly text or hexadecimal representation of the value.

        Returns
        -------
        : :class:`str`
            The text representation if all octets are printable ASCII,
            otherwise a "0x"-prefixed hexadecimal representation.
        """
        # first see if subclass has its own .prettyOut()
        value = self.prettyOut(self._value)

        if value is not self._value:
            return value

        numbers = self.asNumbers()

        for x in numbers:
            # hexify if needed
            if x < 32 or x > 126:
                return "0x" + "".join(f"{x:02x}" for x in numbers)
        # this prevents infinite recursion
        return OctetString._asText(self)

    @staticmethod
    def fromBinaryString(value: typing.Any) -> typing.Any:
        """Create a |ASN.1| object initialized from a string of '0' and '1'.

        Parameters
        ----------
        value: :class:`str`
            Text string like '1010111'
        """
        bitNo = 8
        byte = 0
        r = []
        for v in value:
            if bitNo:
                bitNo -= 1
            else:
                bitNo = 7
                r.append(byte)
                byte = 0
            if v in ("0", "1"):
                v = int(v)
            else:
                raise error.PyAsn1Error(f"Non-binary OCTET STRING initializer {v}")
            byte |= v << bitNo

        r.append(byte)

        return bytes(r)

    @staticmethod
    def fromHexString(value: typing.Any) -> typing.Any:
        """Create a |ASN.1| object initialized from the hex string.

        Parameters
        ----------
        value: :class:`str`
            Text string like 'DEADBEEF'
        """
        r = []
        p = ""
        for v in value:
            if p:
                r.append(int(p + v, 16))
                p = ""
            else:
                p = v
        if p:
            r.append(int(p + "0", 16))

        return bytes(r)

    # Immutable sequence object protocol

    def __len__(self) -> int:
        return len(self._value)

    def __getitem__(self, i: typing.Any) -> typing.Any:
        if i.__class__ is slice:
            return self.clone(self._value[i])
        else:
            return self._value[i]

    def __iter__(self) -> Iterator[typing.Any]:
        return iter(self._value)

    def __contains__(self, value: object) -> bool:
        return value in self._value

    def __add__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value + self.prettyIn(value))

    def __radd__(self, value: typing.Any) -> typing.Any:
        return self.clone(self.prettyIn(value) + self._value)

    def __mul__(self, value: typing.Any) -> typing.Any:
        return self.clone(self._value * value)

    def __rmul__(self, value: typing.Any) -> typing.Any:
        return self * value

    def __int__(self) -> int:
        return int(self._value)

    def __float__(self) -> float:
        return float(self._value)

    def __reversed__(self) -> Iterator[typing.Any]:
        return reversed(self._value)


class Null(OctetString):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`str` objects
    (always empty).

    Keyword Args
    ------------
    value: :class:`str` or |ASN.1| object
        Python empty :class:`str` literal or any object that evaluates to :obj:`False`
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class Ack(Null):
            '''
            ASN.1 specification:

            Ack ::= NULL
            '''
        ack = Ack('')
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x05))
    subtypeSpec = OctetString.subtypeSpec + constraint.SingleValueConstraint(
        "".encode("iso-8859-1")
    )

    # Optimization for faster codec lookup
    typeId = OctetString.getTypeId()

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into an empty :class:`bytes` object.

        Parameters
        ----------
        value: :class:`object`
            Value to coerce. Any falsy value yields an empty byte string;
            any truthy value is returned unchanged (and later rejected by
            `subtypeSpec`).

        Returns
        -------
        : :class:`bytes`
            The coerced NULL value.
        """
        if value:
            return value

        return "".encode("iso-8859-1")


intTypes: Final = (int,)

numericTypes: Final = intTypes + (float,)


class ObjectIdentifier(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`tuple` objects
    (tuple of non-negative integers).

    Keyword Args
    ------------
    value: :class:`tuple`, :class:`str` or |ASN.1| object
        Python sequence of :class:`int` or :class:`str` literal or |ASN.1| object.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class ID(ObjectIdentifier):
            '''
            ASN.1 specification:

            ID ::= OBJECT IDENTIFIER

            id-edims ID ::= { joint-iso-itu-t mhs-motif(6) edims(7) }
            id-bp ID ::= { id-edims 11 }
            '''
        id_edims = ID('2.6.7')
        id_bp = id_edims + (11,)
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x06))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    def __add__(self, other: typing.Any) -> typing.Any:
        return self.clone(self._value + other)

    def __radd__(self, other: typing.Any) -> typing.Any:
        return self.clone(other + self._value)

    def asTuple(self) -> tuple[int, ...]:
        """Get |ASN.1| value as a tuple of integer sub-identifiers."""
        return self._value

    # Sequence object protocol

    def __len__(self) -> int:
        return len(self._value)

    def __getitem__(self, i: typing.Any) -> typing.Any:
        if i.__class__ is slice:
            return self.clone(self._value[i])
        else:
            return self._value[i]

    def __iter__(self) -> Iterator[typing.Any]:
        return iter(self._value)

    def __contains__(self, value: object) -> bool:
        return value in self._value

    def index(self, suboid: typing.Any) -> int:
        """Return the position of the first occurrence of `suboid`.

        Parameters
        ----------
        suboid: :class:`int`
            Sub-identifier value to look up.

        Returns
        -------
        : :class:`int`
            Zero-based position of `suboid` within this |ASN.1| object.

        Raises
        ------
        ValueError
            If `suboid` is not present.
        """
        return self._value.index(suboid)

    def isPrefixOf(self, other: typing.Any) -> bool:
        """Indicate if this |ASN.1| object is a prefix of other |ASN.1| object.

        Parameters
        ----------
        other: |ASN.1| object
            |ASN.1| object

        Returns
        -------
        : :class:`bool`
            :obj:`True` if this |ASN.1| object is a parent (e.g. prefix) of the other |ASN.1| object
            or :obj:`False` otherwise.
        """
        l = len(self)
        if l <= len(other):
            if self._value[:l] == other[:l]:
                return True
        return False

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into a tuple of non-negative integers.

        Parameters
        ----------
        value: :class:`tuple`, :class:`str` or |ASN.1| object
            A dotted-decimal string like '2.6.7', an iterable of
            non-negative integers, or another |ASN.1| ObjectIdentifier.

        Returns
        -------
        : :class:`tuple`
            The coerced tuple of sub-identifiers.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If `value` is malformed (e.g. contains a hyphen, a
            non-integer, or a negative sub-identifier).
        """
        if isinstance(value, ObjectIdentifier):
            return tuple(value)
        elif isinstance(value, str):
            if "-" in value:
                raise error.PyAsn1Error(
                    f"Malformed Object ID {value} at {self.__class__.__name__}"
                )
            try:
                return tuple([int(subOid) for subOid in value.split(".") if subOid])
            except ValueError as exc:
                raise error.PyAsn1Error(
                    f"Malformed Object ID {value} at {self.__class__.__name__}: {exc}"
                ) from exc

        try:
            tupleOfInts = tuple([int(subOid) for subOid in value if subOid >= 0])

        except (ValueError, TypeError) as exc:
            raise error.PyAsn1Error(
                f"Malformed Object ID {value} at {self.__class__.__name__}: {exc}"
            ) from exc

        if len(tupleOfInts) == len(value):
            return tupleOfInts

        raise error.PyAsn1Error(
            f"Malformed Object ID {value} at {self.__class__.__name__}"
        )

    def prettyOut(self, value: typing.Any) -> typing.Any:
        """Return the dotted-decimal text representation of `value`.

        Parameters
        ----------
        value: :class:`tuple`
            Sequence of integer sub-identifiers.

        Returns
        -------
        : :class:`str`
            Dotted-decimal string, e.g. '2.6.7'.
        """
        return ".".join([str(x) for x in value])


class Real(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`float` objects.
    Additionally, |ASN.1| objects behave like a :class:`tuple` in which case its
    elements are mantissa, base and exponent.

    Keyword Args
    ------------
    value: :class:`tuple`, :class:`float` or |ASN.1| object
        Python sequence of :class:`int` (representing mantissa, base and
        exponent) or :class:`float` instance or |ASN.1| object.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class Pi(Real):
            '''
            ASN.1 specification:

            Pi ::= REAL

            pi Pi ::= { mantissa 314159, base 10, exponent -5 }

            '''
        pi = Pi((314159, 10, -5))
    """

    binEncBase = None  # binEncBase = 16 is recommended for large numbers

    _plusInf = float("inf")
    _minusInf = float("-inf")
    _inf = _plusInf, _minusInf

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x09))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    @staticmethod
    def __normalizeBase10(value: typing.Any) -> typing.Any:
        m, b, e = value
        while m and m % 10 == 0:
            m /= 10
            e += 1
        return m, b, e

    def prettyIn(self, value: typing.Any) -> typing.Any:
        """Convert an initializer value into an internal (mantissa, base, exponent) tuple.

        Parameters
        ----------
        value: :class:`tuple`, :class:`int`, :class:`float`, :class:`str`
        or |ASN.1| object
            A (mantissa, base, exponent) tuple, a plain number, a string
            parseable as a float, or another |ASN.1| Real object. Infinite
            float values are passed through unchanged.

        Returns
        -------
        : :class:`tuple` or :class:`float`
            The coerced (mantissa, base, exponent) tuple, or an infinite
            :class:`float` value.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If `value` is of an unsupported type or shape, uses a base
            other than 2 or 10, or is a string that cannot be parsed as
            a float.
        """
        if isinstance(value, tuple) and len(value) == 3:
            if (
                not isinstance(value[0], numericTypes)
                or not isinstance(value[1], intTypes)
                or not isinstance(value[2], intTypes)
            ):
                raise error.PyAsn1Error(f"Lame Real value syntax: {value}")
            if isinstance(value[0], float) and self._inf and value[0] in self._inf:
                return value[0]
            if value[1] not in (2, 10):
                raise error.PyAsn1Error(f"Prohibited base for Real value: {value[1]}")
            if value[1] == 10:
                value = self.__normalizeBase10(value)
            return value
        elif isinstance(value, intTypes):
            return self.__normalizeBase10((value, 10, 0))
        elif isinstance(value, float) or isinstance(value, str):
            if isinstance(value, str):
                try:
                    value = float(value)
                except ValueError as exc:
                    raise error.PyAsn1Error(f"Bad real value syntax: {value}") from exc
            if self._inf and value in self._inf:
                return value
            else:
                e = 0
                while int(value) != value:
                    value *= 10
                    e -= 1
                return self.__normalizeBase10((int(value), 10, e))
        elif isinstance(value, Real):
            return tuple(typing.cast(typing.Iterable[typing.Any], value))
        raise error.PyAsn1Error(f"Bad real value syntax: {value}")

    def prettyPrint(self, scope: int = 0) -> str:
        """Return a human-friendly text representation of the value.

        Returns
        -------
        : :class:`str`
            Text representation of the float value, or '<overflow>' if
            the value cannot be represented as a Python float.
        """
        try:
            return self.prettyOut(float(self))

        except OverflowError:
            return "<overflow>"

    @property
    def isPlusInf(self) -> bool:
        """Indicate PLUS-INFINITY object value.

        Returns
        -------
        : :class:`bool`
            :obj:`True` if calling object represents plus infinity
            or :obj:`False` otherwise.

        """
        return self._value == self._plusInf

    @property
    def isMinusInf(self) -> bool:
        """Indicate MINUS-INFINITY object value.

        Returns
        -------
        : :class:`bool`
            :obj:`True` if calling object represents minus infinity
            or :obj:`False` otherwise.
        """
        return self._value == self._minusInf

    @property
    def isInf(self) -> bool:
        """Indicate whether the calling object represents plus or minus infinity."""
        return self._value in self._inf

    def __add__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) + value)

    def __radd__(self, value: typing.Any) -> typing.Any:
        return self + value

    def __mul__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) * value)

    def __rmul__(self, value: typing.Any) -> typing.Any:
        return self * value

    def __sub__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) - value)

    def __rsub__(self, value: typing.Any) -> typing.Any:
        return self.clone(value - float(self))

    def __mod__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) % value)

    def __rmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(value % float(self))

    def __pow__(self, value: typing.Any, modulo: typing.Any = None) -> typing.Any:
        return self.clone(pow(float(self), value, modulo))

    def __rpow__(self, value: typing.Any) -> typing.Any:
        return self.clone(pow(value, float(self)))

    def __truediv__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) / value)

    def __rtruediv__(self, value: typing.Any) -> typing.Any:
        return self.clone(value / float(self))

    def __divmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(float(self) // value)

    def __rdivmod__(self, value: typing.Any) -> typing.Any:
        return self.clone(value // float(self))

    def __int__(self) -> int:
        return int(float(self))

    def __float__(self) -> float:
        value = self._cmpValue("__float__")
        if value in self._inf:
            return value
        else:
            return float(value[0] * pow(value[1], value[2]))

    def __abs__(self) -> typing.Any:
        return self.clone(abs(float(self)))

    def __pos__(self) -> typing.Any:
        return self.clone(+float(self))

    def __neg__(self) -> typing.Any:
        return self.clone(-float(self))

    def __round__(self, n: int = 0) -> typing.Any:
        r = round(float(self), n)
        if n:
            return self.clone(r)
        else:
            return r

    def __floor__(self) -> int:
        return self.clone(math.floor(float(self)))

    def __ceil__(self) -> int:
        return self.clone(math.ceil(float(self)))

    def __trunc__(self) -> int:
        return self.clone(math.trunc(float(self)))

    def __lt__(self, other: typing.Any) -> bool:
        return float(self) < other

    def __le__(self, other: typing.Any) -> bool:
        return float(self) <= other

    def __eq__(self, other: object) -> bool:
        return self is other or float(self) == other

    def __ne__(self, other: object) -> bool:
        return self is not other and float(self) != other

    def __gt__(self, other: typing.Any) -> bool:
        return float(self) > other

    def __ge__(self, other: typing.Any) -> bool:
        return float(self) >= other

    def __bool__(self) -> bool:
        return bool(float(self))

    __hash__ = base.SimpleAsn1Type.__hash__

    def __getitem__(self, idx: typing.Any) -> typing.Any:
        if self._value in self._inf:
            raise error.PyAsn1Error("Invalid infinite value operation")
        else:
            return self._value[idx]


class Enumerated(Integer):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`int` objects.

    Keyword Args
    ------------
    value: :class:`int`, :class:`str` or |ASN.1| object
        Python :class:`int` or :class:`str` literal or |ASN.1| object.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    namedValues: :py:class:`~pyasn1.type.namedval.NamedValues`
        Object representing non-default symbolic aliases for numbers

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------

    .. code-block:: python

        class RadioButton(Enumerated):
            '''
            ASN.1 specification:

            RadioButton ::= ENUMERATED { button1(0), button2(1),
                                         button3(2) }

            selected-by-default RadioButton ::= button1
            '''
            namedValues = NamedValues(
                ('button1', 0), ('button2', 1),
                ('button3', 2)
            )

        selected_by_default = RadioButton('button1')
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x0A))

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Optimization for faster codec lookup
    typeId = Integer.getTypeId()

    #: Default :py:class:`~pyasn1.type.namedval.NamedValues` object
    #: representing symbolic aliases for numbers
    namedValues = namedval.NamedValues()


# "Structured" ASN.1 types


class SequenceOfAndSetOfBase(base.ConstructedAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.ConstructedAsn1Type`,
    its objects are mutable and duck-type Python :class:`list` objects.

    Keyword Args
    ------------
    componentType : :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
        A pyasn1 object representing ASN.1 type allowed within |ASN.1| type

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type can only occur on explicit
        `.isInconsistent` call.

    Examples
    --------

    .. code-block:: python

        class LotteryDraw(SequenceOf):  #  SetOf is similar
            '''
            ASN.1 specification:

            LotteryDraw ::= SEQUENCE OF INTEGER
            '''
            componentType = Integer()

        lotteryDraw = LotteryDraw()
        lotteryDraw.extend([123, 456, 789])
    """

    def __init__(self, **kwargs: typing.Any) -> None:
        self._componentValues = noValue

        base.ConstructedAsn1Type.__init__(self, **kwargs)

    # Python list protocol

    def __getitem__(self, idx: typing.Any) -> typing.Any:
        try:
            return self.getComponentByPosition(idx)

        except error.PyAsn1Error as exc:
            raise IndexError(exc) from exc

    def __setitem__(self, idx: typing.Any, value: typing.Any) -> None:
        try:
            self.setComponentByPosition(idx, value)

        except error.PyAsn1Error as exc:
            raise IndexError(exc) from exc

    def append(self, value: typing.Any) -> None:
        """Append `value` as a new component at the end of the |ASN.1| object."""
        if self._componentValues is noValue:
            pos = 0

        else:
            pos = len(self._componentValues)

        self[pos] = value

    def count(self, value: typing.Any) -> int:
        """Return the number of components equal to `value`."""
        return list(self._componentValues.values()).count(value)

    def extend(self, values: typing.Any) -> None:
        """Append each item of `values` as a new component."""
        for value in values:
            self.append(value)

        if self._componentValues is noValue:
            self._componentValues = {}

    def index(self, value: typing.Any, start: int = 0, stop: typing.Any = None) -> int:
        """Return the position of the first component equal to `value`.

        Parameters
        ----------
        value: :class:`object`
            Component value to look up.

        start: :class:`int`
            Position to start searching from (default 0).

        stop: :class:`int`
            Position to stop searching at (default the object length).

        Returns
        -------
        : :class:`int`
            Zero-based position of `value` within this |ASN.1| object.

        Raises
        ------
        ValueError
            If `value` is not present in the given range.
        """
        if stop is None:
            stop = len(self)

        indices, componentValues = zip(*self._componentValues.items())

        values = list(componentValues)

        try:
            return indices[values.index(value, start, stop)]

        except error.PyAsn1Error as exc:
            raise ValueError(exc) from exc

    def reverse(self) -> None:
        """Reverse the order of components in place."""
        self._componentValues.reverse()

    def sort(self, key: typing.Any = None, reverse: bool = False) -> None:
        """Sort the components in place.

        Parameters
        ----------
        key: :class:`~collections.abc.Callable`
            Function of one argument used to extract a comparison key
            from each component.

        reverse: :class:`bool`
            If :obj:`True`, sort in descending order.
        """
        self._componentValues = dict(
            enumerate(sorted(self._componentValues.values(), key=key, reverse=reverse))
        )

    def __len__(self) -> int:
        if self._componentValues is noValue or not self._componentValues:
            return 0

        return max(self._componentValues) + 1

    def __iter__(self) -> Iterator[typing.Any]:
        for idx in range(0, len(self)):
            yield self.getComponentByPosition(idx)

    def _cloneComponentValues(
        self, myClone: typing.Any, cloneValueFlag: typing.Any
    ) -> None:
        for idx, componentValue in self._componentValues.items():
            if componentValue is not noValue:
                if isinstance(componentValue, base.ConstructedAsn1Type):
                    myClone.setComponentByPosition(
                        idx, componentValue.clone(cloneValueFlag=cloneValueFlag)
                    )
                else:
                    myClone.setComponentByPosition(idx, componentValue.clone())

    def getComponentByPosition(
        self, idx: int, default: typing.Any = noValue, instantiate: bool = True
    ) -> typing.Any:
        """Return |ASN.1| type component value by position.

        Equivalent to Python sequence subscription operation (e.g. `[]`).

        Parameters
        ----------
        idx : :class:`int`
            Component index (zero-based). Must either refer to an existing
            component or to N+1 component (if *componentType* is set). In the latter
            case a new component type gets instantiated and appended to the |ASN.1|
            sequence.

        Keyword Args
        ------------
        default: :class:`object`
            If set and requested component is a schema object, return the `default`
            object instead of the requested component.

        instantiate: :class:`bool`
            If :obj:`True` (default), inner component will be automatically instantiated.
            If :obj:`False` either existing component or the :class:`NoValue` object will be
            returned.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            Instantiate |ASN.1| component type or return existing component value

        Examples
        --------

        .. code-block:: python

            # can also be SetOf
            class MySequenceOf(SequenceOf):
                componentType = OctetString()

            s = MySequenceOf()

            # returns component #0 with `.isValue` property False
            s.getComponentByPosition(0)

            # returns None
            s.getComponentByPosition(0, default=None)

            s.clear()

            # returns noValue
            s.getComponentByPosition(0, instantiate=False)

            # sets component #0 to OctetString() ASN.1 schema
            # object and returns it
            s.getComponentByPosition(0, instantiate=True)

            # sets component #0 to ASN.1 value object
            s.setComponentByPosition(0, 'ABCD')

            # returns OctetString('ABCD') value object
            s.getComponentByPosition(0, instantiate=False)

            s.clear()

            # returns noValue
            s.getComponentByPosition(0, instantiate=False)
        """
        if isinstance(idx, slice):
            indices = tuple(range(len(self)))
            return [
                self.getComponentByPosition(subidx, default, instantiate)
                for subidx in indices[idx]
            ]

        if idx < 0:
            idx = len(self) + idx
            if idx < 0:
                raise error.PyAsn1Error("SequenceOf/SetOf index is out of range")

        try:
            componentValue = self._componentValues[idx]

        except (KeyError, error.PyAsn1Error):
            if not instantiate:
                return default

            self.setComponentByPosition(idx)

            componentValue = self._componentValues[idx]

        if default is noValue or componentValue.isValue:
            return componentValue
        else:
            return default

    def setComponentByPosition(
        self,
        idx: int,
        value: typing.Any = noValue,
        verifyConstraints: bool = True,
        matchTags: bool = True,
        matchConstraints: bool = True,
    ) -> typing.Any:
        """Assign |ASN.1| type component by position.

        Equivalent to Python sequence item assignment operation (e.g. `[]`)
        or list.append() (when idx == len(self)).

        Parameters
        ----------
        idx: :class:`int`
            Component index (zero-based). Must either refer to existing
            component or to N+1 component. In the latter case a new component
            type gets instantiated (if *componentType* is set, or given ASN.1
            object is taken otherwise) and appended to the |ASN.1| sequence.

        Keyword Args
        ------------
        value: :class:`object` or :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
            A Python value to initialize |ASN.1| component with (if *componentType* is set)
            or ASN.1 value object to assign to |ASN.1| component.
            If `value` is not given, schema object will be set as a component.

        verifyConstraints: :class:`bool`
             If :obj:`False`, skip constraints validation

        matchTags: :class:`bool`
             If :obj:`False`, skip component tags matching

        matchConstraints: :class:`bool`
             If :obj:`False`, skip component constraints matching

        Returns
        -------
        self

        Raises
        ------
        ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
            On constraint violation or bad initializer
        IndexError
            When idx > len(self)
        """
        if isinstance(idx, slice):
            indices = tuple(range(len(self)))
            startIdx = indices[idx][0] if indices else 0
            for subIdx, subValue in enumerate(value):
                self.setComponentByPosition(
                    startIdx + subIdx,
                    subValue,
                    verifyConstraints,
                    matchTags,
                    matchConstraints,
                )
            return self

        if idx < 0:
            idx = len(self) + idx
            if idx < 0:
                raise error.PyAsn1Error("SequenceOf/SetOf index is out of range")

        componentType = self.componentType

        if self._componentValues is noValue:
            componentValues = {}

        else:
            componentValues = self._componentValues

        currentValue = componentValues.get(idx, noValue)

        if value is noValue:
            if componentType is not None:
                value = componentType.clone()

            elif currentValue is noValue:
                raise error.PyAsn1Error("Component type not defined")

        elif not isinstance(value, base.Asn1Item):
            if componentType is not None and isinstance(
                componentType, base.SimpleAsn1Type
            ):
                value = componentType.clone(value=value)

            elif currentValue is not noValue and isinstance(
                currentValue, base.SimpleAsn1Type
            ):
                value = currentValue.clone(value=value)

            else:
                raise error.PyAsn1Error(
                    f"Non-ASN.1 value {value!r} and undefined component"
                    f" type at {self!r}"
                )

        elif componentType is not None and (matchTags or matchConstraints):
            subtypeChecker = (
                self.strictConstraints
                and componentType.isSameTypeWith
                or componentType.isSuperTypeOf
            )

            if not subtypeChecker(
                value,
                verifyConstraints and matchTags,
                verifyConstraints and matchConstraints,
            ):
                # TODO: we should wrap componentType with UnnamedType to carry
                # additional properties associated with componentType
                if componentType.typeId != Any.typeId:
                    raise error.PyAsn1Error(
                        f"Component value is tag-incompatible: {value!r} vs "
                        f"{componentType!r}"
                    )

        componentValues[idx] = value

        self._componentValues = componentValues

        return self

    @property
    def componentTagMap(self) -> typing.Any:
        """Return a :class:`~pyasn1.type.tagmap.TagMap` for `componentType`, or :obj:`None`."""
        if self.componentType is not None:
            return self.componentType.tagMap

    @property
    def components(self) -> typing.Any:
        """Return the list of component values, ordered by position."""
        return [self._componentValues[idx] for idx in sorted(self._componentValues)]

    def clear(self) -> typing.Any:
        """Remove all components and become an empty |ASN.1| value object.

        Has the same effect on |ASN.1| object as it does on :class:`list`
        built-in.
        """
        self._componentValues = {}
        return self

    def reset(self) -> typing.Any:
        """Remove all components and become a |ASN.1| schema object.

        See :meth:`isValue` property for more information on the
        distinction between value and schema objects.
        """
        self._componentValues = noValue
        return self

    def prettyPrint(self, scope: int = 0) -> str:
        """Return an object representation string.

        Returns
        -------
        : :class:`str`
            Human-friendly object representation.
        """
        scope += 1
        representation = self.__class__.__name__ + ":\n"

        if not self.isValue:
            return representation

        for idx, componentValue in enumerate(self):
            representation += " " * scope
            if componentValue is noValue and self.componentType is not None:
                representation += "<empty>"
            else:
                representation += componentValue.prettyPrint(scope)

        return representation

    def prettyPrintType(self, scope: int = 0) -> str:
        """Return an object type layout string.

        Returns
        -------
        : :class:`str`
            Human-friendly object type representation.
        """
        scope += 1
        representation = f"{self.tagSet} -> {self.__class__.__name__} {{\n"
        if self.componentType is not None:
            representation += " " * scope
            representation += self.componentType.prettyPrintType(scope)
        return representation + "\n" + " " * (scope - 1) + "}"

    @property
    def isValue(self) -> bool:
        """Indicate that |ASN.1| object represents ASN.1 value.

        If *isValue* is :obj:`False` then this object represents just ASN.1 schema.

        If *isValue* is :obj:`True` then, in addition to its ASN.1 schema features,
        this object can also be used like a Python built-in object
        (e.g. :class:`int`, :class:`str`, :class:`dict` etc.).

        Returns
        -------
        : :class:`bool`
            :obj:`False` if object represents just ASN.1 schema.
            :obj:`True` if object represents ASN.1 schema and can be used as a normal value.

        Note
        ----
        There is an important distinction between PyASN1 schema and value objects.
        The PyASN1 schema objects can only participate in ASN.1 schema-related
        operations (e.g. defining or testing the structure of the data). Most
        obvious uses of ASN.1 schema is to guide serialisation codecs whilst
        encoding/decoding serialised ASN.1 contents.

        The PyASN1 value objects can **additionally** participate in many operations
        involving regular Python objects (e.g. arithmetic, comprehension etc).
        """
        if self._componentValues is noValue:
            return False

        if len(self._componentValues) != len(self):
            return False

        for componentValue in self._componentValues.values():
            if componentValue is noValue or not componentValue.isValue:
                return False

        return True

    @property
    def isInconsistent(self) -> typing.Any:
        """Run necessary checks to ensure |ASN.1| object consistency.

        Default action is to verify |ASN.1| object against constraints imposed
        by `subtypeSpec`.

        Raises
        ------
        :py:class:`~pyasn1.error.PyAsn1tError` on any inconsistencies found
        """
        if self.componentType is noValue or not self.subtypeSpec:
            return False

        if self._componentValues is noValue:
            return True

        mapping = {}

        for idx, value in self._componentValues.items():
            # Absent fields are not in the mapping
            if value is noValue:
                continue

            mapping[idx] = value

        try:
            # Represent SequenceOf/SetOf as a bare dict to constraints chain
            self.subtypeSpec(mapping)

        except error.PyAsn1Error as exc:
            return exc

        return False


class SequenceOf(SequenceOfAndSetOfBase):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = SequenceOfAndSetOfBase.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatConstructed, 0x10)
    )

    #: Default :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
    #: object representing ASN.1 type allowed within |ASN.1| type
    componentType = None

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Disambiguation ASN.1 types identification
    typeId = SequenceOfAndSetOfBase.getTypeId()


class SetOf(SequenceOfAndSetOfBase):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = SequenceOfAndSetOfBase.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatConstructed, 0x11)
    )

    #: Default :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
    #: object representing ASN.1 type allowed within |ASN.1| type
    componentType = None

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Disambiguation ASN.1 types identification
    typeId = SequenceOfAndSetOfBase.getTypeId()


class SequenceAndSetBase(base.ConstructedAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.ConstructedAsn1Type`,
    its objects are mutable and duck-type Python :class:`dict` objects.

    Keyword Args
    ------------
    componentType: :py:class:`~pyasn1.type.namedtype.NamedType`
        Object holding named ASN.1 types allowed within this collection

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s).  Constraints
        verification for |ASN.1| type can only occur on explicit
        `.isInconsistent` call.

    Examples
    --------

    .. code-block:: python

        class Description(Sequence):  #  Set is similar
            '''
            ASN.1 specification:

            Description ::= SEQUENCE {
                surname    IA5String,
                first-name IA5String OPTIONAL,
                age        INTEGER DEFAULT 40
            }
            '''
            componentType = NamedTypes(
                NamedType('surname', IA5String()),
                OptionalNamedType('first-name', IA5String()),
                DefaultedNamedType('age', Integer(40))
            )

        descr = Description()
        descr['surname'] = 'Smith'
        descr['first-name'] = 'John'
    """

    #: Default :py:class:`~pyasn1.type.namedtype.NamedTypes`
    #: object representing named ASN.1 types allowed within |ASN.1| type
    componentType: typing.Any = namedtype.NamedTypes()

    class DynamicNames:
        """Fields names/positions mapping for component-less objects."""

        def __init__(self) -> None:
            self._keyToIdxMap: dict[typing.Any, int] = {}
            self._idxToKeyMap: dict[int, typing.Any] = {}

        def __len__(self) -> int:
            return len(self._keyToIdxMap)

        def __contains__(self, item: object) -> bool:
            return item in self._keyToIdxMap or item in self._idxToKeyMap

        def __iter__(self) -> Iterator[typing.Any]:
            return (self._idxToKeyMap[idx] for idx in range(len(self._idxToKeyMap)))

        def __getitem__(self, item: typing.Any) -> typing.Any:
            try:
                return self._keyToIdxMap[item]

            except KeyError:
                return self._idxToKeyMap[item]

        def getNameByPosition(self, idx: int) -> typing.Any:
            """Return the field name assigned to position `idx`.

            Raises
            ------
            ~pyasn1.error.PyAsn1Error
                If `idx` was not previously registered with `addField`.
            """
            try:
                return self._idxToKeyMap[idx]

            except KeyError as exc:
                raise error.PyAsn1Error("Type position out of range") from exc

        def getPositionByName(self, name: str) -> int:
            """Return the position assigned to field `name`.

            Raises
            ------
            ~pyasn1.error.PyAsn1Error
                If `name` was not previously registered with `addField`.
            """
            try:
                return self._keyToIdxMap[name]

            except KeyError as exc:
                raise error.PyAsn1Error(f"Name {name} not found") from exc

        def addField(self, idx: int) -> None:
            """Register a synthetic 'field-<idx>' name for position `idx`."""
            self._keyToIdxMap[f"field-{idx}"] = idx
            self._idxToKeyMap[idx] = f"field-{idx}"

    def __init__(self, **kwargs: typing.Any) -> None:
        base.ConstructedAsn1Type.__init__(self, **kwargs)
        self._componentTypeLen: int = len(self.componentType)
        if self._componentTypeLen:
            self._componentValues = []
        else:
            self._componentValues = noValue
        self._dynamicNames: typing.Any = self._componentTypeLen or self.DynamicNames()

    def __getitem__(self, idx: typing.Any) -> typing.Any:
        if isinstance(idx, str):
            try:
                return self.getComponentByName(idx)

            except error.PyAsn1Error as exc:
                # duck-typing dict
                raise KeyError(exc) from exc

        else:
            try:
                return self.getComponentByPosition(idx)

            except error.PyAsn1Error as exc:
                # duck-typing list
                raise IndexError(exc) from exc

    def __setitem__(self, idx: typing.Any, value: typing.Any) -> None:
        if isinstance(idx, str):
            try:
                self.setComponentByName(idx, value)

            except error.PyAsn1Error as exc:
                # duck-typing dict
                raise KeyError(exc) from exc

        else:
            try:
                self.setComponentByPosition(idx, value)

            except error.PyAsn1Error as exc:
                # duck-typing list
                raise IndexError(exc) from exc

    def __contains__(self, key: object) -> bool:
        if self._componentTypeLen:
            return key in self.componentType
        else:
            return key in self._dynamicNames

    def __len__(self) -> int:
        return len(self._componentValues)

    def __iter__(self) -> Iterator[typing.Any]:
        return iter(self.componentType or self._dynamicNames)

    # Python dict protocol

    def values(self) -> typing.Any:
        """Return an iterator over the component values."""
        for idx in range(self._componentTypeLen or len(self._dynamicNames)):
            yield self[idx]

    def keys(self) -> typing.Any:
        """Return an iterator over the component names."""
        return iter(self)

    def items(self) -> typing.Any:
        """Return an iterator over (name, value) pairs for each component."""
        for idx in range(self._componentTypeLen or len(self._dynamicNames)):
            if self._componentTypeLen:
                yield self.componentType[idx].name, self[idx]
            else:
                yield self._dynamicNames[idx], self[idx]

    def update(self, *iterValue: typing.Any, **mappingValue: typing.Any) -> None:
        """Set components from an iterable of (name, value) pairs and/or keyword arguments."""
        for k, v in iterValue:
            self[k] = v
        for k, v in mappingValue.items():
            self[k] = v

    def clear(self) -> typing.Any:
        """Remove all components and become an empty |ASN.1| value object.

        Has the same effect on |ASN.1| object as it does on :class:`dict`
        built-in.
        """
        self._componentValues = []
        self._dynamicNames = self.DynamicNames()
        return self

    def reset(self) -> typing.Any:
        """Remove all components and become a |ASN.1| schema object.

        See :meth:`isValue` property for more information on the
        distinction between value and schema objects.
        """
        self._componentValues = noValue
        self._dynamicNames = self.DynamicNames()
        return self

    @property
    def components(self) -> typing.Any:
        """Return the list of component values, in declaration order."""
        return self._componentValues

    def _cloneComponentValues(
        self, myClone: typing.Any, cloneValueFlag: typing.Any
    ) -> None:
        if self._componentValues is noValue:
            return

        for idx, componentValue in enumerate(self._componentValues):
            if componentValue is not noValue:
                if isinstance(componentValue, base.ConstructedAsn1Type):
                    myClone.setComponentByPosition(
                        idx, componentValue.clone(cloneValueFlag=cloneValueFlag)
                    )
                else:
                    myClone.setComponentByPosition(idx, componentValue.clone())

    def getComponentByName(
        self, name: str, default: typing.Any = noValue, instantiate: bool = True
    ) -> typing.Any:
        """Return |ASN.1| type component by name.

        Equivalent to Python :class:`dict` subscription operation (e.g. `[]`).

        Parameters
        ----------
        name: :class:`str`
            |ASN.1| type component name

        Keyword Args
        ------------
        default: :class:`object`
            If set and requested component is a schema object, return the `default`
            object instead of the requested component.

        instantiate: :class:`bool`
            If :obj:`True` (default), inner component will be automatically
            instantiated.
            If :obj:`False` either existing component or the :class:`NoValue`
            object will be returned.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            Instantiate |ASN.1| component type or return existing
            component value
        """
        if self._componentTypeLen:
            idx = self.componentType.getPositionByName(name)
        else:
            try:
                idx = self._dynamicNames.getPositionByName(name)

            except KeyError as exc:
                raise error.PyAsn1Error(f"Name {name} not found") from exc

        return self.getComponentByPosition(
            idx, default=default, instantiate=instantiate
        )

    def setComponentByName(
        self,
        name: str,
        value: typing.Any = noValue,
        verifyConstraints: bool = True,
        matchTags: bool = True,
        matchConstraints: bool = True,
    ) -> typing.Any:
        """Assign |ASN.1| type component by name.

        Equivalent to Python :class:`dict` item assignment operation (e.g. `[]`).

        Parameters
        ----------
        name: :class:`str`
            |ASN.1| type component name

        Keyword Args
        ------------
        value: :class:`object` or :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
            A Python value to initialize |ASN.1| component with (if *componentType* is set)
            or ASN.1 value object to assign to |ASN.1| component.
            If `value` is not given, schema object will be set as a component.

        verifyConstraints: :class:`bool`
             If :obj:`False`, skip constraints validation

        matchTags: :class:`bool`
             If :obj:`False`, skip component tags matching

        matchConstraints: :class:`bool`
             If :obj:`False`, skip component constraints matching

        Returns
        -------
        self
        """
        if self._componentTypeLen:
            idx = self.componentType.getPositionByName(name)
        else:
            try:
                idx = self._dynamicNames.getPositionByName(name)

            except KeyError as exc:
                raise error.PyAsn1Error(f"Name {name} not found") from exc

        return self.setComponentByPosition(
            idx, value, verifyConstraints, matchTags, matchConstraints
        )

    def getComponentByPosition(
        self, idx: int, default: typing.Any = noValue, instantiate: bool = True
    ) -> typing.Any:
        """Return |ASN.1| type component by index.

        Equivalent to Python sequence subscription operation (e.g. `[]`).

        Parameters
        ----------
        idx: :class:`int`
            Component index (zero-based). Must either refer to an existing
            component or (if *componentType* is set) new ASN.1 schema object gets
            instantiated.

        Keyword Args
        ------------
        default: :class:`object`
            If set and requested component is a schema object, return the `default`
            object instead of the requested component.

        instantiate: :class:`bool`
            If :obj:`True` (default), inner component will be automatically
            instantiated.
            If :obj:`False` either existing component or the :class:`NoValue`
            object will be returned.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            a PyASN1 object

        Examples
        --------

        .. code-block:: python

            # can also be Set
            class MySequence(Sequence):
                componentType = NamedTypes(
                    NamedType('id', OctetString())
                )

            s = MySequence()

            # returns component #0 with `.isValue` property False
            s.getComponentByPosition(0)

            # returns None
            s.getComponentByPosition(0, default=None)

            s.clear()

            # returns noValue
            s.getComponentByPosition(0, instantiate=False)

            # sets component #0 to OctetString() ASN.1 schema
            # object and returns it
            s.getComponentByPosition(0, instantiate=True)

            # sets component #0 to ASN.1 value object
            s.setComponentByPosition(0, 'ABCD')

            # returns OctetString('ABCD') value object
            s.getComponentByPosition(0, instantiate=False)

            s.clear()

            # returns noValue
            s.getComponentByPosition(0, instantiate=False)
        """
        try:
            if self._componentValues is noValue:
                componentValue = noValue

            else:
                componentValue = self._componentValues[idx]

        except IndexError:
            componentValue = noValue

        if not instantiate:
            if componentValue is noValue or not componentValue.isValue:
                return default
            else:
                return componentValue

        if componentValue is noValue:
            self.setComponentByPosition(idx)

        componentValue = self._componentValues[idx]

        if default is noValue or componentValue.isValue:
            return componentValue
        else:
            return default

    def setComponentByPosition(
        self,
        idx: int,
        value: typing.Any = noValue,
        verifyConstraints: bool = True,
        matchTags: bool = True,
        matchConstraints: bool = True,
    ) -> typing.Any:
        """Assign |ASN.1| type component by position.

        Equivalent to Python sequence item assignment operation (e.g. `[]`).

        Parameters
        ----------
        idx : :class:`int`
            Component index (zero-based). Must either refer to existing
            component (if *componentType* is set) or to N+1 component
            otherwise. In the latter case a new component of given ASN.1
            type gets instantiated and appended to |ASN.1| sequence.

        Keyword Args
        ------------
        value: :class:`object` or :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
            A Python value to initialize |ASN.1| component with (if *componentType* is set)
            or ASN.1 value object to assign to |ASN.1| component.
            If `value` is not given, schema object will be set as a component.

        verifyConstraints : :class:`bool`
             If :obj:`False`, skip constraints validation

        matchTags: :class:`bool`
             If :obj:`False`, skip component tags matching

        matchConstraints: :class:`bool`
             If :obj:`False`, skip component constraints matching

        Returns
        -------
        self
        """
        componentType = self.componentType
        componentTypeLen = self._componentTypeLen

        if self._componentValues is noValue:
            componentValues = []

        else:
            componentValues = self._componentValues

        try:
            currentValue = componentValues[idx]

        except IndexError as exc:
            currentValue = noValue
            if componentTypeLen:
                if componentTypeLen < idx:
                    raise error.PyAsn1Error("component index out of range") from exc

                componentValues = [noValue] * componentTypeLen

        if value is noValue:
            if componentTypeLen:
                value = componentType.getTypeByPosition(idx)
                if isinstance(value, base.ConstructedAsn1Type):
                    value = value.clone(cloneValueFlag=componentType[idx].isDefaulted)

            elif currentValue is noValue:
                raise error.PyAsn1Error("Component type not defined")

        elif not isinstance(value, base.Asn1Item):
            if componentTypeLen:
                subComponentType = componentType.getTypeByPosition(idx)
                if isinstance(subComponentType, base.SimpleAsn1Type):
                    value = subComponentType.clone(value=value)

                else:
                    raise error.PyAsn1Error(
                        f"{componentType.__class__.__name__} can cast only scalar values"
                    )

            elif currentValue is not noValue and isinstance(
                currentValue, base.SimpleAsn1Type
            ):
                value = currentValue.clone(value=value)

            else:
                raise error.PyAsn1Error(
                    f"{componentType.__class__.__name__} undefined component type"
                )

        elif (verifyConstraints or matchTags or matchConstraints) and componentTypeLen:
            subComponentType = componentType.getTypeByPosition(idx)
            if subComponentType is not noValue:
                subtypeChecker = (
                    self.strictConstraints
                    and subComponentType.isSameTypeWith
                    or subComponentType.isSuperTypeOf
                )

                if not subtypeChecker(
                    value,
                    verifyConstraints and matchTags,
                    verifyConstraints and matchConstraints,
                ):
                    if not componentType[idx].openType:
                        raise error.PyAsn1Error(
                            f"Component value is tag-incompatible: {value!r} vs {componentType!r}"
                        )

        if componentTypeLen or idx in self._dynamicNames:
            componentValues[idx] = value

        elif len(componentValues) == idx:
            componentValues.append(value)
            self._dynamicNames.addField(idx)

        else:
            raise error.PyAsn1Error("Component index out of range")

        self._componentValues = componentValues

        return self

    @property
    def isValue(self) -> bool:
        """Indicate that |ASN.1| object represents ASN.1 value.

        If *isValue* is :obj:`False` then this object represents just ASN.1 schema.

        If *isValue* is :obj:`True` then, in addition to its ASN.1 schema features,
        this object can also be used like a Python built-in object (e.g.
        :class:`int`, :class:`str`, :class:`dict` etc.).

        Returns
        -------
        : :class:`bool`
            :obj:`False` if object represents just ASN.1 schema.
            :obj:`True` if object represents ASN.1 schema and can be used as a
            normal value.

        Note
        ----
        There is an important distinction between PyASN1 schema and value objects.
        The PyASN1 schema objects can only participate in ASN.1 schema-related
        operations (e.g. defining or testing the structure of the data). Most
        obvious uses of ASN.1 schema is to guide serialisation codecs whilst
        encoding/decoding serialised ASN.1 contents.

        The PyASN1 value objects can **additionally** participate in many operations
        involving regular Python objects (e.g. arithmetic, comprehension etc).

        It is sufficient for |ASN.1| objects to have all non-optional and non-defaulted
        components being value objects to be considered as a value objects as a whole.
        In other words, even having one or more optional components not turned into
        value objects, |ASN.1| object is still considered as a value object. Defaulted
        components are normally value objects by default.
        """
        if self._componentValues is noValue:
            return False

        componentType = self.componentType

        if componentType:
            for idx, subComponentType in enumerate(componentType.namedTypes):
                if subComponentType.isDefaulted or subComponentType.isOptional:
                    continue

                if not self._componentValues:
                    return False

                componentValue = self._componentValues[idx]
                if componentValue is noValue or not componentValue.isValue:
                    return False

        else:
            for componentValue in self._componentValues:
                if componentValue is noValue or not componentValue.isValue:
                    return False

        return True

    @property
    def isInconsistent(self) -> typing.Any:
        """Run necessary checks to ensure |ASN.1| object consistency.

        Default action is to verify |ASN.1| object against constraints imposed
        by `subtypeSpec`.

        Raises
        ------
        :py:class:`~pyasn1.error.PyAsn1tError` on any inconsistencies found
        """
        if self.componentType is noValue or not self.subtypeSpec:
            return False

        if self._componentValues is noValue:
            return True

        mapping = {}

        for idx, value in enumerate(self._componentValues):
            # Absent fields are not in the mapping
            if value is noValue:
                continue

            name = self.componentType.getNameByPosition(idx)

            mapping[name] = value

        try:
            # Represent Sequence/Set as a bare dict to constraints chain
            self.subtypeSpec(mapping)

        except error.PyAsn1Error as exc:
            return exc

        return False

    def prettyPrint(self, scope: int = 0) -> str:
        """Return an object representation string.

        Returns
        -------
        : :class:`str`
            Human-friendly object representation.
        """
        scope += 1
        representation = self.__class__.__name__ + ":\n"
        for idx, componentValue in enumerate(self._componentValues):
            if componentValue is not noValue and componentValue.isValue:
                representation += " " * scope
                if self.componentType:
                    representation += self.componentType.getNameByPosition(idx)
                else:
                    representation += self._dynamicNames.getNameByPosition(idx)
                representation = (
                    f"{representation}={componentValue.prettyPrint(scope)}\n"
                )
        return representation

    def prettyPrintType(self, scope: int = 0) -> str:
        """Return an object type layout string.

        Returns
        -------
        : :class:`str`
            Human-friendly object type representation.
        """
        scope += 1
        representation = f"{self.tagSet} -> {self.__class__.__name__} {{\n"
        for idx, componentType in enumerate(
            self.componentType.values() or self._componentValues
        ):
            representation += " " * scope
            if self.componentType:
                representation += f'"{self.componentType.getNameByPosition(idx)}"'
            else:
                representation += f'"{self._dynamicNames.getNameByPosition(idx)}"'
            representation = (
                f"{representation} = {componentType.prettyPrintType(scope)}\n"
            )
        return representation + "\n" + " " * (scope - 1) + "}"

    def getNameByPosition(self, idx: int) -> typing.Any:
        """Return the component name at position `idx`, or :obj:`None` if `componentType` is unset."""
        if self._componentTypeLen:
            return self.componentType[idx].name


class Sequence(SequenceAndSetBase):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = SequenceAndSetBase.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatConstructed, 0x10)
    )

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    #: Default collection of ASN.1 types of component (e.g. :py:class:`~pyasn1.type.namedtype.NamedType`)
    #: object imposing size constraint on |ASN.1| objects
    componentType: typing.Any = namedtype.NamedTypes()

    # Disambiguation ASN.1 types identification
    typeId = SequenceAndSetBase.getTypeId()


class Set(SequenceAndSetBase):  # noqa: D101 - docstring aliased from the base type below
    __doc__ = SequenceAndSetBase.__doc__

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatConstructed, 0x11)
    )

    #: Default collection of ASN.1 types of component (e.g. :py:class:`~pyasn1.type.namedtype.NamedType`)
    #: object representing ASN.1 type allowed within |ASN.1| type
    componentType: typing.Any = namedtype.NamedTypes()

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Disambiguation ASN.1 types identification
    typeId = SequenceAndSetBase.getTypeId()

    def getComponent(self, innerFlag: bool = False) -> typing.Any:
        """Return this |ASN.1| object itself (a SET has no single "current" component)."""
        return self

    def getComponentByType(
        self,
        tagSet: tag.TagSet,
        default: typing.Any = noValue,
        instantiate: bool = True,
        innerFlag: bool = False,
    ) -> typing.Any:
        """Return |ASN.1| type component by ASN.1 tag.

        Parameters
        ----------
        tagSet : :py:class:`~pyasn1.type.tag.TagSet`
            Object representing ASN.1 tags to identify one of
            |ASN.1| object component

        Keyword Args
        ------------
        default: :class:`object`
            If set and requested component is a schema object, return the `default`
            object instead of the requested component.

        instantiate: :class:`bool`
            If :obj:`True` (default), inner component will be automatically
            instantiated.
            If :obj:`False` either existing component or the :class:`noValue`
            object will be returned.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            a pyasn1 object
        """
        componentValue = self.getComponentByPosition(
            self.componentType.getPositionByType(tagSet),
            default=default,
            instantiate=instantiate,
        )
        if innerFlag and isinstance(componentValue, Set):
            # get inner component by inner tagSet
            return componentValue.getComponent(innerFlag=True)
        else:
            # get outer component by inner tagSet
            return componentValue

    def setComponentByType(
        self,
        tagSet: tag.TagSet,
        value: typing.Any = noValue,
        verifyConstraints: bool = True,
        matchTags: bool = True,
        matchConstraints: bool = True,
        innerFlag: bool = False,
    ) -> typing.Any:
        """Assign |ASN.1| type component by ASN.1 tag.

        Parameters
        ----------
        tagSet : :py:class:`~pyasn1.type.tag.TagSet`
            Object representing ASN.1 tags to identify one of
            |ASN.1| object component

        Keyword Args
        ------------
        value: :class:`object` or :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
            A Python value to initialize |ASN.1| component with (if *componentType* is set)
            or ASN.1 value object to assign to |ASN.1| component.
            If `value` is not given, schema object will be set as a component.

        verifyConstraints : :class:`bool`
            If :obj:`False`, skip constraints validation

        matchTags: :class:`bool`
            If :obj:`False`, skip component tags matching

        matchConstraints: :class:`bool`
            If :obj:`False`, skip component constraints matching

        innerFlag: :class:`bool`
            If :obj:`True`, search for matching *tagSet* recursively.

        Returns
        -------
        self
        """
        idx = self.componentType.getPositionByType(tagSet)

        if innerFlag:  # set inner component by inner tagSet
            componentType = self.componentType.getTypeByPosition(idx)

            if componentType.tagSet:
                return self.setComponentByPosition(
                    idx, value, verifyConstraints, matchTags, matchConstraints
                )
            else:
                componentType = self.getComponentByPosition(idx)
                return componentType.setComponentByType(
                    tagSet,
                    value,
                    verifyConstraints,
                    matchTags,
                    matchConstraints,
                    innerFlag=innerFlag,
                )
        else:  # set outer component by inner tagSet
            return self.setComponentByPosition(
                idx, value, verifyConstraints, matchTags, matchConstraints
            )

    @property
    def componentTagMap(self) -> typing.Any:
        """Return a unique :class:`~pyasn1.type.tagmap.TagMap` for `componentType`, or :obj:`None`."""
        if self.componentType:
            return self.componentType.tagMapUnique


class Choice(Set):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.ConstructedAsn1Type`,
    its objects are mutable and duck-type Python :class:`list` objects.

    Keyword Args
    ------------
    componentType: :py:class:`~pyasn1.type.namedtype.NamedType`
        Object holding named ASN.1 types allowed within this collection

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s).  Constraints
        verification for |ASN.1| type can only occur on explicit
        `.isInconsistent` call.

    Examples
    --------

    .. code-block:: python

        class Afters(Choice):
            '''
            ASN.1 specification:

            Afters ::= CHOICE {
                cheese  [0] IA5String,
                dessert [1] IA5String
            }
            '''
            componentType = NamedTypes(
                NamedType('cheese', IA5String().subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0)
                ),
                NamedType('dessert', IA5String().subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 1)
                )
            )

        afters = Afters()
        afters['cheese'] = 'Mascarpone'
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.TagSet()  # untagged

    #: Default collection of ASN.1 types of component (e.g. :py:class:`~pyasn1.type.namedtype.NamedType`)
    #: object representing ASN.1 type allowed within |ASN.1| type
    componentType: typing.Any = namedtype.NamedTypes()

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection(
        constraint.ValueSizeConstraint(1, 1)
    )

    # Disambiguation ASN.1 types identification
    typeId = Set.getTypeId()

    _currentIdx = None

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if self._cmpComponents("__eq__"):
            return self._componentValues[self._currentIdx] == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if self is other:
            return False
        if self._cmpComponents("__ne__"):
            return self._componentValues[self._currentIdx] != other
        return NotImplemented

    def __lt__(self, other: typing.Any) -> bool:
        if self._cmpComponents("__lt__"):
            return self._componentValues[self._currentIdx] < other
        return NotImplemented

    def __le__(self, other: typing.Any) -> bool:
        if self._cmpComponents("__le__"):
            return self._componentValues[self._currentIdx] <= other
        return NotImplemented

    def __gt__(self, other: typing.Any) -> bool:
        if self._cmpComponents("__gt__"):
            return self._componentValues[self._currentIdx] > other
        return NotImplemented

    def __ge__(self, other: typing.Any) -> bool:
        if self._cmpComponents("__ge__"):
            return self._componentValues[self._currentIdx] >= other
        return NotImplemented

    def __bool__(self) -> bool:
        return bool(self._componentValues)

    def __len__(self) -> int:
        return int(self._currentIdx is not None)

    def __contains__(self, key: object) -> bool:
        if self._currentIdx is None:
            return False
        return key == self.componentType[self._currentIdx].name

    def __iter__(self) -> Iterator[typing.Any]:
        if self._currentIdx is None:
            return
        yield self.componentType[self._currentIdx].name

    # Python dict protocol

    def values(self) -> typing.Any:
        """Return an iterator yielding the chosen component's value, if any."""
        if self._currentIdx is not None:
            yield self._componentValues[self._currentIdx]

    def keys(self) -> typing.Any:
        """Return an iterator yielding the chosen component's name, if any."""
        if self._currentIdx is not None:
            yield self.componentType[self._currentIdx].name

    def items(self) -> typing.Any:
        """Return an iterator yielding the chosen (name, value) pair, if any."""
        if self._currentIdx is not None:
            yield self.componentType[self._currentIdx].name, self[self._currentIdx]

    def checkConsistency(self) -> None:
        """Verify that a component has been chosen.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If no component has been chosen.
        """
        if self._currentIdx is None:
            raise error.PyAsn1Error("Component not chosen")

    def _cloneComponentValues(
        self, myClone: typing.Any, cloneValueFlag: typing.Any
    ) -> None:
        try:
            component = self.getComponent()
        except error.PyAsn1Error:
            pass
        else:
            if isinstance(component, Choice):
                tagSet = component.effectiveTagSet
            else:
                tagSet = component.tagSet
            if isinstance(component, base.ConstructedAsn1Type):
                myClone.setComponentByType(
                    tagSet, component.clone(cloneValueFlag=cloneValueFlag)
                )
            else:
                myClone.setComponentByType(tagSet, component.clone())

    def getComponentByPosition(
        self, idx: int, default: typing.Any = noValue, instantiate: bool = True
    ) -> typing.Any:
        """Return |ASN.1| type component by index.

        Equivalent to Python sequence subscription operation (e.g. `[]`).

        Parameters
        ----------
        idx: :class:`int`
            Component index (zero-based).

        Keyword Args
        ------------
        default: :class:`object`
            If set and requested component is a schema object, return the `default`
            object instead of the requested component.

        instantiate: :class:`bool`
            If :obj:`True` (default), inner component will be automatically
            instantiated.
            If :obj:`False` either existing component or the :class:`NoValue`
            object will be returned.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            Instantiate |ASN.1| component type or return existing
            component value
        """
        if self._currentIdx is None or self._currentIdx != idx:
            return Set.getComponentByPosition(
                self, idx, default=default, instantiate=instantiate
            )

        return self._componentValues[idx]

    def setComponentByPosition(
        self,
        idx: int,
        value: typing.Any = noValue,
        verifyConstraints: bool = True,
        matchTags: bool = True,
        matchConstraints: bool = True,
    ) -> typing.Any:
        """Assign |ASN.1| type component by position.

        Equivalent to Python sequence item assignment operation (e.g. `[]`).

        Parameters
        ----------
        idx: :class:`int`
            Component index (zero-based). Must either refer to existing
            component or to N+1 component. In the latter case a new component
            type gets instantiated (if *componentType* is set, or given ASN.1
            object is taken otherwise) and appended to the |ASN.1| sequence.

        Keyword Args
        ------------
        value: :class:`object` or :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
            A Python value to initialize |ASN.1| component with (if *componentType* is set)
            or ASN.1 value object to assign to |ASN.1| component. Once a new value is
            set to *idx* component, previous value is dropped.
            If `value` is not given, schema object will be set as a component.

        verifyConstraints : :class:`bool`
            If :obj:`False`, skip constraints validation

        matchTags: :class:`bool`
            If :obj:`False`, skip component tags matching

        matchConstraints: :class:`bool`
            If :obj:`False`, skip component constraints matching

        Returns
        -------
        self
        """
        oldIdx = self._currentIdx
        Set.setComponentByPosition(
            self, idx, value, verifyConstraints, matchTags, matchConstraints
        )
        self._currentIdx = idx
        if oldIdx is not None and oldIdx != idx:
            self._componentValues[oldIdx] = noValue
        return self

    @property
    def effectiveTagSet(self) -> typing.Any:
        """Return a :class:`~pyasn1.type.tag.TagSet` object of the currently initialized component or self (if |ASN.1| is tagged)."""
        if self.tagSet:
            return self.tagSet
        else:
            component = self.getComponent()
            return component.effectiveTagSet

    @property
    def tagMap(self) -> typing.Any:
        """Return a :class:`~pyasn1.type.tagmap.TagMap` object.

        Maps ASN.1 tags to ASN.1 objects contained within callee.
        """
        if self.tagSet:
            return Set.tagMap.fget(self)  # type: ignore[attr-defined]
        else:
            return self.componentType.tagMapUnique

    def getComponent(self, innerFlag: bool = False) -> typing.Any:
        """Return currently assigned component of the |ASN.1| object.

        Returns
        -------
        : :py:class:`~pyasn1.type.base.PyAsn1Item`
            a PyASN1 object
        """
        if self._currentIdx is None:
            raise error.PyAsn1Error("Component not chosen")
        else:
            c = self._componentValues[self._currentIdx]
            if innerFlag and isinstance(c, Choice):
                return c.getComponent(innerFlag)
            else:
                return c

    def getName(self, innerFlag: bool = False) -> typing.Any:
        """Return the name of currently assigned component of the |ASN.1| object.

        Returns
        -------
        : :py:class:`str`
            |ASN.1| component name
        """
        if self._currentIdx is None:
            raise error.PyAsn1Error("Component not chosen")
        else:
            if innerFlag:
                c = self._componentValues[self._currentIdx]
                if isinstance(c, Choice):
                    return c.getName(innerFlag)
            return self.componentType.getNameByPosition(self._currentIdx)

    @property
    def isValue(self) -> bool:
        """Indicate that |ASN.1| object represents ASN.1 value.

        If *isValue* is :obj:`False` then this object represents just ASN.1 schema.

        If *isValue* is :obj:`True` then, in addition to its ASN.1 schema features,
        this object can also be used like a Python built-in object (e.g.
        :class:`int`, :class:`str`, :class:`dict` etc.).

        Returns
        -------
        : :class:`bool`
            :obj:`False` if object represents just ASN.1 schema.
            :obj:`True` if object represents ASN.1 schema and can be used as a normal
            value.

        Note
        ----
        There is an important distinction between PyASN1 schema and value objects.
        The PyASN1 schema objects can only participate in ASN.1 schema-related
        operations (e.g. defining or testing the structure of the data). Most
        obvious uses of ASN.1 schema is to guide serialisation codecs whilst
        encoding/decoding serialised ASN.1 contents.

        The PyASN1 value objects can **additionally** participate in many operations
        involving regular Python objects (e.g. arithmetic, comprehension etc).
        """
        if self._currentIdx is None:
            return False

        componentValue = self._componentValues[self._currentIdx]

        return componentValue is not noValue and componentValue.isValue

    def clear(self) -> typing.Any:
        """Remove the chosen component and become an empty |ASN.1| value object."""
        self._currentIdx = None
        return Set.clear(self)


class Any(OctetString):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`,
    its objects are immutable and duck-type Python 2 :class:`str` or Python 3
    :class:`bytes`. When used in Unicode context, |ASN.1| type assumes
    "|encoding|" serialisation.

    Keyword Args
    ------------
    value: :class:`str`, :class:`bytes` or |ASN.1| object
        :class:`str` or :class:`bytes`,
        representing character string to be serialised into octets (note
        `encoding` parameter) or |ASN.1| object.
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
        in text string context.

    binValue: :py:class:`str`
        Binary string initializer to use instead of the *value*.
        Example: '10110011'.

    hexValue: :py:class:`str`
        Hexadecimal string initializer to use instead of the *value*.
        Example: 'DEADBEEF'.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class Error(Sequence):
            '''
            ASN.1 specification:

            Error ::= SEQUENCE {
                code      INTEGER,
                parameter ANY DEFINED BY code  -- Either INTEGER or REAL
            }
            '''
            componentType=NamedTypes(
                NamedType('code', Integer()),
                NamedType('parameter', Any(),
                          openType=OpenType('code', {1: Integer(),
                                                     2: Real()}))
            )

        error = Error()
        error['code'] = 1
        error['parameter'] = Integer(1234)
    """

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.TagSet()  # untagged

    _tagMap: tagmap.TagMap

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Disambiguation ASN.1 types identification
    typeId = OctetString.getTypeId()

    @property
    def tagMap(self) -> typing.Any:
        """Return a :class:`~pyasn1.type.tagmap.TagMap` object.

        Maps ASN.1 tags to ASN.1 objects contained within callee.
        """
        try:
            return self._tagMap

        except AttributeError:
            self._tagMap = tagmap.TagMap(
                {self.tagSet: self}, {eoo.endOfOctets.tagSet: eoo.endOfOctets}, self
            )

            return self._tagMap


# XXX
# coercion rules?
