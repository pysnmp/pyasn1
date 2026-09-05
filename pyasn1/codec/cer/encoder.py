#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""CER encoder for ASN.1 types."""

from typing import Any, Final

from pyasn1 import error
from pyasn1.codec.ber import encoder
from pyasn1.type import univ, useful

__all__ = ["encode"]


class BooleanEncoder(encoder.IntegerEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if value == 0:
            substrate = (0,)
        else:
            substrate = (255,)
        return substrate, False, False


class RealEncoder(encoder.RealEncoder):
    def _chooseEncBase(self, value: Any) -> tuple[int, int, int, int]:
        m, b, e = value
        return self._dropFloatingPoint(m, b, e)

    @staticmethod
    def _encodeCharacter(mantissa: int, exponent: int) -> bytes:
        """Encode a decimal REAL in the form X.690 11.3.2 admits.

        The BER spelling omits the FULL STOP that 11.3.2.5 requires and signs
        a positive exponent that 11.3.2.6 says to leave bare, so it is
        rewritten here rather than reused.
        """
        # Real.prettyIn divides the mantissa down with true division, so a
        # normalised value arrives here as a float and would render with a
        # spurious ".0".
        mantissa = int(mantissa)

        # 11.3.2.4: "Neither the first nor the last digit of the mantissa may
        # be a 0." A trailing zero moves into the exponent; a leading one
        # cannot arise, since the mantissa is held as an integer.
        while mantissa and not mantissa % 10:
            mantissa //= 10
            exponent += 1

        # 11.3.2.6: a zero exponent is written "+0"; otherwise PLUS SIGN is
        # not used, and str() spells a negative exponent with its MINUS SIGN.
        exponentPart = "+0" if not exponent else str(exponent)

        # 11.3.2.5: the last mantissa digit is immediately followed by FULL
        # STOP, then the exponent-mark. 11.3.2.3 leaves a negative mantissa
        # to begin with the MINUS SIGN that str() supplies.
        return f"\x03{mantissa}.E{exponentPart}".encode("ascii")


# specialized GeneralStringEncoder here


class TimeEncoderMixIn:
    Z_CHAR = ord("Z")
    PLUS_CHAR = ord("+")
    MINUS_CHAR = ord("-")
    COMMA_CHAR = ord(",")
    DOT_CHAR = ord(".")
    ZERO_CHAR = ord("0")

    MIN_LENGTH = 12
    MAX_LENGTH = 19

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        # CER encoding constraints:
        # - minutes are mandatory, seconds are optional
        # - sub-seconds must NOT be zero / no meaningless zeros
        # - no hanging fraction dot
        # - time in UTC (Z)
        # - only dot is allowed for fractions

        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        numbers = value.asNumbers()

        if self.PLUS_CHAR in numbers or self.MINUS_CHAR in numbers:
            raise error.PyAsn1Error("Must be UTC time", value=value)

        if numbers[-1] != self.Z_CHAR:
            raise error.PyAsn1Error('Missing "Z" time zone specifier', value=value)

        if self.COMMA_CHAR in numbers:
            raise error.PyAsn1Error("Comma in fractions disallowed", value=value)

        if self.DOT_CHAR in numbers:
            isModified = False

            numbers = list(numbers)

            searchIndex = min(numbers.index(self.DOT_CHAR) + 4, len(numbers) - 1)

            while numbers[searchIndex] != self.DOT_CHAR:
                if numbers[searchIndex] == self.ZERO_CHAR:
                    del numbers[searchIndex]
                    isModified = True

                searchIndex -= 1

            searchIndex += 1

            if searchIndex < len(numbers):
                if numbers[searchIndex] == self.Z_CHAR:
                    # drop hanging comma
                    del numbers[searchIndex - 1]
                    isModified = True

            if isModified:
                value = value.clone(numbers)

        if not self.MIN_LENGTH < len(numbers) < self.MAX_LENGTH:
            raise error.PyAsn1Error("Length constraint violated", value=value)

        # The normalisation above fixes what it can; this rejects what is
        # left, notably a missing seconds element and hour 24 for midnight.
        value.verifyCanonicalForm()

        options.update(maxChunkSize=1000)

        return encoder.OctetStringEncoder.encodeValue(
            self,  # type: ignore[arg-type]
            value,
            asn1Spec,
            encodeFun,
            **options,
        )


class GeneralizedTimeEncoder(TimeEncoderMixIn, encoder.OctetStringEncoder):
    MIN_LENGTH = 12
    MAX_LENGTH = 20


class UTCTimeEncoder(TimeEncoderMixIn, encoder.OctetStringEncoder):
    MIN_LENGTH = 10
    MAX_LENGTH = 14


class SetOfEncoder(encoder.SequenceOfEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        chunks = self._encodeComponents(value, asn1Spec, encodeFun, **options)

        # sort by serialised and padded components
        if len(chunks) > 1:
            zero = b"\x00"
            maxLen = max(map(len, chunks))
            paddedChunks = [(x.ljust(maxLen, zero), x) for x in chunks]
            paddedChunks.sort(key=lambda x: x[0])

            chunks = [x[1] for x in paddedChunks]

        return b"".join(chunks), True, True


class SequenceOfEncoder(encoder.SequenceOfEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if options.get("ifNotEmpty", False) and not len(value):
            return b"", True, True

        chunks = self._encodeComponents(value, asn1Spec, encodeFun, **options)

        return b"".join(chunks), True, True


class SetEncoder(encoder.SequenceEncoder):
    @staticmethod
    def _componentSortKey(componentAndType: Any) -> Any:
        """Sort SET components by tag.

        Sort regardless of the Choice value (static sort)
        """
        component, asn1Spec = componentAndType

        if asn1Spec is None:
            asn1Spec = component

        if asn1Spec.typeId == univ.Choice.typeId and not asn1Spec.tagSet:
            if asn1Spec.tagSet:
                return asn1Spec.tagSet
            else:
                return asn1Spec.componentType.minTagSet
        else:
            return asn1Spec.tagSet

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        substrate = b""

        comps = []
        compsMap = {}

        if asn1Spec is None:
            # instance of ASN.1 schema
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.inconsistencyError(inconsistency, value)

            namedTypes = value.componentType

            # Iterating values() would instantiate absent OPTIONAL and DEFAULT
            # components, so encoding would alter the object it is given.
            for idx, component in enumerate(value.valuesNotInstantiating()):
                if namedTypes:
                    namedType = namedTypes[idx]

                    if component is univ.noValue:
                        if namedType.isOptional or namedType.isDefaulted:
                            continue

                        # A mandatory component that was never set: encode the
                        # schema object, as instantiating on access used to.
                        component = namedType.asn1Object

                    if namedType.isOptional and not component.isValue:
                        continue

                    if namedType.isDefaulted and component == namedType.asn1Object:
                        continue

                    compsMap[id(component)] = namedType

                else:
                    compsMap[id(component)] = None

                comps.append((component, asn1Spec))

        else:
            # bare Python value + ASN.1 schema
            for idx, namedType in enumerate(asn1Spec.componentType.namedTypes):
                try:
                    component = value[namedType.name]

                except KeyError as exc:
                    raise error.PyAsn1Error(
                        "Component name not found",
                        name=namedType.name,
                        value=value,
                    ) from exc

                if namedType.isOptional and namedType.name not in value:
                    continue

                if namedType.isDefaulted and component == namedType.asn1Object:
                    continue

                compsMap[id(component)] = namedType
                comps.append((component, asn1Spec[idx]))

        omitEmptyOptionals = options.get("omitEmptyOptionals", self.omitEmptyOptionals)

        for comp, compType in sorted(comps, key=self._componentSortKey):
            namedType = compsMap[id(comp)]

            # Every component reaching here is present -- absent OPTIONAL and
            # DEFAULT ones were skipped above -- so an empty encoding is the
            # component's value, not a sign of absence. X.690 11.5 lets DER
            # and CER omit only a component equal to its DEFAULT value.
            if namedType and omitEmptyOptionals:
                options.update(ifNotEmpty=namedType.isOptional)

            chunk = encodeFun(comp, compType, **options)

            # wrap open type blob if needed
            if namedType and namedType.openType:
                wrapType = namedType.asn1Object
                if wrapType.tagSet and not wrapType.isSameTypeWith(comp):
                    chunk = encodeFun(chunk, wrapType, **options)

            substrate += chunk

        return substrate, True, True


class SequenceEncoder(encoder.SequenceEncoder):
    # Formerly True, to drop OPTIONAL components that the encoder had itself
    # instantiated while walking the object. Absence is now detected directly
    # (see valuesNotInstantiating), so emptiness no longer stands in for it --
    # and X.690 gives no licence to omit a component that is present. 11.5
    # restricts DER and CER to omitting a component equal to its DEFAULT
    # value, which says nothing about an OPTIONAL one whose encoding happens
    # to have empty contents.
    omitEmptyOptionals = False


tagMap: Final = encoder.tagMap.copy()
tagMap.update(
    {
        univ.Boolean.tagSet: BooleanEncoder(),
        univ.Real.tagSet: RealEncoder(),
        useful.GeneralizedTime.tagSet: GeneralizedTimeEncoder(),
        useful.UTCTime.tagSet: UTCTimeEncoder(),
        # Sequence & Set have same tags as SequenceOf & SetOf
        univ.SetOf.tagSet: SetOfEncoder(),
        # FIXME: every other entry here is keyed by tagSet; this one is keyed
        # by typeId, so it can never match a tag lookup. Inherited verbatim
        # from upstream pyasn1. Left as-is because univ.Sequence.tagSet equals
        # univ.SequenceOf.tagSet, so correcting the key would displace the
        # inherited SequenceOfEncoder and change CER output.
        univ.Sequence.typeId: SequenceEncoder(),  # type: ignore[dict-item]
    }
)

typeMap: Final = encoder.typeMap.copy()
typeMap.update(
    {
        univ.Boolean.typeId: BooleanEncoder(),
        univ.Real.typeId: RealEncoder(),
        useful.GeneralizedTime.typeId: GeneralizedTimeEncoder(),
        useful.UTCTime.typeId: UTCTimeEncoder(),
        # Sequence & Set have same tags as SequenceOf & SetOf
        univ.Set.typeId: SetEncoder(),
        univ.SetOf.typeId: SetOfEncoder(),
        univ.Sequence.typeId: SequenceEncoder(),
        univ.SequenceOf.typeId: SequenceOfEncoder(),
    }
)


class Encoder(encoder.Encoder):
    fixedDefLengthMode = False
    fixedChunkSize = 1000


#: Turns ASN.1 object into CER octet stream.
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a CER octet stream.
#:
#: Parameters
#: ----------
#: value: either a Python or pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     A Python or pyasn1 object to encode. If Python object is given, `asnSpec`
#:     parameter is required to guide the encoding process.
#:
#: Keyword Args
#: ------------
#: asn1Spec:
#:     Optional ASN.1 schema or value object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:
#: Returns
#: -------
#: : :py:class:`bytes` (Python 3) or :py:class:`str` (Python 2)
#:     Given ASN.1 object encoded into BER octet-stream
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode Python value into CER with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> encode([1, 2, 3], asn1Spec=seq)
#:    b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00'
#:
#: Encode ASN.1 value object into CER
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00'
#:
encode: Final = Encoder(tagMap, typeMap)

# EncoderFactory queries class instance and builds a map of tags -> encoders
