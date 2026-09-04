#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""BER encoder for ASN.1 types."""

import logging
from typing import Any, Final

from pyasn1 import error
from pyasn1.codec.ber import eoo
from pyasn1.type import char, tag, univ, useful


def _int_to_bytes(value: int, signed: bool = False, length: int = 0) -> bytes:
    """Convert an integer to bytes with length calculation.

    Signed conversion uses the fewest two's complement octets that hold
    ``value``, as X.690 8.3.2 requires. ``int.bit_length`` ignores the sign
    and so undercounts negative powers of two -- ``(-128).bit_length()`` is
    8, yet -128 is exactly representable in one octet -- hence the sign is
    folded in with ``~value`` before sizing rather than by padding an octet.
    """
    if signed:
        size = ((value if value >= 0 else ~value).bit_length() // 8) + 1
        return value.to_bytes(max(size, (length + 7) // 8), "big", signed=True)

    length = max(value.bit_length(), length)
    return value.to_bytes((length + 7) // 8, "big", signed=False)


__all__ = ["encode"]

LOG = logging.getLogger(__name__)


class AbstractItemEncoder:
    supportIndefLenMode = True

    # An outcome of otherwise legit call `encodeFun(eoo.endOfOctets)`
    eooIntegerSubstrate = (0, 0)
    eooOctetsSubstrate = bytes(eooIntegerSubstrate)

    # noinspection PyMethodMayBeStatic
    def encodeTag(self, singleTag: tag.Tag, isConstructed: bool) -> tuple[int, ...]:
        tagClass, tagFormat, tagId = singleTag
        encodedTag = tagClass | tagFormat
        if isConstructed:
            encodedTag |= tag.tagFormatConstructed

        if tagId < 31:
            return (encodedTag | tagId,)

        else:
            substrate: tuple[int, ...] = (tagId & 0x7F,)

            tagId >>= 7

            while tagId:
                substrate = (0x80 | (tagId & 0x7F),) + substrate
                tagId >>= 7

            return (encodedTag | 0x1F,) + substrate

    def encodeLength(self, length: int, defMode: bool) -> tuple[int, ...]:
        if not defMode and self.supportIndefLenMode:
            return (0x80,)

        if length < 0x80:
            return (length,)

        else:
            substrate: tuple[int, ...] = ()
            while length:
                substrate = (length & 0xFF,) + substrate
                length >>= 8

            substrateLen = len(substrate)

            if substrateLen > 126:
                raise error.PyAsn1Error("Length octets overflow", length=substrateLen)

            return (0x80 | substrateLen,) + substrate

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        raise error.PyAsn1Error("Not implemented")

    def encode(
        self, value: Any, asn1Spec: Any = None, encodeFun: Any = None, **options: Any
    ) -> bytes:
        if asn1Spec is None:
            tagSet = value.tagSet
        else:
            tagSet = asn1Spec.tagSet

        # untagged item?
        if not tagSet:
            substrate, isConstructed, isOctets = self.encodeValue(
                value, asn1Spec, encodeFun, **options
            )
            return substrate

        defMode = options.get("defMode", True)

        substrate = b""

        for idx, singleTag in enumerate(tagSet.superTags):
            defModeOverride = defMode

            # base tag?
            if not idx:
                try:
                    substrate, isConstructed, isOctets = self.encodeValue(
                        value, asn1Spec, encodeFun, **options
                    )

                except error.PyAsn1Error as exc:
                    raise error.PyAsn1Error(
                        "Error encoding value", value=value, cause=exc
                    ) from exc

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug(
                        "encoded value",
                        extra={
                            "constructed": isConstructed,
                            "value": value,
                            "substrate": substrate,
                        },
                    )

                if not substrate and isConstructed and options.get("ifNotEmpty", False):
                    return substrate

                if not isConstructed:
                    defModeOverride = True

                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "overridden encoding mode into definitive for primitive type"
                        )

            header = self.encodeTag(singleTag, isConstructed)

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "encoded tag",
                    extra={
                        "constructed": isConstructed,
                        "tag": singleTag,
                        "header": bytes(header),
                    },
                )

            header += self.encodeLength(len(substrate), defModeOverride)

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "encoded octets into header",
                    extra={
                        "substrateLength": len(substrate),
                        "header": bytes(header),
                    },
                )

            if isOctets:
                substrate = bytes(header) + substrate

                if not defModeOverride:
                    substrate += self.eooOctetsSubstrate

            else:
                substrate = header + substrate

                if not defModeOverride:
                    substrate += self.eooIntegerSubstrate

        if not isOctets:
            substrate = bytes(substrate)

        return substrate


class EndOfOctetsEncoder(AbstractItemEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        return b"", False, True


class BooleanEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        return (1,) if value else (0,), False, False


class IntegerEncoder(AbstractItemEncoder):
    supportIndefLenMode = False
    supportCompactZero = False

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if value == 0:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "encoding payload for zero INTEGER",
                    extra={"supportCompactZero": self.supportCompactZero},
                )

            # de-facto way to encode zero
            if self.supportCompactZero:
                return (), False, False
            else:
                return (0,), False, False

        return _int_to_bytes(int(value), signed=True), False, True


class BitStringEncoder(AbstractItemEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is not None:
            # TODO: try to avoid ASN.1 schema instantiation
            value = asn1Spec.clone(value)

        valueLength = len(value)
        if valueLength % 8:
            alignedValue = value << (8 - valueLength % 8)
        else:
            alignedValue = value

        maxChunkSize = options.get("maxChunkSize", 0)

        # maxChunkSize budgets the contents octets of a fragment, and 8.6.2.2
        # spends the first of them on the unused-bit count, so a fragment
        # carries one octet less of bit data than the budget suggests. CER
        # 9.2 counts the same way when it caps a fragment at 1000 contents
        # octets. A budget of one leaves no room at all; keep a single octet
        # of bit data so chunking still makes progress.
        maxChunkBits = max(maxChunkSize - 1, 1) * 8 if maxChunkSize else 0

        if not maxChunkBits or len(alignedValue) <= maxChunkBits:
            substrate = alignedValue.asOctets()
            return bytes((len(substrate) * 8 - valueLength,)) + substrate, False, True

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("encoding into chunks", extra={"maxChunkSize": maxChunkSize})

        baseTag = value.tagSet.baseTag

        # strip off explicit tags
        if baseTag:
            tagSet = tag.TagSet(baseTag, baseTag)

        else:
            tagSet = tag.TagSet()

        alignedValue = alignedValue.clone(tagSet=tagSet)

        stop = 0
        substrate = b""
        while stop < valueLength:
            start = stop
            stop = min(start + maxChunkBits, valueLength)
            substrate += encodeFun(alignedValue[start:stop], asn1Spec, **options)

        return substrate, True, True


class OctetStringEncoder(AbstractItemEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is None:
            substrate = value.asOctets()

        elif not isinstance(value, bytes):
            substrate = asn1Spec.clone(value).asOctets()

        else:
            substrate = value

        maxChunkSize = options.get("maxChunkSize", 0)

        if not maxChunkSize or len(substrate) <= maxChunkSize:
            return substrate, False, True

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("encoding into chunks", extra={"maxChunkSize": maxChunkSize})

        # 8.23.3 encodes a character string as if it were an implicitly tagged
        # octetstring, and 8.7.3.2 gives its fragments the universal OCTET
        # STRING tag whatever the outer type. So the fragments are cut from the
        # octets, not from the characters: the two part company for the string
        # types that spend more than one octet on a character, where a chunk
        # counted in characters overruns the budget and segments again forever.
        fragmentSpec = univ.OctetString()

        pos = 0
        fragments = b""

        while True:
            chunk = substrate[pos : pos + maxChunkSize]
            if not chunk:
                break

            fragments += encodeFun(fragmentSpec.clone(chunk), None, **options)
            pos += maxChunkSize

        return fragments, True, True


class NullEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        return b"", False, True


class ObjectIdentifierEncoder(AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        oid = value.asTuple()

        # Build the first pair
        try:
            first = oid[0]
            second = oid[1]

        except IndexError as exc:
            raise error.PyAsn1Error("Short OID", value=value) from exc

        if 0 <= second <= 39:
            if first == 1:
                oid = (second + 40,) + oid[2:]
            elif first == 0:
                oid = (second,) + oid[2:]
            elif first == 2:
                oid = (second + 80,) + oid[2:]
            else:
                raise error.PyAsn1Error("Impossible first/second arcs", value=value)

        elif first == 2:
            oid = (second + 80,) + oid[2:]

        else:
            raise error.PyAsn1Error("Impossible first/second arcs", value=value)

        # Accumulated in a list: repeated tuple concatenation is quadratic in
        # the arc count, which turns a large OID into a CPU exhaustion vector.
        octets: list[int] = []

        # Cycle through subIds
        for subOid in oid:
            if 0 <= subOid <= 127:
                # Optimize for the common case
                octets.append(subOid)

            elif subOid > 127:
                # Pack large Sub-Object IDs
                res: list[int] = [subOid & 0x7F]
                subOid >>= 7

                while subOid:
                    res.append(0x80 | (subOid & 0x7F))
                    subOid >>= 7

                # Add packed Sub-Object ID to resulted Object ID
                octets.extend(reversed(res))

            else:
                raise error.PyAsn1Error("Negative OID arc", arc=subOid, value=value)

        return tuple(octets), False, False


class RealEncoder(AbstractItemEncoder):
    supportIndefLenMode = False
    binEncBase = 2  # set to None to choose encoding base automatically

    @staticmethod
    def _dropFloatingPoint(m: float, encbase: int, e: int) -> tuple[int, int, int, int]:
        ms, es = 1, 1
        if m < 0:
            ms = -1  # mantissa sign

        if e < 0:
            es = -1  # exponent sign

        m *= ms

        if encbase == 8:
            m *= 2 ** (abs(e) % 3 * es)
            e = abs(e) // 3 * es

        elif encbase == 16:
            m *= 2 ** (abs(e) % 4 * es)
            e = abs(e) // 4 * es

        while True:
            if int(m) != m:
                m *= encbase
                e -= 1
                continue
            break

        return ms, int(m), encbase, e

    def _chooseEncBase(self, value: Any) -> tuple[int, int, int, int]:
        m, b, e = value
        encBase = [2, 8, 16]
        if value.binEncBase in encBase:
            return self._dropFloatingPoint(m, value.binEncBase, e)

        elif self.binEncBase in encBase:
            return self._dropFloatingPoint(m, self.binEncBase, e)

        # auto choosing base 2/8/16
        mantissa = [m, m, m]
        exponent = [e, e, e]
        sign = 1
        encbase = 2
        e = float("inf")

        for i in range(3):
            sign, mantissa[i], encBase[i], exponent[i] = self._dropFloatingPoint(
                mantissa[i], encBase[i], exponent[i]
            )

            if abs(exponent[i]) < abs(e) or (
                abs(exponent[i]) == abs(e) and mantissa[i] < m
            ):
                e = exponent[i]
                m = int(mantissa[i])
                encbase = encBase[i]

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "automatically chosen REAL encoding base",
                extra={"encBase": encbase, "sign": sign, "mantissa": m, "exponent": e},
            )

        return sign, m, encbase, e

    @staticmethod
    def _encodeExponent(exponent: int) -> bytes:
        if exponent in (0, -1):
            return bytes((exponent & 0xFF,))

        octets = b""
        while exponent not in (0, -1):
            octets = bytes((exponent & 0xFF,)) + octets
            exponent >>= 8

        if exponent == 0 and octets[0] & 0x80:
            return bytes((0,)) + octets
        if exponent == -1 and not octets[0] & 0x80:
            return bytes((0xFF,)) + octets
        return octets

    @staticmethod
    def _encodeMantissa(mantissa: int) -> bytes:
        octets = b""
        while mantissa:
            octets = bytes((mantissa & 0xFF,)) + octets
            mantissa >>= 8
        return octets

    def _encodeBinary(self, value: Any) -> bytes:
        firstOctet = 0x80
        sign, mantissa, encbase, exponent = self._chooseEncBase(value)

        if sign < 0:
            firstOctet |= 0x40

        if encbase == 2:
            while mantissa & 0x1 == 0:
                mantissa >>= 1
                exponent += 1

        elif encbase == 8:
            while mantissa & 0x7 == 0:
                mantissa >>= 3
                exponent += 1
            firstOctet |= 0x10

        else:  # encbase = 16
            while mantissa & 0xF == 0:
                mantissa >>= 4
                exponent += 1
            firstOctet |= 0x20

        scaleFactor = 0
        while mantissa & 0x1 == 0:
            mantissa >>= 1
            scaleFactor += 1

        if scaleFactor > 3:
            raise error.PyAsn1Error("Scale factor overflow")

        firstOctet |= scaleFactor << 2
        exponentOctets = self._encodeExponent(exponent)
        exponentLength = len(exponentOctets)

        if exponentLength > 0xFF:
            raise error.PyAsn1Error("Real exponent overflow")
        if exponentLength == 2:
            firstOctet |= 1
        elif exponentLength == 3:
            firstOctet |= 2
        elif exponentLength > 3:
            firstOctet |= 3
            exponentOctets = bytes((exponentLength,)) + exponentOctets

        return bytes((firstOctet,)) + exponentOctets + self._encodeMantissa(mantissa)

    @staticmethod
    def _encodeCharacter(mantissa: int, exponent: int) -> bytes:
        """Encode a base 10 REAL as an ISO 6093 NR3 field (X.690 8.5.8).

        NR3 requires a decimal mark. This used to emit "15E-1", which
        declares NR3 in the first contents octet and then carries NR2-shaped
        octets, so a decoder holding the sender to the form it named could
        not read it back.
        """
        # str() already spells a negative exponent with its MINUS SIGN, and
        # ISO 6093 leaves the PLUS SIGN optional on a positive one. The
        # canonical spelling of 11.3.2.6 is tighter still and belongs to the
        # CER and DER encoders, which override this.
        return f"\x03{mantissa}.E{exponent}".encode("ascii")

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        if value.isPlusInf:
            return (0x40,), False, False

        if value.isMinusInf:
            return (0x41,), False, False

        if value.isNaN:
            return (0x42,), False, False

        if value.isMinusZero:
            return (0x43,), False, False

        m, b, e = value

        if not m:
            return b"", False, True

        if b == 10:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("encoding REAL into character form")

            return self._encodeCharacter(m, e), False, True

        elif b == 2:
            return self._encodeBinary(value), False, True

        else:
            raise error.PyAsn1Error("Prohibited Real base", base=b)


class SequenceEncoder(AbstractItemEncoder):
    omitEmptyOptionals = False

    # TODO: handling three flavors of input is too much -- split over codecs

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        substrate = b""

        omitEmptyOptionals = options.get("omitEmptyOptionals", self.omitEmptyOptionals)

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "encoding empty OPTIONAL components",
                extra={"omitEmptyOptionals": omitEmptyOptionals},
            )

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
                        if LOG.isEnabledFor(logging.DEBUG):
                            LOG.debug(
                                "not encoding OPTIONAL component",
                                extra={"namedType": namedType},
                            )
                        continue

                    if namedType.isDefaulted and component == namedType.asn1Object:
                        if LOG.isEnabledFor(logging.DEBUG):
                            LOG.debug(
                                "not encoding DEFAULT component",
                                extra={"namedType": namedType},
                            )
                        continue

                    if omitEmptyOptionals:
                        options.update(ifNotEmpty=namedType.isOptional)

                # wrap open type blob if needed
                if namedTypes and namedType.openType:
                    wrapType = namedType.asn1Object

                    if wrapType.typeId in (univ.SetOf.typeId, univ.SequenceOf.typeId):
                        substrate += encodeFun(
                            component,
                            asn1Spec,
                            **dict(options, wrapType=wrapType.componentType),
                        )

                    else:
                        chunk = encodeFun(component, asn1Spec, **options)

                        if wrapType.isSameTypeWith(component):
                            substrate += chunk

                        else:
                            substrate += encodeFun(chunk, wrapType, **options)

                            if LOG.isEnabledFor(logging.DEBUG):
                                LOG.debug(
                                    "wrapped with wrap type",
                                    extra={"wrapType": wrapType},
                                )

                else:
                    substrate += encodeFun(component, asn1Spec, **options)

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
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "not encoding OPTIONAL component",
                            extra={"namedType": namedType},
                        )
                    continue

                if namedType.isDefaulted and component == namedType.asn1Object:
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug(
                            "not encoding DEFAULT component",
                            extra={"namedType": namedType},
                        )
                    continue

                if omitEmptyOptionals:
                    options.update(ifNotEmpty=namedType.isOptional)

                componentSpec = namedType.asn1Object

                # wrap open type blob if needed
                if namedType.openType:
                    if componentSpec.typeId in (
                        univ.SetOf.typeId,
                        univ.SequenceOf.typeId,
                    ):
                        substrate += encodeFun(
                            component,
                            componentSpec,
                            **dict(options, wrapType=componentSpec.componentType),
                        )

                    else:
                        chunk = encodeFun(component, componentSpec, **options)

                        if componentSpec.isSameTypeWith(component):
                            substrate += chunk

                        else:
                            substrate += encodeFun(chunk, componentSpec, **options)

                            if LOG.isEnabledFor(logging.DEBUG):
                                LOG.debug(
                                    "wrapped with wrap type",
                                    extra={"wrapType": componentSpec},
                                )

                else:
                    substrate += encodeFun(component, componentSpec, **options)

        return substrate, True, True


class SequenceOfEncoder(AbstractItemEncoder):
    def _encodeComponents(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> list[bytes]:
        if asn1Spec is None:
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.inconsistencyError(inconsistency, value)

        else:
            asn1Spec = asn1Spec.componentType

        chunks = []

        wrapType = options.pop("wrapType", None)

        for idx, component in enumerate(value):
            chunk = encodeFun(component, asn1Spec, **options)

            if wrapType is not None and not wrapType.isSameTypeWith(component):
                # wrap encoded value with wrapper container (e.g. ANY)
                chunk = encodeFun(chunk, wrapType, **options)

                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("wrapped with wrap type", extra={"wrapType": wrapType})

            chunks.append(chunk)

        return chunks

    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        chunks = self._encodeComponents(value, asn1Spec, encodeFun, **options)

        return b"".join(chunks), True, True


class ChoiceEncoder(AbstractItemEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is None:
            component = value.getComponent()
        else:
            names = [
                namedType.name
                for namedType in asn1Spec.componentType.namedTypes
                if namedType.name in value
            ]
            if len(names) != 1:
                raise error.PyAsn1Error(
                    "Multiple components for Choice"
                    if names
                    else "No components for Choice",
                    value=value,
                )

            name = names[0]

            component = value[name]
            asn1Spec = asn1Spec[name]

        return encodeFun(component, asn1Spec, **options), True, True


class AnyEncoder(OctetStringEncoder):
    def encodeValue(
        self, value: Any, asn1Spec: Any, encodeFun: Any, **options: Any
    ) -> tuple[Any, bool, bool]:
        if asn1Spec is None:
            value = value.asOctets()
        elif not isinstance(value, bytes):
            value = asn1Spec.clone(value).asOctets()

        return value, not options.get("defMode", True), True


tagMap: Final[dict[tag.TagSet, AbstractItemEncoder]] = {
    eoo.endOfOctets.tagSet: EndOfOctetsEncoder(),
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
    char.UTF8String.tagSet: OctetStringEncoder(),
    char.NumericString.tagSet: OctetStringEncoder(),
    char.PrintableString.tagSet: OctetStringEncoder(),
    char.TeletexString.tagSet: OctetStringEncoder(),
    char.VideotexString.tagSet: OctetStringEncoder(),
    char.IA5String.tagSet: OctetStringEncoder(),
    char.GraphicString.tagSet: OctetStringEncoder(),
    char.VisibleString.tagSet: OctetStringEncoder(),
    char.GeneralString.tagSet: OctetStringEncoder(),
    char.UniversalString.tagSet: OctetStringEncoder(),
    char.BMPString.tagSet: OctetStringEncoder(),
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
    univ.Set.typeId: SequenceEncoder(),
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
    fixedDefLengthMode: bool | None = None
    fixedChunkSize: int | None = None

    def __init__(
        self,
        tagMap: dict[tag.TagSet, AbstractItemEncoder],
        typeMap: dict[int, AbstractItemEncoder] | None = None,
    ) -> None:
        self.__tagMap = tagMap
        self.__typeMap = typeMap if typeMap is not None else {}

    def __call__(self, value: Any, asn1Spec: Any = None, **options: Any) -> bytes:
        try:
            if asn1Spec is None:
                typeId = value.typeId
                tagSet = value.tagSet
            else:
                typeId = asn1Spec.typeId
                tagSet = asn1Spec.tagSet

        except AttributeError as exc:
            raise error.PyAsn1Error(
                'Value is not ASN.1 type instance and "asn1Spec" not given',
                value=value,
            ) from exc

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "encoder called",
                extra={
                    "defMode": options.get("defMode", True),
                    "maxChunkSize": options.get("maxChunkSize", 0),
                    "typeName": value.prettyPrintType()
                    if asn1Spec is None
                    else asn1Spec.prettyPrintType(),
                    "value": value,
                },
            )

        if self.fixedDefLengthMode is not None:
            options.update(defMode=self.fixedDefLengthMode)

        if self.fixedChunkSize is not None:
            options.update(maxChunkSize=self.fixedChunkSize)

        # Give explicitly tagged values an opportunity to select a custom
        # codec. Base tags are deliberately excluded here: several built-in
        # types share them (e.g. SEQUENCE and SEQUENCE OF) and must use the
        # faster, unambiguous type ID dispatch below.
        if tagSet.baseTag:
            baseTagSet = tag.TagSet(tagSet.baseTag, tagSet.baseTag)
        else:
            baseTagSet = tag.TagSet()
        concreteEncoder = None

        if tagSet != baseTagSet:
            concreteEncoder = self.__tagMap.get(tagSet)

            if concreteEncoder and LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "using value codec chosen by complete tagSet",
                    extra={
                        "codec": concreteEncoder.__class__.__name__,
                        "tagSet": tagSet,
                    },
                )

        try:
            if concreteEncoder is None:
                concreteEncoder = self.__typeMap[typeId]

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "using value codec chosen by type ID",
                    extra={
                        "codec": concreteEncoder.__class__.__name__,
                        "typeId": typeId,
                    },
                )

        except KeyError:
            # use base type for codec lookup to recover untagged types
            try:
                concreteEncoder = self.__tagMap[baseTagSet]

            except KeyError as exc:
                raise error.PyAsn1Error(
                    "No encoder for value", value=value, tagSet=tagSet
                ) from exc

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "using value codec chosen by tagSet",
                    extra={
                        "codec": concreteEncoder.__class__.__name__,
                        "tagSet": tagSet,
                    },
                )

        substrate = concreteEncoder.encode(value, asn1Spec, self, **options)

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "codec built substrate",
                extra={
                    "codec": concreteEncoder.__class__.__name__,
                    "substrate": substrate,
                },
            )
            LOG.debug("encoder completed")

        return substrate


#: Turns ASN.1 object into BER octet stream.
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a BER octet stream.
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
#: defMode: :py:class:`bool`
#:     If :obj:`False`, produces indefinite length encoding
#:
#: maxChunkSize: :py:class:`int`
#:     Maximum chunk size in chunked encoding mode (0 denotes unlimited chunk size)
#:
#: Returns
#: -------
#: : :py:class:`bytes` (Python 3) or :py:class:`str` (Python 2)
#:     Given ASN.1 object encoded into BER octetstream
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode Python value into BER with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> encode([1, 2, 3], asn1Spec=seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
#: Encode ASN.1 value object into BER
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
encode: Final = Encoder(tagMap, typeMap)
