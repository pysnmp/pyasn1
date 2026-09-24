#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
"""Schemas and sample values the benchmarks encode and decode.

Two shapes carry the suite. An SNMP-like message is the workload pyasn1
was written for and exercises SEQUENCE, SEQUENCE OF, CHOICE, INTEGER,
OCTET STRING and OBJECT IDENTIFIER together. A certificate-like
structure adds SET, BIT STRING, UTCTime, character strings and an open
type, which is where the CER and DER rules diverge from BER.
"""

from typing import Any

from pyasn1.type import char, namedtype, opentype, tag, univ, useful

__all__ = [
    "ATTRIBUTE_TYPE_MAP",
    "Certificate",
    "Message",
    "Record",
    "buildCertificate",
    "buildMessage",
    "buildRecord",
    "buildSequenceOf",
]


class ObjectSyntax(univ.Choice):
    """The value half of a variable binding."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("number", univ.Integer()),
        namedtype.NamedType("string", univ.OctetString()),
        namedtype.NamedType("object", univ.ObjectIdentifier()),
        namedtype.NamedType("empty", univ.Null()),
    )


class VarBind(univ.Sequence):
    """One OID paired with its value."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("name", univ.ObjectIdentifier()),
        namedtype.NamedType("value", ObjectSyntax()),
    )


class VarBindList(univ.SequenceOf):
    """A list of variable bindings."""

    componentType = VarBind()


class PDU(univ.Sequence):
    """A request carrying a list of variable bindings."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("request-id", univ.Integer()),
        namedtype.NamedType("error-status", univ.Integer()),
        namedtype.NamedType("error-index", univ.Integer()),
        namedtype.NamedType("variable-bindings", VarBindList()),
    )


class Message(univ.Sequence):
    """An SNMP-like message: version, community and a PDU."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("community", univ.OctetString()),
        namedtype.NamedType("data", PDU()),
    )


class Record(univ.Sequence):
    """The tagged-and-defaulted SEQUENCE from the README."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("id", univ.Integer()),
        namedtype.OptionalNamedType(
            "room",
            univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.DefaultedNamedType(
            "house",
            univ.Integer(0).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


ATTRIBUTE_TYPE_MAP = {
    univ.ObjectIdentifier("2.5.4.3"): char.PrintableString(),
    univ.ObjectIdentifier("2.5.4.6"): char.PrintableString(),
    univ.ObjectIdentifier("2.5.4.10"): char.UTF8String(),
}


class AttributeTypeAndValue(univ.Sequence):
    """A distinguished-name attribute, whose value is an open type."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType(
            "value",
            univ.Any(),
            openType=opentype.OpenType("type", ATTRIBUTE_TYPE_MAP),
        ),
    )


class RelativeDistinguishedName(univ.SetOf):
    """A SET OF attributes, which DER has to sort on encoding."""

    componentType = AttributeTypeAndValue()


class Name(univ.SequenceOf):
    """A sequence of relative distinguished names."""

    componentType = RelativeDistinguishedName()


class Validity(univ.Sequence):
    """The two UTCTime bounds of a certificate."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("notBefore", useful.UTCTime()),
        namedtype.NamedType("notAfter", useful.UTCTime()),
    )


class Certificate(univ.Sequence):
    """A certificate-like structure: nested SETs, times and a BIT STRING."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("serialNumber", univ.Integer()),
        namedtype.NamedType("issuer", Name()),
        namedtype.NamedType("validity", Validity()),
        namedtype.NamedType("subject", Name()),
        namedtype.NamedType("subjectPublicKey", univ.BitString()),
        namedtype.NamedType("signature", univ.OctetString()),
    )


#: A handful of OIDs, walked over so no single arc encoding dominates.
OIDS = (
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.2.1.1.3.0",
    "1.3.6.1.2.1.2.2.1.10.1",
    "1.3.6.1.4.1.9.9.42.1.2.9.1.6.4294967295",
    "1.3.6.1.6.3.1.1.4.1.0",
)


def buildMessage(varBinds: int = 32) -> Message:
    """Build a message carrying *varBinds* variable bindings.

    Parameters
    ----------
    varBinds : int
        How many variable bindings to put in the PDU.

    Returns
    -------
    Message
        A fully populated message.
    """
    message = Message()
    message["version"] = 1
    message["community"] = b"public"

    pdu = message["data"]
    pdu["request-id"] = 2029388243
    pdu["error-status"] = 0
    pdu["error-index"] = 0

    bindings = pdu["variable-bindings"]

    for index in range(varBinds):
        varBind = VarBind()
        varBind["name"] = OIDS[index % len(OIDS)]

        value = varBind["value"]
        if index % 3 == 0:
            value["number"] = index * 7919
        elif index % 3 == 1:
            value["string"] = b"interface eth%d" % index
        else:
            value["object"] = OIDS[(index + 1) % len(OIDS)]

        bindings[index] = varBind

    return message


def buildRecord(id_: int = 123, room: int = 321) -> Record:
    """Build the README record, with the defaulted component left out.

    Parameters
    ----------
    id_ : int
        Value of the ``id`` component.
    room : int
        Value of the optional, implicitly tagged ``room`` component.

    Returns
    -------
    Record
        The populated record.
    """
    record = Record()
    record["id"] = id_
    record["room"] = room
    return record


def buildSequenceOf(size: int = 256) -> univ.SequenceOf:
    """Build a SEQUENCE OF INTEGER of *size* elements.

    Parameters
    ----------
    size : int
        Number of integers in the sequence.

    Returns
    -------
    univ.SequenceOf
        The populated sequence.
    """
    sequence = univ.SequenceOf(componentType=univ.Integer())
    for index in range(size):
        sequence[index] = index * 65537
    return sequence


def _attribute(oid: str, value: Any) -> AttributeTypeAndValue:
    """Build one distinguished-name attribute already wrapped in ANY."""
    from pyasn1.codec.der.encoder import encode as derEncode

    attribute = AttributeTypeAndValue()
    attribute["type"] = oid
    attribute["value"] = univ.Any(derEncode(value))
    return attribute


def buildCertificate(attributes: int = 4) -> Certificate:
    """Build a certificate-like value with *attributes* names per side.

    Parameters
    ----------
    attributes : int
        How many relative distinguished names to put in each of the
        issuer and subject names.

    Returns
    -------
    Certificate
        The populated certificate.
    """
    certificate = Certificate()
    certificate["serialNumber"] = 0x0123456789ABCDEF0123456789ABCDEF

    for field, prefix in (("issuer", "Example CA"), ("subject", "example.com")):
        name = certificate[field]
        for index in range(attributes):
            rdn = RelativeDistinguishedName()
            rdn[0] = _attribute("2.5.4.3", char.PrintableString(f"{prefix} {index}"))
            rdn[1] = _attribute("2.5.4.6", char.PrintableString("US"))
            name[index] = rdn

    validity = certificate["validity"]
    validity["notBefore"] = "170612120000Z"
    validity["notAfter"] = "270612120000Z"

    certificate["subjectPublicKey"] = univ.BitString(
        hexValue="3048024100" + "ab" * 64 + "0203010001"
    )
    certificate["signature"] = bytes(range(256)) * 2

    return certificate
