#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
"""Type system benchmarks.

Nothing here touches a codec, yet the codecs spend much of their time in
it: every decoded component is a value being built, tagged and checked
against its constraints, and every schema lookup goes through the named
type machinery.

The operations below are individually far too small to measure -- a tag
set comparison is a handful of nanoseconds -- so each benchmark repeats
its operation ``ROUNDS`` times and measures the loop. What is reported
is the cost of ``ROUNDS`` calls, which moves with the cost of one.
"""

from benchmarks.schemas import VarBind, buildMessage
from pyasn1.type import char, constraint, namedtype, tag, univ

#: How many times a benchmark repeats its operation. Large enough that
#: the loop, and not the harness, is what is being measured.
ROUNDS = 1000

OID_TEXT = "1.3.6.1.4.1.9.9.42.1.2.9.1.6.4294967295"
OID_PREFIX = univ.ObjectIdentifier("1.3.6.1.4.1")
OID_VALUE = univ.ObjectIdentifier(OID_TEXT)

PAYLOAD = b"a moderately sized payload" * 8

IMPLICIT_TAG = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
EXPLICIT_TAG = tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3)

SIZED = constraint.ConstraintsIntersection(
    constraint.ValueSizeConstraint(1, 64),
    constraint.PermittedAlphabetConstraint(*"abcdefghijklmnopqrstuvwxyz0123456789.-"),
)
RANGED = constraint.ConstraintsIntersection(
    constraint.ValueRangeConstraint(0, 4294967295),
    constraint.SingleValueConstraint(*range(0, 4096, 8)),
)

NAMED_TYPES = namedtype.NamedTypes(
    namedtype.NamedType("version", univ.Integer()),
    namedtype.NamedType("community", univ.OctetString()),
    namedtype.NamedType("request-id", univ.Integer()),
    namedtype.NamedType("error-status", univ.Integer()),
    namedtype.NamedType("error-index", univ.Integer()),
    namedtype.NamedType("variable-bindings", univ.SequenceOf()),
)


class Hostname(char.PrintableString):
    """A character string under a size and an alphabet constraint."""

    subtypeSpec = SIZED


class Counter(univ.Integer):
    """An integer under a range and a single-value constraint."""

    subtypeSpec = RANGED


def repeat(operation, *args, **kwargs):
    """Call *operation* ``ROUNDS`` times and return the last result.

    Parameters
    ----------
    operation : callable
        The operation under measurement.
    *args, **kwargs
        Passed through to *operation* unchanged.

    Returns
    -------
    object
        Whatever the last call returned, so the work cannot be elided.
    """
    result = None
    for _ in range(ROUNDS):
        result = operation(*args, **kwargs)
    return result


def test_integer_create(benchmark):
    """Instantiate an INTEGER, the hottest constructor in the library."""
    benchmark(repeat, univ.Integer, 12345)


def test_integer_constrained_create(benchmark):
    """Instantiate an INTEGER whose value has to clear two constraints."""
    benchmark(repeat, Counter, 2048)


def test_octet_string_create(benchmark):
    """Instantiate an OCTET STRING from bytes."""
    benchmark(repeat, univ.OctetString, PAYLOAD)


def test_character_string_constrained_create(benchmark):
    """Instantiate a character string checked against a permitted alphabet."""
    benchmark(repeat, Hostname, "router-7.example.com")


def test_object_identifier_parse(benchmark):
    """Parse an OID out of its dotted text form."""
    benchmark(repeat, univ.ObjectIdentifier, OID_TEXT)


def test_object_identifier_is_prefix_of(benchmark):
    """Test one OID against another for prefix containment."""
    benchmark(repeat, OID_PREFIX.isPrefixOf, OID_VALUE)


def test_bit_string_from_binary(benchmark):
    """Build a BIT STRING out of a 512-bit binary literal."""
    benchmark(repeat, univ.BitString, binValue="1011" * 128)


def test_clone(benchmark):
    """Clone a value, which every decoded component ends up doing."""
    value = univ.Integer(42)
    benchmark(repeat, value.clone, 43)


def test_subtype_implicit_tag(benchmark):
    """Derive an implicitly tagged subtype from a value."""
    value = univ.Integer(42)
    benchmark(repeat, value.subtype, implicitTag=IMPLICIT_TAG)


def test_tag_set_tag_implicitly(benchmark):
    """Re-tag a tag set in place, as implicit tagging does."""
    benchmark(repeat, univ.Integer.tagSet.tagImplicitly, IMPLICIT_TAG)


def test_tag_set_tag_explicitly(benchmark):
    """Wrap a tag set in an outer tag, as explicit tagging does."""
    benchmark(repeat, univ.Integer.tagSet.tagExplicitly, EXPLICIT_TAG)


def test_tag_set_is_super_tag_set_of(benchmark):
    """Compare two tag sets, which the decoder does per component."""
    tagSet = univ.Integer.tagSet.tagImplicitly(IMPLICIT_TAG)
    benchmark(repeat, univ.Integer.tagSet.isSuperTagSetOf, tagSet)


def test_named_types_position_by_name(benchmark):
    """Look a component up by name in a schema's named types."""
    benchmark(repeat, NAMED_TYPES.getPositionByName, "variable-bindings")


def test_sequence_build(benchmark):
    """Build a two-component SEQUENCE through its schema."""

    def build():
        varBind = VarBind()
        varBind["name"] = OID_TEXT
        varBind["value"]["number"] = 4096
        return varBind

    benchmark(build)


def test_sequence_iterate(benchmark):
    """Walk every variable binding of a decoded-looking message."""
    message = buildMessage()

    def walk():
        total = 0
        for varBind in message["data"]["variable-bindings"]:
            total += len(varBind["name"])
        return total

    benchmark(walk)


def test_sequence_equality(benchmark):
    """Compare two equal messages component by component."""
    left = buildMessage()
    right = buildMessage()
    benchmark(left.__eq__, right)


def test_prettyprint_message(benchmark):
    """Render a nested value the way debugging output does."""
    message = buildMessage()
    benchmark(message.prettyPrint)
