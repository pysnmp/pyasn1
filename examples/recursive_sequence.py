#!/usr/bin/env python3
"""Recursive SEQUENCE: a self-referencing type.

Demonstrates how to model recursive ASN.1 structures such as linked
lists or tree nodes where a type contains an optional reference to
itself.
"""
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, univ


class LinkedList(univ.Sequence):
    """ASN.1:

    LinkedList ::= SEQUENCE {
        value    INTEGER,
        next     LinkedList OPTIONAL
    }
    """

    # The componentType is assigned after class definition to allow
    # the self-referential 'next' field.


LinkedList.componentType = namedtype.NamedTypes(
    namedtype.NamedType("value", univ.Integer()),
    namedtype.OptionalNamedType("next", LinkedList()),
)


def main():
    # Build: 1 -> 2 -> 3
    lst = LinkedList()
    lst["value"] = 1
    lst["next"] = LinkedList()
    lst["next"]["value"] = 2
    lst["next"]["next"] = LinkedList()
    lst["next"]["next"]["value"] = 3

    print("Original:", repr(lst))

    # Encode / decode round-trip
    der = der_encode(lst)
    recovered, _ = der_decode(der, asn1Spec=LinkedList())

    # Walk the list using positional access
    values = []
    node = recovered
    while node is not None and node[0].isValue:
        values.append(int(node[0]))
        node = node[1] if len(node) > 1 else None

    print("Recovered values:", values)
    assert values == [1, 2, 3]
    print("Recursive round-trip OK")


if __name__ == "__main__":
    main()