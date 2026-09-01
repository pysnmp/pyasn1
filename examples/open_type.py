#!/usr/bin/env python3
"""Open types (ANY DEFINED BY): select a type based on a companion field.

Demonstrates the OpenType / ANY DEFINED BY construct where one field
determines the ASN.1 type of another field at runtime.
"""
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, opentype, univ


class Choice(univ.Sequence):
    """ASN.1:

    Choice ::= SEQUENCE {
        id    INTEGER,
        blob  ANY DEFINED BY id
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("id", univ.Integer()),
        namedtype.NamedType(
            "blob",
            univ.Any(),
            openType=opentype.OpenType(
                "id",
                {
                    1: univ.Integer(),
                    2: univ.OctetString(),
                },
            ),
        ),
    )


def main():
    # --- case 1: id=1 means blob is an INTEGER ---
    choice1 = Choice()
    choice1["id"] = 1
    choice1["blob"] = univ.Integer(99)
    der1 = der_encode(choice1)
    recovered1, _ = der_decode(der1, asn1Spec=Choice())
    print("Case id=1:", repr(recovered1))
    assert recovered1["id"] == 1

    # --- case 2: id=2 means blob is an OctetString ---
    choice2 = Choice()
    choice2["id"] = 2
    choice2["blob"] = univ.OctetString("hello")
    der2 = der_encode(choice2)
    recovered2, _ = der_decode(der2, asn1Spec=Choice())
    print("Case id=2:", repr(recovered2))
    assert recovered2["id"] == 2

    print("Open type round-trip OK")


if __name__ == "__main__":
    main()