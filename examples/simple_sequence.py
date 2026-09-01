#!/usr/bin/env python3
"""Simple SEQUENCE: define, populate, encode, and decode.

Demonstrates the most common pyasn1 workflow:
  1. Define an ASN.1 schema as a Python class
  2. Instantiate and populate it with values
  3. Encode to DER bytes
  4. Decode back from DER bytes
"""
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import char, namedtype, univ


class User(univ.Sequence):
    """ASN.1: User ::= SEQUENCE { id INTEGER, name UTF8String }"""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("id", univ.Integer()),
        namedtype.NamedType("name", char.UTF8String()),
    )


def main():
    # --- populate ---
    user = User()
    user["id"] = 42
    user["name"] = "Alice"
    print("Original:", repr(user))

    # --- encode to DER ---
    der_bytes = der_encode(user)
    print("DER bytes:", der_bytes.hex())

    # --- decode from DER ---
    recovered, rest = der_decode(der_bytes, asn1Spec=User())
    assert rest == b"", "Trailing bytes after decode"
    print("Recovered:", repr(recovered))
    assert recovered["id"] == 42
    assert recovered["name"] == "Alice"
    print("Round-trip OK")


if __name__ == "__main__":
    main()