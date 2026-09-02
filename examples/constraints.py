#!/usr/bin/env python3
"""Constraints: restrict valid values for ASN.1 types.

Demonstrates ValueRangeConstraint, ValueSizeConstraint,
SingleValueConstraint, and PermittedAlphabetConstraint.
"""

from pyasn1 import error
from pyasn1.type import char, constraint, univ


def main():
    # --- ValueRangeConstraint on INTEGER ---
    class Age(univ.Integer):
        subtypeSpec = constraint.ValueRangeConstraint(0, 150)

    age = Age(25)
    print("Age(25):", repr(age))

    try:
        Age(200)
    except error.PyAsn1Error as e:
        print("Age(200) correctly rejected:", type(e).__name__)

    # --- ValueSizeConstraint on OctetString ---
    class Password(univ.OctetString):
        subtypeSpec = constraint.ValueSizeConstraint(8, 64)

    pw = Password(b"secure123")
    print("Password:", repr(pw))

    try:
        Password(b"short")
    except error.PyAsn1Error as e:
        print("Short password correctly rejected:", type(e).__name__)

    # --- SingleValueConstraint on INTEGER ---
    class Protocol(univ.Integer):
        subtypeSpec = constraint.SingleValueConstraint(1, 6, 17)

    proto = Protocol(6)
    print("Protocol(6):", repr(proto))

    try:
        Protocol(99)
    except error.PyAsn1Error as e:
        print("Protocol(99) correctly rejected:", type(e).__name__)

    # --- PermittedAlphabetConstraint on IA5String ---
    # Note: PermittedAlphabetConstraint checks individual characters.
    # Pass each allowed character as a separate argument.
    class HexString(char.IA5String):
        subtypeSpec = constraint.PermittedAlphabetConstraint(
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
        )

    hs = HexString("DEADBEEF")
    print("HexString:", repr(hs))

    try:
        HexString("hello")
    except error.PyAsn1Error as e:
        print("Non-hex string correctly rejected:", type(e).__name__)


if __name__ == "__main__":
    main()
