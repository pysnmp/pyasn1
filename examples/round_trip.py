#!/usr/bin/env python3
"""Round-trip across all codecs: BER, CER, DER, and native.

Demonstrates encoding the same ASN.1 value with every codec pyasn1
ships and verifying they all agree.
"""
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.cer.decoder import decode as cer_decode
from pyasn1.codec.cer.encoder import encode as cer_encode
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as native_decode
from pyasn1.codec.native.encoder import encode as native_encode
from pyasn1.type import namedtype, univ


class Point(univ.Sequence):
    """ASN.1: Point ::= SEQUENCE { x INTEGER, y INTEGER }"""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("x", univ.Integer()),
        namedtype.NamedType("y", univ.Integer()),
    )


def main():
    point = Point()
    point["x"] = 10
    point["y"] = -20

    # --- DER ---
    der = der_encode(point)
    p_der, _ = der_decode(der, asn1Spec=Point())
    assert (p_der["x"], p_der["y"]) == (10, -20)
    print("DER:", der.hex())

    # --- BER ---
    ber = ber_encode(point)
    p_ber, _ = ber_decode(ber, asn1Spec=Point())
    assert (p_ber["x"], p_ber["y"]) == (10, -20)
    print("BER:", ber.hex())

    # --- CER ---
    cer = cer_encode(point)
    p_cer, _ = cer_decode(cer, asn1Spec=Point())
    assert (p_cer["x"], p_cer["y"]) == (10, -20)
    print("CER:", cer.hex())

    # --- native (Python dict) ---
    py_point = native_encode(point)
    print("Native:", py_point)
    p_native = native_decode(py_point, asn1Spec=Point())
    assert (p_native["x"], p_native["y"]) == (10, -20)

    print("All codec round-trips OK")


if __name__ == "__main__":
    main()