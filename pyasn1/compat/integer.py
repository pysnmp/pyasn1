#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys

from pyasn1.compat.octets import oct2int, null


def from_bytes(octets, signed=False):
    return int.from_bytes(bytes(octets), "big", signed=signed)


def to_bytes(value, signed=False, length=0):
    length = max(value.bit_length(), length)

    if signed and length % 8 == 0:
        length += 1

    return value.to_bytes(length // 8 + (length % 8 and 1 or 0), "big", signed=signed)


def bitLength(number):
    return int(number).bit_length()
