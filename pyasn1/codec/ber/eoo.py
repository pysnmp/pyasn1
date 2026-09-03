#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""BER End-of-Octets marker type used to close indefinite-length values."""

from typing import Any, Final

from pyasn1.type import base, tag

__all__ = ["endOfOctets"]


class EndOfOctets(base.SimpleAsn1Type):
    defaultValue = 0
    tagSet = tag.initTagSet(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x00))

    _instance: "EndOfOctets | None" = None

    def __new__(cls, *args: Any, **kwargs: Any) -> "EndOfOctets":
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kwargs)

        return cls._instance


endOfOctets: Final = EndOfOctets()
