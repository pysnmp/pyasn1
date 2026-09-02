#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Map ASN.1 tag sets to the types they identify."""

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from pyasn1 import error

if TYPE_CHECKING:
    from pyasn1.type.tag import TagSet

__all__ = ["TagMap"]


class TagMap:
    """Map *TagSet* objects to ASN.1 types.

    Create an object mapping *TagSet* object to ASN.1 type.

    *TagMap* objects are immutable and duck-type read-only Python
    :class:`dict` objects holding *TagSet* objects as keys and ASN.1
    type objects as values.

    Parameters
    ----------
    presentTypes: :py:class:`dict`
        Map of :class:`~pyasn1.type.tag.TagSet` to ASN.1 objects considered
        as being unconditionally present in the *TagMap*.

    skipTypes: :py:class:`dict`
        A collection of :class:`~pyasn1.type.tag.TagSet` objects considered
        as absent in the *TagMap* even when *defaultType* is present.

    defaultType: ASN.1 type object
        An ASN.1 type object callee *TagMap* returns for any *TagSet* key not present
        in *presentTypes* (unless given key is present in *skipTypes*).
    """

    def __init__(
        self,
        presentTypes: "dict[TagSet, Any] | None" = None,
        skipTypes: "dict[TagSet, Any] | None" = None,
        defaultType: Any = None,
    ) -> None:
        self.__presentTypes = presentTypes or {}
        self.__skipTypes = skipTypes or {}
        self.__defaultType = defaultType

    def __contains__(self, tagSet: "TagSet") -> bool:
        return (
            tagSet in self.__presentTypes
            or self.__defaultType is not None
            and tagSet not in self.__skipTypes
        )

    def __getitem__(self, tagSet: "TagSet") -> Any:
        try:
            return self.__presentTypes[tagSet]
        except KeyError as exc:
            if self.__defaultType is None:
                raise KeyError from None
            elif tagSet in self.__skipTypes:
                raise error.PyAsn1Error("Key in negative map") from exc
            else:
                return self.__defaultType

    def __iter__(self) -> "Iterator[TagSet]":
        return iter(self.__presentTypes)

    def __repr__(self) -> str:
        representation = "%s object" % self.__class__.__name__

        if self.__presentTypes:
            representation += ", present %s" % repr(self.__presentTypes)

        if self.__skipTypes:
            representation += ", skip %s" % repr(self.__skipTypes)

        if self.__defaultType is not None:
            representation += ", default %s" % repr(self.__defaultType)

        return "<%s>" % representation

    @property
    def presentTypes(self) -> "dict[TagSet, Any]":
        """Return *TagSet* to ASN.1 type map present in callee *TagMap*."""
        return self.__presentTypes

    @property
    def skipTypes(self) -> "dict[TagSet, Any]":
        """Return *TagSet* collection unconditionally absent in callee *TagMap*."""
        return self.__skipTypes

    @property
    def defaultType(self) -> Any:
        """Return default ASN.1 type being returned for any missing *TagSet*."""
        return self.__defaultType
