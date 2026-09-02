#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""ASN.1 tag and tag-set classes used to distinguish types."""

from collections import namedtuple
from typing import Any, Final

from pyasn1 import error

__all__ = [
    "Tag",
    "TagSet",
    "tagCategoryExplicit",
    "tagCategoryImplicit",
    "tagCategoryUntagged",
    "tagClassApplication",
    "tagClassContext",
    "tagClassPrivate",
    "tagClassUniversal",
    "tagFormatConstructed",
    "tagFormatSimple",
]

#: Identifier for ASN.1 class UNIVERSAL
tagClassUniversal: Final = 0x00

#: Identifier for ASN.1 class APPLICATION
tagClassApplication: Final = 0x40

#: Identifier for ASN.1 class context-specific
tagClassContext: Final = 0x80

#: Identifier for ASN.1 class private
tagClassPrivate: Final = 0xC0

#: Identifier for "simple" ASN.1 structure (e.g. scalar)
tagFormatSimple: Final = 0x00

#: Identifier for "constructed" ASN.1 structure (e.g. may have inner components)
tagFormatConstructed: Final = 0x20

tagCategoryImplicit: Final = 0x01
tagCategoryExplicit: Final = 0x02
tagCategoryUntagged: Final = 0x04

#: Human-readable names for the ASN.1 tag classes, used by ``repr()``.
_TAG_CLASS_NAMES: Final = {
    tagClassUniversal: "UNIVERSAL",
    tagClassApplication: "APPLICATION",
    tagClassContext: "CONTEXT",
    tagClassPrivate: "PRIVATE",
}

#: Human-readable names for the ASN.1 tag formats, used by ``repr()``.
_TAG_FORMAT_NAMES: Final = {
    tagFormatSimple: "simple",
    tagFormatConstructed: "constructed",
}


def _tagClassName(tagClass: int) -> str:
    """Return a human-readable name for ASN.1 tag class *tagClass*."""
    return _TAG_CLASS_NAMES.get(tagClass, f"0x{tagClass:02x}")


def _tagFormatName(tagFormat: int) -> str:
    """Return a human-readable name for ASN.1 tag format *tagFormat*."""
    return _TAG_FORMAT_NAMES.get(tagFormat, f"0x{tagFormat:02x}")


_TagBase = namedtuple("_TagBase", ["tagClass", "tagFormat", "tagId"])


class Tag(_TagBase):
    """Create ASN.1 tag.

    Represents ASN.1 tag that can be attached to a ASN.1 type to make
    types distinguishable from each other.

    *Tag* objects are immutable and duck-type Python :class:`tuple` objects
    holding three integer components of a tag.

    Parameters
    ----------
    tagClass: :py:class:`int`
        Tag *class* value

    tagFormat: :py:class:`int`
        Tag *format* value

    tagId: :py:class:`int`
        Tag ID value
    """

    __slots__ = ()

    def __new__(cls, tagClass: int, tagFormat: int, tagId: int) -> "Tag":
        """Construct a *Tag*, rejecting a negative *tagId*."""
        if tagId < 0:
            raise error.PyAsn1Error("Negative tag ID not allowed", tagId=tagId)
        return super().__new__(cls, tagClass, tagFormat, tagId)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} object, tag [{_tagClassName(self.tagClass)}:{_tagFormatName(self.tagFormat)}:{self.tagId}]>"

    # Equality and hashing intentionally consider only (tagClass, tagId),
    # matching the original implementation.  tagFormat is excluded so that
    # a simple and a constructed tag with the same class/id compare equal.
    def __eq__(self, other: object) -> bool:
        return (self.tagClass, self.tagId) == other

    def __ne__(self, other: object) -> bool:
        return (self.tagClass, self.tagId) != other

    def __lt__(self, other: Any) -> bool:
        return (self.tagClass, self.tagId) < other

    def __le__(self, other: Any) -> bool:
        return (self.tagClass, self.tagId) <= other

    def __gt__(self, other: Any) -> bool:
        return (self.tagClass, self.tagId) > other

    def __ge__(self, other: Any) -> bool:
        return (self.tagClass, self.tagId) >= other

    def __hash__(self) -> int:
        return hash((self.tagClass, self.tagId))


class TagSet:
    """Create a collection of ASN.1 tags.

    Represents a combination of :class:`~pyasn1.type.tag.Tag` objects
    that can be attached to a ASN.1 type to make types distinguishable
    from each other.

    *TagSet* objects are immutable and duck-type Python :class:`tuple` objects
    holding arbitrary number of :class:`~pyasn1.type.tag.Tag` objects.

    Parameters
    ----------
    baseTag: :class:`~pyasn1.type.tag.Tag`
        Base *Tag* object. This tag survives IMPLICIT tagging.

    *superTags: :class:`~pyasn1.type.tag.Tag`
        Additional *Tag* objects taking part in subtyping.

    Examples
    --------
    .. code-block:: python

        class OrderNumber(NumericString):
            '''
            ASN.1 specification

            Order-number ::=
                [APPLICATION 5] IMPLICIT NumericString
            '''
            tagSet = NumericString.tagSet.tagImplicitly(
                Tag(tagClassApplication, tagFormatSimple, 5)
            )

        orderNumber = OrderNumber('1234')
    """

    def __init__(self, baseTag: "Tag | tuple[()]" = (), *superTags: Tag) -> None:
        self.__baseTag = baseTag
        self.__superTags = superTags
        self.__superTagsClassId = tuple(
            [(superTag.tagClass, superTag.tagId) for superTag in superTags]
        )
        self.__lenOfSuperTags = len(superTags)
        self.__hash = hash(self.__superTagsClassId)

    def __repr__(self) -> str:
        if not self.__superTags:
            return f"<{self.__class__.__name__} object, untagged>"

        return "<{} object, tags {}>".format(
            self.__class__.__name__,
            "-".join(
                f"{_tagClassName(x.tagClass)}:{x.tagId}" for x in self.__superTags
            ),
        )

    def __add__(self, superTag: Tag) -> "TagSet":
        return self.__class__(self.__baseTag, *self.__superTags + (superTag,))

    def __radd__(self, superTag: Tag) -> "TagSet":
        return self.__class__(self.__baseTag, *(superTag,) + self.__superTags)

    def __getitem__(self, i: Any) -> Any:
        if i.__class__ is slice:
            return self.__class__(self.__baseTag, *self.__superTags[i])
        else:
            return self.__superTags[i]

    def __eq__(self, other: object) -> bool:
        return self.__superTagsClassId == other

    def __ne__(self, other: object) -> bool:
        return self.__superTagsClassId != other

    def __lt__(self, other: Any) -> bool:
        return self.__superTagsClassId < other

    def __le__(self, other: Any) -> bool:
        return self.__superTagsClassId <= other

    def __gt__(self, other: Any) -> bool:
        return self.__superTagsClassId > other

    def __ge__(self, other: Any) -> bool:
        return self.__superTagsClassId >= other

    def __hash__(self) -> int:
        return self.__hash

    def __len__(self) -> int:
        return self.__lenOfSuperTags

    @property
    def baseTag(self) -> Any:
        """Return base ASN.1 tag.

        Returns
        -------
        : :class:`~pyasn1.type.tag.Tag`
            Base tag of this *TagSet*
        """
        return self.__baseTag

    @property
    def superTags(self) -> tuple[Tag, ...]:
        """Return ASN.1 tags.

        Returns
        -------
        : :py:class:`tuple`
            Tuple of :class:`~pyasn1.type.tag.Tag` objects that this *TagSet* contains
        """
        return self.__superTags

    def tagExplicitly(self, superTag: Tag) -> "TagSet":
        """Return explicitly tagged *TagSet*.

        Create a new *TagSet* representing callee *TagSet* explicitly tagged
        with passed tag(s). With explicit tagging mode, new tags are appended
        to existing tag(s).

        Parameters
        ----------
        superTag: :class:`~pyasn1.type.tag.Tag`
            *Tag* object to tag this *TagSet*

        Returns
        -------
        : :class:`~pyasn1.type.tag.TagSet`
            New *TagSet* object
        """
        if superTag.tagClass == tagClassUniversal:
            raise error.PyAsn1Error("Can't tag with UNIVERSAL class tag")
        if superTag.tagFormat != tagFormatConstructed:
            superTag = Tag(superTag.tagClass, tagFormatConstructed, superTag.tagId)
        return self + superTag

    def tagImplicitly(self, superTag: Tag) -> "TagSet":
        """Return implicitly tagged *TagSet*.

        Create a new *TagSet* representing callee *TagSet* implicitly tagged
        with passed tag(s). With implicit tagging mode, new tag(s) replace the
        last existing tag.

        Parameters
        ----------
        superTag: :class:`~pyasn1.type.tag.Tag`
            *Tag* object to tag this *TagSet*

        Returns
        -------
        : :class:`~pyasn1.type.tag.TagSet`
            New *TagSet* object
        """
        if self.__superTags:
            superTag = Tag(
                superTag.tagClass, self.__superTags[-1].tagFormat, superTag.tagId
            )
        return self[:-1] + superTag

    def isSuperTagSetOf(self, tagSet: "TagSet") -> bool:
        """Test type relationship against given *TagSet*.

        The callee is considered to be a supertype of given *TagSet*
        tag-wise if all tags in *TagSet* are present in the callee and
        they are in the same order.

        Parameters
        ----------
        tagSet: :class:`~pyasn1.type.tag.TagSet`
            *TagSet* object to evaluate against the callee

        Returns
        -------
        : :py:class:`bool`
            :obj:`True` if callee is a supertype of *tagSet*
        """
        if len(tagSet) < self.__lenOfSuperTags:
            return False
        return self.__superTags == tagSet[: self.__lenOfSuperTags]


def initTagSet(tag: Tag) -> TagSet:
    return TagSet(tag, tag)
