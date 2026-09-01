#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
from collections import namedtuple

from pyasn1 import error

__all__ = [
    "tagClassUniversal",
    "tagClassApplication",
    "tagClassContext",
    "tagClassPrivate",
    "tagFormatSimple",
    "tagFormatConstructed",
    "tagCategoryImplicit",
    "tagCategoryExplicit",
    "tagCategoryUntagged",
    "Tag",
    "TagSet",
]

#: Identifier for ASN.1 class UNIVERSAL
tagClassUniversal = 0x00

#: Identifier for ASN.1 class APPLICATION
tagClassApplication = 0x40

#: Identifier for ASN.1 class context-specific
tagClassContext = 0x80

#: Identifier for ASN.1 class private
tagClassPrivate = 0xC0

#: Identifier for "simple" ASN.1 structure (e.g. scalar)
tagFormatSimple = 0x00

#: Identifier for "constructed" ASN.1 structure (e.g. may have inner components)
tagFormatConstructed = 0x20

tagCategoryImplicit = 0x01
tagCategoryExplicit = 0x02
tagCategoryUntagged = 0x04

# Human-readable names for repr() output
_TAG_CLASS_NAMES = {
    tagClassUniversal: "UNIVERSAL",
    tagClassApplication: "APPLICATION",
    tagClassContext: "CONTEXT",
    tagClassPrivate: "PRIVATE",
}

_TAG_FORMAT_NAMES = {
    tagFormatSimple: "simple",
    tagFormatConstructed: "constructed",
}


def _tagClassName(tagClass):
    """Return a human-readable name for an ASN.1 tag class."""
    return _TAG_CLASS_NAMES.get(tagClass, "0x%02x" % tagClass)


def _tagFormatName(tagFormat):
    """Return a human-readable name for an ASN.1 tag format."""
    return _TAG_FORMAT_NAMES.get(tagFormat, "0x%02x" % tagFormat)


_TagBase = namedtuple("Tag", ["tagClass", "tagFormat", "tagId"])


class Tag(_TagBase):
    """Create ASN.1 tag

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

    def __new__(cls, tagClass, tagFormat, tagId):
        if tagId < 0:
            raise error.PyAsn1Error("Negative tag ID (%s) not allowed" % tagId)
        return super().__new__(cls, tagClass, tagFormat, tagId)

    def __repr__(self):
        return "<%s object, tag [%s:%s:%d]>" % (
            self.__class__.__name__,
            _tagClassName(self.tagClass),
            _tagFormatName(self.tagFormat),
            self.tagId,
        )

    # Equality and hashing intentionally consider only (tagClass, tagId),
    # matching the original implementation.  tagFormat is excluded so that
    # a simple and a constructed tag with the same class/id compare equal.
    def __eq__(self, other):
        return (self.tagClass, self.tagId) == other

    def __ne__(self, other):
        return (self.tagClass, self.tagId) != other

    def __lt__(self, other):
        return (self.tagClass, self.tagId) < other

    def __le__(self, other):
        return (self.tagClass, self.tagId) <= other

    def __gt__(self, other):
        return (self.tagClass, self.tagId) > other

    def __ge__(self, other):
        return (self.tagClass, self.tagId) >= other

    def __hash__(self):
        return hash((self.tagClass, self.tagId))


class TagSet:
    """Create a collection of ASN.1 tags

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

    def __init__(self, baseTag=(), *superTags):
        self.__baseTag = baseTag
        self.__superTags = superTags
        self.__superTagsClassId = tuple(
            [(superTag.tagClass, superTag.tagId) for superTag in superTags]
        )
        self.__lenOfSuperTags = len(superTags)
        self.__hash = hash(self.__superTagsClassId)

    def __repr__(self):
        if not self.__superTags:
            return "<%s object, untagged>" % self.__class__.__name__

        parts = []
        for t in self.__superTags:
            parts.append("%s:%d" % (_tagClassName(t.tagClass), t.tagId))

        return "<%s object, tags %s>" % (
            self.__class__.__name__,
            "-".join(parts),
        )

    def __add__(self, superTag):
        return self.__class__(self.__baseTag, *self.__superTags + (superTag,))

    def __radd__(self, superTag):
        return self.__class__(self.__baseTag, *(superTag,) + self.__superTags)

    def __getitem__(self, i):
        if i.__class__ is slice:
            return self.__class__(self.__baseTag, *self.__superTags[i])
        else:
            return self.__superTags[i]

    def __eq__(self, other):
        return self.__superTagsClassId == other

    def __ne__(self, other):
        return self.__superTagsClassId != other

    def __lt__(self, other):
        return self.__superTagsClassId < other

    def __le__(self, other):
        return self.__superTagsClassId <= other

    def __gt__(self, other):
        return self.__superTagsClassId > other

    def __ge__(self, other):
        return self.__superTagsClassId >= other

    def __hash__(self):
        return self.__hash

    def __len__(self):
        return self.__lenOfSuperTags

    @property
    def baseTag(self):
        """Return base ASN.1 tag

        Returns
        -------
        : :class:`~pyasn1.type.tag.Tag`
            Base tag of this *TagSet*
        """
        return self.__baseTag

    @property
    def superTags(self):
        """Return ASN.1 tags

        Returns
        -------
        : :py:class:`tuple`
            Tuple of :class:`~pyasn1.type.tag.Tag` objects that this *TagSet* contains
        """
        return self.__superTags

    def tagExplicitly(self, superTag):
        """Return explicitly tagged *TagSet*

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

    def tagImplicitly(self, superTag):
        """Return implicitly tagged *TagSet*

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

    def isSuperTagSetOf(self, tagSet):
        """Test type relationship against given *TagSet*

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


def initTagSet(tag):
    return TagSet(tag, tag)
