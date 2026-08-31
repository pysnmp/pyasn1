#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest


def _str2octs(s):
    return s.encode("iso-8859-1")

from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, opentype, tag, univ
from tests.base import BaseTestCase


class UntaggedAnyTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType("blob", univ.Any()),
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s["blob"] = univ.Any(_str2octs("xxx"))

        # this should succeed because Any is untagged and unconstrained
        self.s["blob"] = univ.Integer(123)


class TaggedAnyTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.taggedAny = univ.Any().subtype(
            implicitTag=tag.Tag(tag.tagClassPrivate, tag.tagFormatSimple, 20)
        )

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType("blob", self.taggedAny),
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s["blob"] = self.taggedAny.clone("xxx")

        try:
            self.s.setComponentByName("blob", univ.Integer(123))

        except PyAsn1Error:
            pass

        else:
            assert False, "non-open type assignment tolerated"


class TaggedAnyOpenTypeTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.taggedAny = univ.Any().subtype(
            implicitTag=tag.Tag(tag.tagClassPrivate, tag.tagFormatSimple, 20)
        )

        class Sequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob", self.taggedAny, openType=opentype.OpenType(name="id")
                ),
            )

        self.s = Sequence()

    def testTypeCheckOnAssignment(self):

        self.s.clear()

        self.s["blob"] = univ.Any(_str2octs("xxx"))
        self.s["blob"] = univ.Integer(123)


class OpenTypeStdlibIntegrationTestCase(BaseTestCase):
    """Verify OpenType behaves as a dict subtype."""

    def testIsDict(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        assert isinstance(ot, dict)

    def testDictGetItem(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        # Schema objects can't be compared with ==, so check identity
        assert ot[1] is not None
        assert ot[2] is not None

    def testDictContains(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        assert 1 in ot
        assert 3 not in ot

    def testDictIter(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        assert set(iter(ot)) == {1, 2}

    def testDictKeys(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        assert set(ot.keys()) == {1, 2}

    def testDictValues(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        vals = list(ot.values())
        assert len(vals) == 2

    def testDictItems(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        items = dict(ot.items())
        assert set(items.keys()) == {1, 2}

    def testDictLen(self):
        ot = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        assert len(ot) == 2

    def testNameAttribute(self):
        ot = opentype.OpenType("id", {1: univ.Integer()})
        assert ot.name == "id"

    def testEmptyOpenTypeIsTruthy(self):
        """An empty OpenType must still be truthy so type-check code sees it."""
        ot = opentype.OpenType("id")
        assert bool(ot) is True

    def testEmptyOpenTypeName(self):
        ot = opentype.OpenType(name="id")
        assert ot.name == "id"
        assert len(ot) == 0

    def testDictUpdate(self):
        """OpenType is a mutable dict — updates are reflected."""
        ot = opentype.OpenType("id", {1: univ.Integer()})
        ot[2] = univ.OctetString()
        assert 2 in ot
        assert len(ot) == 2

    def testDictGet(self):
        ot = opentype.OpenType("id", {1: univ.Integer()})
        assert ot.get(1) is not None
        assert ot.get(99) is None


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
