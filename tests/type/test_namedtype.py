#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ
from tests.base import BaseTestCase


class NamedTypeCaseBase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.e = namedtype.NamedType("age", univ.Integer(0))

    def testIter(self):
        n, t = self.e
        assert n == "age" or t == univ.Integer(), "unpack fails"

    def testRepr(self):
        assert "age" in repr(self.e)


class NamedTypeStdlibIntegrationTestCase(BaseTestCase):
    """Verify NamedType behaves as a namedtuple / tuple subtype."""

    def setUp(self):
        BaseTestCase.setUp(self)
        self.nt = namedtype.NamedType("age", univ.Integer(0))

    def testIsTupleSubtype(self):
        assert isinstance(self.nt, tuple)
        assert self.nt._fields == ("name", "asn1Object", "openType")

    def testTupleUnpacking(self):
        n, t = self.nt
        assert n == "age"
        assert t == univ.Integer(0)

    def testFieldAccessByName(self):
        assert self.nt.name == "age"
        assert self.nt.asn1Object == univ.Integer(0)

    def testFieldAccessByIndex(self):
        assert self.nt[0] == "age"
        assert self.nt[1] == univ.Integer(0)

    def testIterYieldsTwo(self):
        result = list(self.nt)
        assert len(result) == 2, "iter should yield (name, asn1Object) only"

    def testEqIgnoresOpenType(self):
        """Equality should not consider openType (only name + asn1Object)."""
        # Use value objects (not schema) so == works on the asn1Object side
        nt1 = namedtype.NamedType("x", univ.Integer(0), openType=None)
        nt2 = namedtype.NamedType("x", univ.Integer(0), openType={"k": "v"})
        assert nt1 == nt2, "openType should not affect equality"

    def testHashIgnoresOpenType(self):
        nt1 = namedtype.NamedType("x", univ.Integer(0), openType=None)
        nt2 = namedtype.NamedType("x", univ.Integer(0), openType={"k": "v"})
        assert hash(nt1) == hash(nt2)

    def testOpenTypeProperty(self):
        nt = namedtype.NamedType("x", univ.Integer(), openType={"k": "v"})
        assert nt.openType == {"k": "v"}

    def testOpenTypeDefaultsNone(self):
        assert self.nt.openType is None

    def testOptionalFlag(self):
        nt = namedtype.OptionalNamedType("x", univ.Integer())
        assert nt.isOptional is True
        assert nt.isDefaulted is False

    def testDefaultedFlag(self):
        nt = namedtype.DefaultedNamedType("x", univ.Integer(0))
        assert nt.isDefaulted is True
        assert nt.isOptional is False

    def testAsDictKey(self):
        d = {self.nt: "value"}
        assert d[self.nt] == "value"


class NamedTypesCaseBase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.e = namedtype.NamedTypes(
            namedtype.NamedType("first-name", univ.OctetString("")),
            namedtype.OptionalNamedType("age", univ.Integer(0)),
            namedtype.NamedType("family-name", univ.OctetString("")),
        )

    def testRepr(self):
        assert "first-name" in repr(self.e)

    def testContains(self):
        assert "first-name" in self.e
        assert "<missing>" not in self.e

    # noinspection PyUnusedLocal
    def testGetItem(self):
        assert self.e[0] == namedtype.NamedType("first-name", univ.OctetString(""))

    def testIter(self):
        assert list(self.e) == ["first-name", "age", "family-name"]

    def testGetTypeByPosition(self):
        assert self.e.getTypeByPosition(0) == univ.OctetString(""), "getTypeByPosition() fails"

    def testGetNameByPosition(self):
        assert self.e.getNameByPosition(0) == "first-name", "getNameByPosition() fails"

    def testGetPositionByName(self):
        assert self.e.getPositionByName("first-name") == 0, "getPositionByName() fails"

    def testGetTypesNearPosition(self):
        assert self.e.getTagMapNearPosition(0).presentTypes == {
            univ.OctetString.tagSet: univ.OctetString("")
        }
        assert self.e.getTagMapNearPosition(1).presentTypes == {
            univ.Integer.tagSet: univ.Integer(0),
            univ.OctetString.tagSet: univ.OctetString(""),
        }
        assert self.e.getTagMapNearPosition(2).presentTypes == {
            univ.OctetString.tagSet: univ.OctetString("")
        }

    def testGetTagMap(self):
        assert self.e.tagMap.presentTypes == {
            univ.OctetString.tagSet: univ.OctetString(""),
            univ.Integer.tagSet: univ.Integer(0),
        }

    def testStrTagMap(self):
        assert "TagMap" in str(self.e.tagMap)
        assert "OctetString" in str(self.e.tagMap)
        assert "Integer" in str(self.e.tagMap)

    def testReprTagMap(self):
        assert "TagMap" in repr(self.e.tagMap)
        assert "OctetString" in repr(self.e.tagMap)
        assert "Integer" in repr(self.e.tagMap)

    def testGetTagMapWithDups(self):
        try:
            self.e.tagMapUnique[0]
        except PyAsn1Error:
            pass
        else:
            assert 0, "Duped types not noticed"

    def testGetPositionNearType(self):
        assert self.e.getPositionNearType(univ.OctetString.tagSet, 0) == 0
        assert self.e.getPositionNearType(univ.Integer.tagSet, 1) == 1
        assert self.e.getPositionNearType(univ.OctetString.tagSet, 2) == 2


class OrderedNamedTypesCaseBase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.e = namedtype.NamedTypes(
            namedtype.NamedType("first-name", univ.OctetString("")),
            namedtype.NamedType("age", univ.Integer(0)),
        )

    def testGetTypeByPosition(self):
        assert self.e.getTypeByPosition(0) == univ.OctetString(""), "getTypeByPosition() fails"


class DuplicateNamedTypesCaseBase(BaseTestCase):
    def testDuplicateDefaultTags(self):
        nt = namedtype.NamedTypes(
            namedtype.NamedType("first-name", univ.Any()),
            namedtype.NamedType("age", univ.Any()),
        )

        assert isinstance(nt.tagMap, namedtype.NamedTypes.PostponedError)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
