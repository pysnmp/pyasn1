#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
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

    def testLenMatchesTwoItemInterface(self):
        # len() must match the two items exposed by __iter__/__getitem__,
        # not the three underlying namedtuple fields.
        assert len(self.nt) == 2
        assert len(self.nt) == len(list(self.nt))

    def testCopyPreservesOpenType(self):
        import copy

        nt = namedtype.NamedType("x", univ.Integer(), openType={"k": "v"})
        assert copy.copy(nt).openType == {"k": "v"}

    def testPicklePreservesOpenType(self):
        import pickle

        nt = namedtype.NamedType("x", univ.Integer(), openType={"k": "v"})
        assert pickle.loads(pickle.dumps(nt)).openType == {"k": "v"}

    def testFieldAccessDoesNotGoThroughGetitem(self):
        """Reading a field must not depend on what namedtuple generated.

        How a namedtuple exposes its fields is an implementation detail of
        the interpreter: CPython builds _tuplegetter, which reads the tuple
        slot in C, and PyPy builds property(operator.itemgetter(n)), which
        calls __getitem__. NamedType overrides __getitem__ to expose two
        items rather than three, so a field read that went through it
        recursed forever on .name and raised IndexError on .openType -- and
        importing any module declaring a Choice or a Sequence did exactly
        that on PyPy.

        The accessors this class defines are what makes the two interpreters
        agree, and this simulates PyPy's on whichever one is running so the
        guard holds everywhere.
        """
        import operator

        class PyPyStyleNamedType(namedtype.NamedType):
            """NamedType with the field accessors PyPy would generate."""

            __slots__ = ()

            name = property(operator.itemgetter(0))
            asn1Object = property(operator.itemgetter(1))
            openType = property(operator.itemgetter(2))

        pypy_style = PyPyStyleNamedType("x", univ.Integer(0), openType={"k": "v"})

        # Whatever the accessors do, the class's own reads must terminate and
        # must produce the same three values.
        assert namedtype.NamedType.name.fget(pypy_style) == "x"
        assert namedtype.NamedType.asn1Object.fget(pypy_style) == univ.Integer(0)
        assert namedtype.NamedType.openType.fget(pypy_style) == {"k": "v"}

        # And the accessors are the reason: overridden ones that route back
        # through __getitem__ cannot serve openType at all.
        try:
            pypy_style.openType
        except IndexError:
            pass
        else:  # pragma: no cover - only if a future interpreter changes this
            assert pypy_style.openType == {"k": "v"}

    def testImportingAModuleWithAChoiceWorks(self):
        """The failure this guards was an import, not a field read.

        A Choice's NamedTypes computes its minimum tag set at class creation
        time by reading .asn1Object off every field, so a field accessor that
        does not terminate takes the import down with it.
        """

        class Syntax(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("integer-value", univ.Integer()),
                namedtype.NamedType("string-value", univ.OctetString()),
                namedtype.NamedType("objectID-value", univ.ObjectIdentifier()),
            )

        field = Syntax().componentType["string-value"]
        assert field.name == "string-value"
        assert isinstance(field.asn1Object, univ.OctetString)


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
        assert self.e.getTypeByPosition(0) == univ.OctetString(""), (
            "getTypeByPosition() fails"
        )

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
        assert self.e.getTypeByPosition(0) == univ.OctetString(""), (
            "getTypeByPosition() fails"
        )


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
