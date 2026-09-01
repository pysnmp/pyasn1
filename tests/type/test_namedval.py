#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.type import namedval
from tests.base import BaseTestCase


class NamedValuesCaseBase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.e = namedval.NamedValues(("off", 0), ("on", 1))

    def testDict(self):
        assert set(self.e.items()) == set([("off", 0), ("on", 1)])
        assert set(self.e.keys()) == set(["off", "on"])
        assert set(self.e) == set(["off", "on"])
        assert set(self.e.values()) == set([0, 1])
        assert "on" in self.e and "off" in self.e and "xxx" not in self.e
        assert 0 in self.e and 1 in self.e and 2 not in self.e

    def testInit(self):
        assert namedval.NamedValues(off=0, on=1) == {"off": 0, "on": 1}
        assert namedval.NamedValues("off", "on") == {"off": 0, "on": 1}
        assert namedval.NamedValues(("c", 0)) == {"c": 0}
        assert namedval.NamedValues("a", "b", ("c", 0), d=1) == {
            "c": 0,
            "d": 1,
            "a": 2,
            "b": 3,
        }

    def testLen(self):
        assert len(self.e) == 2
        assert len(namedval.NamedValues()) == 0

    def testAdd(self):
        assert namedval.NamedValues(off=0) + namedval.NamedValues(on=1) == {
            "off": 0,
            "on": 1,
        }

    def testClone(self):
        assert namedval.NamedValues(off=0).clone(("on", 1)) == {"off": 0, "on": 1}
        assert namedval.NamedValues(off=0).clone(on=1) == {"off": 0, "on": 1}

    def testStrRepr(self):
        assert str(self.e)
        assert repr(self.e)


class NamedValuesStdlibIntegrationTestCase(BaseTestCase):
    """Verify NamedValues behaves as a dict subtype."""

    def testIsDict(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert isinstance(nv, dict)

    def testDictLen(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert len(nv) == 2

    def testDictIter(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert set(iter(nv)) == {"off", "on"}

    def testDictKeys(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert set(nv.keys()) == {"off", "on"}

    def testDictValues(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert set(nv.values()) == {0, 1}

    def testDictItems(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert dict(nv.items()) == {"off": 0, "on": 1}

    def testBidirectionalLookupByName(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert nv["off"] == 0
        assert nv["on"] == 1

    def testBidirectionalLookupByNumber(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert nv[0] == "off"
        assert nv[1] == "on"

    def testContainsByName(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert "off" in nv
        assert "missing" not in nv

    def testContainsByNumber(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert 0 in nv
        assert 99 not in nv

    def testEqWithDict(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert nv == {"off": 0, "on": 1}

    def testAnonymousNames(self):
        nv = namedval.NamedValues("a", "b", ("c", 0), d=1)
        assert nv["a"] == 2
        assert nv["b"] == 3
        assert nv["c"] == 0
        assert nv["d"] == 1

    def testAdd(self):
        nv1 = namedval.NamedValues(("off", 0))
        nv2 = namedval.NamedValues(("on", 1))
        merged = nv1 + nv2
        assert merged == {"off": 0, "on": 1}

    def testClone(self):
        nv = namedval.NamedValues(("off", 0))
        cloned = nv.clone(("on", 1))
        assert cloned == {"off": 0, "on": 1}

    def testDuplicateNameRaises(self):
        from pyasn1.error import PyAsn1Error

        try:
            namedval.NamedValues(("off", 0), ("off", 1))
            assert False, "duplicate name should raise"
        except PyAsn1Error:
            pass

    def testDuplicateNumberRaises(self):
        from pyasn1.error import PyAsn1Error

        try:
            namedval.NamedValues(("off", 0), ("on", 0))
            assert False, "duplicate number should raise"
        except PyAsn1Error:
            pass

    def testEmptyNamedValues(self):
        nv = namedval.NamedValues()
        assert len(nv) == 0
        assert bool(nv) is False

    def testReprContainsClassName(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))
        assert "NamedValues" in repr(nv)

    def testImmutableBlocksMutation(self):
        from pyasn1.error import PyAsn1Error

        nv = namedval.NamedValues(("off", 0), ("on", 1))
        for op in (
            lambda: nv.__setitem__("new", 2),
            lambda: nv.__delitem__("off"),
            lambda: nv.update({"new": 2}),
            lambda: nv.pop("off"),
            lambda: nv.popitem(),
            lambda: nv.clear(),
            lambda: nv.setdefault("new", 2),
        ):
            try:
                op()
                assert False, "mutation should be blocked on immutable NamedValues"
            except PyAsn1Error:
                pass

        # Mutation attempts must not have left the reverse index stale.
        assert nv[0] == "off"
        assert nv[1] == "on"
        assert len(nv) == 2

    def testKeysValuesItemsReturnDictViews(self):
        nv = namedval.NamedValues(("off", 0), ("on", 1))

        keys = nv.keys()
        assert hasattr(keys, "__len__")
        assert len(keys) == 2
        # key-view set operations work
        assert keys & {"off"} == {"off"}

        values = nv.values()
        assert hasattr(values, "__len__")
        assert len(values) == 2

        items = nv.items()
        assert hasattr(items, "__len__")
        assert len(items) == 2
        assert dict(items) == {"off": 0, "on": 1}


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
