#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.compat import octets
from tests.base import BaseTestCase


class OctetsTestCase(BaseTestCase):
    def test_ints2octs(self):
        assert [1, 2, 3] == list(octets.ints2octs([1, 2, 3]))

    def test_ints2octs_empty(self):
        assert not octets.ints2octs([])

    def test_int2oct(self):
        assert [12] == list(octets.int2oct(12))

    def test_octs2ints(self):
        assert [1, 2, 3] == list(octets.octs2ints(bytes([1, 2, 3])))

    def test_octs2ints_empty(self):
        assert not octets.octs2ints(bytes([]))

    def test_oct2int(self):
        assert 12 == octets.oct2int(bytes([12]))[0]

    def test_str2octs(self):
        assert bytes([1, 2, 3]) == octets.str2octs("\x01\x02\x03")

    def test_str2octs_empty(self):
        assert not octets.str2octs("")

    def test_octs2str(self):
        assert "\x01\x02\x03" == octets.octs2str(bytes([1, 2, 3]))

    def test_octs2str_empty(self):
        assert not octets.octs2str(bytes([]))

    def test_isOctetsType(self):
        assert octets.isOctetsType("abc") == False
        assert octets.isOctetsType(123) == False
        assert octets.isOctetsType(bytes()) == True

    def test_isStringType(self):
        assert octets.isStringType("abc") == True
        assert octets.isStringType(123) == False
        assert octets.isStringType(bytes()) == False

    def test_ensureString(self):
        assert b"abc" == octets.ensureString(b"abc")
        assert bytes([1, 2, 3]) == octets.ensureString([1, 2, 3])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
