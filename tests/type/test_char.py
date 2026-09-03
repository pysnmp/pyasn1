#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import pickle
import sys
import unittest

from pyasn1 import error
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, constraint, univ
from tests.base import BaseTestCase


class AbstractStringTestCase:
    initializer = ()
    encoding = "us-ascii"
    asn1Type = None

    def setUp(self):
        BaseTestCase.setUp(self)

        self.asn1String = self.asn1Type(bytes(self.initializer), encoding=self.encoding)
        self.pythonString = bytes(self.initializer).decode(self.encoding)

    def testUnicode(self):
        assert self.asn1String == self.pythonString, "unicode init fails"

    def testLength(self):
        assert len(self.asn1String) == len(self.pythonString), "unicode len() fails"

    def testSizeConstraint(self):
        asn1Spec = self.asn1Type(subtypeSpec=constraint.ValueSizeConstraint(1, 1))

        try:
            asn1Spec.clone(self.pythonString)
        except PyAsn1Error:
            pass
        else:
            assert False, "Size constraint tolerated"

        try:
            asn1Spec.clone(self.pythonString[0])
        except PyAsn1Error:
            assert False, "Size constraint failed"

    def testSerialised(self):
        assert bytes(self.asn1String) == self.pythonString.encode(self.encoding), (
            "__str__() fails"
        )

    def testPrintable(self):
        assert str(self.asn1String) == self.pythonString, "__str__() fails"

    def testInit(self):
        assert self.asn1Type(self.pythonString) == self.pythonString
        assert (
            self.asn1Type(self.pythonString.encode(self.encoding)) == self.pythonString
        )
        assert (
            self.asn1Type(univ.OctetString(self.pythonString.encode(self.encoding)))
            == self.pythonString
        )
        assert self.asn1Type(self.asn1Type(self.pythonString)) == self.pythonString
        assert (
            self.asn1Type(self.initializer, encoding=self.encoding) == self.pythonString
        )

    def testInitFromAsn1(self):
        assert self.asn1Type(self.asn1Type(self.pythonString)) == self.pythonString
        assert (
            self.asn1Type(
                univ.OctetString(
                    self.pythonString.encode(self.encoding), encoding=self.encoding
                )
            )
            == self.pythonString
        )

    def testAsOctets(self):
        assert self.asn1String.asOctets() == self.pythonString.encode(self.encoding), (
            "testAsOctets() fails"
        )

    def testAsNumbers(self):
        assert self.asn1String.asNumbers() == self.initializer, "testAsNumbers() fails"

    def testSeq(self):
        assert self.asn1String[0] == self.pythonString[0], "__getitem__() fails"

    def testEmpty(self):
        try:
            str(self.asn1Type())
        except PyAsn1Error:
            pass
        else:
            assert 0, "Value operation on ASN1 type tolerated"

    def testAdd(self):
        assert (
            self.asn1String + self.pythonString.encode(self.encoding)
            == self.pythonString + self.pythonString
        ), "__add__() fails"

    def testRadd(self):
        assert (
            self.pythonString.encode(self.encoding) + self.asn1String
            == self.pythonString + self.pythonString
        ), "__radd__() fails"

    def testMul(self):
        assert self.asn1String * 2 == self.pythonString * 2, "__mul__() fails"

    def testRmul(self):
        assert 2 * self.asn1String == 2 * self.pythonString, "__rmul__() fails"

    def testContains(self):
        assert self.pythonString in self.asn1String
        assert self.pythonString + self.pythonString not in self.asn1String

    def testReverse(self):
        assert list(reversed(self.asn1String)) == list(reversed(self.pythonString))

    def testSchemaPickling(self):
        old_asn1 = self.asn1Type()
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert type(new_asn1) == self.asn1Type
        assert old_asn1.isSameTypeWith(new_asn1)

    def testValuePickling(self):
        old_asn1 = self.asn1String
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert new_asn1 == self.asn1String


class VisibleStringTestCase(AbstractStringTestCase, BaseTestCase):
    initializer = (97, 102)
    encoding = "us-ascii"
    asn1Type = char.VisibleString


class GeneralStringTestCase(AbstractStringTestCase, BaseTestCase):
    initializer = (169, 174)
    encoding = "iso-8859-1"
    asn1Type = char.GeneralString


class UTF8StringTestCase(AbstractStringTestCase, BaseTestCase):
    initializer = (209, 132, 208, 176)
    encoding = "utf-8"
    asn1Type = char.UTF8String


class BMPStringTestCase(AbstractStringTestCase, BaseTestCase):
    initializer = (4, 48, 4, 68)
    encoding = "utf-16-be"
    asn1Type = char.BMPString


class UniversalStringTestCase(AbstractStringTestCase, BaseTestCase):
    initializer = (0, 0, 4, 48, 0, 0, 4, 68)
    encoding = "utf-32-be"
    asn1Type = char.UniversalString


class PermittedAlphabetTestCase(BaseTestCase):
    """X.680 41: the repertoire each restricted character string type defines.

    The constraints ship opt-in, so each case asserts both that the default
    type still accepts an out-of-repertoire value and that a subtype carrying
    the alphabet rejects it.
    """

    # (type, in-repertoire sample, out-of-repertoire sample, alphabet size)
    ALPHABETS = (
        # X.680 41.2, Table 9: digits and SPACE only.
        (char.NumericString, "0123456789 ", "12-34", 11),
        # X.680 41.4, Table 10. "*" and "@" are ASCII graphics but are not
        # in Table 10, which is the whole point of the type.
        (char.PrintableString, "Ab9 '()+,-./:=?", "user@host", 74),
        (char.PrintableString, "Ab9 '()+,-./:=?", "wild*card", 74),
        # X.680 41.1, Table 8: registrations 1 and 6 + SPACE + DELETE.
        (char.IA5String, "\x00 ~\x7f", "é", 128),
        # X.680 41.1, Table 8: registration 6 + SPACE. No controls, no DELETE.
        (char.VisibleString, " ~", "\x7f", 95),
        (char.VisibleString, " ~", "\t", 95),
        (char.ISO646String, " ~", "\x7f", 95),
    )

    def testRepertoireIsOptIn(self):
        for asn1Type, _, outside, _size in self.ALPHABETS:
            with self.subTest(asn1Type.__name__, value=outside):
                # The bare type must keep decoding what it decodes today.
                self.assertEqual(str(asn1Type(outside)), outside)

    def testAlphabetAcceptsRepertoire(self):
        for asn1Type, inside, _, _size in self.ALPHABETS:
            with self.subTest(asn1Type.__name__, value=inside):
                strict = asn1Type(inside, subtypeSpec=asn1Type.permittedAlphabet)
                self.assertEqual(str(strict), inside)

    def testAlphabetRejectsOutsideRepertoire(self):
        for asn1Type, _, outside, _size in self.ALPHABETS:
            with self.subTest(asn1Type.__name__, value=outside):
                self.assertRaises(
                    error.ValueConstraintError,
                    asn1Type,
                    outside,
                    subtypeSpec=asn1Type.permittedAlphabet,
                )

    def testAlphabetSize(self):
        for asn1Type, _, _, size in self.ALPHABETS:
            with self.subTest(asn1Type.__name__):
                self.assertEqual(len(list(asn1Type.permittedAlphabet)), size)

    def testRegistrationDefinedTypesCarryNoAlphabet(self):
        # X.680 Table 8 defines these by ISO register entries, and 41.6/41.15
        # /41.16 by the whole of ISO/IEC 10646. Shipping a set for those would
        # be either wrong or enormous, so they stay None.
        for asn1Type in (
            char.TeletexString,
            char.T61String,
            char.VideotexString,
            char.GraphicString,
            char.GeneralString,
            char.UniversalString,
            char.BMPString,
            char.UTF8String,
        ):
            with self.subTest(asn1Type.__name__):
                self.assertIsNone(asn1Type.permittedAlphabet)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
