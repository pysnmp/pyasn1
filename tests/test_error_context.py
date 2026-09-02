#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import ast
import copy
import pathlib
import pickle
import sys
import unittest

from pyasn1 import debug, error
from pyasn1.codec.ber import decoder as ber_decoder
from tests.base import BaseTestCase

PYASN1_ROOT = pathlib.Path(debug.__file__).parent


def raiseSites():
    """Every exception construction in the library, however it is spelled.

    Covers ``raise error.PyAsn1Error(...)``, the ``exc.__class__(...)``
    re-raise in :mod:`pyasn1.type.base`, and the deferred
    ``NamedTypes.PostponedError(...)``.
    """
    for path in sorted(PYASN1_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                call = node.exc

            elif isinstance(node, ast.Call):
                call = node

            else:
                continue

            name = ast.unparse(call.func)

            # Builtin exceptions raised on protocol paths are not ours to shape.
            if not name.startswith("error.") and not name.endswith(
                ("PostponedError", "__class__")
            ):
                continue

            yield path.relative_to(PYASN1_ROOT.parent), node.lineno, call


def buildsMessageDynamically(node):
    """True if any positional argument interpolates at the call site."""
    for arg in node.args:
        if isinstance(arg, ast.JoinedStr):
            return True

        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"
        ):
            return True

    return False


class StructuredErrorTestCase(BaseTestCase):
    """pyasn1 raises invariant messages with the varying parts in ``context``.

    This mirrors the logging contract: a caller that needs the offending
    length or tag set should read it off the exception rather than parse it
    back out of prose.
    """

    def testMessagesAreConstant(self):
        offenders = [
            f"{path}:{lineno}"
            for path, lineno, node in raiseSites()
            if buildsMessageDynamically(node)
        ]

        assert not offenders, (
            "exception messages must be constant strings with the varying "
            "parts passed as keywords: {}".format(", ".join(offenders))
        )


class ErrorContextTestCase(BaseTestCase):
    def testContextIsExposed(self):
        exc = error.PyAsn1Error("Short substrate", shortBy=3, length=8)

        assert exc.context == {"shortBy": 3, "length": 8}

    def testContextRendersOnDemand(self):
        exc = error.PyAsn1Error("Short substrate", shortBy=3)

        assert str(exc) == "Short substrate (shortBy=3)"

    def testMessageWithoutContextIsUnchanged(self):
        assert str(error.PyAsn1Error("Method not implemented")) == (
            "Method not implemented"
        )

    def testContextWithoutMessageRendersAlone(self):
        assert str(error.PyAsn1Error(length=5)) == "length=5"

    def testEmptyExceptionRendersEmpty(self):
        assert str(error.PyAsn1Error()) == ""

    def testMultiplePositionalArgumentsStillWork(self):
        """``Exception('a', 'b')`` is legal and must stay legal."""
        assert str(error.PyAsn1Error("a", "b")) == "('a', 'b')"

    def testRepr(self):
        exc = error.SubstrateUnderrunError("Short substrate", shortBy=3)

        assert repr(exc) == "SubstrateUnderrunError('Short substrate', shortBy=3)"

    def testUnrepresentableValueDoesNotMaskTheError(self):
        class Unrepresentable:
            def __repr__(self):
                raise RuntimeError("no repr for you")

        exc = error.PyAsn1Error("Bad value", value=Unrepresentable())

        assert str(exc) == "Bad value (value=<unrepresentable Unrepresentable>)"

    def testContextSurvivesPickling(self):
        exc = error.SubstrateUnderrunError("Short substrate", shortBy=3)
        restored = pickle.loads(pickle.dumps(exc))

        assert restored.context == {"shortBy": 3}
        assert str(restored) == "Short substrate (shortBy=3)"

    def testContextSurvivesCopying(self):
        exc = error.PyAsn1Error("Short substrate", shortBy=3)

        assert copy.copy(exc).context == {"shortBy": 3}


class UnicodeErrorContextTestCase(BaseTestCase):
    """The Unicode subclasses mix in UnicodeError, whose ``__init__`` differs."""

    def testEncodeErrorCarriesContext(self):
        exc = error.PyAsn1UnicodeEncodeError(
            "Can't encode string with codec",
            UnicodeEncodeError("us-ascii", "’", 0, 1, "bad"),
            codec="us-ascii",
        )

        assert exc.context == {"codec": "us-ascii"}
        assert str(exc) == "Can't encode string with codec (codec='us-ascii')"
        assert isinstance(exc, UnicodeError)
        assert isinstance(exc, error.PyAsn1Error)

    def testDecodeErrorWithoutInnerErrorIsAccepted(self):
        exc = error.PyAsn1UnicodeDecodeError("Can't decode string with codec")

        assert exc.context == {}
        assert str(exc) == "Can't decode string with codec"


class DecoderErrorContextTestCase(BaseTestCase):
    """The context reaches callers from a real decode, not just unit tests."""

    def testShortSubstrateReportsShortfall(self):
        with self.assertRaises(error.SubstrateUnderrunError) as caught:
            ber_decoder.decode(bytes((0x04, 0x08, 0x01, 0x02)))

        assert caught.exception.context["shortBy"] == 6
        assert caught.exception.context["length"] == 8
        assert caught.exception.context["available"] == 2

    def testNestingDepthReportsLimit(self):
        depth = ber_decoder.MAX_NESTING_DEPTH + 5
        substrate = (
            bytes((0x30, 0x80)) * depth
            + bytes((0x05, 0x00))
            + bytes((0x00, 0x00)) * depth
        )

        with self.assertRaises(error.PyAsn1Error) as caught:
            ber_decoder.decode(substrate)

        assert caught.exception.context["limit"] == ber_decoder.MAX_NESTING_DEPTH


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
