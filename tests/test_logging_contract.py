#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import ast
import logging
import pathlib
import sys
import unittest

from pyasn1 import debug
from tests.base import BaseTestCase

LOG_METHODS = frozenset(
    ("debug", "info", "warning", "error", "exception", "critical", "log")
)

PYASN1_ROOT = pathlib.Path(debug.__file__).parent


def logCalls():
    """Every logging call in the library, as (path, lineno, node)."""
    for path in sorted(PYASN1_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text())

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            if not isinstance(func, ast.Attribute) or func.attr not in LOG_METHODS:
                continue

            if not isinstance(func.value, ast.Name) or func.value.id != "LOG":
                continue

            yield path.relative_to(PYASN1_ROOT.parent), node.lineno, node


class StructuredLoggingTestCase(BaseTestCase):
    """pyasn1 logs invariant messages with the varying parts in ``extra``.

    An interpolated message forces every consumer back to parsing prose, and
    it costs the interpolation even when nobody is listening. Both are caught
    here statically, because a call site that is never reached at DEBUG would
    otherwise never be checked.
    """

    def testMessagesAreConstant(self):
        offenders = [
            f"{path}:{lineno}"
            for path, lineno, node in logCalls()
            if len(node.args) != 1 or not isinstance(node.args[0], ast.Constant)
        ]

        assert not offenders, (
            "log messages must be constant strings with context in `extra`: {}".format(
                ", ".join(offenders)
            )
        )

    def testContextKeysDoNotShadowRecordAttributes(self):
        """A shadowing key makes ``logger.debug()`` itself raise ``KeyError``."""
        offenders = []

        for path, lineno, node in logCalls():
            for keyword in node.keywords:
                if keyword.arg != "extra":
                    continue

                assert isinstance(keyword.value, ast.Dict), (
                    f"{path}:{lineno}: `extra` must be a dict literal"
                )

                for key in keyword.value.keys:
                    assert isinstance(key, ast.Constant), (
                        f"{path}:{lineno}: `extra` keys must be literals"
                    )

                    if key.value in debug._RECORD_ATTRS:
                        offenders.append(f"{path}:{lineno}: {key.value}")

        assert not offenders, "`extra` keys shadow LogRecord attributes: {}".format(
            ", ".join(offenders)
        )


class ContextFormatterTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.formatter = debug.ContextFormatter("%(message)s")

    def format(self, **context):
        record = logging.LogRecord(
            "pyasn1", logging.DEBUG, __file__, 1, "decoding", None, None
        )
        record.__dict__.update(context)
        return self.formatter.format(record)

    def testPlainRecordIsUnchanged(self):
        assert self.format() == "decoding"

    def testContextIsAppendedSorted(self):
        assert self.format(tagSet="[0]", length=3) == "decoding length=3 tagSet=[0]"

    def testBytesRenderAsSingleLineHex(self):
        text = self.format(substrate=b"\x04\x02\x0c")

        assert text == "decoding substrate=04 02 0c", text
        assert "\n" not in text, f"a record must render on one line: {text!r}"


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
