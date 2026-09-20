#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
import ast
import logging
import pathlib
import sys
import unittest

from pyasn1 import debug
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ
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


class DebugFlagScopeTestCase(BaseTestCase):
    """The debug flag is snapshotted per frame, so debug.scope stays balanced.

    ``Decoder.__call__`` pushes onto the module-level ``debug.scope`` near its
    start and pops at its end, both under the debug guard. If the guard can
    change its mind in between, the stack goes out of step: a push with no pop
    leaks an entry, and a pop with no push raises ``IndexError`` on an empty
    list, out of an ordinary decode.

    ``_DEBUG`` is a module global refreshed by whichever decode is at nesting
    level zero, so another thread starting a decode can move it under a frame
    that is midway between its push and its pop. That is the window the frame
    local closes, and it is what the first test below drives, by flipping the
    global from inside ``debug.scope.push`` rather than by running threads.
    """

    def setUp(self):
        BaseTestCase.setUp(self)
        self.octets = encoder.encode(univ.Integer(42))
        self.realLog = decoder.LOG
        self.realDebug = decoder._DEBUG
        # debug.scope is a module-level stack other tests have pushed onto,
        # so what matters is that a decode leaves it as it found it.
        self.scopeDepth = len(debug.scope._list)

    def tearDown(self):
        decoder.LOG = self.realLog
        decoder._DEBUG = self.realDebug
        del debug.scope._list[self.scopeDepth :]
        BaseTestCase.tearDown(self)

    def testScopeBalancesWhenTheFlagFlipsMidDecode(self):
        class Enabled:
            """A logger that is on, so the frame takes the guarded path."""

            def isEnabledFor(self, level):
                return True

            def debug(self, *args, **kwargs):
                pass

        decoder.LOG = Enabled()

        realPush = debug.scope.push

        def flippingPush(token):
            # Stand in for another thread reaching nesting level zero and
            # refreshing the module flag, landing exactly between this
            # frame's push and the pop that has to match it.
            realPush(token)
            decoder._DEBUG = False

        debug.scope.push = flippingPush

        try:
            decoder.decode(self.octets, asn1Spec=univ.Integer())

        finally:
            del debug.scope.push

        self.assertEqual(
            self.scopeDepth,
            len(debug.scope._list),
            "debug.scope did not return to its starting depth: the flag moved "
            "between the push and the pop, and the pop was skipped",
        )

    def testTheFlagIsReadOncePerDecode(self):
        """Pins what #188 bought, which no test of its own covers.

        This one holds on the parent commit too, deliberately: it guards the
        hoist out of the per-component path, not the frame local above it.
        """

        class Counting:
            def __init__(self):
                self.answers = 0

            def isEnabledFor(self, level):
                self.answers += 1
                return False

            def debug(self, *args, **kwargs):
                pass

        counting = Counting()
        decoder.LOG = counting

        decoder.decode(self.octets, asn1Spec=univ.Integer())

        self.assertEqual(
            1,
            counting.answers,
            "the guard is being evaluated more than once per decode",
        )


class EncoderDebugFlagTestCase(BaseTestCase):
    """The encoder reads the debug flag once per encode, not per component.

    This is only expressible because ``Encoder.__call__`` -- the public entry
    -- is separate from the recursion beneath it. Concrete encoders re-enter
    the codec through the bound ``encodeFun`` they are handed, not through
    ``__call__``. Before the split, ``Encoder`` was its own ``encodeFun``, so
    no point in the call graph ran exactly once per operation and there was
    nowhere to put the flag read.

    The earlier attempt threaded a re-entrancy marker through the encoder's
    ``**options`` chain instead, and measured 13% *slower* than the calls it
    removed, because the key then rides through ~65 nested expansions per
    encode. Hence the structural split rather than a marker.
    """

    def setUp(self):
        BaseTestCase.setUp(self)
        # Nested on purpose: a flat value would recurse once and make
        # "once per operation" indistinguishable from "once per component".
        self.value = univ.SequenceOf(componentType=univ.Integer())
        self.value.extend(range(8))
        self.realLog = encoder.LOG
        self.realDebug = encoder._DEBUG

    def tearDown(self):
        encoder.LOG = self.realLog
        encoder._DEBUG = self.realDebug
        BaseTestCase.tearDown(self)

    def testTheFlagIsReadOncePerEncode(self):
        class Counting:
            def __init__(self):
                self.answers = 0

            def isEnabledFor(self, level):
                self.answers += 1
                return False

            def debug(self, *args, **kwargs):
                pass

        counting = Counting()
        encoder.LOG = counting

        encoder.encode(self.value)

        self.assertEqual(
            1,
            counting.answers,
            "the guard is being evaluated more than once per encode",
        )

    def testTheRecursionDoesNotReenterThePublicEntry(self):
        """Pins the split itself, which counting the guard alone would not.

        A refactor that routed ``encodeFun`` back through ``__call__`` would
        restore the per-component flag read, and the count above would only
        notice because the flag happens to be read there.
        """
        entries = []
        realCall = encoder.Encoder.__call__

        def countingCall(self, value, asn1Spec=None, **options):
            entries.append(value)
            return realCall(self, value, asn1Spec, **options)

        encoder.Encoder.__call__ = countingCall

        try:
            octets = encoder.encode(self.value)

        finally:
            encoder.Encoder.__call__ = realCall

        self.assertEqual(
            1,
            len(entries),
            f"the public entry was re-entered {len(entries)} times; concrete "
            "encoders must recurse through encodeFun, not through __call__",
        )
        self.assertEqual(octets, encoder.encode(self.value))

    def testSetLevelIsPickedUpByTheNextEncode(self):
        """The documented way of enabling debugging must keep working.

        pyasn1 tells people to call
        ``logging.getLogger("pyasn1").setLevel(logging.DEBUG)``. A flag read
        at import would be faster still and would silently ignore exactly
        that, so the refresh belongs per operation.
        """
        log = logging.getLogger("pyasn1.codec.ber.encoder")
        wasLevel = log.level

        try:
            log.setLevel(logging.DEBUG)
            encoder.encode(self.value)
            self.assertTrue(encoder._DEBUG, "setLevel(DEBUG) was not picked up")

            log.setLevel(logging.WARNING)
            encoder.encode(self.value)
            self.assertFalse(encoder._DEBUG, "the flag did not turn back off")

        finally:
            log.setLevel(wasLevel)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
