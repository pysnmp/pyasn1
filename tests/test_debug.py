#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import logging
import subprocess
import sys
import unittest
import warnings

from pyasn1 import debug, error
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ
from tests.base import BaseTestCase


class Collector(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def roundTrip():
    """Exercise both codecs so either category has something to say."""
    decoder.decode(encoder.encode(univ.Integer(42)))


def setLoggerQuietly(userLogger):
    """Drive the deprecated switch without tripping the warning filter."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        debug.setLogger(userLogger)


def debugQuietly(*flags, **options):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return debug.Debug(*flags, **options)


class DebugCaseBase(BaseTestCase):
    def testKnownFlags(self):
        setLoggerQuietly(0)
        setLoggerQuietly(debugQuietly("all", "encoder", "decoder"))
        setLoggerQuietly(0)

    def testUnknownFlags(self):
        try:
            debugQuietly("all", "unknown", loggerName="xxx")

        except error.PyAsn1Error:
            setLoggerQuietly(0)
            return

        else:
            setLoggerQuietly(0)
            assert 0, "unknown debug flag tolerated"


class StdlibLoggingCaseBase(unittest.TestCase):
    """The supported way in: configure :mod:`logging`, touch no pyasn1 API."""

    def setUp(self):
        self.logger = logging.getLogger("pyasn1")
        self.level = self.logger.level
        self.collector = Collector()
        self.logger.addHandler(self.collector)
        # The suite-wide fixture runs pyasn1 at DEBUG; these tests are about
        # what a given configuration turns on, so start from nothing set.
        self.logger.setLevel(logging.NOTSET)

    def tearDown(self):
        self.logger.removeHandler(self.collector)
        self.logger.setLevel(self.level)
        for name in (
            "pyasn1.codec.ber.decoder",
            "pyasn1.codec.ber.encoder",
            "pyasn1.codec.native.decoder",
            "pyasn1.codec.native.encoder",
        ):
            logging.getLogger(name).setLevel(logging.NOTSET)

    def testLevelOnRootOfNamespaceEnablesEverything(self):
        self.logger.setLevel(logging.DEBUG)
        roundTrip()

        assert self.collector.records, "setting the pyasn1 level emitted nothing"
        assert {r.name for r in self.collector.records} == {
            "pyasn1.codec.ber.decoder",
            "pyasn1.codec.ber.encoder",
        }, sorted({r.name for r in self.collector.records})

    def testPerModuleLevelIsHonoured(self):
        # Finer than the legacy flags could express: one codec module, not
        # every decoder in the library.
        logging.getLogger("pyasn1.codec.ber.decoder").setLevel(logging.DEBUG)
        roundTrip()

        assert self.collector.records, "per-module level emitted nothing"
        assert {r.name for r in self.collector.records} == {
            "pyasn1.codec.ber.decoder"
        }, sorted({r.name for r in self.collector.records})

    def testQuietByDefault(self):
        roundTrip()

        assert (
            not self.collector.records
        ), "records emitted without any level being set: %r" % (self.collector.records,)

    def testRecordsKeepTheirFormatArguments(self):
        """The point of lazy arguments: ``msg`` stays a template.

        A record whose message was pre-rendered cannot be grouped by call
        site downstream, which is what structured handlers key on.
        """
        self.logger.setLevel(logging.DEBUG)
        roundTrip()

        parameterised = [r for r in self.collector.records if r.args]

        assert parameterised, "no record carried deferred arguments"

        for record in parameterised:
            assert "%" in record.msg, "record has args but no placeholders: %r" % (
                record.msg,
            )
            record.getMessage()


class LegacyDebugCaseBase(unittest.TestCase):
    """The deprecated switch must keep working while it is still shipped."""

    def tearDown(self):
        setLoggerQuietly(0)

    def testDeprecationIsAnnounced(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            dbg = debug.Debug("all", printer=lambda msg: None)
            debug.setLogger(dbg)
            debug.setLogger(0)

        messages = [str(w.message) for w in caught]

        assert any("Debug is deprecated" in m for m in messages), messages
        assert any("setLogger is deprecated" in m for m in messages), messages

    def testLegacySwitchStillEmits(self):
        messages = []
        setLoggerQuietly(debugQuietly("all", printer=messages.append))
        roundTrip()

        assert messages, "legacy setLogger produced no output after migration"

    def testFlagsStillIsolateCategories(self):
        for flag, enabled, disabled in (
            ("encoder", "pyasn1.codec.ber.encoder", "pyasn1.codec.ber.decoder"),
            ("decoder", "pyasn1.codec.ber.decoder", "pyasn1.codec.ber.encoder"),
        ):
            setLoggerQuietly(debugQuietly(flag, printer=lambda msg: None))

            assert logging.getLogger(enabled).isEnabledFor(
                logging.DEBUG
            ), "flag %r did not enable %s" % (flag, enabled)
            assert not logging.getLogger(disabled).isEnabledFor(
                logging.DEBUG
            ), "flag %r leaked into %s" % (flag, disabled)

            setLoggerQuietly(0)

    def testApplicationLevelsAreRestored(self):
        app = logging.getLogger("pyasn1.codec.ber.decoder")
        app.setLevel(logging.WARNING)

        try:
            setLoggerQuietly(debugQuietly("all", printer=lambda msg: None))
            assert app.level == logging.DEBUG, logging.getLevelName(app.level)

            setLoggerQuietly(0)
            assert (
                app.level == logging.WARNING
            ), "setLogger(0) left the application level at %s" % logging.getLevelName(
                app.level
            )

        finally:
            app.setLevel(logging.NOTSET)

    def testPrinterAimedAtPyasn1DoesNotRecurse(self):
        """A printer writing back into ``pyasn1`` must not loop forever."""
        setLoggerQuietly(debugQuietly("all", loggerName="pyasn1"))
        roundTrip()


class LoggingHygieneCaseBase(unittest.TestCase):
    """A library must never configure logging on behalf of its importer."""

    def testImportConfiguresNothing(self):
        # Must run in a fresh interpreter: by the time this test executes,
        # pyasn1 is long imported and any import-time damage already done.
        script = (
            "import logging\n"
            "from pyasn1 import debug\n"
            "from pyasn1.codec.ber import decoder, encoder\n"
            "from pyasn1.codec.native import decoder as nd, encoder as ne\n"
            "log = logging.getLogger('pyasn1')\n"
            "assert log.level == logging.NOTSET, 'import set level to %s' % log.level\n"
            "assert log.handlers, 'no NullHandler installed on the pyasn1 logger'\n"
            "assert all(isinstance(h, logging.NullHandler) for h in log.handlers), (\n"
            "    'import attached %r' % (log.handlers,))\n"
            "assert debug.Debug.defaultPrinter is None, 'default printer built at import'\n"
            "for mod in (decoder, encoder, nd, ne):\n"
            "    assert isinstance(mod.LOG, logging.Logger), (\n"
            "        '%s.LOG is %r' % (mod.__name__, mod.LOG))\n"
            "    assert mod.LOG.level == logging.NOTSET, (\n"
            "        'import set %s level to %s' % (mod.__name__, mod.LOG.level))\n"
            "    assert not mod.LOG.handlers, (\n"
            "        'import attached handlers to %s' % mod.__name__)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True
        )
        assert completed.returncode == 0, completed.stderr

    def testDebugDoesEmitOnceEnabled(self):
        records = []

        class RecordCollector(logging.Handler):
            def emit(self, record):
                records.append(record)

        collector = RecordCollector()
        log = logging.getLogger("pyasn1-test-optin")
        log.setLevel(logging.DEBUG)
        log.addHandler(collector)

        try:
            setLoggerQuietly(debugQuietly("all", loggerName="pyasn1-test-optin"))
            assert records, "no records emitted after opting in"

        finally:
            setLoggerQuietly(0)
            log.handlers.clear()
            log.setLevel(logging.NOTSET)

    def testCallerLoggerLeftAlone(self):
        log = logging.getLogger("pyasn1-test-app")
        log.setLevel(logging.WARNING)
        handlersBefore = list(log.handlers)

        try:
            for _ in range(3):
                setLoggerQuietly(debugQuietly("all", loggerName="pyasn1-test-app"))

            assert log.level == logging.WARNING, (
                "pyasn1 overrode the application logger level: %s" % log.level
            )
            assert (
                log.handlers == handlersBefore
            ), "pyasn1 attached handlers to the application logger: %r" % (
                log.handlers,
            )

        finally:
            setLoggerQuietly(0)
            log.handlers.clear()
            log.setLevel(logging.NOTSET)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
