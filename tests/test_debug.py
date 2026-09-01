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

from pyasn1 import debug, error
from tests.base import BaseTestCase


class DebugCaseBase(BaseTestCase):
    def testKnownFlags(self):
        debug.setLogger(0)
        debug.setLogger(debug.Debug("all", "encoder", "decoder"))
        debug.setLogger(0)

    def testUnknownFlags(self):
        try:
            debug.setLogger(debug.Debug("all", "unknown", loggerName="xxx"))

        except error.PyAsn1Error:
            debug.setLogger(0)
            return

        else:
            debug.setLogger(0)
            assert 0, "unknown debug flag tolerated"


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
        )
        completed = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True
        )
        assert completed.returncode == 0, completed.stderr

    def testDebugDoesEmitOnceEnabled(self):
        records = []

        class Collector(logging.Handler):
            def emit(self, record):
                records.append(record)

        collector = Collector()
        log = logging.getLogger("pyasn1-test-optin")
        log.setLevel(logging.DEBUG)
        log.addHandler(collector)

        try:
            debug.setLogger(debug.Debug("all", loggerName="pyasn1-test-optin"))
            assert records, "no records emitted after opting in"

        finally:
            debug.setLogger(0)
            log.handlers.clear()
            log.setLevel(logging.NOTSET)

    def testCallerLoggerLeftAlone(self):
        log = logging.getLogger("pyasn1-test-app")
        log.setLevel(logging.WARNING)
        handlersBefore = list(log.handlers)

        try:
            for _ in range(3):
                debug.setLogger(debug.Debug("all", loggerName="pyasn1-test-app"))

            assert log.level == logging.WARNING, (
                "pyasn1 overrode the application logger level: %s" % log.level
            )
            assert log.handlers == handlersBefore, (
                "pyasn1 attached handlers to the application logger: %r"
                % (log.handlers,)
            )

        finally:
            debug.setLogger(0)
            log.handlers.clear()
            log.setLevel(logging.NOTSET)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
