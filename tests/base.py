#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#

import logging
import unittest


class RenderingHandler(logging.Handler):
    """Render every record and throw it away.

    Running the suite with pyasn1's loggers at DEBUG keeps the debug branches
    covered, and rendering each record proves the format string and its lazy
    arguments actually agree. A mismatch surfaces only at render time, so a
    handler that discarded records without formatting them would hide exactly
    the bug this catches.
    """

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.failures: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            record.getMessage()
        except Exception as exc:
            self.failures.append(
                "%s: %r %% %r -- %s" % (record.name, record.msg, record.args, exc)
            )


class BaseTestCase(unittest.TestCase):
    """Common base for the suite.

    Debug records are enabled and checked for every test by the autouse
    fixture in ``tests/conftest.py``, which covers the many subclasses that
    override :meth:`setUp` without chaining up.
    """
