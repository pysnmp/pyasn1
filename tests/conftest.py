#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import logging

import pytest

from tests.base import RenderingHandler


@pytest.fixture(autouse=True)
def renderDebugRecords():
    """Run every test with pyasn1 debugging on and every record rendered.

    This lives in a fixture rather than in ``BaseTestCase.setUp`` because
    most test classes override ``setUp`` without chaining up, which would
    leave the majority of the suite unguarded.
    """
    logger = logging.getLogger("pyasn1")
    level = logger.level
    handler = RenderingHandler()

    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    try:
        yield handler

    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)

    assert not handler.failures, "malformed debug records: {}".format(
        "; ".join(handler.failures)
    )
