#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://github.com/pysnmp/pyasn1/blob/main/LICENSE.rst
#
import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    [
        "tests.test_debug.suite",
        "tests.type.__main__.suite",
        "tests.codec.__main__.suite",
        "tests.compat.__main__.suite",
    ]
)


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
