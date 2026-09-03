#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import itertools
import random
import sys
import unittest

from pyasn1 import error
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.der import decoder as der_decoder
from tests.base import BaseTestCase


def malformedSubstrates():
    """Every 1- and 2-octet substrate, plus a fixed pseudo-random sample."""
    for length in (1, 2):
        for octets in itertools.product(range(256), repeat=length):
            yield bytes(octets)

    rnd = random.Random(7)
    for _ in range(3000):
        yield bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))


class DecoderErrorContractTestCase(BaseTestCase):
    """Callers guard decoding with ``except PyAsn1Error``.

    Any other exception escaping a decoder is a hole in that contract, since
    decoders are routinely pointed at hostile, attacker-supplied octets.
    """

    def testAllDecoderFailuresArePyAsn1Errors(self):
        leaks = {}

        for name, decode in (
            ("ber", ber_decoder.decode),
            ("cer", cer_decoder.decode),
            ("der", der_decoder.decode),
        ):
            for substrate in malformedSubstrates():
                try:
                    decode(substrate)

                except error.PyAsn1Error:
                    continue

                except Exception as exc:  # noqa: BLE001
                    leaks.setdefault(
                        (name, type(exc).__name__), (substrate.hex(), str(exc))
                    )

        assert not leaks, f"non-PyAsn1Error escaped a decoder: {leaks!r}"


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
