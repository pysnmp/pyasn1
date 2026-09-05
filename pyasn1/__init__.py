# https://www.python.org/dev/peps/pep-0396/
"""ASN.1 types and codecs for Python."""

import logging

__version__ = "1.3.0-rc.3"

# Libraries must not configure logging for the application that imports them.
# A NullHandler keeps pyasn1's records silent until the application opts in,
# and is the only logging setup this package performs at import time.
logging.getLogger(__name__).addHandler(logging.NullHandler())
