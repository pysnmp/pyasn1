# https://www.python.org/dev/peps/pep-0396/
import logging

__version__ = "1.2.0-beta.4"

# Libraries must not configure logging for the application that imports them.
# A NullHandler keeps pyasn1's records silent until the application opts in,
# and is the only logging setup this package performs at import time.
logging.getLogger(__name__).addHandler(logging.NullHandler())
