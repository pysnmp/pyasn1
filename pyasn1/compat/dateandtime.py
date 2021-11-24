#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import time
from datetime import datetime

__all__ = ["strptime"]


def strptime(text, dateFormat):
    return datetime.strptime(text, dateFormat)
