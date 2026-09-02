#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Exceptions raised by ASN.1 type value handling."""

from pyasn1.error import PyAsn1Error

__all__ = ["PyAsn1Error", "ValueConstraintError"]


class ValueConstraintError(PyAsn1Error):
    """Raised when a value violates a type's constraint."""

    pass
