#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Exceptions raised by ASN.1 type value handling."""

from pyasn1.error import PyAsn1Error, ValueConstraintError

# Re-exported, not redefined. This module used to declare its own
# ValueConstraintError, a sibling of the one in pyasn1.error rather than the
# same class, so the handler named throughout the type documentation
# ("~pyasn1.error.ValueConstraintError") never fired for a constraint
# violation raised from here.
__all__ = ["PyAsn1Error", "ValueConstraintError"]
