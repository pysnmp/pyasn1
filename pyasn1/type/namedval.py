#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
# ASN.1 named integers
#
from pyasn1 import error

__all__ = ["NamedValues"]


class NamedValues(dict):
    """Create named values object.

    The |NamedValues| object represents a collection of string names
    associated with numeric IDs. These objects are used for giving
    names to otherwise numerical values.

    |NamedValues| objects are immutable and duck-type Python
    :class:`dict` object mapping ID to name and vice-versa.

    Parameters
    ----------
    *args: variable number of two-element :py:class:`tuple`

        name: :py:class:`str`
            Value label

        value: :py:class:`int`
            Numeric value

    Keyword Args
    ------------
    name: :py:class:`str`
        Value label

    value: :py:class:`int`
        Numeric value

    Examples
    --------

    .. code-block:: pycon

        >>> nv = NamedValues('a', 'b', ('c', 0), d=1)
        >>> nv
        >>> {'c': 0, 'd': 1, 'a': 2, 'b': 3}
        >>> nv[0]
        'c'
        >>> nv['a']
        2
    """

    def __init__(self, *args, **kwargs):
        # The primary dict stores name -> number (the natural dict mapping).
        # A reverse index stores number -> name for bidirectional lookup.
        self._numbers = {}

        anonymousNames = []

        for namedValue in args:
            if isinstance(namedValue, (tuple, list)):
                try:
                    name, number = namedValue

                except ValueError:
                    raise error.PyAsn1Error("Not a proper attribute-value pair %r" % (namedValue,))

            else:
                anonymousNames.append(namedValue)
                continue

            if name in self:
                raise error.PyAsn1Error("Duplicate name %s" % (name,))

            if number in self._numbers:
                raise error.PyAsn1Error("Duplicate number  %s=%s" % (name, number))

            self[name] = number
            self._numbers[number] = name

        for name, number in kwargs.items():
            if name in self:
                raise error.PyAsn1Error("Duplicate name %s" % (name,))

            if number in self._numbers:
                raise error.PyAsn1Error("Duplicate number  %s=%s" % (name, number))

            self[name] = number
            self._numbers[number] = name

        if anonymousNames:

            number = self._numbers and max(self._numbers) + 1 or 0

            for name in anonymousNames:

                if name in self:
                    raise error.PyAsn1Error("Duplicate name %s" % (name,))

                self[name] = number
                self._numbers[number] = name

                number += 1

    def __repr__(self):
        representation = ", ".join(["%s=%d" % x for x in self.items()])

        if len(representation) > 64:
            representation = representation[:32] + "..." + representation[-32:]

        return "<%s object, enums %s>" % (self.__class__.__name__, representation)

    # Bidirectional lookup: key can be either a name (str) or a number (int).
    def __getitem__(self, key):
        try:
            return self._numbers[key]

        except (KeyError, TypeError):
            return super().__getitem__(key)

    def __contains__(self, key):
        return super().__contains__(key) or key in self._numbers

    def __iter__(self):
        return super().__iter__()

    def values(self):
        return iter(self._numbers)

    def keys(self):
        return super().__iter__()

    def items(self):
        for name in super().__iter__():
            yield name, self[name]

    # support merging

    def __add__(self, namedValues):
        return self.__class__(*tuple(self.items()) + tuple(namedValues.items()))

    # XXX clone/subtype?

    def clone(self, *args, **kwargs):
        new = self.__class__(*args, **kwargs)
        return self + new
