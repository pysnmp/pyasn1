#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
# ASN.1 named integers
#
"""Named-value maps used to label numeric ASN.1 values."""

from collections.abc import Iterator
from typing import Any, NoReturn

from pyasn1 import error

__all__ = ["NamedValues"]


class NamedValues(dict[Any, Any]):
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

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # The primary dict stores name -> number (the natural dict mapping).
        # A reverse index stores number -> name for bidirectional lookup.
        self._numbers: dict[Any, Any] = {}

        anonymousNames = []

        for namedValue in args:
            if isinstance(namedValue, tuple | list):
                try:
                    name, number = namedValue

                except ValueError as exc:
                    raise error.PyAsn1Error(
                        "Not a proper attribute-value pair", namedValue=namedValue
                    ) from exc

            else:
                anonymousNames.append(namedValue)
                continue

            if name in self:
                raise error.PyAsn1Error("Duplicate name", name=name)

            if number in self._numbers:
                raise error.PyAsn1Error("Duplicate number", name=name, number=number)

            dict.__setitem__(self, name, number)
            self._numbers[number] = name

        for name, number in kwargs.items():
            if name in self:
                raise error.PyAsn1Error("Duplicate name", name=name)

            if number in self._numbers:
                raise error.PyAsn1Error("Duplicate number", name=name, number=number)

            dict.__setitem__(self, name, number)
            self._numbers[number] = name

        if anonymousNames:
            number = max(self._numbers) + 1 if self._numbers else 0

            for name in anonymousNames:
                if name in self:
                    raise error.PyAsn1Error("Duplicate name", name=name)

                dict.__setitem__(self, name, number)
                self._numbers[number] = name

                number += 1

    # NamedValues is immutable (see class docstring).  Block every dict
    # mutation path so the primary name->number mapping and the _numbers
    # reverse index can never fall out of sync.  Construction populates the
    # storage via dict.__setitem__ to bypass these guards.
    def _immutable(self, op: str) -> NoReturn:
        raise error.PyAsn1Error("NamedValues is immutable", operation=op)

    def __setitem__(self, key: Any, value: Any) -> NoReturn:
        self._immutable("item assignment")

    def __delitem__(self, key: Any) -> NoReturn:
        self._immutable("item deletion")

    def update(self, *args: Any, **kwargs: Any) -> NoReturn:
        """Raise `PyAsn1Error`; `NamedValues` objects are immutable."""
        self._immutable("update")

    def pop(self, *args: Any, **kwargs: Any) -> NoReturn:
        """Raise `PyAsn1Error`; `NamedValues` objects are immutable."""
        self._immutable("pop")

    def popitem(self, *args: Any, **kwargs: Any) -> NoReturn:
        """Raise `PyAsn1Error`; `NamedValues` objects are immutable."""
        self._immutable("popitem")

    def clear(self) -> NoReturn:
        """Raise `PyAsn1Error`; `NamedValues` objects are immutable."""
        self._immutable("clear")

    def setdefault(self, *args: Any, **kwargs: Any) -> NoReturn:
        """Raise `PyAsn1Error`; `NamedValues` objects are immutable."""
        self._immutable("setdefault")

    def __ior__(self, other: Any) -> NoReturn:  # type: ignore[misc]
        self._immutable("in-place merge")

    def __reduce__(self) -> tuple[Any, ...]:
        # Reconstruct via __init__ (which populates storage with
        # dict.__setitem__, bypassing the immutability guards) rather than
        # the default dict pickle path that restores items through
        # __setitem__/update.  __init__ rebuilds the _numbers reverse index.
        return (self.__class__, tuple(self.items()))

    def __repr__(self) -> str:
        representation = ", ".join([f"{k}={v}" for k, v in self.items()])

        if len(representation) > 64:
            representation = representation[:32] + "..." + representation[-32:]

        return f"<{self.__class__.__name__} object, enums {representation}>"

    # Bidirectional lookup: key can be either a name (str) or a number (int).
    def __getitem__(self, key: Any) -> Any:
        try:
            return self._numbers[key]

        except (KeyError, TypeError):
            return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        return super().__contains__(key) or key in self._numbers

    def __iter__(self) -> Iterator[Any]:
        return super().__iter__()

    # support merging

    def __add__(self, namedValues: "NamedValues") -> "NamedValues":
        return self.__class__(*tuple(self.items()) + tuple(namedValues.items()))

    # XXX clone/subtype?

    def clone(self, *args: Any, **kwargs: Any) -> "NamedValues":
        """Return a new `NamedValues` merging *args*/*kwargs* into this one."""
        new = self.__class__(*args, **kwargs)
        return self + new
