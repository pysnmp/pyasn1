#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#

from collections.abc import ItemsView, Iterator, KeysView, ValuesView
from typing import Any

__all__ = ["OpenType"]


class OpenType(dict):
    """Create ASN.1 type map indexed by a value

    The *OpenType* object models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used together with :class:`~pyasn1.type.univ.Any` object.

    OpenType objects duck-type a read-only Python :class:`dict` objects,
    however the passed `typeMap` is not copied, but stored by reference.
    That means the user can manipulate `typeMap` at run time having this
    reflected on *OpenType* object behavior.

    The |OpenType| class models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used with :class:`~pyasn1.type.univ.Any` type.

    Parameters
    ----------
    name: :py:class:`str`
        Field name

    typeMap: :py:class:`dict`
        A map of value->ASN.1 type. It's stored by reference and can be
        mutated later to register new mappings.

    Examples
    --------

    For untyped scalars:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', Any(), openType=openType)
            )
        )

    For untyped `SET OF` or `SEQUENCE OF` vectors:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', SetOf(componentType=Any()),
                          openType=openType)
            )
        )
    """

    def __init__(self, name: str, typeMap: dict[Any, Any] | None = None) -> None:
        self.name = name
        # Store the caller's mapping by reference (do not copy) so that
        # additions made to it after construction remain visible through this
        # OpenType, e.g. via namedType.openType[governingValue] during BER
        # decoding.  All dict operations below delegate to the live mapping.
        self._typeMap = typeMap if typeMap is not None else {}

    def __bool__(self) -> bool:
        # An OpenType is always considered truthy, even when the typeMap is
        # empty, so that downstream type-checking code can distinguish "has an
        # open type" from "no open type" (which would be None / absent).
        return True

    # Python dict protocol, delegating to the live typeMap so that the
    # OpenType and the caller's mapping stay in sync in both directions.
    def __len__(self) -> int:
        return len(self._typeMap)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._typeMap)

    def __contains__(self, key: object) -> bool:
        return key in self._typeMap

    def __getitem__(self, key: Any) -> Any:
        return self._typeMap[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._typeMap[key] = value

    def __delitem__(self, key: Any) -> None:
        del self._typeMap[key]

    def keys(self) -> KeysView[Any]:  # type: ignore[override]
        return self._typeMap.keys()

    def values(self) -> ValuesView[Any]:  # type: ignore[override]
        return self._typeMap.values()

    def items(self) -> ItemsView[Any, Any]:  # type: ignore[override]
        return self._typeMap.items()

    def get(self, key: Any, default: Any = None) -> Any:
        return self._typeMap.get(key, default)

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._typeMap.update(*args, **kwargs)

    def pop(self, *args: Any, **kwargs: Any) -> Any:
        return self._typeMap.pop(*args, **kwargs)

    def popitem(self) -> tuple[Any, Any]:
        return self._typeMap.popitem()

    def clear(self) -> None:
        self._typeMap.clear()

    def setdefault(self, *args: Any, **kwargs: Any) -> Any:
        return self._typeMap.setdefault(*args, **kwargs)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OpenType):
            other = other._typeMap
        return self._typeMap == other

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return repr(self._typeMap)

    def copy(self) -> dict[Any, Any]:
        return self._typeMap.copy()

    def __reduce__(self) -> tuple[Any, ...]:
        # Reconstruct via __init__ so the live typeMap reference (and the
        # name) are restored.  The default dict pickle path would instead
        # call __setitem__ on a fresh instance whose _typeMap does not yet
        # exist.
        return (self.__class__, (self.name, self._typeMap))
