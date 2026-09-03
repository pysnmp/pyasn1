#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Exception classes raised throughout pyasn1.

Every pyasn1 exception carries an optional mapping of structured context
alongside its message. Raising sites pass a constant message plus keyword
arguments naming the values involved::

    raise error.PyAsn1Error("Short substrate for sub-OID", oid=oid)

The values are kept on the exception as :attr:`PyAsn1Error.context` for
programmatic inspection, and are rendered into the human-readable message
only when the exception is formatted::

    >>> str(exc)
    "Short substrate for sub-OID (oid='1.3.6')"

This mirrors the convention the package follows for logging, where the log
message is a constant and varying data travels in the ``extra`` mapping, and
it spares callers from parsing values back out of prose.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PyAsn1Error",
    "PyAsn1UnicodeDecodeError",
    "PyAsn1UnicodeEncodeError",
    "PyAsn1UnicodeError",
    "SubstrateUnderrunError",
    "ValueConstraintError",
]


def _renderContext(context: dict[str, Any]) -> str:
    """Render a context mapping as comma-separated ``key=value`` pairs.

    A value whose :func:`repr` raises is rendered as ``<unrepresentable
    ClassName>`` rather than propagating: formatting an exception must not
    itself fail, or the original error is lost.
    """
    parts = []

    for key, value in context.items():
        try:
            rendering = repr(value)

        except Exception:  # noqa: BLE001
            rendering = f"<unrepresentable {value.__class__.__name__}>"

        parts.append(f"{key}={rendering}")

    return ", ".join(parts)


class PyAsn1Error(Exception):
    """Base pyasn1 exception.

    `PyAsn1Error` is the base exception class (based on
    :class:`Exception`) that represents all possible ASN.1 related
    errors.

    Parameters
    ----------
    *args:
        Exception arguments, conventionally a single constant message.

    **context:
        Structured data describing the failure. Kept as :attr:`context` and
        appended to the formatted message on demand.

    Examples
    --------
    >>> exc = PyAsn1Error("Excessive components decoded", componentCount=4)
    >>> exc.context["componentCount"]
    4
    >>> str(exc)
    'Excessive components decoded (componentCount=4)'
    """

    def __init__(self, *args: Any, **context: Any) -> None:
        # Bound to Exception rather than super(): the Unicode subclasses below
        # mix in UnicodeEncodeError/UnicodeDecodeError, which sit after this
        # class in their MRO and demand five arguments.
        Exception.__init__(self, *args)
        self.context: dict[str, Any] = context

    def __str__(self) -> str:
        """Render the message, suffixing ``key=value`` context when present."""
        message = Exception.__str__(self)

        if not self.context:
            return message

        details = _renderContext(self.context)

        return f"{message} ({details})" if message else details

    def __repr__(self) -> str:
        """Render class name, exception arguments and context keywords."""
        arguments = [repr(arg) for arg in self.args]
        arguments += [f"{key}={value!r}" for key, value in self.context.items()]

        return f"{self.__class__.__name__}({', '.join(arguments)})"


class ValueConstraintError(PyAsn1Error):
    """ASN.1 type constraints violation exception.

    The `ValueConstraintError` exception indicates an ASN.1 value
    constraint violation.

    It might happen on value object instantiation (for scalar types) or on
    serialization (for constructed types).
    """


class SubstrateUnderrunError(PyAsn1Error):
    """ASN.1 data structure deserialization error.

    The `SubstrateUnderrunError` exception indicates insufficient serialised
    data on input of a de-serialization codec.
    """


class PyAsn1UnicodeError(PyAsn1Error, UnicodeError):
    """Unicode text processing error.

    The `PyAsn1UnicodeError` exception is a base class for errors relating to
    unicode text de/serialization.

    Apart from inheriting from :class:`PyAsn1Error`, it also inherits from
    :class:`UnicodeError` to help the caller catching unicode-related errors.
    """

    def __init__(
        self,
        message: str,
        unicode_error: Exception | None = None,
        **context: Any,
    ) -> None:
        if isinstance(unicode_error, UnicodeError):
            UnicodeError.__init__(self, *unicode_error.args)
        PyAsn1Error.__init__(self, message, **context)


class PyAsn1UnicodeDecodeError(PyAsn1UnicodeError, UnicodeDecodeError):
    """Unicode text decoding error.

    The `PyAsn1UnicodeDecodeError` exception represents a failure to
    deserialize unicode text.

    Apart from inheriting from :class:`PyAsn1UnicodeError`, it also inherits
    from :class:`UnicodeDecodeError` to help the caller catching unicode-related
    errors.
    """


class PyAsn1UnicodeEncodeError(PyAsn1UnicodeError, UnicodeEncodeError):
    """Unicode text encoding error.

    The `PyAsn1UnicodeEncodeError` exception represents a failure to
    serialize unicode text.

    Apart from inheriting from :class:`PyAsn1UnicodeError`, it also inherits
    from :class:`UnicodeEncodeError` to help the caller catching
    unicode-related errors.
    """
