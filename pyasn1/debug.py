#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Debug logging for pyasn1.

pyasn1 logs through :mod:`logging` under the ``pyasn1`` namespace, one logger
per codec module::

    pyasn1.codec.ber.decoder
    pyasn1.codec.ber.encoder
    pyasn1.codec.native.decoder
    pyasn1.codec.native.encoder

Applications turn debugging on the ordinary way, and no pyasn1 API is
involved::

    logging.getLogger("pyasn1.codec.ber.decoder").setLevel(logging.DEBUG)

The :class:`Debug` / :func:`setLogger` / :func:`registerLoggee` trio predates
that and is deprecated. It is kept working for downstream code, but it drives
logger levels behind your back and cannot express anything the standard
configuration cannot.
"""

import logging
import sys
import threading
import warnings
from collections.abc import Callable
from typing import Any, Final

from pyasn1 import __version__, error

__all__ = ["ContextFormatter", "Debug", "hexdump", "setLogger"]

DEBUG_NONE: Final = 0x0000
DEBUG_ENCODER: Final = 0x0001
DEBUG_DECODER: Final = 0x0002
DEBUG_ALL: Final = 0xFFFF

FLAG_MAP: Final[dict[str, int]] = {
    "none": DEBUG_NONE,
    "encoder": DEBUG_ENCODER,
    "decoder": DEBUG_DECODER,
    "all": DEBUG_ALL,
}

#: Root of the library's logger namespace.
LOGGER_NAME: Final = "pyasn1"

#: Which loggers each legacy debug flag stands for. The flags exist only
#: because the modules could not be addressed by name before; they can now.
FLAG_LOGGER_MAP: Final[dict[int, tuple[str, ...]]] = {
    DEBUG_ENCODER: ("pyasn1.codec.ber.encoder", "pyasn1.codec.native.encoder"),
    DEBUG_DECODER: ("pyasn1.codec.ber.decoder", "pyasn1.codec.native.decoder"),
}

LOGGEE_MAP: Final[dict[Any, tuple[str, int]]] = {}


#: Attributes :class:`logging.LogRecord` defines itself, plus the two that
#: :meth:`logging.Formatter.format` adds while rendering. Everything outside
#: this set on a record came from an ``extra`` mapping.
_RECORD_ATTRS: Final[frozenset[str]] = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None))
) | {"message", "asctime"}


class ContextFormatter(logging.Formatter):
    """Render a record's ``extra`` fields after its message.

    pyasn1 logs invariant messages and puts every varying value in ``extra``,
    so a formatter that renders ``%(message)s`` alone would drop the whole
    payload. Structured handlers read the fields off the record directly and
    do not need this; it is here so that plain text output stays as
    informative as the old interpolated messages were.

    ``bytes`` fields are rendered as space-separated hex rather than through
    :func:`hexdump`, whose row breaks would split one record across several
    lines and defeat any line-oriented log reader.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Read the fields before formatting: the base class writes `message`
        # and `asctime` onto the record, which would otherwise show up here.
        context = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RECORD_ATTRS
        }

        text = super().format(record)

        if not context:
            return text

        return "%s %s" % (
            text,
            " ".join(
                "%s=%s" % (key, value.hex(" ") if isinstance(value, bytes) else value)
                for key, value in sorted(context.items())
            ),
        )


class Printer:
    """Emit pyasn1 debug records through :mod:`logging`.

    Only the library's own ``pyasn1`` logger is configured here: it gets a
    level and a handler. A logger supplied by the caller is left exactly as
    found -- no level change, and no handler unless the caller passed one --
    because that logger belongs to the application, not to pyasn1.
    """

    # noinspection PyShadowingNames
    def __init__(
        self,
        logger: logging.Logger | None = None,
        handler: logging.Handler | None = None,
        formatter: logging.Formatter | None = None,
    ) -> None:
        if logger is None:
            logger = logging.getLogger(LOGGER_NAME)
            logger.setLevel(logging.DEBUG)

            if handler is None:
                handler = logging.StreamHandler()

        if handler is not None:
            if formatter is None:
                formatter = ContextFormatter("%(asctime)s %(name)s: %(message)s")

            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)
            logger.addHandler(handler)

        self.__logger = logger

    @property
    def logger(self) -> logging.Logger:
        """The logger this printer writes to."""
        return self.__logger

    def __call__(self, msg: str) -> None:
        self.__logger.debug(msg)

    def __str__(self) -> str:
        return "<python logging>"


NullHandler: Final = logging.NullHandler

_defaultPrinterLock: Final = threading.Lock()


class Debug:
    """Deprecated switch for pyasn1 debug output.

    Configure :mod:`logging` instead; see the module docstring.
    """

    #: Printer shared by all :class:`Debug` instances that were not given one.
    #: Built on first use, never at import time, so that merely importing
    #: pyasn1 never attaches a handler to anybody's logger.
    defaultPrinter: "Printer | None" = None

    _printer: Callable[[str], None]

    def __init__(self, *flags: str, **options: Any) -> None:
        warnings.warn(
            "pyasn1.debug.Debug is deprecated; enable debugging with "
            "logging.getLogger('pyasn1').setLevel(logging.DEBUG) instead",
            DeprecationWarning,
            stacklevel=2,
        )

        self._flags = DEBUG_NONE

        if "loggerName" in options:
            # Route our records to the caller's logger and let them propagate.
            # No handler is attached: the logger is the application's, and
            # every construction would otherwise add another one to it.
            self._printer = Printer(logger=logging.getLogger(options["loggerName"]))

        elif "printer" in options:
            self._printer = options["printer"]

        else:
            # Building a Printer attaches a handler, so two threads racing
            # through first use would attach two and double every record.
            with _defaultPrinterLock:
                if Debug.defaultPrinter is None:
                    Debug.defaultPrinter = Printer()

            self._printer = Debug.defaultPrinter

        self._printer(
            "running pyasn1 %s, debug flags %s" % (__version__, ", ".join(flags))
        )

        for flag in flags:
            inverse = flag and flag[0] in ("!", "~")
            if inverse:
                flag = flag[1:]
            try:
                if inverse:
                    self._flags &= ~FLAG_MAP[flag]
                else:
                    self._flags |= FLAG_MAP[flag]
            except KeyError as exc:
                raise error.PyAsn1Error("bad debug flag %s" % flag) from exc

            self._printer(
                "debug category '%s' %s" % (flag, "disabled" if inverse else "enabled")
            )

    @property
    def printer(self) -> Callable[[str], None]:
        """Where this instance sends rendered debug messages."""
        return self._printer

    def __str__(self) -> str:
        return "logger %s, flags %x" % (self._printer, self._flags)

    def __call__(self, msg: str) -> None:
        self._printer(msg)

    def __and__(self, flag: int) -> int:
        return self._flags & flag

    def __rand__(self, flag: int) -> int:
        return flag & self._flags


class _PrinterHandler(logging.Handler):
    """Feed records from the ``pyasn1`` loggers to a legacy printer.

    A legacy printer takes one rendered string, so the record's ``extra``
    fields are rendered into it here. Handing it ``record.getMessage()``
    instead would give it the invariant message alone and drop every value
    the record carries.

    Re-entry is blocked per thread: a :class:`Printer` writes by calling
    ``logger.debug()``, so without the guard a printer aimed back at a logger
    that reaches this handler would recurse until the stack ran out.
    """

    def __init__(self, printer: Callable[[str], None]) -> None:
        super().__init__(logging.DEBUG)
        self._printer = printer
        self._busy = threading.local()
        self.setFormatter(ContextFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._busy, "active", False):
            return

        self._busy.active = True

        try:
            self._printer(self.format(record))
        except Exception:  # noqa: BLE001 - logging.Handler contract: a broken printer must never escape into the code that logged
            self.handleError(record)
        finally:
            self._busy.active = False


def _reaches_pyasn1_logger(printer: Callable[[str], None]) -> bool:
    """Would records written by ``printer`` come back to the pyasn1 loggers?

    True when the printer targets ``pyasn1`` itself or one of its ancestors,
    in which case pyasn1's own records already arrive there by propagation and
    bridging would only duplicate them.
    """
    if not isinstance(printer, Printer):
        return False

    name = printer.logger.name

    return (
        name == LOGGER_NAME
        or name in ("root", logging.root.name)
        or printer.logger is logging.root
        or LOGGER_NAME.startswith(name + ".")
    )


_LOG: "Debug | int" = DEBUG_NONE

_setLoggerLock: Final = threading.Lock()

#: Levels replaced by the last :func:`setLogger` call, so they can be restored.
_savedLevels: dict[str, int] = {}

_bridgeHandler: "_PrinterHandler | None" = None


def _restoreLoggers() -> None:
    """Undo whatever the previous :func:`setLogger` call changed."""
    global _bridgeHandler

    if _bridgeHandler is not None:
        logging.getLogger(LOGGER_NAME).removeHandler(_bridgeHandler)
        _bridgeHandler = None

    while _savedLevels:
        name, level = _savedLevels.popitem()
        logging.getLogger(name).setLevel(level)


def setLogger(userLogger: "Debug | int | None") -> None:
    """Deprecated. Turn pyasn1 debugging on or off.

    Passing a :class:`Debug` instance raises the level of the loggers its
    flags name and, when needed, routes their records to the instance's
    printer. Passing a false value puts every level back as it was.

    This overrides application-set levels on the ``pyasn1.codec.*`` loggers
    for as long as it is in effect. Configure :mod:`logging` directly to
    avoid that.
    """
    warnings.warn(
        "pyasn1.debug.setLogger is deprecated; enable debugging with "
        "logging.getLogger('pyasn1').setLevel(logging.DEBUG) instead",
        DeprecationWarning,
        stacklevel=2,
    )

    _setLogger(userLogger)


def _setLogger(userLogger: "Debug | int | None") -> None:
    """:func:`setLogger` without the deprecation warning, for internal use."""
    global _LOG, _bridgeHandler

    with _setLoggerLock:
        _restoreLoggers()

        _LOG = userLogger if userLogger else DEBUG_NONE

        if isinstance(_LOG, Debug):
            for flag, names in FLAG_LOGGER_MAP.items():
                # Disabled categories are pinned above DEBUG rather than left
                # alone: they would otherwise inherit an enabling level from
                # an ancestor and leak the very output the flags exclude.
                level = logging.DEBUG if _LOG & flag else logging.INFO

                for name in names:
                    logger = logging.getLogger(name)
                    _savedLevels[name] = logger.level
                    logger.setLevel(level)

            if not _reaches_pyasn1_logger(_LOG.printer):
                _bridgeHandler = _PrinterHandler(_LOG.printer)
                pyasn1Logger = logging.getLogger(LOGGER_NAME)
                _savedLevels[LOGGER_NAME] = pyasn1Logger.level
                pyasn1Logger.setLevel(logging.DEBUG)
                pyasn1Logger.addHandler(_bridgeHandler)

        # Update legacy logging clients registered by out-of-tree modules.
        for module, (name, flags) in LOGGEE_MAP.items():
            setattr(module, name, _LOG if _LOG & flags else DEBUG_NONE)


def registerLoggee(module: str, name: str = "LOG", flags: int = DEBUG_NONE) -> Any:
    """Deprecated. Bind a module-global debug switch updated by :func:`setLogger`.

    pyasn1's own modules no longer use this; they hold ordinary
    :class:`logging.Logger` objects. It remains for out-of-tree code.
    """
    warnings.warn(
        "pyasn1.debug.registerLoggee is deprecated; use "
        "logging.getLogger(__name__) and guard with Logger.isEnabledFor()",
        DeprecationWarning,
        stacklevel=2,
    )

    LOGGEE_MAP[sys.modules[module]] = name, flags
    _setLogger(_LOG)
    return _LOG


def hexdump(octets: bytes) -> str:
    return " ".join(
        [
            "%s%.2X" % ("\n%.5d: " % n if n % 16 == 0 else "", x)
            for n, x in zip(range(len(octets)), octets)
        ]
    )


class Scope:
    def __init__(self) -> None:
        self._list: list[str] = []

    def __str__(self) -> str:
        return ".".join(self._list)

    def push(self, token: str) -> None:
        self._list.append(token)

    def pop(self) -> str:
        return self._list.pop()


scope: Final = Scope()
