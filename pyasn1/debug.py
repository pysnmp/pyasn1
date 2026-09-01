#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import logging
import sys
import threading
from collections.abc import Callable
from typing import Any, Final

from pyasn1 import __version__, error

__all__ = ["Debug", "hexdump", "setLogger"]

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

LOGGEE_MAP: Final[dict[Any, tuple[str, int]]] = {}


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
            logger = logging.getLogger("pyasn1")
            logger.setLevel(logging.DEBUG)

            if handler is None:
                handler = logging.StreamHandler()

        if handler is not None:
            if formatter is None:
                formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s")

            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)
            logger.addHandler(handler)

        self.__logger = logger

    def __call__(self, msg: str) -> None:
        self.__logger.debug(msg)

    def __str__(self) -> str:
        return "<python logging>"


NullHandler: Final = logging.NullHandler

_defaultPrinterLock: Final = threading.Lock()


class Debug:
    #: Printer shared by all :class:`Debug` instances that were not given one.
    #: Built on first use, never at import time, so that merely importing
    #: pyasn1 never attaches a handler to anybody's logger.
    defaultPrinter: "Printer | None" = None

    _printer: Callable[[str], None]

    def __init__(self, *flags: str, **options: Any) -> None:
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

    def __str__(self) -> str:
        return "logger %s, flags %x" % (self._printer, self._flags)

    def __call__(self, msg: str) -> None:
        self._printer(msg)

    def __and__(self, flag: int) -> int:
        return self._flags & flag

    def __rand__(self, flag: int) -> int:
        return flag & self._flags


_LOG: "Debug | int" = DEBUG_NONE


def setLogger(userLogger: "Debug | int | None") -> None:
    global _LOG

    if userLogger:
        _LOG = userLogger
    else:
        _LOG = DEBUG_NONE

    # Update registered logging clients
    for module, (name, flags) in LOGGEE_MAP.items():
        setattr(module, name, _LOG if _LOG & flags else DEBUG_NONE)


def registerLoggee(module: str, name: str = "LOG", flags: int = DEBUG_NONE) -> Any:
    LOGGEE_MAP[sys.modules[module]] = name, flags
    setLogger(_LOG)
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
