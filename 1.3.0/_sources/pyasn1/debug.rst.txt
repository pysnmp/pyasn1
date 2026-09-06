.. _pyasn1-debugging:

Debugging and logging
=====================

pyasn1 is a library, so it never configures logging on behalf of the
application that imports it. Importing pyasn1 attaches a
:class:`logging.NullHandler` to the ``pyasn1`` logger and does nothing
else -- no handler that writes anywhere, no level change, on the
``pyasn1`` logger or on any other. Debug output only appears once you
ask for it.

Turning debugging on
--------------------

pyasn1 logs through :mod:`logging` under the ``pyasn1`` namespace. There
is no pyasn1 API to call: raise the level the way you would for any
other library.

.. code-block:: python

   import logging

   logging.basicConfig(level=logging.INFO)
   logging.getLogger('pyasn1').setLevel(logging.DEBUG)

Everything pyasn1 traces is emitted at ``DEBUG``. Records propagate to
your handlers, so levels, filters and formatters you already configure
apply to them unchanged.

Turn it back off by putting the level back:

.. code-block:: python

   logging.getLogger('pyasn1').setLevel(logging.NOTSET)

Selecting what is traced
------------------------

Each codec module owns a logger named after it, so tracing is selected
by logger name:

=================================  ==================================
Logger                             Traces
=================================  ==================================
``pyasn1.codec.ber.decoder``       BER/CER/DER de-serialisation
``pyasn1.codec.ber.encoder``       BER/CER/DER serialisation
``pyasn1.codec.native.decoder``    conversion from native objects
``pyasn1.codec.native.encoder``    conversion to native objects
``pyasn1``                         all of the above
=================================  ==================================

To trace only BER decoding, and nothing else:

.. code-block:: python

   logging.getLogger('pyasn1.codec.ber.decoder').setLevel(logging.DEBUG)

To trace everything except the encoders, enable the namespace and pin
the encoders above ``DEBUG``:

.. code-block:: python

   logging.getLogger('pyasn1').setLevel(logging.DEBUG)
   logging.getLogger('pyasn1.codec.ber.encoder').setLevel(logging.INFO)
   logging.getLogger('pyasn1.codec.native.encoder').setLevel(logging.INFO)

Records carry their format arguments
------------------------------------

Trace points pass arguments to :mod:`logging` rather than pre-rendering
them, so ``record.msg`` stays the format string and ``record.args``
holds the values:

.. code-block:: python

   LOG.debug('tag decoded into %s, decoding length', tagSet)

A structured handler can therefore group records by call site, and emit
the arguments as fields, without parsing the rendered message.

Cost when disabled
------------------

Every trace point is guarded with
:meth:`~logging.Logger.isEnabledFor`, so disabled tracing costs one
level check per call site and neither formats a message nor builds its
arguments. Leaving the guards in place in production is fine; enabling
``DEBUG`` on a hot decoding path is not, as the records embed hexdumps
of the substrate.

.. _pyasn1-debug-deprecated:

Deprecated: the Debug switch
----------------------------

:class:`~pyasn1.debug.Debug`, :func:`~pyasn1.debug.setLogger` and
``registerLoggee`` predate the move to per-module loggers and are
deprecated. They still work, and using them raises a
:exc:`DeprecationWarning`.

.. code-block:: python

   from pyasn1 import debug

   debug.setLogger(debug.Debug('all'))   # deprecated
   debug.setLogger(None)

The ``encoder``, ``decoder``, ``all`` and ``none`` flags map onto the
loggers in the table above, and ``!``/``~`` still subtracts a category.
While a :class:`~pyasn1.debug.Debug` instance is installed,
:func:`~pyasn1.debug.setLogger` drives the levels of the
``pyasn1.codec.*`` loggers itself, overriding any level your
application set on them; ``setLogger(None)`` puts them back.

Prefer plain :mod:`logging` configuration: it needs no pyasn1 import,
survives this deprecation, and addresses individual codec modules, which
the flags cannot.

Errors
------

Debugging tells you what a codec did; exceptions tell you why it
stopped. Every failure raised by pyasn1 derives from
:class:`~pyasn1.error.PyAsn1Error`, including failures provoked by
malformed or hostile input, so a single ``except`` clause is enough to
contain decoding:

.. code-block:: python

   from pyasn1 import error

   try:
       asn1Object, rest = decode(substrate, asn1Spec=Certificate())

   except error.PyAsn1Error as exc:
       log.warning('cannot decode certificate: %s', exc)

See :ref:`the exception reference <pyasn1-errors>` for the hierarchy.
