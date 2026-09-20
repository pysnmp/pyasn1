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

Disabled tracing costs **one** :meth:`~logging.Logger.isEnabledFor` call per
*operation* -- per :func:`~pyasn1.codec.ber.decoder.decode` or
:func:`~pyasn1.codec.ber.encoder.encode` call, not per ASN.1 component. Both
BER codecs read the level once on entry, into a module-level flag that the
trace points then test.

That distinction is the whole reason the flag exists. The guards used to
evaluate ``isEnabledFor`` at each site, which is sound advice applied at a
granularity a codec cannot afford: decoding a ten-binding SNMPv2c response
asked the question 551 times and encoding one asked it 337 times, getting the
same answer every time, for several per cent of the operation -- paid by every
installation, for output nobody had enabled.

The flag is re-read per operation rather than settled at import, so the
``setLevel()`` calls above keep working: a level change is picked up by the
next decode or encode, with no pyasn1-specific API to call.

The guards themselves stay, and earn their keep: they are what stops the
``extra`` dicts and the substrate hexdumps from being built when nothing will
print them. Only the placement of the *check* changed.

Enabling ``DEBUG`` on a hot codec path is still not something to run with.
:class:`logging.LogRecord` construction calls ``findCaller()``, which walks
the stack for every record, and a codec emitting hundreds of records per
message is not usable at that rate. The capability is for diagnosis, not for
production.

.. note::

   The rule these placements follow is written down once, for pyasn1, pysmi
   and pysnmp together, as pysnmp's `logging and tracing contract
   <https://docs.lextudio.com/pysnmp/docs/observability-contract>`_: *what an
   observability mechanism costs must be proportional to the granularity of
   the thing it observes.* It also covers why nothing below the PDU boundary
   may reach a production telemetry pipeline, and how to measure a change of
   this kind. Read it before adding a trace point to a hot path.

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

Both are still part of the public API while they remain deprecated, so they
are documented here rather than only referred to.

.. autoclass:: pyasn1.debug.Debug
   :members:

.. autofunction:: pyasn1.debug.setLogger

.. autoclass:: pyasn1.debug.Printer
   :members:

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
