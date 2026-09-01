
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

Route pyasn1's debug records into logging you already configure:

.. code-block:: python

   import logging
   from pyasn1 import debug

   logging.basicConfig(level=logging.DEBUG)

   debug.setLogger(debug.Debug('all', loggerName='myapp.asn1'))

``loggerName`` names the logger records are emitted on, so ordinary
:mod:`logging` configuration -- levels, handlers, filters, formatters --
applies to them. pyasn1 does not touch a logger you name -- it adds no
handler and changes no level or propagation setting; that logger is
yours. Records simply propagate to whatever you have configured.

To get output on stderr without configuring anything, omit
``loggerName``. pyasn1 then owns the ``pyasn1`` logger and attaches a
:class:`logging.StreamHandler` to it:

.. code-block:: python

   debug.setLogger(debug.Debug('all'))

Turn it back off with:

.. code-block:: python

   debug.setLogger(None)

Selecting what is traced
------------------------

:class:`~pyasn1.debug.Debug` accepts one or more category flags:

============  ==================================================
Flag          Traces
============  ==================================================
``encoder``   serialisation
``decoder``   de-serialisation
``all``       everything
``none``      nothing
============  ==================================================

Prefixing a flag with ``!`` or ``~`` subtracts it, so tracing everything
except the encoder is:

.. code-block:: python

   debug.setLogger(debug.Debug('all', '!encoder'))

An unrecognised flag raises :class:`~pyasn1.error.PyAsn1Error`.

Cost when disabled
------------------

Debug tracing is off by default and every trace point is guarded, so
disabled tracing costs one truthiness test per call site and never
formats a message. Leaving the guards in place in production is fine;
enabling ``all`` on a hot decoding path is not, as the records embed
hexdumps of the substrate.

Custom sinks
------------

To send records somewhere other than :mod:`logging`, pass any callable
taking a single string:

.. code-block:: python

   debug.setLogger(debug.Debug('all', printer=my_sink))

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
