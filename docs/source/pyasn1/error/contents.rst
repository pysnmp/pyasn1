
.. _error.context:

Structured error context
------------------------

Every pyasn1 exception carries a constant message plus a mapping of the
values involved, reachable as ``exc.context``. Read the values off the
exception rather than parsing them back out of the message:

.. code-block:: pycon

   >>> from pyasn1 import error
   >>> from pyasn1.codec.ber import decoder
   >>> try:
   ...     decoder.decode(bytes((0x04, 0x08, 0x01, 0x02)))
   ... except error.SubstrateUnderrunError as exc:
   ...     print(exc.context['shortBy'], 'octets missing')
   ...
   6 octets missing

The context renders into the message only when the exception is formatted,
so nothing is interpolated on a path where the error is caught and handled:

.. code-block:: pycon

   >>> str(exc)
   'Short substrate (shortBy=6, length=8, available=2)'

The mapping is a plain :class:`dict` and can be handed straight to the
``extra`` argument of a :mod:`logging` call, subject to the standard library's
rule that its keys must not collide with :class:`~logging.LogRecord`
attributes.

.. _error.PyAsn1Error:

.. |PyAsn1Error| replace:: PyAsn1Error

|PyAsn1Error|
-------------

.. autoclass:: pyasn1.error.PyAsn1Error
   :members:

.. _error.ValueConstraintError:

.. |ValueConstraintError| replace:: ValueConstraintError

|ValueConstraintError|
----------------------

.. autoclass:: pyasn1.error.ValueConstraintError
   :members:

.. _error.SubstrateUnderrunError:

.. |SubstrateUnderrunError| replace:: SubstrateUnderrunError

|SubstrateUnderrunError|
------------------------

.. autoclass:: pyasn1.error.SubstrateUnderrunError
   :members:

.. _error.PyAsn1UnicodeError:

.. |PyAsn1UnicodeError| replace:: PyAsn1UnicodeError

|PyAsn1UnicodeError|
--------------------

.. autoclass:: pyasn1.error.PyAsn1UnicodeError
   :members:

.. _error.PyAsn1UnicodeDecodeError:

.. |PyAsn1UnicodeDecodeError| replace:: PyAsn1UnicodeDecodeError

|PyAsn1UnicodeDecodeError|
--------------------------

.. autoclass:: pyasn1.error.PyAsn1UnicodeDecodeError
   :members:

.. _error.PyAsn1UnicodeEncodeError:

.. |PyAsn1UnicodeEncodeError| replace:: PyAsn1UnicodeEncodeError

|PyAsn1UnicodeEncodeError|
--------------------------

.. autoclass:: pyasn1.error.PyAsn1UnicodeEncodeError
   :members:
