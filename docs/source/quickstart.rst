Quick start
============

.. _quickstart:

This page gives a concise introduction to pyasn1 for new users.  It covers
the three core concepts — **types**, **codecs**, and **native conversion** —
with copy-pasteable snippets.

Define an ASN.1 schema
----------------------

ASN.1 types are expressed as Python classes that subclass the appropriate
base type from :mod:`pyasn1.type.univ`:

.. code-block:: python

    from pyasn1.type import char, namedtype, univ

    class User(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('name', char.UTF8String()),
            namedtype.OptionalNamedType('email', char.UTF8String()),
        )

Instantiate and populate
------------------------

Constructed types (``Sequence``, ``Set``, ``SequenceOf``, ``SetOf``) behave
like Python containers:

.. code-block:: python

    user = User()
    user['id'] = 42
    user['name'] = 'Alice'
    user['email'] = 'alice@example.com'

    # Check whether a component holds a value
    assert user['id'].isValue

    # Access values directly
    assert user['id'] == 42

Encode to DER
-------------

.. code-block:: python

    from pyasn1.codec.der.encoder import encode as der_encode

    der_bytes = der_encode(user)
    # der_bytes is a bytes object ready for storage / transmission

Decode from DER
---------------

.. code-block:: python

    from pyasn1.codec.der.decoder import decode as der_decode

    recovered, rest = der_decode(der_bytes, asn1Spec=User())
    assert rest == b''
    assert recovered['name'] == 'Alice'

Convert to / from native Python types
-------------------------------------

The :mod:`pyasn1.codec.native` codec maps ASN.1 objects to plain Python
dicts, lists, ints, strings, etc.:

.. code-block:: python

    from pyasn1.codec.native.encoder import encode as native_encode
    from pyasn1.codec.native.decoder import decode as native_decode

    # ASN.1 -> Python dict
    py_user = native_encode(user)
    # {'id': 42, 'name': 'Alice', 'email': 'alice@example.com'}

    # Python dict -> ASN.1
    user2 = native_decode(py_user, asn1Spec=User())
    assert user2['id'] == 42

Inspecting objects with repr()
------------------------------

The ``repr()`` of pyasn1 objects is designed to be concise and readable.
Schema objects show only the class name; value objects show the payload:

.. code-block:: pycon

    >>> from pyasn1.type import char, namedtype, univ
    >>> class User(univ.Sequence):
    ...     componentType = namedtype.NamedTypes(
    ...         namedtype.NamedType('id', univ.Integer()),
    ...         namedtype.NamedType('name', char.UTF8String()),
    ...     )
    >>> schema = User()
    >>> repr(schema)
    '<User schema object>'
    >>> user = User()
    >>> user['id'] = 42
    >>> user['name'] = 'Alice'
    >>> repr(user)
    '<User value object, payload [id=Integer value object, payload [42], name=UTF8String value object, payload [Alice]]>'

Tags also use human-readable class names:

.. code-block:: pycon

    >>> from pyasn1.type import tag
    >>> repr(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 2))
    '<Tag object, tag [UNIVERSAL:simple:2]>'

Using constraints
-----------------

Constraints restrict the set of valid values for a type:

.. code-block:: python

    from pyasn1.type import univ, constraint

    class SmallInt(univ.Integer):
        subtypeSpec = constraint.ValueRangeConstraint(1, 100)

    # Valid
    SmallInt(50)

    # Raises ValueConstraintError
    # SmallInt(200)

Open types (ANY DEFINED BY)
----------------------------

Open types model the ``ANY DEFINED BY`` construct:

.. code-block:: python

    from pyasn1.type import univ, namedtype, opentype

    class Choice(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(),
                                openType=opentype.OpenType(
                                    'id', {1: univ.Integer(),
                                           2: univ.OctetString()}))
        )