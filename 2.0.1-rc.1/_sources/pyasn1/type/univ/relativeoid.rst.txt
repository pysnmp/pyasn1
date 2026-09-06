.. _univ.RelativeOID:

.. |ASN.1| replace:: RelativeOID

|ASN.1| type
------------

.. autoclass:: pyasn1.type.univ.RelativeOID(value=NoValue(), tagSet=TagSet(), subtypeSpec=ConstraintsIntersection())
   :members: isValue, isSameTypeWith, isSuperTypeOf, tagSet, effectiveTagSet, tagMap, subtypeSpec, isPrefixOf

   .. note::

        The |ASN.1| type models ASN.1 RELATIVE-OID as a sequence of integer
        numbers. Unlike :ref:`ObjectIdentifier <univ.ObjectIdentifier>`, the
        arcs are relative to an object identifier supplied by the context, so
        there are no distinguished first two arcs and no restriction on the
        value of the leading one.

   .. automethod:: pyasn1.type.univ.RelativeOID.clone(value=NoValue(), tagSet=TagSet(), subtypeSpec=ConstraintsIntersection())
   .. automethod:: pyasn1.type.univ.RelativeOID.subtype(value=NoValue(), implicitTag=Tag(), explicitTag=Tag(), subtypeSpec=ConstraintsIntersection())
