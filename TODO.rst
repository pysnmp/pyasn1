
Things to be done
=================

Big things to tackle, anyone interested is welcome to fork pyasn1, work on
it and come up with a PR!

Each item below has been validated against the current codebase as of
2026-09-01.  Items are grouped into phases ranked from **least breaking**
to **most breaking** so that earlier phases can land independently without
disrupting downstream consumers.


Completed (removed from backlog)
--------------------------------

* **Use Python standard library types where possible** — DONE (unreleased
  CHANGES.rst).  ``Tag`` is now a ``namedtuple`` subclass, ``NamedType`` is a
  ``namedtuple`` subclass, ``OpenType`` is a ``dict`` subclass, ``NamedValues``
  is a ``dict`` subclass with reverse index.  No further action needed.


Phase 1 — Non-breaking cleanup & documentation (DONE)
----------------------------------------------------

Lowest risk.  No API changes, no behavioural shifts.  Safe to ship
independently.

* **PEP 8 cleanup** — DONE.  Fixed E402 import-order violations in test
  files, applied ``black`` formatting to ``ber/encoder.py`` and
  ``test_univ.py``.  All of ``pyasn1/`` and ``tests/`` now pass
  ``flake8``, ``ruff``, and ``black --check``.
* **Simplify ``repr()``** — DONE.  ``Tag`` and ``TagSet`` now use
  human-readable class names (``UNIVERSAL``, ``CONTEXT``, etc.) instead of
  raw hex.  ``SimpleAsn1Type`` and ``ConstructedAsn1Type`` repr no longer
  dump verbose ``tagSet`` / ``subtypeSpec`` / ``componentType`` at every
  level; value objects show only ``payload [...]`` with field names for
  constructed types; schema objects show only the class name.
* **Documentation** — DONE.  Added ``docs/source/quickstart.rst`` with
  copy-pasteable snippets covering schema definition, encode/decode,
  native conversion, repr inspection, constraints, and open types.
  Linked from the main ``contents.rst`` toctree.
* **Examples** — DONE.  Added ``examples/`` directory with five runnable
  scripts: ``simple_sequence.py``, ``open_type.py``, ``constraints.py``,
  ``recursive_sequence.py``, ``round_trip.py``.


Phase 2 — Low-risk type-system improvements
-------------------------------------------

Internal enhancements to ``pyasn1.type`` that are additive and unlikely to
break existing callers.  New constraints / pretty-printing are opt-in.

* **``type.useful``: implement ``prettyIn``/``prettyOut``** —
  ``GeneralizedTime`` / ``UTCTime`` / ``ObjectDescriptor`` currently rely on
  inherited ``OctetString`` / ``GraphicString`` pretty-printing.  Custom
  pretty-printing would improve debugging output.
* **``type.char``: implement constraints** — character string types
  (``PrintableString``, ``NumericString``, ``IA5String``, etc.) accept
  ``subtypeSpec`` but do not enforce per-alphabet constraints by default.
  Adding ``PermittedAlphabetConstraint`` instances would close this gap.
* **Specialise ASN.1 character and useful types** — individual character
  string classes are thin subclasses of ``AbstractCharacterString``; useful
  types are thin subclasses of char types.  Specialising them (distinct
  validation, encoding hooks) improves correctness.
* **``type.namedtypes``: type vs tagset name convention** — clarify naming
  convention for components identified by type vs by tagset; current code
  mixes both in ``NamedTypes`` lookup methods.
* **Untagged ``TagSet`` initialisation** — ``TagSet()`` defaults to
  ``baseTag=()``; document and possibly enforce a sentinel so untagged types
  are distinguishable from "not yet tagged".


Phase 3 — Codec improvements (moderate risk)
-------------------------------------------

Changes to ``codec/ber`` encoder/decoder.  May affect encoding/decoding
edge-cases; require test coverage but should not change the public API.

* **``ber.encoder``: large length encoder** — ``encodeLength`` raises
  ``PyAsn1Error`` when length octets exceed 126.  Implement multi-byte
  length encoding for very large payloads (> 126 length octets).
* **``ber.encoder``: lookup type by tag first for custom codecs** — the
  encoder currently resolves by ``typeId`` first, then falls back to
  ``baseTagSet``.  Full ``tagSet`` lookup is needed so custom codecs for
  non-base (tagged) types can be registered.
* **``ber.encoder``: ``clone()`` / shallow-copy issue** — ``clone()`` on
  constructed types does not deep-copy component values by default
  (``cloneValueFlag`` is ``False``).  Review whether encoder's internal
  ``clone()`` calls should preserve values.
* **``ber.decoder``: suspend codec on underrun error** —
  ``SubstrateUnderrunError`` is raised but not recoverable.  Consider
  suspending and resuming when more substrate arrives (streaming decode).
* **``ber.decoder``: present subtypes** — ensure all subtypes are presented
  / materialised during decode rather than left as schema objects.
* **``ber.decoder``: component presence check at inner type constraint** —
  ``WITH COMPONENTS`` constraint presence checking does not work for
  inner-type constraints.
* **``ber.decoder``: type vs value, ``defaultValue``** — clarify handling
  of default values during decode (when to inject ``defaultValue`` vs
  leave component absent).
* **Real type and codecs refactoring** — ``Real`` encoder/decoder are
  complex (binary / character / NR1/NR2 encoding, base 2/8/16 selection).
  Refactor for clarity, add round-trip tests for edge cases (NaN, infinity,
  subnormal, very large exponents).


Phase 4 — New codecs (high effort, additive)
--------------------------------------------

New codec packages under ``pyasn1/codec/``.  Additive — does not change
existing codecs — but each is a substantial implementation effort.

* **JSON codec** — aligned with existing experimental schemas; lowest
  barrier since no binary substrate handling needed.
* **XER codec** — XML Encoding Rules (X.693).  Well-specified, text-based.
* **OER codec** — Octet Encoding Rules (X.696).  Binary, compact.
* **PER codec** — Packed Encoding Rules (X.691).  Most complex binary codec;
  aligned and unaligned variants.
* **LWER codec** — Lightweight Encoding Rules; niche, lowest priority.


Phase 5 — Architectural changes (most breaking)
-----------------------------------------------

Fundamental changes to the library architecture.  Highest risk of breaking
downstream consumers; should be designed carefully with migration paths.

* **Lazy codecs** — thin layer over base types to cache substrate pieces
  until ASN.1 object access.  Requires changes to type access patterns.
* **Codecs generator interface** — make codecs iterable / generators for
  indefinite-length or chunked encoding, producing/consuming
  substrate/objects incrementally.  Changes the ``encode``/``decode``
  function signatures.
* **Base types: X.680 constructs & information schema** — implement
  information object classes, object sets, table constraints per X.680.
  May require new type hierarchy elements.
* **ASN.1 schema compiler** — parse modern ``.asn`` schema files and emit
  code for arbitrary languages (including SQL).  Separate tool, but
  integration with pyasn1 types is needed.
* **More fresh modules** — compile and ship more Pythonised ASN.1 modules
  for various protocols (Kerberos, LDAP, SNMP v3, etc.).  Refresh outdated
  modules in ``pyasn1-packages``.  External repository but depends on
  pyasn1 type system stability.
