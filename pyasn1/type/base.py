#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
from typing import TYPE_CHECKING, Any, Final

from pyasn1 import error
from pyasn1.type import constraint, namedtype, tag, tagmap

__all__ = ["Asn1Item", "Asn1Type", "ConstructedAsn1Type", "SimpleAsn1Type"]


class Asn1Item:
    _typeCounter: int

    @classmethod
    def getTypeId(cls, increment: int = 1) -> int:
        try:
            Asn1Item._typeCounter += increment
        except AttributeError:
            Asn1Item._typeCounter = increment
        return Asn1Item._typeCounter


class Asn1Type(Asn1Item):
    """Base class for all classes representing ASN.1 types.

    In the user code, |ASN.1| class is normally used only for telling
    ASN.1 objects from others.

    Note
    ----
    For as long as ASN.1 is concerned, a way to compare ASN.1 types
    is to use :meth:`isSameTypeWith` and :meth:`isSuperTypeOf` methods.
    """

    #: Set or return a :py:class:`~pyasn1.type.tag.TagSet` object representing
    #: ASN.1 tag(s) associated with |ASN.1| type.
    tagSet = tag.TagSet()

    #: Default :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
    #: object imposing constraints on initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Disambiguation ASN.1 types identification
    typeId: Any = None

    def __init__(self, **kwargs: Any) -> None:
        readOnly = {"tagSet": self.tagSet, "subtypeSpec": self.subtypeSpec}

        readOnly.update(kwargs)

        self.__dict__.update(readOnly)

        self._readOnly = readOnly

    def __setattr__(self, name: str, value: Any) -> None:
        if name[0] != "_" and name in self._readOnly:
            raise error.PyAsn1Error('read-only instance attribute "%s"' % name)

        self.__dict__[name] = value

    def __str__(self) -> str:
        return self.prettyPrint()

    @property
    def readOnly(self) -> dict[str, Any]:
        return self._readOnly

    @property
    def effectiveTagSet(self) -> tag.TagSet:
        """For |ASN.1| type is equivalent to *tagSet*"""
        return self.tagSet  # used by untagged types

    @property
    def tagMap(self) -> tagmap.TagMap:
        """Return a :class:`~pyasn1.type.tagmap.TagMap` object mapping ASN.1 tags to ASN.1 objects within callee object."""
        return tagmap.TagMap({self.tagSet: self})

    def isSameTypeWith(
        self, other: Any, matchTags: bool = True, matchConstraints: bool = True
    ) -> bool:
        """Examine |ASN.1| type for equality with other ASN.1 type.

        ASN.1 tags (:py:mod:`~pyasn1.type.tag`) and constraints
        (:py:mod:`~pyasn1.type.constraint`) are examined when carrying
        out ASN.1 types comparison.

        Python class inheritance relationship is NOT considered.

        Parameters
        ----------
        other: a pyasn1 type object
            Class instance representing ASN.1 type.

        Returns
        -------
        : :class:`bool`
            :obj:`True` if *other* is |ASN.1| type,
            :obj:`False` otherwise.
        """
        return (
            self is other
            or (not matchTags or self.tagSet == other.tagSet)
            and (not matchConstraints or self.subtypeSpec == other.subtypeSpec)
        )

    def isSuperTypeOf(
        self, other: Any, matchTags: bool = True, matchConstraints: bool = True
    ) -> bool:
        """Examine |ASN.1| type for subtype relationship with other ASN.1 type.

        ASN.1 tags (:py:mod:`~pyasn1.type.tag`) and constraints
        (:py:mod:`~pyasn1.type.constraint`) are examined when carrying
        out ASN.1 types comparison.

        Python class inheritance relationship is NOT considered.

        Parameters
        ----------
            other: a pyasn1 type object
                Class instance representing ASN.1 type.

        Returns
        -------
            : :class:`bool`
                :obj:`True` if *other* is a subtype of |ASN.1| type,
                :obj:`False` otherwise.
        """
        return (
            not matchTags
            or (self.tagSet.isSuperTagSetOf(other.tagSet))
            and (
                not matchConstraints
                or self.subtypeSpec.isSuperTypeOf(other.subtypeSpec)
            )
        )

    @staticmethod
    def isNoValue(*values: Any) -> bool:
        for value in values:
            if value is not noValue:
                return False
        return True

    def prettyPrint(self, scope: int = 0) -> str:
        raise NotImplementedError()


class NoValue:
    """Create a singleton instance of NoValue class.

    The *NoValue* sentinel object represents an instance of ASN.1 schema
    object as opposed to ASN.1 value object.

    Only ASN.1 schema-related operations can be performed on ASN.1
    schema objects.

    Warning
    -------
    Any operation attempted on the *noValue* object will raise the
    *PyAsn1Error* exception.
    """

    #: Operations that only make sense on a value object. Python looks special
    #: methods up on the type rather than on the instance, so `__getattr__`
    #: below never sees them -- each one has to be planted on the class.
    plugMethods = (
        # comparison
        "__lt__",
        "__le__",
        "__eq__",
        "__ne__",
        "__gt__",
        "__ge__",
        # arithmetic
        "__add__",
        "__sub__",
        "__mul__",
        "__truediv__",
        "__floordiv__",
        "__mod__",
        "__divmod__",
        "__pow__",
        "__lshift__",
        "__rshift__",
        "__and__",
        "__or__",
        "__xor__",
        # reflected arithmetic
        "__radd__",
        "__rsub__",
        "__rmul__",
        "__rtruediv__",
        "__rfloordiv__",
        "__rmod__",
        "__rdivmod__",
        "__rpow__",
        "__rlshift__",
        "__rrshift__",
        "__rand__",
        "__ror__",
        "__rxor__",
        # in-place arithmetic
        "__iadd__",
        "__isub__",
        "__imul__",
        "__itruediv__",
        "__ifloordiv__",
        "__imod__",
        "__ipow__",
        "__ilshift__",
        "__irshift__",
        "__iand__",
        "__ior__",
        "__ixor__",
        # unary and rounding
        "__neg__",
        "__pos__",
        "__abs__",
        "__invert__",
        "__round__",
        "__floor__",
        "__ceil__",
        "__trunc__",
        # conversion
        "__bool__",
        "__int__",
        "__float__",
        "__complex__",
        "__index__",
        "__str__",
        "__format__",
        "__hash__",
        # container protocol
        "__len__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__iter__",
        "__reversed__",
        "__contains__",
    )

    _instance = None

    def __new__(cls) -> "NoValue":
        if cls._instance is None:
            cls._instance = object.__new__(cls)

        return cls._instance

    def __getattr__(self, attr: str) -> Any:
        # Let protocol probes (`__deepcopy__`, `__getstate__` and friends) fail
        # the way they would on any other object, or copying and pickling of
        # schema objects would blow up instead of falling back.
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError("Attribute %s not present" % attr)

        raise error.PyAsn1Error(
            'Attempted "%s" operation on ASN.1 schema object' % attr
        )

    def __repr__(self) -> str:
        return "<%s object>" % self.__class__.__name__


def _plugSchemaOperation(name: str) -> Any:
    def operation(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise error.PyAsn1Error(
            'Attempted "%s" operation on ASN.1 schema object' % name
        )

    operation.__name__ = name

    return operation


for _plugName in NoValue.plugMethods:
    setattr(NoValue, _plugName, _plugSchemaOperation(_plugName))

del _plugName


noValue: Final = NoValue()


class SimpleAsn1Type(Asn1Type):
    """Base class for all simple classes representing ASN.1 types.

    ASN.1 distinguishes types by their ability to hold other objects.
    Scalar types are known as *simple* in ASN.1.

    In the user code, |ASN.1| class is normally used only for telling
    ASN.1 objects from others.

    Note
    ----
    For as long as ASN.1 is concerned, a way to compare ASN.1 types
    is to use :meth:`isSameTypeWith` and :meth:`isSuperTypeOf` methods.
    """

    #: Default payload value
    defaultValue: Any = noValue

    def __init__(self, value: Any = noValue, **kwargs: Any) -> None:
        Asn1Type.__init__(self, **kwargs)
        if value is noValue:
            value = self.defaultValue
        else:
            value = self.prettyIn(value)
            try:
                self.subtypeSpec(value)

            except error.PyAsn1Error as exc:
                raise exc.__class__(
                    "%s at %s" % (exc, self.__class__.__name__)
                ) from exc

        self._value = value

    def __repr__(self) -> str:
        if self.isValue:
            value = self.prettyPrint()
            if len(value) > 32:
                value = value[:16] + "..." + value[-16:]
            return "<%s value object, payload [%s]>" % (
                self.__class__.__name__,
                value,
            )
        return "<%s schema object>" % self.__class__.__name__

    def _cmpValue(self, operation: str) -> Any:
        if self._value is noValue:
            raise error.PyAsn1Error(
                'Attempted "%s" operation on ASN.1 schema object' % operation
            )

        return self._value

    def __eq__(self, other: object) -> bool:
        return self is other or self._cmpValue("__eq__") == other

    def __ne__(self, other: object) -> bool:
        return self is not other and self._cmpValue("__ne__") != other

    def __lt__(self, other: Any) -> bool:
        return self._cmpValue("__lt__") < other

    def __le__(self, other: Any) -> bool:
        return self._cmpValue("__le__") <= other

    def __gt__(self, other: Any) -> bool:
        return self._cmpValue("__gt__") > other

    def __ge__(self, other: Any) -> bool:
        return self._cmpValue("__ge__") >= other

    def __bool__(self) -> bool:
        return bool(self._value)

    def __hash__(self) -> int:
        return hash(self._value)

    @property
    def isValue(self) -> bool:
        """Indicate that |ASN.1| object represents ASN.1 value.

        If *isValue* is :obj:`False` then this object represents just
        ASN.1 schema.

        If *isValue* is :obj:`True` then, in addition to its ASN.1 schema
        features, this object can also be used like a Python built-in object
        (e.g. :class:`int`, :class:`str`, :class:`dict` etc.).

        Returns
        -------
        : :class:`bool`
            :obj:`False` if object represents just ASN.1 schema.
            :obj:`True` if object represents ASN.1 schema and can be used as a normal value.

        Note
        ----
        There is an important distinction between PyASN1 schema and value objects.
        The PyASN1 schema objects can only participate in ASN.1 schema-related
        operations (e.g. defining or testing the structure of the data). Most
        obvious uses of ASN.1 schema is to guide serialisation codecs whilst
        encoding/decoding serialised ASN.1 contents.

        The PyASN1 value objects can **additionally** participate in many operations
        involving regular Python objects (e.g. arithmetic, comprehension etc).
        """
        return self._value is not noValue

    def clone(self, value: Any = noValue, **kwargs: Any) -> Any:
        """Create a modified version of |ASN.1| schema or value object.

        The `clone()` method accepts the same set arguments as |ASN.1|
        class takes on instantiation except that all arguments
        of the `clone()` method are optional.

        Whatever arguments are supplied, they are used to create a copy
        of `self` taking precedence over the ones used to instantiate `self`.

        Note
        ----
        Due to the immutable nature of the |ASN.1| object, if no arguments
        are supplied, no new |ASN.1| object will be created and `self` will
        be returned instead.
        """
        if value is noValue:
            if not kwargs:
                return self

            value = self._value

        initializers = self.readOnly.copy()
        initializers.update(kwargs)

        return self.__class__(value, **initializers)

    def subtype(self, value: Any = noValue, **kwargs: Any) -> Any:
        """Create a specialization of |ASN.1| schema or value object.

        The subtype relationship between ASN.1 types has no correlation with
        subtype relationship between Python types. ASN.1 type is mainly identified
        by its tag(s) (:py:class:`~pyasn1.type.tag.TagSet`) and value range
        constraints (:py:class:`~pyasn1.type.constraint.ConstraintsIntersection`).
        These ASN.1 type properties are implemented as |ASN.1| attributes.

        The `subtype()` method accepts the same set arguments as |ASN.1|
        class takes on instantiation except that all parameters
        of the `subtype()` method are optional.

        With the exception of the arguments described below, the rest of
        supplied arguments they are used to create a copy of `self` taking
        precedence over the ones used to instantiate `self`.

        The following arguments to `subtype()` create a ASN.1 subtype out of
        |ASN.1| type:

        Other Parameters
        ----------------
        implicitTag: :py:class:`~pyasn1.type.tag.Tag`
            Implicitly apply given ASN.1 tag object to `self`'s
            :py:class:`~pyasn1.type.tag.TagSet`, then use the result as
            new object's ASN.1 tag(s).

        explicitTag: :py:class:`~pyasn1.type.tag.Tag`
            Explicitly apply given ASN.1 tag object to `self`'s
            :py:class:`~pyasn1.type.tag.TagSet`, then use the result as
            new object's ASN.1 tag(s).

        subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
            Add ASN.1 constraints object to one of the `self`'s, then
            use the result as new object's ASN.1 constraints.

        Returns
        -------
        :
            new instance of |ASN.1| schema or value object

        Note
        ----
        Due to the immutable nature of the |ASN.1| object, if no arguments
        are supplied, no new |ASN.1| object will be created and `self` will
        be returned instead.
        """
        if value is noValue:
            if not kwargs:
                return self

            value = self._value

        initializers = self.readOnly.copy()

        implicitTag = kwargs.pop("implicitTag", None)
        if implicitTag is not None:
            initializers["tagSet"] = self.tagSet.tagImplicitly(implicitTag)

        explicitTag = kwargs.pop("explicitTag", None)
        if explicitTag is not None:
            initializers["tagSet"] = self.tagSet.tagExplicitly(explicitTag)

        for arg, option in kwargs.items():
            initializers[arg] += option

        return self.__class__(value, **initializers)

    def prettyIn(self, value: Any) -> Any:
        return value

    def prettyOut(self, value: Any) -> Any:
        return str(value)

    def prettyPrint(self, scope: int = 0) -> str:
        return self.prettyOut(self._value)

    def prettyPrintType(self, scope: int = 0) -> str:
        return "%s -> %s" % (self.tagSet, self.__class__.__name__)


# Constructed types:
# * There are five of them: Sequence, SequenceOf/SetOf, Set and Choice
# * ASN1 types and values are represened by Python class instances
# * Value initialization is made for defaulted components only
# * Primary method of component addressing is by-position. Data model for base
#   type is Python sequence. Additional type-specific addressing methods
#   may be implemented for particular types.
# * SequenceOf and SetOf types do not implement any additional methods
# * Sequence, Set and Choice types also implement by-identifier addressing
# * Sequence, Set and Choice types also implement by-asn1-type (tag) addressing
# * Sequence and Set types may include optional and defaulted
#   components
# * Constructed types hold a reference to component types used for value
#   verification and ordering.
# * Component type is a scalar type for SequenceOf/SetOf types and a list
#   of types for Sequence/Set/Choice.
#


class ConstructedAsn1Type(Asn1Type):
    """Base class for all constructed classes representing ASN.1 types.

    ASN.1 distinguishes types by their ability to hold other objects.
    Those "nesting" types are known as *constructed* in ASN.1.

    In the user code, |ASN.1| class is normally used only for telling
    ASN.1 objects from others.

    Note
    ----
    For as long as ASN.1 is concerned, a way to compare ASN.1 types
    is to use :meth:`isSameTypeWith` and :meth:`isSuperTypeOf` methods.
    """

    #: If :obj:`True`, requires exact component type matching,
    #: otherwise subtype relation is only enforced
    strictConstraints = False

    componentType: Any = None

    _componentValues: Any

    if TYPE_CHECKING:
        # Declared read-only so subclasses may implement it as a property.
        # Type-check time only; the attribute itself comes from subclasses.
        @property
        def isValue(self) -> bool: ...

    def __init__(self, **kwargs: Any) -> None:
        readOnly = {"componentType": self.componentType}

        readOnly.update(kwargs)

        Asn1Type.__init__(self, **readOnly)

    def __repr__(self) -> str:
        if self.isValue and self.components:
            parts = []
            # Try to include field names for named-component types (Sequence/Set)
            component_type = getattr(self, "componentType", None)
            has_named_components = (
                isinstance(component_type, namedtype.NamedTypes)
                and len(component_type) > 0
            )

            for idx, component in enumerate(self.components):
                r = repr(component)
                # Strip outer angle brackets for cleaner inline display
                if r.startswith("<") and r.endswith(">"):
                    r = r[1:-1]
                if has_named_components and component_type is not None:
                    try:
                        name = component_type[idx].name
                        parts.append("%s=%s" % (name, r))
                    except (IndexError, KeyError):
                        parts.append(r)
                else:
                    parts.append(r)
            return "<%s value object, payload [%s]>" % (
                self.__class__.__name__,
                ", ".join(parts),
            )
        return "<%s schema object>" % self.__class__.__name__

    def _cmpComponents(self, operation: str) -> Any:
        if self._componentValues is noValue:
            raise error.PyAsn1Error(
                'Attempted "%s" operation on ASN.1 schema object' % operation
            )

        return self.components

    def __eq__(self, other: object) -> bool:
        return self is other or self._cmpComponents("__eq__") == other

    def __ne__(self, other: object) -> bool:
        return self is not other and self._cmpComponents("__ne__") != other

    def __lt__(self, other: Any) -> bool:
        return self._cmpComponents("__lt__") < other

    def __le__(self, other: Any) -> bool:
        return self._cmpComponents("__le__") <= other

    def __gt__(self, other: Any) -> bool:
        return self._cmpComponents("__gt__") > other

    def __ge__(self, other: Any) -> bool:
        return self._cmpComponents("__ge__") >= other

    def __bool__(self) -> bool:
        return bool(self.components)

    @property
    def components(self) -> Any:
        raise error.PyAsn1Error("Method not implemented")

    def _cloneComponentValues(self, myClone: Any, cloneValueFlag: Any) -> None:
        pass

    def clone(self, **kwargs: Any) -> Any:
        """Create a modified version of |ASN.1| schema object.

        The `clone()` method accepts the same set arguments as |ASN.1|
        class takes on instantiation except that all arguments
        of the `clone()` method are optional.

        Whatever arguments are supplied, they are used to create a copy
        of `self` taking precedence over the ones used to instantiate `self`.

        Possible values of `self` are never copied over thus `clone()` can
        only create a new schema object.

        Returns
        -------
        :
            new instance of |ASN.1| type/value

        Note
        ----
        Due to the mutable nature of the |ASN.1| object, even if no arguments
        are supplied, a new |ASN.1| object will be created and returned.
        """
        cloneValueFlag = kwargs.pop("cloneValueFlag", False)

        initializers = self.readOnly.copy()
        initializers.update(kwargs)

        clone = self.__class__(**initializers)

        if cloneValueFlag:
            self._cloneComponentValues(clone, cloneValueFlag)

        return clone

    def subtype(self, **kwargs: Any) -> Any:
        """Create a specialization of |ASN.1| schema object.

        The `subtype()` method accepts the same set arguments as |ASN.1|
        class takes on instantiation except that all parameters
        of the `subtype()` method are optional.

        With the exception of the arguments described below, the rest of
        supplied arguments they are used to create a copy of `self` taking
        precedence over the ones used to instantiate `self`.

        The following arguments to `subtype()` create a ASN.1 subtype out of
        |ASN.1| type.

        Other Parameters
        ----------------
        implicitTag: :py:class:`~pyasn1.type.tag.Tag`
            Implicitly apply given ASN.1 tag object to `self`'s
            :py:class:`~pyasn1.type.tag.TagSet`, then use the result as
            new object's ASN.1 tag(s).

        explicitTag: :py:class:`~pyasn1.type.tag.Tag`
            Explicitly apply given ASN.1 tag object to `self`'s
            :py:class:`~pyasn1.type.tag.TagSet`, then use the result as
            new object's ASN.1 tag(s).

        subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
            Add ASN.1 constraints object to one of the `self`'s, then
            use the result as new object's ASN.1 constraints.


        Returns
        -------
        :
            new instance of |ASN.1| type/value

        Note
        ----
        Due to the mutable nature of the |ASN.1| object, even if no arguments
        are supplied, a new |ASN.1| object will be created and returned.
        """

        initializers = self.readOnly.copy()

        cloneValueFlag = kwargs.pop("cloneValueFlag", False)

        implicitTag = kwargs.pop("implicitTag", None)
        if implicitTag is not None:
            initializers["tagSet"] = self.tagSet.tagImplicitly(implicitTag)

        explicitTag = kwargs.pop("explicitTag", None)
        if explicitTag is not None:
            initializers["tagSet"] = self.tagSet.tagExplicitly(explicitTag)

        for arg, option in kwargs.items():
            initializers[arg] += option

        clone = self.__class__(**initializers)

        if cloneValueFlag:
            self._cloneComponentValues(clone, cloneValueFlag)

        return clone

    def getComponentByPosition(self, idx: int) -> Any:
        raise error.PyAsn1Error("Method not implemented")

    def setComponentByPosition(
        self, idx: int, value: Any, verifyConstraints: bool = True
    ) -> Any:
        raise error.PyAsn1Error("Method not implemented")

    def setComponents(self, *args: Any, **kwargs: Any) -> Any:
        for idx, value in enumerate(args):
            self[idx] = value  # type: ignore[index]
        for k, v in kwargs.items():
            self[k] = v  # type: ignore[index]
        return self
