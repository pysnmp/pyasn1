#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import datetime
import warnings
from typing import Final

from pyasn1 import error
from pyasn1.type import char, tag, univ

__all__ = ["GeneralizedTime", "ObjectDescriptor", "UTCTime"]

NoValue = univ.NoValue
noValue: Final = univ.noValue


class ObjectDescriptor(char.GraphicString):
    __doc__ = char.GraphicString.__doc__

    #: Default :py:class:`~pyasn1.type.tag.TagSet` object for |ASN.1| objects
    tagSet = char.GraphicString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 7)
    )

    # Optimization for faster codec lookup
    typeId = char.GraphicString.getTypeId()


class TimeMixIn:
    _yearsDigits = 4
    _hasSubsecond = False
    _optionalMinutes = False
    _shortTZ = False

    #: Alias for :py:const:`datetime.timezone.utc`.
    UTC = datetime.timezone.utc

    @staticmethod
    def FixedOffset(offset=0, name="UTC"):
        """Fixed offset in minutes east from UTC.

        .. deprecated::
           Use :py:class:`datetime.timezone` with a
           :py:class:`datetime.timedelta` offset instead.
        """
        warnings.warn(
            "TimeMixIn.FixedOffset() is deprecated, use "
            "datetime.timezone(datetime.timedelta(minutes=offset), name)",
            DeprecationWarning,
            stacklevel=2,
        )
        return datetime.timezone(datetime.timedelta(minutes=offset), name)

    @property
    def asDateTime(self):
        """Create :py:class:`datetime.datetime` object from a |ASN.1| object.

        Returns
        -------
        :
            new instance of :py:class:`datetime.datetime` object
        """
        text = str(self)
        if text.endswith("Z"):
            tzinfo = TimeMixIn.UTC
            text = text[:-1]

        elif "-" in text or "+" in text:
            if "+" in text:
                text, plusminus, tz = text.partition("+")
            else:
                text, plusminus, tz = text.partition("-")

            if self._shortTZ and len(tz) == 2:
                tz += "00"

            if len(tz) != 4:
                raise error.PyAsn1Error("malformed time zone offset %s" % tz)

            try:
                minutes = int(tz[:2]) * 60 + int(tz[2:])
                if plusminus == "-":
                    minutes *= -1

            except ValueError as exc:
                raise error.PyAsn1Error("unknown time specification %s" % self) from exc

            tzinfo = datetime.timezone(datetime.timedelta(minutes=minutes), "?")

        else:
            tzinfo = None

        if "." in text or "," in text:
            if "." in text:
                text, _, ms = text.partition(".")
            else:
                text, _, ms = text.partition(",")

            try:
                ms = int(ms) * 1000

            except ValueError as exc:
                raise error.PyAsn1Error(
                    "bad sub-second time specification %s" % self
                ) from exc

        else:
            ms = 0

        if self._optionalMinutes and len(text) - self._yearsDigits == 6:
            text += "0000"
        elif len(text) - self._yearsDigits == 8:
            text += "00"

        try:
            dt = datetime.datetime.strptime(
                text, "%Y%m%d%H%M%S" if self._yearsDigits == 4 else "%y%m%d%H%M%S"
            )

        except ValueError as exc:
            raise error.PyAsn1Error("malformed datetime format %s" % self) from exc

        return dt.replace(microsecond=ms, tzinfo=tzinfo)

    @classmethod
    def fromDateTime(cls, dt):
        """Create |ASN.1| object from a :py:class:`datetime.datetime` object.

        Parameters
        ----------
        dt: :py:class:`datetime.datetime` object
            The `datetime.datetime` object to initialize the |ASN.1| object
            from

        Returns
        -------
        :
            new instance of |ASN.1| value
        """
        text = dt.strftime("%Y%m%d%H%M%S" if cls._yearsDigits == 4 else "%y%m%d%H%M%S")
        if cls._hasSubsecond:
            text += ".%d" % (dt.microsecond // 1000)

        if dt.utcoffset():
            seconds = dt.utcoffset().seconds
            if seconds < 0:
                text += "-"
            else:
                text += "+"
            text += "%.2d%.2d" % (seconds // 3600, seconds % 3600)
        else:
            text += "Z"

        return cls(text)


class GeneralizedTime(char.VisibleString, TimeMixIn):
    __doc__ = char.VisibleString.__doc__

    #: Default :py:class:`~pyasn1.type.tag.TagSet` object for |ASN.1| objects
    tagSet = char.VisibleString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 24)
    )

    # Optimization for faster codec lookup
    typeId = char.VideotexString.getTypeId()

    _yearsDigits = 4
    _hasSubsecond = True
    _optionalMinutes = True
    _shortTZ = True


class UTCTime(char.VisibleString, TimeMixIn):
    __doc__ = char.VisibleString.__doc__

    #: Default :py:class:`~pyasn1.type.tag.TagSet` object for |ASN.1| objects
    tagSet = char.VisibleString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 23)
    )

    # Optimization for faster codec lookup
    typeId = char.VideotexString.getTypeId()

    _yearsDigits = 2
    _hasSubsecond = False
    _optionalMinutes = False
    _shortTZ = False
