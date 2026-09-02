#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Useful ASN.1 types: ObjectDescriptor, GeneralizedTime and UTCTime."""

import datetime
import warnings
from typing import Any, Final

from pyasn1 import error
from pyasn1.type import char, tag, univ

__all__ = ["GeneralizedTime", "ObjectDescriptor", "UTCTime"]

NoValue = univ.NoValue
noValue: Final = univ.noValue


class ObjectDescriptor(char.GraphicString):  # noqa: D101 - docstring aliased from the base type below
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

    def prettyOut(self: Any, value: Any) -> Any:
        """Render the instant in ISO 8601 form for human-facing output.

        The stored value is the ASN.1 spelling, e.g. ``19851106210627.3Z``,
        and that is what :func:`str` and the codecs keep using. Only
        :meth:`prettyPrint` differs, showing
        ``1985-11-06T21:06:27.300000+00:00`` so that a debug log reads as a
        timestamp rather than as an undifferentiated character string.

        A value that does not parse is handed back untouched. The BER
        decoder calls :meth:`prettyPrint` while logging, so this must not
        raise on the lax spellings BER still accepts.
        """
        if not isinstance(value, str):
            return value

        try:
            return self.asDateTime.isoformat()

        except (error.PyAsn1Error, ValueError):
            return value

    @staticmethod
    def FixedOffset(offset: int = 0, name: str = "UTC") -> datetime.timezone:
        """Return a fixed offset in minutes east of UTC.

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

    def verifyCanonicalForm(self) -> None:
        """Check the value against the CER and DER restrictions on time.

        X.690 11.7 and 11.8 cut the many BER spellings of an instant down to
        one: the encoding terminates with "Z", the seconds element is always
        present, fractional seconds carry no trailing zeros and are omitted
        outright when they would be zero, and midnight is written as the
        start of the following day rather than as hour 24.

        Raises
        ------
        ~pyasn1.error.PyAsn1Error
            If the value is not in the canonical form.
        """
        text = str(self)

        if not text.endswith("Z"):
            raise error.PyAsn1Error('Time value must terminate with "Z"', value=text)

        body = text[:-1]

        if "," in body:
            raise error.PyAsn1Error(
                "Fractional seconds must use a full stop, not a comma", value=text
            )

        integral, dot, fraction = body.partition(".")

        # YYYYMMDDHHMMSS, or YYMMDDHHMMSS for UTCTime. The seconds element is
        # not optional here, however optional X.680 leaves it.
        expectedDigits = self._yearsDigits + 10

        if len(integral) != expectedDigits or not integral.isdigit():
            raise error.PyAsn1Error(
                "Time value must carry the seconds element and nothing else",
                value=text,
                expectedDigits=expectedDigits,
            )

        if dot:
            if not self._hasSubsecond:
                raise error.PyAsn1Error("Fractional seconds prohibited", value=text)

            if not fraction.isdigit():
                raise error.PyAsn1Error("Malformed fractional seconds", value=text)

            # A trailing zero covers both spurious precision ("26.520") and a
            # fraction that is wholly zero ("26.0"), which 11.7.3 requires be
            # dropped along with the decimal point.
            if fraction.endswith("0"):
                raise error.PyAsn1Error(
                    "Fractional seconds must omit trailing zeros", value=text
                )

        hours = integral[self._yearsDigits + 4 : self._yearsDigits + 6]
        if hours == "24":
            raise error.PyAsn1Error(
                "Midnight must be encoded as 000000 of the following day",
                value=text,
            )

    @property
    def asDateTime(self) -> datetime.datetime:
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
                raise error.PyAsn1Error("malformed time zone offset", timeZone=tz)

            try:
                minutes = int(tz[:2]) * 60 + int(tz[2:])
                if plusminus == "-":
                    minutes *= -1

            except ValueError as exc:
                raise error.PyAsn1Error(
                    "unknown time specification", value=str(self)
                ) from exc

            tzinfo = datetime.timezone(datetime.timedelta(minutes=minutes), "?")

        else:
            tzinfo = None

        if "." in text or "," in text:
            if "." in text:
                text, _, subsecond = text.partition(".")
            else:
                text, _, subsecond = text.partition(",")

            if not subsecond.isdigit():
                raise error.PyAsn1Error(
                    "bad sub-second time specification", value=str(self)
                )

            # X.680 46.3 a) 2: the fraction is a decimal fraction of a second,
            # so ".3" is 300 ms and ".003" is 3 ms. Scale by the position of
            # the digits, not by how many of them there are.
            #
            # 46.3 admits a fraction "to any degree of accuracy", which is
            # finer than datetime can hold, so the digits past microsecond
            # resolution are dropped the way datetime.fromisoformat drops
            # them. Rounding instead would carry ".9999999" up to a whole
            # second, which datetime rejects as a microsecond count. Padding
            # and slicing keeps this exact: a fraction long enough to matter
            # has already exhausted the precision of a float.
            microsecond = int(subsecond[:6].ljust(6, "0"))

        else:
            microsecond = 0

        if self._optionalMinutes and len(text) - self._yearsDigits == 6:
            text += "0000"
        elif len(text) - self._yearsDigits == 8:
            text += "00"

        try:
            dt = datetime.datetime.strptime(
                text, "%Y%m%d%H%M%S" if self._yearsDigits == 4 else "%y%m%d%H%M%S"
            )

        except ValueError as exc:
            raise error.PyAsn1Error(
                "malformed datetime format", value=str(self)
            ) from exc

        return dt.replace(microsecond=microsecond, tzinfo=tzinfo)

    @classmethod
    def fromDateTime(cls, dt: datetime.datetime) -> Any:
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

        if cls._hasSubsecond and dt.microsecond:
            # X.680 46.3 a) 2: a decimal fraction of a second, so 300000 us is
            # ".3". Trailing zeros carry no accuracy here and X.690 11.7.3
            # bars them from the canonical form, so drop them. A whole second
            # takes no fraction at all, for the same reason.
            text += f".{dt.microsecond:06d}".rstrip("0")

        utcOffset = dt.utcoffset()

        if utcOffset:
            # timedelta normalises a negative offset into a negative day plus
            # a positive seconds count, so -05:00 is days=-1, seconds=68400.
            # Read the sign off the whole offset rather than off .seconds,
            # which is never negative.
            minutes = round(utcOffset.total_seconds() / 60)
            sign = "-" if minutes < 0 else "+"
            minutes = abs(minutes)

            # X.680 46.3 c): the difference from UTC is written as HHMM.
            text += f"{sign}{minutes // 60:02d}{minutes % 60:02d}"

        else:
            # Both UTC and a naive datetime land here. pyasn1 has always read
            # a naive value as UTC rather than as X.680 46.3 a) local time.
            text += "Z"

        return cls(text)  # type: ignore[call-arg]


class GeneralizedTime(char.VisibleString, TimeMixIn):  # noqa: D101 - docstring aliased from the base type below
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

    # TimeMixIn trails AbstractCharacterString in the MRO, so its prettyOut
    # would lose to the identity one inherited from the string types. Bind it
    # here rather than reorder the bases.
    prettyOut = TimeMixIn.prettyOut


class UTCTime(char.VisibleString, TimeMixIn):  # noqa: D101 - docstring aliased from the base type below
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

    # See the note on GeneralizedTime.prettyOut.
    prettyOut = TimeMixIn.prettyOut
