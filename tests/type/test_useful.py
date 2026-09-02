#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import datetime
import pickle
import sys
import unittest
from copy import deepcopy

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import useful
from tests.base import BaseTestCase


class FixedOffset(datetime.tzinfo):
    def __init__(self, offset, name):
        self.__offset = datetime.timedelta(minutes=offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return datetime.timedelta(0)


UTC = FixedOffset(0, "UTC")
UTC2 = FixedOffset(120, "UTC")


class ObjectDescriptorTestCase(BaseTestCase):
    pass


class GeneralizedTimeTestCase(BaseTestCase):
    # X.680 46.3 a) 2 makes the fraction a decimal fraction of a second, and
    # its own example reads "19851106210627.3" as 27.3 seconds. So ".3" is
    # 300000 us. These cases used to pair ".3" with 3000 us in both
    # directions, which is the same instant only if the fraction is read as a
    # count of milliseconds.
    def testFromDateTime(self):
        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC)
            )
            == "20170711000102.3Z"
        )

    def testFromDateTimeMilliseconds(self):
        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, 3000, tzinfo=UTC)
            )
            == "20170711000102.003Z"
        )

    def testFromDateTimeDropsEmptyFraction(self):
        # X.690 11.7.3 bars a fraction that is wholly zero, along with its
        # decimal point.
        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
            )
            == "20170711000102Z"
        )

    def testFromDateTimeDropsTrailingZeros(self):
        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, 250000, tzinfo=UTC)
            )
            == "20170711000102.25Z"
        )

    def testFromDateTimePositiveOffset(self):
        # X.680 46.3 c): the difference from UTC is written HHMM. The minutes
        # used to come out as the whole remaining seconds count, so +05:30
        # rendered as the six-digit "+051800".
        offset = datetime.timezone(datetime.timedelta(hours=5, minutes=30))

        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=offset)
            )
            == "20170711000102+0530"
        )

    def testFromDateTimeNegativeOffset(self):
        # timedelta normalises -09:30 to days=-1, seconds=52200, so reading
        # the sign off .seconds always yielded "+" and the wrong magnitude.
        offset = datetime.timezone(datetime.timedelta(hours=-9, minutes=-30))

        assert (
            useful.GeneralizedTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=offset)
            )
            == "20170711000102-0930"
        )

    def testDateTimeRoundTrip(self):
        for dt in (
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC),
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC),
            datetime.datetime(2017, 7, 11, 0, 1, 2, 3000, tzinfo=UTC),
            datetime.datetime(
                2017,
                7,
                11,
                0,
                1,
                2,
                tzinfo=datetime.timezone(datetime.timedelta(hours=-9, minutes=-30)),
            ),
        ):
            assert useful.GeneralizedTime.fromDateTime(dt).asDateTime == dt

    def testLongFractionTruncates(self):
        # X.680 46.3 a) 2 admits a fraction "to any degree of accuracy", which
        # is finer than datetime holds. Digits past microsecond resolution are
        # dropped, as datetime.fromisoformat drops them. Rounding instead
        # carried ".9999999" up to 1000000 us, which datetime rejects.
        assert useful.GeneralizedTime(
            "20170101000000.9999999Z"
        ).asDateTime == datetime.datetime(2017, 1, 1, 0, 0, 0, 999999, tzinfo=UTC)

        assert useful.GeneralizedTime(
            "20170101000000.1234567Z"
        ).asDateTime == datetime.datetime(2017, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)

    def testSpecExample(self):
        # X.680 46.3, case b): "19851106210627.3Z" is 6 minutes, 27.3 seconds
        # after 9 pm on 6 November 1985.
        assert useful.GeneralizedTime(
            "19851106210627.3Z"
        ).asDateTime == datetime.datetime(1985, 11, 6, 21, 6, 27, 300000, tzinfo=UTC)

    def testToDateTime0(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2)
            == useful.GeneralizedTime("20170711000102").asDateTime
        )

    def testToDateTime1(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
            == useful.GeneralizedTime("20170711000102Z").asDateTime
        )

    def testToDateTime2(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC)
            == useful.GeneralizedTime("20170711000102.3Z").asDateTime
        )

    def testToDateTime3(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC)
            == useful.GeneralizedTime("20170711000102,3Z").asDateTime
        )

    def testToDateTime4(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC)
            == useful.GeneralizedTime("20170711000102.3+0000").asDateTime
        )

    def testToDateTime5(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC2)
            == useful.GeneralizedTime("20170711000102.3+0200").asDateTime
        )

    def testToDateTime6(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, 300000, tzinfo=UTC2)
            == useful.GeneralizedTime("20170711000102.3+02").asDateTime
        )

    def testToDateTime7(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1)
            == useful.GeneralizedTime("201707110001").asDateTime
        )

    def testToDateTime8(self):
        assert (
            datetime.datetime(2017, 7, 11, 0)
            == useful.GeneralizedTime("2017071100").asDateTime
        )

    def testCopy(self):
        dt = useful.GeneralizedTime("20170916234254+0130").asDateTime
        assert dt == deepcopy(dt)

    def testFromDateTimeIsDerEncodable(self):
        # The ".0" that fromDateTime used to append to every whole second is
        # a trailing zero, which X.690 11.7.3 forbids, so nothing built this
        # way could be DER encoded at all.
        value = useful.GeneralizedTime.fromDateTime(
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
        )

        assert der_encoder.encode(value) == bytes.fromhex(
            "180f32303137303731313030303130325a"
        )

    def testPrettyPrintRendersIso(self):
        value = useful.GeneralizedTime("19851106210627.3Z")

        assert value.prettyPrint() == "1985-11-06T21:06:27.300000+00:00"
        # str() and the codecs keep seeing the ASN.1 spelling.
        assert str(value) == "19851106210627.3Z"

    def testPrettyPrintKeepsUnparsableValue(self):
        # prettyPrint() runs inside decoder debug logging, so it must not
        # raise on a spelling that BER still accepts but asDateTime cannot
        # make sense of.
        assert useful.GeneralizedTime("not-a-time").prettyPrint() == "not-a-time"


class GeneralizedTimePicklingTestCase(unittest.TestCase):
    def testSchemaPickling(self):
        old_asn1 = useful.GeneralizedTime()
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert type(new_asn1) == useful.GeneralizedTime
        assert old_asn1.isSameTypeWith(new_asn1)

    def testValuePickling(self):
        old_asn1 = useful.GeneralizedTime("20170916234254+0130")
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert new_asn1 == old_asn1


class UTCTimeTestCase(BaseTestCase):
    def testFromDateTime(self):
        assert (
            useful.UTCTime.fromDateTime(
                datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
            )
            == "170711000102Z"
        )

    def testToDateTime0(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2)
            == useful.UTCTime("170711000102").asDateTime
        )

    def testToDateTime1(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
            == useful.UTCTime("170711000102Z").asDateTime
        )

    def testToDateTime2(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC)
            == useful.UTCTime("170711000102+0000").asDateTime
        )

    def testToDateTime3(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1, 2, tzinfo=UTC2)
            == useful.UTCTime("170711000102+0200").asDateTime
        )

    def testToDateTime4(self):
        assert (
            datetime.datetime(2017, 7, 11, 0, 1)
            == useful.UTCTime("1707110001").asDateTime
        )


class UTCTimePicklingTestCase(unittest.TestCase):
    def testSchemaPickling(self):
        old_asn1 = useful.UTCTime()
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert type(new_asn1) == useful.UTCTime
        assert old_asn1.isSameTypeWith(new_asn1)

    def testValuePickling(self):
        old_asn1 = useful.UTCTime("170711000102")
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert new_asn1 == old_asn1


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
