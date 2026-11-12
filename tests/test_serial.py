"""RFC 1982 serial comparison edge cases."""

import pytest

from app.serial import SerialRelation as R
from app.serial import compare_serial


@pytest.mark.parametrize(
    "incoming, stored, expected",
    [
        (10, 5, R.NEWER),
        (5, 10, R.OLDER),
        (12345, 12345, R.EQUAL),
        (0, 2**31, R.AMBIGUOUS),
        (2**31, 0, R.AMBIGUOUS),
        (100, (100 + 2**31) % 2**32, R.AMBIGUOUS),
        # wrap-around: 0 is the immediate successor of 2^32-1
        (0, 2**32 - 1, R.NEWER),
        (2**32 - 1, 0, R.OLDER),
        # just inside the half-space window
        (10, 10 + 2**31 - 1, R.OLDER),
        (10 + 2**31 - 1, 10, R.NEWER),
    ],
)
def test_compare_serial(incoming, stored, expected):
    assert compare_serial(incoming, stored) is expected


def test_compare_serial_rejects_out_of_range():
    with pytest.raises(ValueError):
        compare_serial(2**32, 0)
    with pytest.raises(ValueError):
        compare_serial(-1, 0)
