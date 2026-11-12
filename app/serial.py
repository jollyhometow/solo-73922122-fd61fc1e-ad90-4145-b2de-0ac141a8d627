"""RFC 1982 serial number arithmetic for 32-bit DNS SOA serials.

The backup commit rule is expressed as an explicit three-way comparison so the
two undefined/edge cases are handled deterministically:

* equal serials           -> :data:`SerialRelation.EQUAL` (no replacement)
* difference == 2**31     -> :data:`SerialRelation.AMBIGUOUS` (rejected)
* otherwise               -> NEWER or OLDER per RFC 1982 section 3.2
"""

from __future__ import annotations

from enum import Enum

SERIAL_BITS = 32
SERIAL_MOD = 1 << SERIAL_BITS
HALF_SPACE = 1 << (SERIAL_BITS - 1)  # 2**31


class SerialRelation(str, Enum):
    NEWER = "newer"
    EQUAL = "equal"
    OLDER = "older"
    AMBIGUOUS = "ambiguous"


def compare_serial(incoming: int, stored: int) -> SerialRelation:
    """Compare *incoming* against *stored* using RFC 1982 arithmetic.

    Both values are 32-bit unsigned serials.  When the modular distance is
    exactly 2**31 the ordering is undefined by RFC 1982 and we return
    :data:`SerialRelation.AMBIGUOUS` so the caller rejects the transfer.
    """
    if not (0 <= incoming < SERIAL_MOD and 0 <= stored < SERIAL_MOD):
        raise ValueError("serial numbers must be unsigned 32-bit integers")
    if incoming == stored:
        return SerialRelation.EQUAL
    diff = (incoming - stored) % SERIAL_MOD
    if diff == HALF_SPACE:
        return SerialRelation.AMBIGUOUS
    if diff < HALF_SPACE:
        return SerialRelation.NEWER
    return SerialRelation.OLDER
