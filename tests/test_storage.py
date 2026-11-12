"""Storage: atomic version replacement, RFC 1982 commit gate, persistence."""

import os

import pytest

from app.serial import SerialRelation
from app.storage import CommitRejected, Storage, render_zone_file

def _rrs(serial: int):
    return [
        ("z.test.", 3600, "SOA",
         f"ns1.z.test. admin.z.test. {serial} 7200 3600 1209600 3600"),
        ("z.test.", 3600, "NS", "ns1.z.test."),
        ("ns1.z.test.", 3600, "A", "10.0.0.1"),
    ]


RRS_V1 = _rrs(100)
RRS_V2 = _rrs(101) + [("host1.z.test.", 300, "A", "10.0.1.5")]


@pytest.fixture()
def storage(tmp_path):
    return Storage(tmp_path / "backup.db", tmp_path / "zones")


def test_first_copy_saved_directly(storage):
    outcome = storage.commit_backup("z.test.", 100, RRS_V1, 3)
    assert outcome.status == "saved"
    zone = storage.get_zone("z.test.")
    assert zone.serial == 100
    assert zone.record_count == 3
    assert os.path.exists(zone.zone_file)


def test_equal_serial_leaves_untouched(storage):
    storage.commit_backup("z.test.", 100, RRS_V1, 3)
    before = storage.get_zone("z.test.")
    outcome = storage.commit_backup("z.test.", 100, RRS_V2, 4)
    assert outcome.status == "unchanged"
    after = storage.get_zone("z.test.")
    assert after.serial == 100
    assert after.record_count == 3
    assert after.updated_at == before.updated_at


def test_newer_serial_replaces_whole_version(storage):
    storage.commit_backup("z.test.", 100, RRS_V1, 3)
    outcome = storage.commit_backup("z.test.", 101, RRS_V2, 4)
    assert outcome.status == "saved"
    zone = storage.get_zone("z.test.")
    assert zone.serial == 101 and zone.record_count == len(RRS_V2)
    content = storage.read_zone_file(zone)
    # download cannot mix versions: v2-only record present, metadata matches
    assert "host1.z.test." in content
    assert "101" in content


def test_older_serial_rejected_and_old_version_kept(storage):
    storage.commit_backup("z.test.", 101, RRS_V2, 4)
    with pytest.raises(CommitRejected) as excinfo:
        storage.commit_backup("z.test.", 50, RRS_V1, 3)
    assert excinfo.value.relation is SerialRelation.OLDER
    zone = storage.get_zone("z.test.")
    assert zone.serial == 101 and zone.record_count == 4


def test_half_space_difference_rejected(storage):
    storage.commit_backup("z.test.", 101, RRS_V1, 3)
    ambiguous = (101 + 2**31) % 2**32
    with pytest.raises(CommitRejected) as excinfo:
        storage.commit_backup("z.test.", ambiguous, RRS_V2, 4)
    assert excinfo.value.relation is SerialRelation.AMBIGUOUS
    assert storage.get_zone("z.test.").serial == 101


def test_wraparound_newer_serial_accepted(storage):
    high = 2**32 - 5
    storage.commit_backup("z.test.", high, RRS_V1, 3)
    wrapped = 2  # newer per RFC 1982 across the wrap
    outcome = storage.commit_backup("z.test.", wrapped, RRS_V2, 4)
    assert outcome.status == "saved"
    assert storage.get_zone("z.test.").serial == wrapped


def test_persistence_across_reopen(tmp_path):
    db = tmp_path / "backup.db"
    files = tmp_path / "zones"
    Storage(db, files).commit_backup("z.test.", 7, RRS_V1, 3)
    reopened = Storage(db, files)
    zone = reopened.get_zone("z.test.")
    assert zone is not None and zone.serial == 7
    assert "SOA" in reopened.read_zone_file(zone)


def test_attempts_record_failure_reasons(storage):
    attempt_id = storage.record_attempt_start("z.test.")
    storage.record_attempt_finish(attempt_id, False, None, None, "断流：连接关闭")
    rows = storage.recent_attempts()
    assert len(rows) == 1
    assert rows[0]["ok"] == 0
    assert "断流" in rows[0]["reason"]


def test_render_zone_file_is_master_format():
    text = render_zone_file("z.test.", RRS_V1)
    assert "$ORIGIN ." in text
    assert "z.test.\t3600\tIN\tSOA\t" in text
    assert text.endswith("\n")
