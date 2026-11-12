"""Guarantee: network waiting never holds a SQLite write lock.

A backup spends up to 5 seconds in network I/O.  During that window another
worker process must still be able to take a write transaction immediately;
this test observes the attempt row *before* the transfer finishes (proving
the only early write was a short autocommit insert that already released) and
confirms a competing write does not block on the transfer.
"""

import sqlite3
import threading
import time

from app.config import DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64, Target

from .conftest import ZONE


def test_no_write_lock_held_during_network_wait(auth_servers, tmp_path):
    from app.service import BackupService, JobRegistry
    from app.storage import Storage

    db_path = tmp_path / "backup.db"
    files_dir = tmp_path / "zones"
    storage = Storage(db_path, files_dir)
    service = BackupService(storage, JobRegistry())
    target = Target(
        target_id="stale",
        label="stale",
        host="127.0.0.1",
        port=auth_servers["stale"],  # server sleeps ~1s before responding
        zone=ZONE,
        key_name=DEFAULT_KEY_NAME,
        key_secret_b64=DEFAULT_KEY_SECRET_B64,
    )

    worker_done = threading.Event()

    def run_transfer():
        service.run_backup(target)
        worker_done.set()

    thread = threading.Thread(target=run_transfer)
    thread.start()

    # While the AXFR is in flight, open a *separate* connection and take a
    # write lock. If the transfer held one, this would block until timeout.
    time.sleep(0.3)
    acquired = threading.Event()

    def compete():
        # Dedicated connection for this thread; BEGIN IMMEDIATE would block
        # (and hit the 2s busy timeout) if the transfer held a write lock.
        competitor = sqlite3.connect(str(db_path), timeout=2)
        competitor.execute("BEGIN IMMEDIATE")
        competitor.execute(
            "INSERT INTO attempts (zone_name, reason) VALUES (?, 'lock-probe')",
            (ZONE,),
        )
        competitor.commit()
        competitor.close()
        acquired.set()

    probe = threading.Thread(target=compete)
    probe.start()
    assert acquired.wait(timeout=3), "competing write blocked during network wait"
    probe.join()

    assert worker_done.wait(timeout=10)
    thread.join()
