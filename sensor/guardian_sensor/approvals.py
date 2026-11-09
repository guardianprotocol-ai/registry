"""Host-owned, single-use approvals for a dedicated structured tool gateway.

The database and caller context are trusted inputs, never agent arguments.
No Kubernetes credentials are issued here. See docs/DELEGATED_APPROVALS.md.
"""
import hashlib
import json
import math
import sqlite3
import time
import uuid
from contextlib import closing


def fingerprint(subject, agent, audience, tool, arguments):
    if not all(isinstance(v, str) and v for v in (subject, agent, audience, tool)):
        raise ValueError('trusted identity and tool are required')
    if not isinstance(arguments, dict):
        raise ValueError('arguments must be an object')
    body = json.dumps([1, subject, agent, audience, tool, arguments],
                      sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(body.encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path):
        # Existing database only: a typo must not silently create an empty policy.
        from pathlib import Path
        self.uri = Path(path).resolve().as_uri() + '?mode=rw'

    @staticmethod
    def initialize(path):
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript('''
                CREATE TABLE approvals (
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                    approver TEXT NOT NULL, expires REAL NOT NULL,
                    consumed REAL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT NOT NULL, digest TEXT NOT NULL,
                    event TEXT NOT NULL, timestamp REAL NOT NULL);
            ''')

    def grant(self, subject, agent, audience, tool, arguments, approver, expires):
        digest = fingerprint(subject, agent, audience, tool, arguments)
        if not isinstance(approver, str) or not approver:
            raise ValueError('authenticated approver required')
        if not math.isfinite(expires) or expires <= time.time():
            raise ValueError('approval must expire in the future')
        aid = str(uuid.uuid4())
        with closing(sqlite3.connect(self.uri, uri=True)) as db, db:
            db.execute('INSERT INTO approvals(id,digest,approver,expires) VALUES(?,?,?,?)',
                       (aid, digest, approver, expires))
            db.execute('INSERT INTO audit(approval_id,digest,event,timestamp) VALUES(?,?,?,?)',
                       (aid, digest, 'granted', time.time()))
        return aid

    def revoke(self, aid):
        with closing(sqlite3.connect(self.uri, uri=True)) as db, db:
            db.execute('UPDATE approvals SET revoked=1 WHERE id=?', (aid,))
            db.execute("INSERT INTO audit(approval_id,digest,event,timestamp) "
                       "SELECT id,digest,'revoked',? FROM approvals WHERE id=?", (time.time(), aid))

    def consume(self, aid, subject, agent, audience, tool, arguments):
        digest = fingerprint(subject, agent, audience, tool, arguments)
        with closing(sqlite3.connect(self.uri, uri=True, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            now = time.time()
            updated = db.execute('UPDATE approvals SET consumed=? WHERE id=? AND digest=? '
                                 'AND expires>? AND consumed IS NULL AND revoked=0',
                                 (now, aid, digest, now)).rowcount
            # Authorization and the durable audit receipt commit together.
            db.execute('INSERT INTO audit(approval_id,digest,event,timestamp) VALUES(?,?,?,?)',
                       (aid, digest, 'consumed' if updated else 'denied', now))
        return updated == 1
