"""SQLite-backed state for the prototype. Replaces the earlier pure
in-memory Store, which lost all enrollment/approval state on every process
restart -- a real bug hit during Android device testing, where a server
restart silently orphaned an already-enrolled phone's locally-cached
device_id. Still prototype-scope (one file, one process, no migrations),
just one that survives a restart.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import sqlite3
import threading

from .models import ApprovalStatus, EnrolledDevice, PendingApproval, PendingEnrollment

# A challenge older than this is treated as unknown, so stale attestation evidence cannot be replayed.
ENROLLMENT_CHALLENGE_TTL = dt.timedelta(minutes=10)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL CHECK(platform IN ('android','ios')),
    challenge BLOB NOT NULL,
    created_at TEXT NOT NULL,
    ios_round TEXT,
    ios_key_id TEXT,
    ios_attestation_public_key BLOB,
    ios_receipt BLOB,
    ios_binding_challenge BLOB
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL CHECK(platform IN ('android','ios')),
    public_key_pem TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    package_name TEXT,
    certificate_sha256 TEXT,
    attestation_chain_json TEXT,
    ios_key_id TEXT,
    ios_receipt_b64 TEXT,
    ios_assertion_counter INTEGER,
    status TEXT NOT NULL DEFAULT 'pending_manual_approval',
    approved_at TEXT,
    approved_by TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    ref TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    request_text TEXT NOT NULL,
    rendered_message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    signature_b64 TEXT,
    completed_at TEXT,
    rejection_reasons TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_approvals_device ON approvals(device_id);
"""


def _iso(value: dt.datetime) -> str:
    return value.isoformat()


def _parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


class Store:
    def __init__(self, db_path: str = ":memory:"):
        self._lock = threading.Lock()
        # check_same_thread=False: FastAPI's sync routes run in a threadpool,
        # so different requests may land on different threads. Every access
        # still goes through self._lock below, so there's no concurrent use
        # of the connection -- just use from more than one thread over time.
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._migrate_devices_table()

    def _migrate_devices_table(self) -> None:
        """Add approval metadata to databases created before manual approval."""
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "status" not in columns:
            self._conn.execute(
                "ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'pending_manual_approval'"
            )
        if "attestation_chain_json" not in columns:
            self._conn.execute("ALTER TABLE devices ADD COLUMN attestation_chain_json TEXT")
        if "approved_at" not in columns:
            self._conn.execute("ALTER TABLE devices ADD COLUMN approved_at TEXT")
        if "approved_by" not in columns:
            self._conn.execute("ALTER TABLE devices ADD COLUMN approved_by TEXT")

    # --- enrollment ---

    def begin_enrollment(self, platform: str) -> PendingEnrollment:
        enrollment = PendingEnrollment(
            enrollment_id=secrets.token_urlsafe(16),
            platform=platform,
            challenge=secrets.token_bytes(32),
            created_at=dt.datetime.now(dt.timezone.utc),
            ios_round="awaiting_attestation" if platform == "ios" else None,
        )
        with self._lock:
            self._conn.execute(
                """INSERT INTO pending_enrollments
                   (enrollment_id, platform, challenge, created_at, ios_round)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    enrollment.enrollment_id,
                    enrollment.platform,
                    enrollment.challenge,
                    _iso(enrollment.created_at),
                    enrollment.ios_round,
                ),
            )
        return enrollment

    def get_enrollment(self, enrollment_id: str) -> PendingEnrollment | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM pending_enrollments WHERE enrollment_id = ?", (enrollment_id,)
            ).fetchone()
        if row is None:
            return None
        enrollment = self._enrollment_from_row(row)
        if dt.datetime.now(dt.timezone.utc) - enrollment.created_at > ENROLLMENT_CHALLENGE_TTL:
            return None
        return enrollment

    def advance_ios_enrollment(
        self,
        enrollment_id: str,
        *,
        key_id: str,
        attestation_public_key_der: bytes,
        receipt: bytes,
        binding_challenge: bytes,
    ) -> None:
        """Save verified App Attest evidence and issue a confirmation-key binding challenge."""
        with self._lock:
            self._conn.execute(
                """UPDATE pending_enrollments SET
                   ios_round = 'awaiting_binding', ios_key_id = ?,
                   ios_attestation_public_key = ?, ios_receipt = ?, ios_binding_challenge = ?
                   WHERE enrollment_id = ?""",
                (key_id, attestation_public_key_der, receipt, binding_challenge, enrollment_id),
            )

    def consume_enrollment(self, enrollment_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM pending_enrollments WHERE enrollment_id = ?", (enrollment_id,))

    @staticmethod
    def _enrollment_from_row(row: sqlite3.Row) -> PendingEnrollment:
        return PendingEnrollment(
            enrollment_id=row["enrollment_id"],
            platform=row["platform"],
            challenge=bytes(row["challenge"]),
            created_at=_parse_iso(row["created_at"]),
            ios_round=row["ios_round"],
            ios_key_id=row["ios_key_id"],
            ios_attestation_public_key_der=bytes(row["ios_attestation_public_key"])
            if row["ios_attestation_public_key"] is not None
            else None,
            ios_receipt=bytes(row["ios_receipt"]) if row["ios_receipt"] is not None else None,
            ios_binding_challenge=bytes(row["ios_binding_challenge"])
            if row["ios_binding_challenge"] is not None
            else None,
        )

    def add_device(self, device: EnrolledDevice) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO devices
                   (device_id, platform, public_key_pem, enrolled_at, package_name,
                    certificate_sha256, attestation_chain_json, ios_key_id, ios_receipt_b64,
                    ios_assertion_counter, status, approved_at, approved_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device.device_id,
                    device.platform,
                    device.public_key_pem,
                    _iso(device.enrolled_at),
                    device.package_name,
                    device.certificate_sha256,
                    json.dumps(device.attestation_chain_der_b64)
                    if device.attestation_chain_der_b64 is not None
                    else None,
                    device.ios_key_id,
                    device.ios_receipt_b64,
                    device.ios_assertion_counter,
                    device.status,
                    _iso(device.approved_at) if device.approved_at else None,
                    device.approved_by,
                ),
            )

    def get_device(self, device_id: str, *, include_pending: bool = False) -> EnrolledDevice | None:
        with self._lock:
            query = "SELECT * FROM devices WHERE device_id = ?"
            params: tuple = (device_id,)
            if not include_pending:
                query += " AND status = 'approved'"
            row = self._conn.execute(query, params).fetchone()
        return self._device_from_row(row) if row is not None else None

    def list_devices(self, *, include_pending: bool = False) -> list[EnrolledDevice]:
        with self._lock:
            query = "SELECT * FROM devices"
            if not include_pending:
                query += " WHERE status = 'approved'"
            rows = self._conn.execute(query).fetchall()
        return [self._device_from_row(row) for row in rows]

    def approve_device(self, device_id: str, administrator: str) -> EnrolledDevice | None:
        approved_at = dt.datetime.now(dt.timezone.utc)
        with self._lock:
            changed = self._conn.execute(
                """UPDATE devices SET status='approved', approved_at=?, approved_by=?
                   WHERE device_id=? AND status='pending_manual_approval'""",
                (_iso(approved_at), administrator, device_id),
            ).rowcount
            if changed != 1:
                return None
            row = self._conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        return self._device_from_row(row)

    @staticmethod
    def _device_from_row(row: sqlite3.Row) -> EnrolledDevice:
        return EnrolledDevice(
            device_id=row["device_id"],
            platform=row["platform"],
            public_key_pem=row["public_key_pem"],
            enrolled_at=_parse_iso(row["enrolled_at"]),
            package_name=row["package_name"],
            certificate_sha256=row["certificate_sha256"],
            attestation_chain_der_b64=json.loads(row["attestation_chain_json"])
            if row["attestation_chain_json"]
            else None,
            ios_key_id=row["ios_key_id"],
            ios_receipt_b64=row["ios_receipt_b64"],
            ios_assertion_counter=row["ios_assertion_counter"],
            status=row["status"],
            approved_at=_parse_iso(row["approved_at"]) if row["approved_at"] else None,
            approved_by=row["approved_by"],
        )

    # --- approvals ---

    def create_approval(self, approval: PendingApproval) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO approvals
                   (ref, device_id, request_text, rendered_message, created_at, expires_at,
                    status, signature_b64, completed_at, rejection_reasons)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                self._approval_params(approval),
            )

    def get_approval(self, ref: str) -> PendingApproval | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM approvals WHERE ref = ?", (ref,)).fetchone()
        return self._approval_from_row(row) if row is not None else None

    def list_approvals_for_device(self, device_id: str) -> list[PendingApproval]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM approvals WHERE device_id = ?", (device_id,)).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def update_approval(self, approval: PendingApproval) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE approvals SET
                   device_id = ?, request_text = ?, rendered_message = ?, created_at = ?,
                   expires_at = ?, status = ?, signature_b64 = ?, completed_at = ?, rejection_reasons = ?
                   WHERE ref = ?""",
                (*self._approval_params(approval)[1:], approval.ref),
            )

    def consume_pending_approval(self, approval: PendingApproval) -> bool:
        """Atomically resolves a pending approval exactly once."""
        with self._lock:
            changed = self._conn.execute(
                """UPDATE approvals SET
                   device_id = ?, request_text = ?, rendered_message = ?, created_at = ?,
                   expires_at = ?, status = ?, signature_b64 = ?, completed_at = ?, rejection_reasons = ?
                   WHERE ref = ? AND status = 'pending'""",
                (*self._approval_params(approval)[1:], approval.ref),
            ).rowcount
        return changed == 1

    @staticmethod
    def _approval_params(approval: PendingApproval) -> tuple:
        return (
            approval.ref,
            approval.device_id,
            approval.request_text,
            approval.rendered_message,
            _iso(approval.created_at),
            _iso(approval.expires_at),
            approval.status.value,
            approval.signature_b64,
            _iso(approval.completed_at) if approval.completed_at else None,
            json.dumps(approval.rejection_reasons),
        )

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> PendingApproval:
        return PendingApproval(
            ref=row["ref"],
            device_id=row["device_id"],
            request_text=row["request_text"],
            rendered_message=row["rendered_message"],
            created_at=_parse_iso(row["created_at"]),
            expires_at=_parse_iso(row["expires_at"]),
            status=ApprovalStatus(row["status"]),
            signature_b64=row["signature_b64"],
            completed_at=_parse_iso(row["completed_at"]) if row["completed_at"] else None,
            rejection_reasons=json.loads(row["rejection_reasons"]),
        )
