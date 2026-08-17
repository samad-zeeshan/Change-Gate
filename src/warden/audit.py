"""
Hash-chained audit log. Each entry commits to the previous one, per tenant.

Editing any past entry changes its hash and breaks every entry after it, which
verify_chain detects.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Stand-in "previous hash" for the first entry in a tenant's chain.
GENESIS_HASH = "0" * 64


def compute_entry_hash(prev_hash: str, payload: dict) -> str:
    # Fold the previous hash into this one so entries form a chain, not independent
    # hashes. Canonical JSON keeps the digest stable across dict ordering.
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}\n{blob}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    tenant_id: str
    subject: str
    action: str
    environment: str
    decision: str
    risk_band: str
    risk_score: float
    before: object
    after: object
    reason: str
    risk_breakdown: dict
    request_id: str
    trace_id: str
    timestamp: str
    prev_hash: str
    entry_hash: str

    def chained_payload(self) -> dict:
        return {
            "seq": self.seq,
            "tenant_id": self.tenant_id,
            "subject": self.subject,
            "action": self.action,
            "environment": self.environment,
            "decision": self.decision,
            "risk_band": self.risk_band,
            "risk_score": self.risk_score,
            "before": self.before,
            "after": self.after,
            "reason": self.reason,
            "risk_breakdown": self.risk_breakdown,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
        }


class AuditLog:

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def head_hash(self, tenant_id: str) -> str:
        for entry in reversed(self._entries):
            if entry.tenant_id == tenant_id:
                return entry.entry_hash
        return GENESIS_HASH

    def next_seq(self, tenant_id: str) -> int:
        return sum(1 for e in self._entries if e.tenant_id == tenant_id) + 1

    def append(
        self,
        *,
        tenant_id: str,
        subject: str,
        action: str,
        environment: str,
        decision: str,
        risk_band: str,
        risk_score: float,
        before: object,
        after: object,
        reason: str,
        risk_breakdown: dict,
        request_id: str,
        trace_id: str,
        timestamp: datetime,
    ) -> AuditEntry:
        prev = self.head_hash(tenant_id)
        seq = self.next_seq(tenant_id)
        payload = {
            "seq": seq,
            "tenant_id": tenant_id,
            "subject": subject,
            "action": action,
            "environment": environment,
            "decision": decision,
            "risk_band": risk_band,
            "risk_score": risk_score,
            "before": before,
            "after": after,
            "reason": reason,
            "risk_breakdown": risk_breakdown,
            "request_id": request_id,
            "trace_id": trace_id,
            "timestamp": timestamp.isoformat(),
        }
        entry_hash = compute_entry_hash(prev, payload)
        entry = AuditEntry(
            **payload, prev_hash=prev, entry_hash=entry_hash
        )
        self._entries.append(entry)
        return entry

    def for_tenant(self, tenant_id: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.tenant_id == tenant_id]

    def verify_chain(self, tenant_id: Optional[str] = None) -> bool:
        prev_by_tenant: dict[str, str] = {}
        seq_by_tenant: dict[str, int] = {}
        # Chains are independent per tenant, so track the running prev hash and seq
        # separately for each one rather than assuming a single global order.
        for entry in self._entries:
            if tenant_id is not None and entry.tenant_id != tenant_id:
                continue
            expected_prev = prev_by_tenant.get(entry.tenant_id, GENESIS_HASH)
            if entry.prev_hash != expected_prev:
                return False
            expected_seq = seq_by_tenant.get(entry.tenant_id, 0) + 1
            if entry.seq != expected_seq:
                return False
            recomputed = compute_entry_hash(entry.prev_hash, entry.chained_payload())
            if recomputed != entry.entry_hash:
                return False
            prev_by_tenant[entry.tenant_id] = entry.entry_hash
            seq_by_tenant[entry.tenant_id] = entry.seq
        return True
