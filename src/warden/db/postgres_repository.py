"""
Postgres-backed repository. Every read and write runs inside the tenant's RLS scope.

The audit insert continues the per-tenant hash chain from whatever the current head is.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, Optional

from ..audit import GENESIS_HASH, AuditEntry, compute_entry_hash, compute_evidence_hash
from ..domain.models import (
    ChangeKind,
    ChangePolicy,
    ChangeRecord,
    ChangeRequest,
    ConfigValue,
    DependencyGraph,
    Decision,
    Environment,
    FreezeWindow,
    IncidentRecord,
    Requester,
    Role,
    Service,
    TenantContext,
)


class PostgresRepository:

    def __init__(self, conn, tenant_id: str) -> None:
        self.conn = conn
        self.tenant_id = tenant_id

    @contextmanager
    def _tx_cursor(self) -> Iterator["object"]:
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                # The trailing true scopes this setting to the transaction. Every
                # query in the block is what current_tenant() in the RLS policies
                # reads, so the tenant must be set before any statement runs.
                cur.execute(
                    "SELECT set_config('app.current_tenant', %s, true)", (self.tenant_id,)
                )
                yield cur


    def get_tenant_context(self) -> TenantContext:
        return TenantContext(
            tenant_id=self.tenant_id,
            policy=self._policy(),
            graph=self._graph(),
            freeze_windows=self._freeze_windows(),
            config=self._config(),
            change_history=self._change_history(),
            incident_history=self._incident_history(),
        )

    def _policy(self) -> ChangePolicy:
        from ..domain.models import RiskBand

        with self._tx_cursor() as cur:
            cur.execute(
                "SELECT env_criticality, env_authority, factor_weights, band_low_max, "
                "band_medium_max, recency_lookback_days, magnitude_full_delta, "
                "blast_radius_saturation, auto_approve_max_band FROM policies"
            )
            row = cur.fetchone()
        ec, ea, fw, blm, bmm, lookback, mfd, brs, band = row
        return ChangePolicy(
            tenant_id=self.tenant_id,
            env_criticality={Environment(k): v for k, v in ec.items()},
            env_authority={
                Environment(k): frozenset(Role(r) for r in v) for k, v in ea.items()
            },
            factor_weights=dict(fw),
            band_low_max=blm,
            band_medium_max=bmm,
            recency_lookback_days=lookback,
            magnitude_full_delta=mfd,
            blast_radius_saturation=brs,
            auto_approve_max_band=RiskBand(band),
        )

    def _graph(self) -> DependencyGraph:
        with self._tx_cursor() as cur:
            cur.execute("SELECT id, name, traffic_fraction FROM services")
            services = {r[0]: Service(r[0], r[1], r[2]) for r in cur.fetchall()}
            cur.execute("SELECT service_id, depends_on_id FROM service_dependencies")
            dep_rows = cur.fetchall()
        deps: dict[str, set] = {sid: set() for sid in services}
        for sid, dep in dep_rows:
            deps.setdefault(sid, set()).add(dep)
        return DependencyGraph(
            services=services,
            depends_on={k: frozenset(v) for k, v in deps.items()},
        )

    def _config(self) -> dict:
        with self._tx_cursor() as cur:
            cur.execute("SELECT key, environment, kind, value FROM config_state")
            rows = cur.fetchall()
        out: dict = {}
        for key, env, kind, value in rows:
            out[(key, Environment(env))] = ConfigValue(
                key=key, environment=Environment(env), kind=ChangeKind(kind), value=value,
            )
        return out

    def _freeze_windows(self) -> list[FreezeWindow]:
        with self._tx_cursor() as cur:
            cur.execute(
                "SELECT id, name, start_ts, end_ts, environments, reason FROM freeze_windows"
            )
            rows = cur.fetchall()
        return [
            FreezeWindow(
                id=r[0], name=r[1], start=r[2], end=r[3],
                environments=frozenset(Environment(e) for e in r[4]),
                reason=r[5],
            )
            for r in rows
        ]

    def _change_history(self) -> list[ChangeRecord]:
        with self._tx_cursor() as cur:
            cur.execute(
                "SELECT service_id, key, environment, at_ts, decision FROM change_history"
            )
            rows = cur.fetchall()
        return [
            ChangeRecord(r[0], r[1], Environment(r[2]), r[3], Decision(r[4])) for r in rows
        ]

    def _incident_history(self) -> list[IncidentRecord]:
        with self._tx_cursor() as cur:
            cur.execute("SELECT service_id, at_ts, severity, resolved FROM incident_history")
            rows = cur.fetchall()
        return [IncidentRecord(r[0], r[1], r[2], r[3]) for r in rows]


    def get_change_request(self, request_id: str) -> Optional[ChangeRequest]:
        with self._tx_cursor() as cur:
            cur.execute(
                "SELECT id, requester_id, requester_role, service_id, key, kind, "
                "environment, current_value, proposed_value, window_start, window_end, "
                "description FROM change_requests WHERE id = %s",
                (request_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return ChangeRequest(
            id=row[0], tenant_id=self.tenant_id,
            requester=Requester(row[1], Role(row[2])),
            service_id=row[3], key=row[4], kind=ChangeKind(row[5]),
            environment=Environment(row[6]),
            current_value=row[7], proposed_value=row[8],
            window_start=row[9], window_end=row[10], description=row[11],
        )

    def get_config_state(self, key: str, env: Environment) -> Optional[ConfigValue]:
        with self._tx_cursor() as cur:
            cur.execute(
                "SELECT kind, value FROM config_state WHERE key = %s AND environment = %s",
                (key, env.value),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return ConfigValue(key=key, environment=env, kind=ChangeKind(row[0]), value=row[1])

    def apply_config_change(
        self, key: str, env: Environment, before: object, after: object
    ) -> ConfigValue:
        with self._tx_cursor() as cur:
            cur.execute(
                "UPDATE config_state SET value = %s WHERE key = %s AND environment = %s "
                "RETURNING kind, value",
                (json.dumps(after), key, env.value),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError(f"unknown key {key!r} in {env.value!r}")
            kind, value = row[0], row[1]
        return ConfigValue(key=key, environment=env, kind=ChangeKind(kind), value=value)


    def append_audit(self, **f) -> AuditEntry:
        ts: datetime = f["timestamp"]
        with self._tx_cursor() as cur:
            # Read the current chain head inside the same transaction that writes
            # the new row. RLS already scopes this to one tenant, so the head is
            # this tenant's last entry, and the genesis hash seeds an empty log.
            cur.execute("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            head = cur.fetchone()
            prev_hash = head[1] if head else GENESIS_HASH
            seq = (head[0] + 1) if head else 1
            payload = {
                "seq": seq,
                "tenant_id": self.tenant_id,
                "subject": f["subject"],
                "action": f["action"],
                "environment": f["environment"],
                "decision": f["decision"],
                "risk_band": f["risk_band"],
                "risk_score": f["risk_score"],
                "before": f["before"],
                "after": f["after"],
                "reason": f["reason"],
                "risk_breakdown": f["risk_breakdown"],
                "request_id": f["request_id"],
                "trace_id": f.get("trace_id", ""),
                "timestamp": ts.isoformat(),
                "evidence": f.get("evidence") or {},
                "evidence_hash": compute_evidence_hash(f.get("evidence") or {}),
            }
            entry_hash = compute_entry_hash(prev_hash, payload)
            cur.execute(
                "INSERT INTO audit_log(tenant_id, seq, subject, action, environment, "
                "decision, risk_band, risk_score, before_val, after_val, reason, "
                "risk_breakdown, request_id, trace_id, ts, prev_hash, entry_hash, evidence, "
                "evidence_hash) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    self.tenant_id, seq, f["subject"], f["action"], f["environment"],
                    f["decision"], f["risk_band"], f["risk_score"],
                    json.dumps(f["before"]), json.dumps(f["after"]), f["reason"],
                    json.dumps(f["risk_breakdown"]), f["request_id"], f.get("trace_id", ""),
                    ts, prev_hash, entry_hash,
                    json.dumps(payload["evidence"], default=str), payload["evidence_hash"],
                ),
            )
        return AuditEntry(**payload, prev_hash=prev_hash, entry_hash=entry_hash)


    _AUDIT_COLUMNS = (
        "SELECT seq, subject, action, environment, decision, risk_band, risk_score, "
        "before_val, after_val, reason, risk_breakdown, request_id, trace_id, ts, "
        "prev_hash, entry_hash, evidence, evidence_hash FROM audit_log "
    )

    def _entry(self, r) -> AuditEntry:
        return AuditEntry(
            seq=r[0], tenant_id=self.tenant_id, subject=r[1], action=r[2],
            environment=r[3], decision=r[4], risk_band=r[5], risk_score=r[6],
            before=r[7], after=r[8], reason=r[9], risk_breakdown=r[10],
            request_id=r[11], trace_id=r[12], timestamp=r[13].isoformat(),
            prev_hash=r[14], entry_hash=r[15], evidence=r[16], evidence_hash=r[17],
        )

    def audit_entries(self, request_id: str) -> list[AuditEntry]:
        # RLS scopes this to the bound tenant, same as every other read.
        with self._tx_cursor() as cur:
            cur.execute(self._AUDIT_COLUMNS + "WHERE request_id = %s ORDER BY seq",
                        (request_id,))
            rows = cur.fetchall()
        return [self._entry(r) for r in rows]

    def audit_log_entries(self) -> list[AuditEntry]:
        with self._tx_cursor() as cur:
            cur.execute(self._AUDIT_COLUMNS + "ORDER BY seq")
            rows = cur.fetchall()
        return [self._entry(r) for r in rows]

    def latest_audit(self, action: str) -> Optional[AuditEntry]:
        with self._tx_cursor() as cur:
            cur.execute(self._AUDIT_COLUMNS + "WHERE action = %s ORDER BY seq DESC LIMIT 1",
                        (action,))
            row = cur.fetchone()
        return self._entry(row) if row else None


def connect(dsn: str, tenant_id: str) -> PostgresRepository:
    import psycopg

    conn = psycopg.connect(dsn)
    return PostgresRepository(conn, tenant_id)
