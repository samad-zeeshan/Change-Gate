
from __future__ import annotations

import copy
from dataclasses import replace
from typing import Optional, Protocol, runtime_checkable

from ..audit import AuditEntry, AuditLog
from ..data import seed
from ..domain.models import (
    ChangeRequest,
    ConfigValue,
    Environment,
    TenantContext,
)


class TenantNotFound(KeyError):
    pass


class CrossTenantAccess(PermissionError):
    pass


@runtime_checkable
class Repository(Protocol):
    tenant_id: str

    def get_tenant_context(self) -> TenantContext: ...
    def get_change_request(self, request_id: str) -> Optional[ChangeRequest]: ...
    def get_config_state(self, key: str, env: Environment) -> Optional[ConfigValue]: ...
    def apply_config_change(
        self, key: str, env: Environment, before: object, after: object
    ) -> ConfigValue: ...
    def append_audit(self, **fields) -> AuditEntry: ...


_REQUESTS: dict[tuple[str, str], ChangeRequest] = {
    (s.request.tenant_id, s.request.id): s.request for s in seed.SCENARIOS
}


class InMemoryRepository:

    def __init__(
        self,
        tenant_id: str,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        if tenant_id not in seed.TENANTS:
            raise TenantNotFound(tenant_id)
        self.tenant_id = tenant_id
        self._audit = audit_log if audit_log is not None else AuditLog()
        base = seed.TENANTS[tenant_id]
        self._config: dict[tuple[str, Environment], ConfigValue] = {
            k: v for k, v in base.config.items()
        }

    @property
    def audit_log(self) -> AuditLog:
        return self._audit

    def get_tenant_context(self) -> TenantContext:
        base = seed.TENANTS[self.tenant_id]
        return replace(base, config=dict(self._config))

    def get_change_request(self, request_id: str) -> Optional[ChangeRequest]:
        for (tid, rid), req in _REQUESTS.items():
            if rid == request_id:
                if tid != self.tenant_id:
                    raise CrossTenantAccess(
                        f"request {request_id!r} belongs to tenant {tid!r}, "
                        f"not {self.tenant_id!r}"
                    )
                return req
        return None

    def get_config_state(self, key: str, env: Environment) -> Optional[ConfigValue]:
        return self._config.get((key, env))

    def apply_config_change(
        self, key: str, env: Environment, before: object, after: object
    ) -> ConfigValue:
        existing = self._config.get((key, env))
        if existing is None:
            raise KeyError(f"unknown key {key!r} in {env.value!r}")
        updated = replace(existing, value=copy.copy(after))
        self._config[(key, env)] = updated
        return updated

    def append_audit(self, **fields) -> AuditEntry:
        fields.setdefault("tenant_id", self.tenant_id)
        if fields["tenant_id"] != self.tenant_id:
            raise CrossTenantAccess("cannot write an audit row for another tenant")
        return self._audit.append(**fields)
