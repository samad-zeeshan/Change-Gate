
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    tenant_id                TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
    env_criticality          JSONB NOT NULL,
    env_authority            JSONB NOT NULL,
    factor_weights           JSONB NOT NULL,
    band_low_max             DOUBLE PRECISION NOT NULL,
    band_medium_max          DOUBLE PRECISION NOT NULL,
    recency_lookback_days    INT NOT NULL,
    magnitude_full_delta     DOUBLE PRECISION NOT NULL,
    blast_radius_saturation  INT NOT NULL,
    auto_approve_max_band    TEXT NOT NULL DEFAULT 'low'
);

CREATE TABLE IF NOT EXISTS services (
    tenant_id         TEXT NOT NULL REFERENCES tenants(tenant_id),
    id                TEXT NOT NULL,
    name              TEXT NOT NULL,
    traffic_fraction  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS service_dependencies (
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id),
    service_id     TEXT NOT NULL,
    depends_on_id  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, service_id, depends_on_id)
);

CREATE TABLE IF NOT EXISTS config_state (
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    key          TEXT NOT NULL,
    environment  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    value        JSONB NOT NULL,
    PRIMARY KEY (tenant_id, key, environment)
);

CREATE TABLE IF NOT EXISTS freeze_windows (
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id),
    id            TEXT NOT NULL,
    name          TEXT NOT NULL,
    start_ts      TIMESTAMPTZ NOT NULL,
    end_ts        TIMESTAMPTZ NOT NULL,
    environments  TEXT[] NOT NULL DEFAULT '{}',
    reason        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS change_history (
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq          BIGSERIAL,
    service_id   TEXT NOT NULL,
    key          TEXT NOT NULL,
    environment  TEXT NOT NULL,
    at_ts        TIMESTAMPTZ NOT NULL,
    decision     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS incident_history (
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq          BIGSERIAL,
    service_id   TEXT NOT NULL,
    at_ts        TIMESTAMPTZ NOT NULL,
    severity     TEXT NOT NULL,
    resolved     BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS change_requests (
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id),
    id              TEXT NOT NULL,
    requester_id    TEXT NOT NULL,
    requester_role  TEXT NOT NULL,
    service_id      TEXT NOT NULL,
    key             TEXT NOT NULL,
    kind            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    current_value   JSONB NOT NULL,
    proposed_value  JSONB NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq             BIGINT NOT NULL,
    subject         TEXT NOT NULL,
    action          TEXT NOT NULL,
    environment     TEXT NOT NULL,
    decision        TEXT NOT NULL,
    risk_band       TEXT NOT NULL,
    risk_score      DOUBLE PRECISION NOT NULL,
    before_val      JSONB,
    after_val       JSONB,
    reason          TEXT NOT NULL,
    risk_breakdown  JSONB NOT NULL,
    request_id      TEXT NOT NULL,
    trace_id        TEXT NOT NULL DEFAULT '',
    ts              TIMESTAMPTZ NOT NULL,
    prev_hash       TEXT NOT NULL,
    entry_hash      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_seq ON audit_log (tenant_id, seq);
CREATE INDEX IF NOT EXISTS idx_deps_tenant ON service_dependencies (tenant_id, depends_on_id);
