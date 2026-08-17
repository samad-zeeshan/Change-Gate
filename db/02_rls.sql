-- Row level security for tenant isolation and an append-only audit log.
-- The app connects as warden_app, which deliberately cannot bypass RLS.

-- NOBYPASSRLS is the whole point. If the app role could bypass RLS, a bug in a
-- WHERE clause would leak across tenants. The policies below become the backstop.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_app') THEN
        CREATE ROLE warden_app LOGIN PASSWORD 'app_password'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END$$;

ALTER ROLE warden_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT USAGE ON SCHEMA public TO warden_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenants, policies, services, service_dependencies, config_state,
    freeze_windows, change_history, incident_history, change_requests
TO warden_app;

GRANT SELECT, INSERT ON audit_log TO warden_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO warden_app;

-- Reads the tenant the app set for this connection via set_config. The second
-- arg (true) makes it return NULL instead of erroring when unset, which means an
-- unscoped connection matches no rows rather than throwing.
CREATE OR REPLACE FUNCTION current_tenant() RETURNS TEXT AS $$
    SELECT current_setting('app.current_tenant', true);
$$ LANGUAGE sql STABLE;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenants','policies','services','service_dependencies','config_state',
        'freeze_windows','change_history','incident_history','change_requests','audit_log'
    ] LOOP
        -- FORCE applies RLS to the table owner too, not just ordinary roles.
        -- Without it, whoever owns the table would quietly skip every policy.
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY;', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I;', t);
        IF t = 'tenants' THEN
            EXECUTE format($f$
                CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = current_tenant())
                WITH CHECK (tenant_id = current_tenant());
            $f$, t);
        ELSE
            EXECUTE format($f$
                CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = current_tenant())
                WITH CHECK (tenant_id = current_tenant());
            $f$, t);
        END IF;
    END LOOP;
END$$;

-- The audit log is the integrity record, so updates and deletes are blocked at
-- the database. Even the app role can only insert. Tampering has to break the
-- hash chain in audit.py, which verify_chain will catch.
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
