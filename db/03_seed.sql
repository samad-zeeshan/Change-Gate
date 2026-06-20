BEGIN;
INSERT INTO tenants(tenant_id, name) VALUES ('acme', 'Acme Corp') ON CONFLICT DO NOTHING;
INSERT INTO policies(tenant_id, env_criticality, env_authority, factor_weights, band_low_max, band_medium_max, recency_lookback_days, magnitude_full_delta, blast_radius_saturation, auto_approve_max_band) VALUES (
  'acme',
  '{"dev": 0.2, "staging": 0.6, "prod": 1.0}',
  '{"dev": ["developer", "lead", "oncall"], "staging": ["lead", "oncall"], "prod": ["lead", "oncall"]}',
  '{"blast_radius": 0.35, "environment_criticality": 0.3, "magnitude": 0.2, "recency": 0.15}',
  30.0, 65.0, 14, 0.5, 5, 'low'
) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'gateway', 'API Gateway', 0.9) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'auth', 'Auth Service', 0.5) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'catalog', 'Catalog Service', 0.6) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'search', 'Search Service', 0.3) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'db-core', 'Core Database', 0.2) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'payments', 'Payments Service', 0.4) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'ledger', 'Ledger Service', 0.1) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('acme', 'notifications', 'Notifications', 0.05) ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'gateway', 'auth') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'gateway', 'catalog') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'auth', 'db-core') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'catalog', 'db-core') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'catalog', 'search') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'search', 'db-core') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'payments', 'auth') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'payments', 'ledger') ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('acme', 'notifications', 'auth') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('acme', 'beta_banner', 'dev', 'flag', 'false') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('acme', 'checkout_v2', 'prod', 'flag', 'false') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('acme', 'db_pool_size', 'prod', 'config', '20') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('acme', 'fraud_threshold', 'staging', 'config', '100.0') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('acme', 'search_timeout_ms', 'dev', 'config', '200') ON CONFLICT DO NOTHING;
INSERT INTO freeze_windows(tenant_id, id, name, start_ts, end_ts, environments, reason) VALUES ('acme', 'acme-freeze-1', 'mid-year-prod-freeze', '2026-06-20T00:00:00+00:00', '2026-06-30T00:00:00+00:00', '{"prod"}', 'Mid-year revenue period: prod changes frozen.') ON CONFLICT DO NOTHING;
INSERT INTO incident_history(tenant_id, service_id, at_ts, severity, resolved) VALUES ('acme', 'payments', '2026-06-20T00:00:00+00:00', 'sev1', true);
INSERT INTO incident_history(tenant_id, service_id, at_ts, severity, resolved) VALUES ('acme', 'search', '2026-01-05T00:00:00+00:00', 'sev2', true);
INSERT INTO change_history(tenant_id, service_id, key, environment, at_ts, decision) VALUES ('acme', 'db-core', 'db_pool_size', 'prod', '2026-03-01T00:00:00+00:00', 'auto_approve');
INSERT INTO tenants(tenant_id, name) VALUES ('globex', 'Globex Inc') ON CONFLICT DO NOTHING;
INSERT INTO policies(tenant_id, env_criticality, env_authority, factor_weights, band_low_max, band_medium_max, recency_lookback_days, magnitude_full_delta, blast_radius_saturation, auto_approve_max_band) VALUES (
  'globex',
  '{"dev": 0.2, "staging": 0.5, "prod": 1.0}',
  '{"dev": ["developer", "lead"], "staging": ["lead"], "prod": ["lead"]}',
  '{"blast_radius": 0.3, "environment_criticality": 0.4, "magnitude": 0.2, "recency": 0.1}',
  25.0, 60.0, 7, 0.5, 3, 'low'
) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('globex', 'edge', 'Edge Proxy', 0.8) ON CONFLICT DO NOTHING;
INSERT INTO services(tenant_id, id, name, traffic_fraction) VALUES ('globex', 'billing', 'Billing', 0.5) ON CONFLICT DO NOTHING;
INSERT INTO service_dependencies(tenant_id, service_id, depends_on_id) VALUES ('globex', 'edge', 'billing') ON CONFLICT DO NOTHING;
INSERT INTO config_state(tenant_id, key, environment, kind, value) VALUES ('globex', 'dark_mode', 'prod', 'flag', 'false') ON CONFLICT DO NOTHING;
INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, key, kind, environment, current_value, proposed_value, window_start, window_end) VALUES (
  'acme', 'cr-001', 'u-dev', 'developer',
  'notifications', 'beta_banner', 'flag', 'dev',
  'false', 'true', '2026-06-26T00:00:00+00:00', '2026-06-26T02:00:00+00:00'
) ON CONFLICT DO NOTHING;
INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, key, kind, environment, current_value, proposed_value, window_start, window_end) VALUES (
  'acme', 'cr-002', 'u-lead', 'lead',
  'db-core', 'db_pool_size', 'config', 'prod',
  '20', '40', '2026-07-05T00:00:00+00:00', '2026-07-05T01:00:00+00:00'
) ON CONFLICT DO NOTHING;
INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, key, kind, environment, current_value, proposed_value, window_start, window_end) VALUES (
  'acme', 'cr-003', 'u-lead', 'lead',
  'gateway', 'checkout_v2', 'flag', 'prod',
  'false', 'true', '2026-06-26T00:00:00+00:00', '2026-06-26T01:00:00+00:00'
) ON CONFLICT DO NOTHING;
INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, key, kind, environment, current_value, proposed_value, window_start, window_end) VALUES (
  'acme', 'cr-004', 'u-dev', 'developer',
  'gateway', 'checkout_v2', 'flag', 'prod',
  'false', 'true', '2026-07-05T00:00:00+00:00', '2026-07-05T01:00:00+00:00'
) ON CONFLICT DO NOTHING;
INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, key, kind, environment, current_value, proposed_value, window_start, window_end) VALUES (
  'acme', 'cr-005', 'u-lead', 'lead',
  'payments', 'fraud_threshold', 'config', 'staging',
  '100.0', '110.0', '2026-06-26T00:00:00+00:00', '2026-06-26T01:00:00+00:00'
) ON CONFLICT DO NOTHING;
COMMIT;
