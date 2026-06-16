
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    pg_dsn: str = os.getenv(
        "CHANGE_GATE_PG_DSN",
        "postgresql://change_gate_app:app_password@postgres:5432/change_gate",
    )

    issuer: str = os.getenv("CHANGE_GATE_ISSUER", "http://keycloak:8080/realms/change-gate")
    jwks_uri: str = os.getenv(
        "CHANGE_GATE_JWKS_URI",
        "http://keycloak:8080/realms/change-gate/protocol/openid-connect/certs",
    )
    resource_url: str = os.getenv("CHANGE_GATE_RESOURCE_URL", "http://localhost:9000/mcp")
    leeway_seconds: int = int(os.getenv("CHANGE_GATE_LEEWAY", "30"))

    host: str = os.getenv("CHANGE_GATE_HOST", "0.0.0.0")
    port: int = int(os.getenv("CHANGE_GATE_PORT", "9000"))

    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "change-gate-mcp")

    now_override: str = os.getenv("CHANGE_GATE_NOW", "")


def settings() -> Settings:
    return Settings()
