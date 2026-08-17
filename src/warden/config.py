"""Server settings read from WARDEN_* environment variables."""


from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    pg_dsn: str = os.getenv(
        "WARDEN_PG_DSN",
        "postgresql://warden_app:app_password@postgres:5432/warden",
    )

    issuer: str = os.getenv("WARDEN_ISSUER", "http://keycloak:8080/realms/warden")
    jwks_uri: str = os.getenv(
        "WARDEN_JWKS_URI",
        "http://keycloak:8080/realms/warden/protocol/openid-connect/certs",
    )
    resource_url: str = os.getenv("WARDEN_RESOURCE_URL", "http://localhost:9000/mcp")
    leeway_seconds: int = int(os.getenv("WARDEN_LEEWAY", "30"))

    host: str = os.getenv("WARDEN_HOST", "0.0.0.0")
    port: int = int(os.getenv("WARDEN_PORT", "9000"))

    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "warden-mcp")

    now_override: str = os.getenv("WARDEN_NOW", "")

    # PEM file for the task-credential signing key. Unset means a fresh key per
    # process, which is fine for one server but breaks if several share traffic.
    task_key_file: str = os.getenv("WARDEN_TASK_KEY_FILE", "")

    def task_key(self):
        if not self.task_key_file:
            return None
        from cryptography.hazmat.primitives import serialization

        with open(self.task_key_file, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)


def settings() -> Settings:
    return Settings()
