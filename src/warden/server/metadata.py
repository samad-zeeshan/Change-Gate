"""OAuth protected-resource metadata, so clients can find the authorization server."""

from __future__ import annotations

from ..security import ALL_SCOPES


def protected_resource_metadata(resource: str, authorization_server: str) -> dict:
    return {
        "resource": resource,
        "authorization_servers": [authorization_server],
        "scopes_supported": list(ALL_SCOPES),
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{resource}/docs",
    }


def well_known_path() -> str:
    return "/.well-known/oauth-protected-resource"
