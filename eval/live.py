"""Red-team transport against live Keycloak and Postgres, with the production server in between.

Needs WARDEN_LIVE_ISSUER, WARDEN_PG_DSN and WARDEN_PG_ADMIN_DSN. The CI job starts both services with docker compose.
"""

from __future__ import annotations

import html
import json
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Optional
from urllib.parse import parse_qs, urlparse

import httpx

from eval.redteam import FOREIGN_REQUEST, _SEED_BY_ID, _TEMPLATE_SOURCE, Actor
from warden.agent.mcp_client import MCPToolClient, fetch_task_credential
from warden.agent.oauth import (
    authorize_endpoint_from_issuer,
    build_authorization_url,
    exchange_code_for_token,
    fetch_token_client_credentials,
    generate_pkce,
    token_endpoint_from_issuer,
)
from warden.audit import AuditEntry, verify_entries
from warden.data import seed
from warden.db.postgres_repository import connect
from warden.domain.models import Requester
from warden.personas import PersonaMap
from warden.security import BINDING_REQUEST, SCOPE_APPROVE, SCOPE_APPROVE_PROD, SCOPE_READ
from warden.sessions import RoleSessions

# The realm export's audience mapper puts this in every token, so the server must
# claim exactly this resource even though it listens on 127.0.0.1.
RESOURCE = "http://localhost:9000/mcp"
CONSOLE_REDIRECT = "http://127.0.0.1:9099/callback"
# Throwaway demo credentials from keycloak/realm-export.json. They exist only in
# the local and CI realm.
AGENT = ("warden-agent", "agent-secret")
APPROVER = ("alice", "alice-demo")
REQUESTER = ("dev-bob", "bob-demo")


def pkce_login(issuer: str, username: str, password: str, scopes: list[str]) -> str:
    """Authorization code with PKCE, driven through Keycloak's own login form."""
    pkce = generate_pkce()
    url = build_authorization_url(
        authorize_endpoint_from_issuer(issuer), client_id="warden-console",
        redirect_uri=CONSOLE_REDIRECT, scopes=scopes, resource=RESOURCE, pkce=pkce,
        state="live-redteam")
    with httpx.Client(follow_redirects=True, timeout=20) as client:
        page = client.get(url)
        page.raise_for_status()
        action = login_form_action(page.text)
        # Nothing listens on the redirect URI, so the code is read off the
        # Location header instead of following it.
        # http.cookiejar will not send cookies set for a bare "localhost" host, so
        # Keycloak's session cookies go back by hand or it answers cookie_not_found.
        cookie = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
        resp = client.post(action, data={"username": username, "password": password},
                           headers={"Cookie": cookie}, follow_redirects=False)
    location = resp.headers.get("location", "")
    code = parse_qs(urlparse(location).query).get("code", [""])[0]
    if not code:
        raise RuntimeError(f"login for {username} returned no code ({resp.status_code})")
    tokens = exchange_code_for_token(token_endpoint_from_issuer(issuer),
                                     client_id="warden-console", code=code,
                                     redirect_uri=CONSOLE_REDIRECT, resource=RESOURCE,
                                     pkce=pkce)
    return tokens["access_token"]


def login_form_action(page: str) -> str:
    match = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page) or \
        re.search(r'<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"', page)
    if not match:
        raise RuntimeError("Keycloak login form not found")
    return html.unescape(match.group(1))


def _sub(token: str) -> str:
    import jwt

    return jwt.decode(token, options={"verify_signature": False})["sub"]


# ------------------------------------------------------------------------ the world


class LiveAudit:
    """The Postgres audit table read as the admin role, which bypasses RLS."""

    def __init__(self, admin_dsn: str) -> None:
        self.admin_dsn = admin_dsn

    def _rows(self) -> list[AuditEntry]:
        import psycopg

        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT tenant_id, seq, subject, action, environment, decision, risk_band, "
                "risk_score, before_val, after_val, reason, risk_breakdown, request_id, "
                "trace_id, ts, prev_hash, entry_hash, evidence, evidence_hash "
                "FROM audit_log ORDER BY tenant_id, seq")
            rows = cur.fetchall()
        return [AuditEntry(
            tenant_id=r[0], seq=r[1], subject=r[2], action=r[3], environment=r[4],
            decision=r[5], risk_band=r[6], risk_score=r[7], before=r[8], after=r[9],
            reason=r[10], risk_breakdown=r[11], request_id=r[12], trace_id=r[13],
            timestamp=r[14].isoformat(), prev_hash=r[15], entry_hash=r[16],
            evidence=r[17], evidence_hash=r[18]) for r in rows]

    def __len__(self) -> int:
        return len(self._rows())

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._rows())

    def verify_chain(self, tenant_id: Optional[str] = None) -> bool:
        return verify_entries(self._rows(), tenant_id)


@dataclass
class LiveWorld:
    audit: LiveAudit
    requests: list
    target: object
    app_dsn: str
    admin_dsn: str
    sessions: RoleSessions = field(default_factory=RoleSessions)
    _repos: dict = field(default_factory=dict)

    def repo(self, tenant: str):
        if tenant not in self._repos:
            self._repos[tenant] = connect(self.app_dsn, tenant)
        return self._repos[tenant]

    def request(self, request_id):
        return next((r for r in self.requests if r.id == request_id), None)

    def config(self) -> dict:
        import psycopg

        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT tenant_id, key, environment, value FROM config_state")
            return {(t, k, e): v for t, k, e, v in cur.fetchall()}


def _insert_request(cur, req) -> None:
    cur.execute(
        "INSERT INTO change_requests(tenant_id, id, requester_id, requester_role, service_id, "
        "key, kind, environment, current_value, proposed_value, window_start, window_end, "
        "description) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (req.tenant_id, req.id, req.requester.id, req.requester.role.value, req.service_id,
         req.key, req.kind.value, req.environment.value, json.dumps(req.current_value),
         json.dumps(req.proposed_value), req.window_start, req.window_end, req.description))


# ------------------------------------------------------------------------ transport


class LiveTransport:
    name = "live"
    guarded = True
    binding = BINDING_REQUEST
    role_delivery = True
    # The open-privilege probe deep-copies an in-memory world. It has no Postgres
    # equivalent here, so the live run reports attacks and oracles only.
    probes = False

    def __init__(self) -> None:
        self.issuer = os.environ["WARDEN_LIVE_ISSUER"]
        self.app_dsn = os.environ["WARDEN_PG_DSN"]
        self.admin_dsn = os.environ["WARDEN_PG_ADMIN_DSN"]
        self.world: Optional[LiveWorld] = None
        self._tokens: dict[tuple[str, str], str] = {}
        self._human: dict[str, str] = {}
        self._saved: dict[str, str] = {}
        self._config_snapshot = None

    def start(self) -> None:
        import logging

        import uvicorn

        from warden.config import Settings
        from warden.server.app import build_server

        for name, level in (("httpx", logging.WARNING), ("mcp", logging.ERROR),
                            ("asyncio", logging.CRITICAL)):
            logging.getLogger(name).setLevel(level)
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", 9000)) == 0:
                raise RuntimeError("port 9000 is taken; the audience mapper needs it")
        cfg = Settings(issuer=self.issuer,
                       jwks_uri=f"{self.issuer}/protocol/openid-connect/certs",
                       resource_url=RESOURCE, host="127.0.0.1", port=9000,
                       pg_dsn=self.app_dsn, now_override=seed.EVAL_NOW.isoformat())
        # Production wiring: JWKS from Keycloak, repositories on Postgres, the
        # server's own task-credential issuer.
        self._mcp = build_server(cfg, sessions_provider=lambda: (
            self.world.sessions if self.world else RoleSessions()))
        self.url = "http://127.0.0.1:9000/mcp"
        self._server = uvicorn.Server(uvicorn.Config(
            self._mcp.streamable_http_app(), host="127.0.0.1", port=9000, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.time() + 30
        while not self._server.started:
            if time.time() > deadline:
                raise RuntimeError("MCP server did not start")
            time.sleep(0.05)
        self._config_snapshot = self._read_config()

    def stop(self) -> None:
        if getattr(self, "_server", None) is not None:
            self._server.should_exit = True
            self._thread.join(timeout=10)

    def _read_config(self):
        import psycopg

        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT tenant_id, key, environment, value FROM config_state")
            return cur.fetchall()

    def make_world(self, case: dict) -> LiveWorld:
        import psycopg

        src = _SEED_BY_ID[_TEMPLATE_SOURCE[case["target"]["template"]]]
        target = replace(src, id=f"rt-{case['id']}",
                         description=case["target"].get("description", ""))
        attacker = case["attacker"]
        if attacker["persona"] == "human":
            login = APPROVER if "change-approver" in attacker.get("realm_roles", []) \
                else REQUESTER
            token = self._human_token(login)
            if attacker.get("subject") == target.requester.id:
                # The self-approval cases need the requester to be the person who
                # logs in, and Keycloak's subject is a UUID, not "u-lead".
                target = replace(target, requester=Requester(_sub(token),
                                                             target.requester.role))
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            # Fresh state per case: empty audit table, seed config, the case's target.
            cur.execute("TRUNCATE audit_log")
            for t, k, e, v in self._config_snapshot:
                cur.execute("UPDATE config_state SET value = %s WHERE tenant_id = %s AND "
                            "key = %s AND environment = %s", (json.dumps(v), t, k, e))
            cur.execute("DELETE FROM change_requests WHERE id LIKE 'rt-%%' OR id = %s",
                        (FOREIGN_REQUEST.id,))
            _insert_request(cur, target)
            _insert_request(cur, FOREIGN_REQUEST)
            conn.commit()
        requests = [s.request for s in seed.SCENARIOS] + [target, FOREIGN_REQUEST]
        return LiveWorld(LiveAudit(self.admin_dsn), requests, target, self.app_dsn,
                         self.admin_dsn)

    def _human_token(self, login: tuple[str, str]) -> str:
        if login[0] not in self._human:
            scopes = [SCOPE_READ, SCOPE_APPROVE] + (
                [SCOPE_APPROVE_PROD] if login == APPROVER else [])
            self._human[login[0]] = pkce_login(self.issuer, login[0], login[1], scopes)
        return self._human[login[0]]

    def adapt_actor(self, actor: Actor) -> Actor:
        if actor.client_id == "warden-console":
            login = APPROVER if "approver" in actor.principal.gate_roles else REQUESTER
            sub = _sub(self._human_token(login))
            return replace(actor, principal=replace(actor.principal, subject=sub))
        return actor

    def begin_case(self, world: LiveWorld, overrides: dict[str, str]) -> None:
        self.world = world
        self._tokens = {}
        manager = self._mcp._tool_manager
        for name, text in overrides.items():
            tool = manager.get_tool(name)
            self._saved[name] = tool.description
            tool.description = f"{tool.description} {text}"

    def end_case(self) -> None:
        manager = self._mcp._tool_manager
        for name, desc in self._saved.items():
            manager.get_tool(name).description = desc
        self._saved = {}
        for repo in (self.world._repos.values() if self.world else ()):
            repo.conn.close()
        self.world = None

    def token(self, actor: Actor) -> str:
        key = (actor.principal.subject, actor.principal.request_id)
        if key not in self._tokens:
            if actor.client_id == "warden-console":
                login = APPROVER if "approver" in actor.principal.gate_roles else REQUESTER
                idp = self._human_token(login)
            else:
                idp = fetch_token_client_credentials(
                    token_endpoint_from_issuer(self.issuer), client_id=AGENT[0],
                    client_secret=AGENT[1],
                    scopes=[SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD], resource=RESOURCE)
            self._tokens[key] = fetch_task_credential(self.url, idp, actor.principal.request_id)
        return self._tokens[key]

    def client_for(self, actor: Actor):
        return MCPToolClient(self.url, self.token(actor))

    def advertised(self, actor: Actor, pmap: PersonaMap) -> dict[str, dict]:
        import anyio
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        async def _list() -> dict[str, dict]:
            headers = {"Authorization": f"Bearer {self.token(actor)}"}
            async with streamablehttp_client(self.url, headers=headers) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
            return {t.name: {"description": t.description or "", "inputSchema": t.inputSchema}
                    for t in listed.tools}

        return anyio.run(_list)

