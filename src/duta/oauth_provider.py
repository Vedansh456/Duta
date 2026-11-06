"""
Duta OAuth provider — integration prototype.

Features:
- In-memory OAuth client and token storage.
- Explicit user approval before authorization codes are issued.
- Short-lived access tokens and refresh tokens.
- Refresh-token rotation and token revocation.
- Per-request CSRF token generation and verification.
- PKCE S256 verification by the MCP SDK during authorization-code exchange.
- Authorization-code redirect URI validation.
- Safe authorization-code fingerprint logging for debugging.

IMPORTANT:
This is still a prototype. Client and token data are lost on restart.
Production use requires persistent storage, comprehensive security testing,
and verification against the OAuth requirements of the MCP SDK.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


logger = logging.getLogger("duta")

ACCESS_TOKEN_LIFETIME = 15 * 60
REFRESH_TOKEN_LIFETIME = 30 * 24 * 60 * 60
AUTHORIZATION_CODE_LIFETIME = 10 * 60


class DutaOAuthProvider(
    OAuthAuthorizationServerProvider[
        AuthorizationCode,
        RefreshToken,
        AccessToken,
    ]
):
    """OAuth provider with explicit consent and in-memory storage."""

    def __init__(self, public_url: str) -> None:
        self.public_url = public_url.rstrip("/")
        self.instance_id = secrets.token_hex(4)

        # Temporary in-memory storage.
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, dict] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

        logger.info(
            "Duta OAuth provider initialized: instance_id=%s, public_url=%s",
            self.instance_id,
            self.public_url,
        )

    async def get_client(
        self,
        client_id: str,
    ) -> OAuthClientInformationFull | None:
        """Return a registered OAuth client."""
        return self.clients.get(client_id)

    async def register_client(
        self,
        client_info: OAuthClientInformationFull,
    ) -> None:
        """Register a client using the SDK-provided client information."""

        if not client_info.client_id:
            raise ValueError("The OAuth client must have a client ID.")

        self.clients[client_info.client_id] = client_info

        logger.info(
            "OAuth client registered: instance_id=%s, client_id=%s",
            self.instance_id,
            client_info.client_id,
        )

    def inspect_client_secret_status(self, client_id: str) -> str:
        """Check whether a client secret exists without revealing its value."""

        client = self.clients.get(client_id)

        if client is None:
            return "Client not found in this server process."

        if getattr(client, "client_secret", None):
            return "A client secret is stored for this client."

        return "No client secret is stored for this client."

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Create a pending authorization request and redirect to consent."""

        if not client.client_id:
            raise ValueError("The OAuth client has no client ID.")

        registered_redirects = {
            str(uri) for uri in (client.redirect_uris or [])
        }

        requested_redirect = str(params.redirect_uri)

        if requested_redirect not in registered_redirects:
            raise ValueError(
                "The redirect URI is not registered for this client."
            )

        # Require PKCE S256.
        if not params.code_challenge:
            raise ValueError("A PKCE code challenge is required.")

        if getattr(params, "code_challenge_method", "S256") != "S256":
            raise ValueError("Only the S256 PKCE method is supported.")

        requested_scopes = list(params.scopes or [])

        if not requested_scopes:
            requested_scopes = ["duta:access"]

        if any(scope != "duta:access" for scope in requested_scopes):
            return construct_redirect_uri(
                requested_redirect,
                error="invalid_scope",
                state=params.state,
            )

        request_id = secrets.token_urlsafe(32)

        self.pending[request_id] = {
            "client_id": client.client_id,
            "redirect_uri": requested_redirect,
            "state": params.state,
            "scopes": requested_scopes,
            "code_challenge": params.code_challenge,
            "code_challenge_method": getattr(
                params,
                "code_challenge_method",
                "S256",
            ),
            "redirect_uri_provided_explicitly": (
                params.redirect_uri_provided_explicitly
            ),
            "resource": str(params.resource) if params.resource else None,
            "csrf_token": secrets.token_urlsafe(32),
            "expires_at": time.time() + AUTHORIZATION_CODE_LIFETIME,
        }

        logger.info(
            "OAuth authorization request created: "
            "instance_id=%s, pending_count=%d",
            self.instance_id,
            len(self.pending),
        )

        return (
            f"{self.public_url}/oauth/consent?"
            + urlencode({"request_id": request_id})
        )

    def get_pending_request(self, request_id: str) -> dict:
        """Return an unexpired pending request for the consent page."""

        request = self.pending.get(request_id)

        if request is None or request["expires_at"] <= time.time():
            self.pending.pop(request_id, None)
            raise ValueError("This authorization request has expired.")

        return dict(request)

    def verify_csrf_token(
        self,
        request_id: str,
        supplied_token: str,
    ) -> bool:
        """Verify the token submitted by the consent form."""

        request = self.pending.get(request_id)

        if request is None or request["expires_at"] <= time.time():
            return False

        expected_token = request.get("csrf_token", "")

        return bool(expected_token) and hmac.compare_digest(
            expected_token,
            supplied_token,
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load an unexpired authorization code belonging to this client."""

        code_fingerprint = hashlib.sha256(
            authorization_code.encode("utf-8")
        ).hexdigest()[:12]

        code = self.codes.get(authorization_code)

        logger.info(
            "OAuth code lookup: "
            "instance_id=%s, fingerprint=%s, found=%s, "
            "client_match=%s, stored_count=%d",
            self.instance_id,
            code_fingerprint,
            code is not None,
            code is not None and code.client_id == client.client_id,
            len(self.codes),
        )

        if code is None or code.client_id != client.client_id:
            return None

        if code.expires_at <= time.time():
            self.codes.pop(authorization_code, None)

            logger.warning(
                "OAuth authorization code expired: "
                "instance_id=%s, fingerprint=%s",
                self.instance_id,
                code_fingerprint,
            )

            return None

        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Exchange a valid, unused authorization code for tokens."""

        if authorization_code.client_id != client.client_id:
            raise ValueError("Authorization code belongs to another client.")

        stored_code = self.codes.get(authorization_code.code)

        if stored_code is None:
            raise ValueError("Authorization code is invalid or already used.")

        if stored_code.client_id != client.client_id:
            raise ValueError("Authorization code belongs to another client.")

        if stored_code.expires_at <= time.time():
            self.codes.pop(authorization_code.code, None)
            raise ValueError("Authorization code has expired.")

        # Consume the code before issuing tokens.
        consumed_code = self.codes.pop(authorization_code.code, None)

        if consumed_code is None:
            raise ValueError("Authorization code has already been used.")

        access_value = secrets.token_urlsafe(48)
        refresh_value = secrets.token_urlsafe(48)
        current_time = int(time.time())

        self.access_tokens[access_value] = AccessToken(
            token=access_value,
            client_id=client.client_id,
            scopes=consumed_code.scopes,
            expires_at=current_time + ACCESS_TOKEN_LIFETIME,
            resource=consumed_code.resource,
        )

        self.refresh_tokens[refresh_value] = RefreshToken(
            token=refresh_value,
            client_id=client.client_id,
            scopes=consumed_code.scopes,
            expires_at=current_time + REFRESH_TOKEN_LIFETIME,
            resource=consumed_code.resource,
        )

        logger.info(
            "OAuth authorization code exchanged successfully: "
            "instance_id=%s",
            self.instance_id,
        )

        return OAuthToken(
            access_token=access_value,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            scope=" ".join(consumed_code.scopes),
            refresh_token=refresh_value,
        )

    async def load_access_token(
        self,
        token: str,
    ) -> AccessToken | None:
        """Return a valid access token or reject it if expired."""

        access = self.access_tokens.get(token)

        if access is None:
            return None

        if access.expires_at <= time.time():
            self.access_tokens.pop(token, None)
            return None

        return access

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load an unexpired refresh token belonging to the client."""

        refresh = self.refresh_tokens.get(refresh_token)

        if refresh is None or refresh.client_id != client.client_id:
            return None

        if refresh.expires_at <= time.time():
            self.refresh_tokens.pop(refresh_token, None)
            return None

        return refresh

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate a valid, unused refresh token."""

        if refresh_token.client_id != client.client_id:
            raise ValueError("Refresh token belongs to another client.")

        stored_refresh = self.refresh_tokens.get(refresh_token.token)

        if stored_refresh is None:
            raise ValueError("Refresh token is invalid or already used.")

        if stored_refresh.client_id != client.client_id:
            raise ValueError("Refresh token belongs to another client.")

        if stored_refresh.expires_at <= time.time():
            self.refresh_tokens.pop(refresh_token.token, None)
            raise ValueError("Refresh token has expired.")

        # If scope is omitted, retain the originally granted scopes.
        effective_scopes = (
            list(scopes) if scopes else list(stored_refresh.scopes)
        )

        if any(
            scope not in stored_refresh.scopes
            for scope in effective_scopes
        ):
            raise ValueError("Cannot increase the scopes of a refresh token.")

        # Consume the old refresh token before issuing replacements.
        consumed_token = self.refresh_tokens.pop(refresh_token.token, None)

        if consumed_token is None:
            raise ValueError("Refresh token has already been used.")

        access_value = secrets.token_urlsafe(48)
        refresh_value = secrets.token_urlsafe(48)
        current_time = int(time.time())

        self.access_tokens[access_value] = AccessToken(
            token=access_value,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=current_time + ACCESS_TOKEN_LIFETIME,
            resource=consumed_token.resource,
        )

        self.refresh_tokens[refresh_value] = RefreshToken(
            token=refresh_value,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=current_time + REFRESH_TOKEN_LIFETIME,
            resource=consumed_token.resource,
        )

        return OAuthToken(
            access_token=access_value,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            scope=" ".join(effective_scopes),
            refresh_token=refresh_value,
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """Revoke an access token or refresh token."""

        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)

        elif isinstance(token, RefreshToken):
            self.refresh_tokens.pop(token.token, None)

    def approve_request(
        self,
        request_id: str,
        csrf_token: str,
    ) -> str:
        """Approve a pending request and return its client redirect URL."""

        if not self.verify_csrf_token(request_id, csrf_token):
            raise ValueError("Invalid or expired consent token.")

        request = self.pending.pop(request_id)

        client = self.clients.get(request["client_id"])

        if client is None:
            raise ValueError(
                "The requesting OAuth client no longer exists."
            )

        registered_redirects = {
            str(uri) for uri in (client.redirect_uris or [])
        }

        if request["redirect_uri"] not in registered_redirects:
            raise ValueError(
                "The redirect URI is not registered for this client."
            )

        code_value = secrets.token_urlsafe(32)

        self.codes[code_value] = AuthorizationCode(
            code=code_value,
            scopes=request["scopes"],
            expires_at=time.time() + AUTHORIZATION_CODE_LIFETIME,
            client_id=request["client_id"],
            code_challenge=request["code_challenge"],
            redirect_uri=request["redirect_uri"],
            redirect_uri_provided_explicitly=(
                request["redirect_uri_provided_explicitly"]
            ),
            resource=request["resource"],
        )

        code_fingerprint = hashlib.sha256(
            code_value.encode("utf-8")
        ).hexdigest()[:12]

        logger.info(
            "OAuth authorization code created: "
            "instance_id=%s, fingerprint=%s, stored_count=%d",
            self.instance_id,
            code_fingerprint,
            len(self.codes),
        )

        return construct_redirect_uri(
            request["redirect_uri"],
            code=code_value,
            state=request["state"],
        )

    def reject_request(
        self,
        request_id: str,
        csrf_token: str,
    ) -> str:
        """Reject a pending request without issuing a code."""

        if not self.verify_csrf_token(request_id, csrf_token):
            raise ValueError("Invalid or expired consent token.")

        request = self.pending.pop(request_id)

        return construct_redirect_uri(
            request["redirect_uri"],
            error="access_denied",
            state=request["state"],
        )