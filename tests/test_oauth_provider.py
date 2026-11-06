import time
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    RefreshToken,
)
import pytest
from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import (
    AuthorizationCode,
    RefreshToken,
)

from duta.oauth_provider import (
    DutaOAuthProvider,
    REFRESH_TOKEN_LIFETIME,
)

from mcp.shared.auth import OAuthClientInformationFull


@pytest.fixture
def provider():
    return DutaOAuthProvider("https://example.com")


@pytest.fixture
def client():
    return OAuthClientInformationFull(
        client_id="test-client",
        redirect_uris=["http://localhost:3000/callback"],
        client_name="Duta Test Client",
    )


def make_authorization_code(client_id="test-client"):
    return AuthorizationCode(
        code="test-authorization-code",
        scopes=["duta:access"],
        expires_at=int(time.time() + 600),
        client_id=client_id,
        code_challenge="test-challenge",
        redirect_uri="http://localhost:3000/callback",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )


def make_refresh_token(client_id="test-client"):
    return RefreshToken(
        token="test-refresh-token",
        client_id=client_id,
        scopes=["duta:access"],
        expires_at=int(time.time() + REFRESH_TOKEN_LIFETIME),
        resource=None,
    )


@pytest.mark.asyncio
async def test_authorization_code_can_only_be_used_once(provider, client):
    code = make_authorization_code()
    provider.codes[code.code] = code

    result = await provider.exchange_authorization_code(client, code)

    assert result.access_token
    assert result.refresh_token
    assert code.code not in provider.codes

    with pytest.raises(ValueError):
        await provider.exchange_authorization_code(client, code)


@pytest.mark.asyncio
async def test_expired_authorization_code_is_rejected(provider, client):
    code = make_authorization_code()

    expired_code = code.model_copy(
        update={"expires_at": int(time.time()) - 10}
    )

    provider.codes[expired_code.code] = expired_code

    with pytest.raises(ValueError, match="expired"):
        await provider.exchange_authorization_code(client, expired_code)


@pytest.mark.asyncio
async def test_authorization_code_wrong_client_is_rejected(provider, client):
    code = make_authorization_code(client_id="another-client")
    provider.codes[code.code] = code

    with pytest.raises(ValueError):
        await provider.exchange_authorization_code(client, code)


@pytest.mark.asyncio
async def test_refresh_token_can_only_be_used_once(provider, client):
    refresh = make_refresh_token()
    provider.refresh_tokens[refresh.token] = refresh

    result = await provider.exchange_refresh_token(
        client,
        refresh,
        ["duta:access"],
    )

    assert result.access_token
    assert result.refresh_token
    assert refresh.token not in provider.refresh_tokens

    with pytest.raises(ValueError):
        await provider.exchange_refresh_token(
            client,
            refresh,
            ["duta:access"],
        )


@pytest.mark.asyncio
async def test_expired_refresh_token_is_rejected(provider, client):
    refresh = make_refresh_token()

    expired_refresh = refresh.model_copy(
        update={"expires_at": int(time.time()) - 10}
    )

    provider.refresh_tokens[expired_refresh.token] = expired_refresh

    with pytest.raises(ValueError, match="expired"):
        await provider.exchange_refresh_token(
            client,
            expired_refresh,
            ["duta:access"],
        )


@pytest.mark.asyncio
async def test_refresh_token_cannot_increase_scopes(provider, client):
    refresh = make_refresh_token()
    provider.refresh_tokens[refresh.token] = refresh

    with pytest.raises(ValueError, match="increase"):
        await provider.exchange_refresh_token(
            client,
            refresh,
            ["duta:access", "admin"],
        )


@pytest.mark.asyncio
async def test_refresh_token_wrong_client_is_rejected(provider, client):
    refresh = make_refresh_token(client_id="another-client")
    provider.refresh_tokens[refresh.token] = refresh

    with pytest.raises(ValueError):
        await provider.exchange_refresh_token(
            client,
            refresh,
            ["duta:access"],
        )

    # --------------------------------------------------
# CONSENT FLOW TESTS
# --------------------------------------------------

def create_pending_request(provider, client):
    """Create a pending request for consent-flow testing."""

    provider.clients[client.client_id] = client

    request_id = "test-request-id"
    csrf_token = "test-csrf-token"

    provider.pending[request_id] = {
        "client_id": client.client_id,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "test-state",
        "scopes": ["duta:access"],
        "code_challenge": "test-code-challenge",
        "code_challenge_method": "S256",
        "redirect_uri_provided_explicitly": True,
        "resource": None,
        "csrf_token": csrf_token,
        "expires_at": int(time.time()) + 600,
    }

    return request_id, csrf_token


def test_csrf_token_validation(provider, client):
    request_id, csrf_token = create_pending_request(
        provider, client
    )

    assert provider.verify_csrf_token(request_id, csrf_token)

    assert not provider.verify_csrf_token(
        request_id,
        "incorrect-token",
    )


def test_approval_creates_authorization_code(provider, client):
    request_id, csrf_token = create_pending_request(
        provider, client
    )

    redirect_url = provider.approve_request(
        request_id,
        csrf_token,
    )

    parsed_url = urlparse(redirect_url)
    query = parse_qs(parsed_url.query)

    assert parsed_url.scheme == "http"
    assert parsed_url.netloc == "localhost:3000"
    assert "code" in query
    assert query["state"] == ["test-state"]

    authorization_code = query["code"][0]

    assert authorization_code in provider.codes
    assert request_id not in provider.pending


def test_rejection_does_not_create_authorization_code(
    provider,
    client,
):
    request_id, csrf_token = create_pending_request(
        provider, client
    )

    redirect_url = provider.reject_request(
        request_id,
        csrf_token,
    )

    parsed_url = urlparse(redirect_url)
    query = parse_qs(parsed_url.query)

    assert query["error"] == ["access_denied"]
    assert query["state"] == ["test-state"]

    assert not provider.codes
    assert request_id not in provider.pending


def test_invalid_csrf_cannot_approve_request(provider, client):
    request_id, _ = create_pending_request(
        provider, client
    )

    with pytest.raises(ValueError):
        provider.approve_request(
            request_id,
            "wrong-csrf-token",
        )

    assert request_id in provider.pending
    assert not provider.codes


# --------------------------------------------------
# TOKEN REVOCATION TESTS
# --------------------------------------------------

@pytest.mark.asyncio
async def test_access_token_revocation(provider, client):
    token_value = "test-access-token"

    access_token = AccessToken(
        token=token_value,
        client_id=client.client_id,
        scopes=["duta:access"],
        expires_at=int(time.time()) + 600,
        resource=None,
    )

    provider.access_tokens[token_value] = access_token

    assert await provider.load_access_token(token_value)

    await provider.revoke_token(access_token)

    assert await provider.load_access_token(token_value) is None


@pytest.mark.asyncio
async def test_refresh_token_revocation(provider, client):
    refresh = make_refresh_token()

    provider.refresh_tokens[refresh.token] = refresh

    assert await provider.load_refresh_token(
        client,
        refresh.token,
    )

    await provider.revoke_token(refresh)

    assert await provider.load_refresh_token(
        client,
        refresh.token,
    ) is None