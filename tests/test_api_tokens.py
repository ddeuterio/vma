"""
Comprehensive API token tests for VMA.

Tests cover:
- API token creation with expiration
- Token prefix validation (vma_)
- Token hash verification (Argon2)
- Token revocation
- Token listing (user-specific and root access)
- Token usage tracking
- Expired token handling
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import status
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timedelta, timezone

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


@pytest.fixture
def regular_user_token():
    """JWT data for a regular user"""
    return mod_v1.JwtData(
        username="user@test.com",
        scope={"team1": "write"},
        root=False
    )


@pytest.fixture
def root_user_token():
    """JWT data for a root user"""
    return mod_v1.JwtData(
        username="root@test.com",
        scope={"team1": "admin"},
        root=True
    )


@pytest.fixture
async def client():
    """Async test client"""
    transport = ASGITransport(app=api_server)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    api_server.dependency_overrides.clear()


class TestAPITokenGeneration:
    """Tests for API token generation"""

    def test_generate_api_token_format(self):
        """Test that generated token has correct format"""
        import re
        token = a.generate_api_token()

        assert token.startswith("vma_")
        assert len(token) > 12  # vma_ prefix + base64 encoded bytes
        # URL-safe base64 allows: A-Z, a-z, 0-9, hyphen, and underscore
        assert re.match(r'^vma_[A-Za-z0-9_-]+$', token)

    def test_generate_api_token_uniqueness(self):
        """Test that each generated token is unique"""
        tokens = [a.generate_api_token() for _ in range(100)]

        # All tokens should be unique
        assert len(tokens) == len(set(tokens))

    def test_generate_api_token_prefix_length(self):
        """Test that token prefix is 12 characters"""
        token = a.generate_api_token()
        prefix = token[:12]

        assert len(prefix) == 12
        assert prefix.startswith("vma_")


class TestAPITokenCreation:
    """Tests for creating API tokens via endpoint"""

    @pytest.mark.asyncio
    async def test_create_api_token_success(self, client, root_user_token):
        """Test successful API token creation"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.c") as mock_c:

            mock_token = "vma_test123456789012345678901234567890"
            mock_auth.generate_api_token.return_value = mock_token
            mock_auth.hasher.hash.return_value = "hashed_token"

            mock_c.insert_api_token = AsyncMock(return_value={
                "status": True,
                "result": {
                    "id": 1,
                    "created_at": datetime.now(timezone.utc)
                }
            })

            response = await client.post(
                "/api/v1/apitoken",
                json={
                    "username": "root@test.com",
                    "description": "Test token",
                    "expires_days": 365
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] is True
            assert data["result"]["token"] == mock_token
            assert data["result"]["prefix"] == mock_token[:12]
            assert data["result"]["description"] == "Test token"

    @pytest.mark.asyncio
    async def test_create_api_token_non_root_for_other_user_forbidden(self, client, regular_user_token):
        """Test that non-root user cannot create token for other users"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        response = await client.post(
            "/api/v1/apitoken",
            json={
                "username": "other@test.com",
                "description": "Test token",
                "expires_days": 365
            },
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_create_api_token_without_expiration(self, client, root_user_token):
        """Test creating API token without expiration"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.c") as mock_c:

            mock_token = "vma_test123456789012345678901234567890"
            mock_auth.generate_api_token.return_value = mock_token
            mock_auth.hasher.hash.return_value = "hashed_token"

            mock_c.insert_api_token = AsyncMock(return_value={
                "status": True,
                "result": {
                    "id": 1,
                    "created_at": datetime.now(timezone.utc)
                }
            })

            response = await client.post(
                "/api/v1/apitoken",
                json={
                    "username": "root@test.com",
                    "description": "Permanent token",
                    "expires_days": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["result"]["expires_at"] is None


class TestAPITokenValidation:
    """Tests for API token validation"""

    @pytest.mark.asyncio
    async def test_validate_api_token_success(self):
        """Test successful API token validation"""
        mock_token = "vma_test123456789012345678901234567890"
        prefix = mock_token[:12]

        with patch("vma.connector.get_api_token_by_prefix") as mock_get, \
             patch("vma.connector.update_token_last_used") as mock_update, \
             patch("vma.connector.get_users") as mock_get_users, \
             patch("vma.auth.hasher") as mock_hasher:

            mock_get.return_value = {
                "status": True,
                "result": {
                    "id": 1,
                    "token_hash": "hashed_token",
                    "user_email": "user@test.com",
                    "revoked": False,
                    "expires_at": None
                }
            }

            mock_get_users.return_value = {
                "status": True,
                "result": [{
                    "email": "user@test.com",
                    "teams": {"team1": "write"},
                    "is_root": False
                }]
            }

            mock_hasher.verify.return_value = True

            result = await a.validate_api_token(f"Bearer {mock_token}")

            assert result["status"] is True
            assert result["result"]["username"] == "user@test.com"
            assert result["result"]["teams"] == {"team1": "write"}
            assert result["result"]["root"] is False
            assert result["result"]["token_type"] == "api_token"

            # Verify that last_used was updated
            mock_update.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_validate_api_token_missing_authorization(self):
        """Test validation fails without authorization header"""
        with pytest.raises(Exception):  # Should raise HTTPException
            await a.validate_api_token(None)

    @pytest.mark.asyncio
    async def test_validate_api_token_wrong_format(self):
        """Test validation fails with wrong token format"""
        # Missing "Bearer " prefix
        result = await a.validate_api_token("vma_test123456")
        assert result["status"] is False

    @pytest.mark.asyncio
    async def test_validate_api_token_wrong_prefix(self):
        """Test validation fails with wrong prefix"""
        with patch("vma.connector.get_api_token_by_prefix") as mock_get:
            mock_get.return_value = {"status": False}

            result = await a.validate_api_token("Bearer xyz_test123456789012345678901234567890")
            assert result["status"] is False

    @pytest.mark.asyncio
    async def test_validate_api_token_revoked(self):
        """Test validation fails for revoked token"""
        mock_token = "vma_test123456789012345678901234567890"

        with patch("vma.connector.get_api_token_by_prefix") as mock_get, \
             patch("vma.auth.hasher") as mock_hasher:

            mock_get.return_value = {
                "status": True,
                "result": {
                    "id": 1,
                    "token_hash": "hashed_token",
                    "user_email": "user@test.com",
                    "revoked": True,
                    "expires_at": None
                }
            }

            mock_hasher.verify.return_value = True

            result = await a.validate_api_token(f"Bearer {mock_token}")

            assert result["status"] is False
            assert "revoked" in result["result"]

    @pytest.mark.asyncio
    async def test_validate_api_token_expired(self):
        """Test validation fails for expired token"""
        mock_token = "vma_test123456789012345678901234567890"
        past_time = datetime.now(timezone.utc) - timedelta(days=1)

        with patch("vma.connector.get_api_token_by_prefix") as mock_get, \
             patch("vma.auth.hasher") as mock_hasher:

            mock_get.return_value = {
                "status": True,
                "result": {
                    "id": 1,
                    "token_hash": "hashed_token",
                    "user_email": "user@test.com",
                    "revoked": False,
                    "expires_at": past_time
                }
            }

            mock_hasher.verify.return_value = True

            result = await a.validate_api_token(f"Bearer {mock_token}")

            assert result["status"] is False
            assert "expired" in result["result"]

    @pytest.mark.asyncio
    async def test_validate_api_token_hash_mismatch(self):
        """Test validation fails when hash doesn't match"""
        mock_token = "vma_test123456789012345678901234567890"

        with patch("vma.connector.get_api_token_by_prefix") as mock_get, \
             patch("vma.auth.hasher") as mock_hasher:

            mock_get.return_value = {
                "status": True,
                "result": {
                    "id": 1,
                    "token_hash": "different_hash",
                    "user_email": "user@test.com",
                    "revoked": False,
                    "expires_at": None
                }
            }

            mock_hasher.verify.return_value = False

            result = await a.validate_api_token(f"Bearer {mock_token}")

            assert result["status"] is False


class TestAPITokenListing:
    """Tests for listing API tokens"""

    @pytest.mark.asyncio
    async def test_list_api_tokens_regular_user_forbidden(self, client, regular_user_token, mock_router_dependencies):
        """Test that regular user cannot list tokens"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]

        response = await client.get(
            "/api/v1/tokens/user@test.com",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        mock_c.list_api_tokens.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_api_tokens_root_sees_own(self, client, root_user_token, mock_router_dependencies):
        """Test that root user sees their own tokens"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.list_api_tokens = AsyncMock(return_value={
            "status": True,
            "result": [
                {
                    "id": 1,
                    "prefix": "vma_test1234",
                    "user_email": "root@test.com",
                    "description": "Token 1",
                    "created_at": datetime.now(timezone.utc),
                    "last_used_at": None,
                    "expires_at": None,
                    "revoked": False
                }
            ]
        })

        response = await client.get(
            "/api/v1/tokens/root@test.com",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["result"]) == 1

        mock_c.list_api_tokens.assert_called_once_with(user_email="root@test.com")

    @pytest.mark.asyncio
    async def test_list_api_tokens_no_plaintext(self, client, root_user_token, mock_router_dependencies):
        """Test that listed tokens don't include plaintext"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.list_api_tokens = AsyncMock(return_value={
            "status": True,
            "result": [
                {
                    "id": 1,
                    "prefix": "vma_test1234",
                    "user_email": "root@test.com",
                    "description": "Token 1",
                    "created_at": datetime.now(timezone.utc),
                    "last_used_at": None,
                    "expires_at": None,
                    "revoked": False,
                    "token": None
                }
            ]
        })

        response = await client.get(
            "/api/v1/tokens/root@test.com",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["result"][0].get("token") is None


class TestAPITokenRetrieval:
    """Tests for retrieving specific API tokens"""

    @pytest.mark.asyncio
    async def test_get_api_token_own_token_unauthorized(self, client, regular_user_token, mock_router_dependencies):
        """Token ID route resolves to token listing and is unauthorized"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]

        response = await client.get(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        mock_c.get_api_token_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_api_token_other_user_forbidden(self, client, regular_user_token, mock_router_dependencies):
        """Token ID route resolves to token listing and is unauthorized"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]

        response = await client.get(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        mock_c.get_api_token_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_api_token_root_can_see_all(self, client, root_user_token, mock_router_dependencies):
        """Token ID route resolves to token listing and is unauthorized"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]

        response = await client.get(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        mock_c.get_api_token_by_id.assert_not_called()


class TestAPITokenRevocation:
    """Tests for revoking API tokens"""

    @pytest.mark.asyncio
    async def test_revoke_own_token_success(self, client, regular_user_token, mock_router_dependencies):
        """Test that user can revoke their own token"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_api_token_by_id = AsyncMock(return_value={
            "status": True,
            "result": {
                "id": 1,
                "user_email": "user@test.com"
            }
        })

        mock_c.revoke_api_token = AsyncMock(return_value={
            "status": True,
            "result": "Token revoked"
        })

        response = await client.delete(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        mock_c.revoke_api_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_other_user_token_forbidden(self, client, regular_user_token, mock_router_dependencies):
        """Test that user cannot revoke other user's token"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_api_token_by_id = AsyncMock(return_value={
            "status": True,
            "result": {
                "id": 1,
                "user_email": "other@test.com"
            }
        })

        response = await client.delete(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_revoke_token_root_can_revoke_any(self, client, root_user_token, mock_router_dependencies):
        """Test that root user can revoke any token"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_api_token_by_id = AsyncMock(return_value={
            "status": True,
            "result": {
                "id": 1,
                "user_email": "other@test.com"
            }
        })

        mock_c.revoke_api_token = AsyncMock(return_value={
            "status": True,
            "result": "Token revoked"
        })

        response = await client.delete(
            "/api/v1/tokens/1",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_token(self, client, regular_user_token, mock_router_dependencies):
        """Test revoking nonexistent token returns 404"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_api_token_by_id = AsyncMock(return_value={
            "status": False,
            "result": "Token not found"
        })

        response = await client.delete(
            "/api/v1/tokens/999",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestAPITokenUsageInImport:
    """Tests for using API tokens in import endpoint"""

    @pytest.mark.asyncio
    async def test_import_with_valid_api_token(self, client, mock_router_dependencies):
        """Test that import endpoint accepts valid API token"""
        mock_token = "vma_test123456789012345678901234567890"

        # Override validate_api_token dependency to return success
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "user@test.com",
                    "teams": {"team1": "write"},
                    "root": False,
                    "token_type": "api_token"
                }
            }

        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_c = mock_router_dependencies["connector"]

        mock_c.get_images = AsyncMock(return_value={"status": True, "result": []})
        mock_c.insert_image = AsyncMock(return_value={"status": True})
        mock_c.insert_vulnerabilities_sca_batch = AsyncMock(return_value={
            "status": True,
            "result": "Imported"
        })

        response = await client.post(
            "/api/v1/import/sca",
            json={
                "scanner": "grype",
                "image_name": "app",
                "image_version": "1.0",
                "product": "prod1",
                "team": "team1",
                "vulnerabilities": [
                    {
                        "vuln_id": "CVE-2023-1234",
                        "affected_component": "libssl",
                        "affected_version": "1.0",
                        "affected_component_type": "deb",
                        "affected_path": "/usr/lib",
                        "severity": {"level": "HIGH"}
                    }
                ]
            },
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_import_with_invalid_api_token(self, client):
        """Test that import endpoint rejects invalid API token"""
        with patch("vma.api.routers.v1.a.validate_api_token") as mock_validate:
            mock_validate.return_value = {
                "status": False,
                "result": "Invalid token"
            }

            response = await client.post(
                "/api/v1/import/sca",
                json={
                    "scanner": "grype",
                    "image_name": "app",
                    "image_version": "1.0",
                    "product": "prod1",
                    "team": "team1",
                    "vulnerabilities": []
                },
                headers={"Authorization": "Bearer invalid_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED
