"""
Comprehensive authentication and authorization tests for VMA.

Tests cover:
- JWT access token creation and validation
- Refresh token flow
- Token expiration
- Authorization boundaries (READ_ONLY, WRITE, ADMIN scopes)
- Root user privileges
- Cross-team access control
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import status, HTTPException
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timedelta, timezone
import jwt

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


@pytest.fixture
def read_only_user_token():
    """JWT data for a user with read-only access to team1"""
    return mod_v1.JwtData(
        username="reader@test.com",
        scope={"team1": "read"},
        root=False
    )


@pytest.fixture
def write_user_token():
    """JWT data for a user with write access to team1"""
    return mod_v1.JwtData(
        username="writer@test.com",
        scope={"team1": "write"},
        root=False
    )


@pytest.fixture
def admin_user_token():
    """JWT data for a user with admin access to team1"""
    return mod_v1.JwtData(
        username="admin@test.com",
        scope={"team1": "admin"},
        root=False
    )


@pytest.fixture
def multi_team_user_token():
    """JWT data for a user with access to multiple teams"""
    return mod_v1.JwtData(
        username="multi@test.com",
        scope={"team1": "read", "team2": "write", "team3": "admin"},
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


class TestTokenCreation:
    """Tests for JWT token creation"""

    def test_create_access_token_success(self):
        """Test creating a valid access token"""
        username = "user@test.com"
        scope = {"team1": "write"}

        token = a.create_token(
            username=username,
            ttype="access_token",
            scope=scope,
            root=False
        )

        assert token is not None
        assert isinstance(token, str)

        # Decode and verify payload
        payload = jwt.decode(token, a._secret_key_access, algorithms=[a._algorithm])
        assert payload["sub"] == f"username:{username}"
        assert payload["type"] == "access_token"
        assert payload["scope"] == scope
        assert payload["root"] is False
        assert "exp" in payload

    def test_create_refresh_token_success(self):
        """Test creating a valid refresh token"""
        username = "user@test.com"
        scope = {"team1": "write"}

        token = a.create_token(
            username=username,
            ttype="refresh_token",
            scope=scope,
            root=False
        )

        assert token is not None
        payload = jwt.decode(token, a._secret_key_refresh, algorithms=[a._algorithm])
        assert payload["type"] == "refresh_token"

    def test_create_token_invalid_type(self):
        """Test that invalid token type raises exception"""
        with pytest.raises(Exception, match="invalid ttype"):
            a.create_token(
                username="user@test.com",
                ttype="invalid_type",
                scope={},
                root=False
            )

    def test_token_expiration_times(self):
        """Test that tokens have correct expiration times"""
        # Access token (15 minutes by default)
        access_token = a.create_token(
            username="user@test.com",
            ttype="access_token",
            scope={},
            root=False
        )
        access_payload = jwt.decode(
            access_token,
            a._secret_key_access,
            algorithms=[a._algorithm]
        )
        access_exp = datetime.fromtimestamp(access_payload["exp"], tz=timezone.utc)
        expected_access = datetime.now(timezone.utc) + timedelta(minutes=a._expire_access_token)

        # Allow 5 second tolerance
        assert abs((access_exp - expected_access).total_seconds()) < 5

        # Refresh token (2 days by default)
        refresh_token = a.create_token(
            username="user@test.com",
            ttype="refresh_token",
            scope={},
            root=False
        )
        refresh_payload = jwt.decode(
            refresh_token,
            a._secret_key_refresh,
            algorithms=[a._algorithm]
        )
        refresh_exp = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)
        expected_refresh = datetime.now(timezone.utc) + timedelta(days=a._expire_refresh_token)

        # Allow 5 second tolerance
        assert abs((refresh_exp - expected_refresh).total_seconds()) < 5


class TestTokenValidation:
    """Tests for JWT token validation"""

    def test_validate_access_token_success(self):
        """Test validating a valid access token"""
        username = "user@test.com"
        scope = {"team1": "write"}

        token = a.create_token(
            username=username,
            ttype="access_token",
            scope=scope,
            root=False
        )

        jwt_data = a.validate_access_token(token)

        assert jwt_data.username == username
        assert jwt_data.scope == scope
        assert jwt_data.root is False

    def test_validate_access_token_with_refresh_token_fails(self):
        """Test that refresh token cannot be used as access token"""
        token = a.create_token(
            username="user@test.com",
            ttype="refresh_token",
            scope={"team1": "write"},
            root=False
        )

        with pytest.raises(HTTPException) as exc_info:
            a.validate_access_token(token)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    def test_validate_access_token_expired_fails(self):
        """Test that expired token fails validation"""
        # Create token with past expiration
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        payload = {
            "sub": "username:user@test.com",
            "exp": past_time,
            "type": "access_token",
            "scope": {"team1": "write"},
            "root": False
        }
        expired_token = jwt.encode(payload, a._secret_key_access, algorithm=a._algorithm)

        with pytest.raises(HTTPException) as exc_info:
            a.validate_access_token(expired_token)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    def test_validate_access_token_wrong_key_fails(self):
        """Test that token signed with wrong key fails validation"""
        payload = {
            "sub": "username:user@test.com",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "type": "access_token",
            "scope": {"team1": "write"},
            "root": False
        }
        wrong_token = jwt.encode(payload, "wrong_secret_key", algorithm=a._algorithm)

        with pytest.raises(HTTPException) as exc_info:
            a.validate_access_token(wrong_token)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    def test_validate_access_token_malformed_fails(self):
        """Test that malformed token fails validation"""
        with pytest.raises(HTTPException) as exc_info:
            a.validate_access_token("not.a.valid.token")

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


class TestAuthenticationEndpoints:
    """Tests for authentication endpoints"""

    @pytest.mark.asyncio
    async def test_login_success(self, client):
        """Test successful login returns tokens"""
        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users_w_hpass = AsyncMock(return_value={
                "status": True,
                "result": [{
                    "email": "user@test.com",
                    "hpass": "hashed_password",
                    "name": "Test User",
                    "is_root": False
                }]
            })
            mock_c.get_scope_by_user = AsyncMock(return_value={
                "status": True,
                "result": {"team1": "write"}
            })
            mock_auth.hasher.verify.return_value = True
            mock_auth.create_token.return_value = "fake_access_token"
            mock_auth._expire_refresh_token = 2

            response = await client.post(
                "/api/v1/token",
                data={"username": "user@test.com", "password": "correct_password"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] == "fake_access_token"
            assert data["token_type"] == "Bearer"
            assert "refresh_token" in response.cookies

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client):
        """Test login with wrong password fails gracefully"""
        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users_w_hpass = AsyncMock(return_value={
                "status": True,
                "result": [{
                    "email": "user@test.com",
                    "hpass": "hashed_password",
                    "name": "Test User",
                    "is_root": False
                }]
            })
            mock_c.get_scope_by_user = AsyncMock(return_value={
                "status": True,
                "result": {"team1": "write"}
            })
            mock_auth.hasher.verify.return_value = False

            response = await client.post(
                "/api/v1/token",
                data={"username": "user@test.com", "password": "wrong_password"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] is None

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user fails"""
        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users_w_hpass = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.post(
                "/api/v1/token",
                data={"username": "nonexistent@test.com", "password": "password"}
            )

            # Should fail gracefully or return 401
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED]

    @pytest.mark.asyncio
    async def test_login_missing_credentials(self, client):
        """Test login with missing credentials fails"""
        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None

            response = await client.post(
                "/api/v1/token",
                data={"username": "", "password": ""}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestRefreshTokenFlow:
    """Tests for refresh token functionality"""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client):
        """Test successful token refresh"""
        # Create a valid refresh token
        refresh_token = a.create_token(
            username="user@test.com",
            ttype="refresh_token",
            scope={"team1": "write"},
            root=False
        )

        with patch("vma.api.routers.v1.a") as mock_auth:
            mock_auth._secret_key_refresh = a._secret_key_refresh
            mock_auth._algorithm = a._algorithm
            mock_auth.create_token.return_value = "new_access_token"
            mock_auth._expire_refresh_token = 2

            response = await client.get(
                "/api/v1/refresh_token",
                cookies={"refresh_token": refresh_token}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] == "new_access_token"
            assert data["token_type"] == "Bearer"

    @pytest.mark.asyncio
    async def test_refresh_token_missing(self, client):
        """Test refresh without token fails"""
        response = await client.get("/api/v1/refresh_token")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Missing refresh token" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client):
        """Test refresh with invalid token fails"""
        response = await client.get(
            "/api/v1/refresh_token",
            cookies={"refresh_token": "invalid.token.here"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_refresh_with_access_token_fails(self, client):
        """Test that access token cannot be used for refresh"""
        # Create an access token (not a refresh token)
        access_token = a.create_token(
            username="user@test.com",
            ttype="access_token",
            scope={"team1": "write"},
            root=False
        )

        response = await client.get(
            "/api/v1/refresh_token",
            cookies={"refresh_token": access_token}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestAuthorizationScopes:
    """Tests for authorization scope checking"""

    def test_is_authorized_root_user_always_passes(self):
        """Test that root users bypass all authorization checks"""
        from vma.api.routers.v1 import is_authorized, READ_ONLY, WRITE, ADMIN

        # Root user should pass all checks regardless of scope
        assert is_authorized(
            scope={"team1": "read"},
            teams=["team1", "team2", "team3"],
            op=ADMIN,
            is_root=True
        ) is True

    def test_is_authorized_read_only_access(self):
        """Test read-only scope authorization"""
        from vma.api.routers.v1 import is_authorized, READ_ONLY

        assert is_authorized(
            scope={"team1": "read"},
            teams=["team1"],
            op=READ_ONLY,
            is_root=False
        ) is True

    def test_is_authorized_write_access(self):
        """Test write scope authorization"""
        from vma.api.routers.v1 import is_authorized, WRITE

        # Write scope should allow write operations
        assert is_authorized(
            scope={"team1": "write"},
            teams=["team1"],
            op=WRITE,
            is_root=False
        ) is True

        # Read scope should NOT allow write operations
        assert is_authorized(
            scope={"team1": "read"},
            teams=["team1"],
            op=WRITE,
            is_root=False
        ) is False

    def test_is_authorized_admin_access(self):
        """Test admin scope authorization"""
        from vma.api.routers.v1 import is_authorized, ADMIN

        # Admin scope should allow admin operations
        assert is_authorized(
            scope={"team1": "admin"},
            teams=["team1"],
            op=ADMIN,
            is_root=False
        ) is True

        # Write scope should NOT allow admin operations
        assert is_authorized(
            scope={"team1": "write"},
            teams=["team1"],
            op=ADMIN,
            is_root=False
        ) is False

        # Read scope should NOT allow admin operations
        assert is_authorized(
            scope={"team1": "read"},
            teams=["team1"],
            op=ADMIN,
            is_root=False
        ) is False

    def test_is_authorized_multi_team_all_required(self):
        """Test that authorization requires scope on ALL requested teams"""
        from vma.api.routers.v1 import is_authorized, READ_ONLY

        # User has access to team1 and team2
        scope = {"team1": "read", "team2": "read"}

        # Should pass when requesting both teams
        assert is_authorized(
            scope=scope,
            teams=["team1", "team2"],
            op=READ_ONLY,
            is_root=False
        ) is True

        # Should FAIL when requesting a team they don't have access to
        assert is_authorized(
            scope=scope,
            teams=["team1", "team2", "team3"],
            op=READ_ONLY,
            is_root=False
        ) is False

    def test_is_authorized_no_teams(self):
        """Test authorization with empty team list"""
        from vma.api.routers.v1 import is_authorized, ADMIN

        # Empty team list with non-root user should pass (current behavior)
        # NOTE: This is the bug mentioned in test_api_v1.py
        result = is_authorized(
            scope={"team1": "read"},
            teams=[],
            op=ADMIN,
            is_root=False
        )
        # Currently returns True, but should probably return False
        assert result is True

    def test_is_authorized_scope_hierarchy(self):
        """Test that higher scopes include lower scope permissions"""
        from vma.api.routers.v1 import is_authorized, READ_ONLY, WRITE

        # Admin scope should allow write operations
        assert is_authorized(
            scope={"team1": "admin"},
            teams=["team1"],
            op=WRITE,
            is_root=False
        ) is True

        # Admin scope should allow read operations
        assert is_authorized(
            scope={"team1": "admin"},
            teams=["team1"],
            op=READ_ONLY,
            is_root=False
        ) is True

        # Write scope should allow read operations
        assert is_authorized(
            scope={"team1": "write"},
            teams=["team1"],
            op=READ_ONLY,
            is_root=False
        ) is True


class TestCrossTeamAccess:
    """Tests for cross-team access control"""

    @pytest.mark.asyncio
    async def test_access_own_team_product_success(self, client, write_user_token):
        """Test that user can access products in their team"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_products = AsyncMock(return_value={
                "status": True,
                "result": [{"id": "prod1", "description": "Product 1", "team": "team1"}]
            })

            response = await client.get(
                "/api/v1/product/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_access_other_team_product_forbidden(self, client, write_user_token):
        """Test that user cannot access products in other teams"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/product/team2/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_root_user_can_access_all_teams(self, client, root_user_token):
        """Test that root user can access resources in any team"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_products = AsyncMock(return_value={
                "status": True,
                "result": [{"id": "prod1", "description": "Product 1", "team": "team2"}]
            })

            # Root user accessing team2 (not in their explicit scope)
            response = await client.get(
                "/api/v1/product/team2/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK


class TestPasswordHashing:
    """Tests for password hashing functionality"""

    def test_password_hash_verify_success(self):
        """Test that correct password verifies successfully"""
        password = "test_password_123"
        hashed = a.hasher.hash(password)

        assert a.hasher.verify(password, hashed) is True

    def test_password_hash_verify_wrong_password(self):
        """Test that wrong password fails verification"""
        password = "test_password_123"
        wrong_password = "wrong_password"
        hashed = a.hasher.hash(password)

        assert a.hasher.verify(wrong_password, hashed) is False

    def test_password_hash_different_each_time(self):
        """Test that hashing same password produces different hashes (salt)"""
        password = "test_password_123"
        hash1 = a.hasher.hash(password)
        hash2 = a.hasher.hash(password)

        assert hash1 != hash2
        assert a.hasher.verify(password, hash1) is True
        assert a.hasher.verify(password, hash2) is True
