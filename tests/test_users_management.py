"""
Comprehensive user management tests for VMA.

Tests cover:
- User creation with scope validation
- User listing (admin/root access)
- User retrieval (own data or admin)
- User updates (password, scopes, root status)
- User deletion (admin/root only)
- Scope format validation (team:scope pairs)
- Self-service user updates
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi import status
from httpx import AsyncClient, ASGITransport

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
def admin_user_token():
    """JWT data for an admin user"""
    return mod_v1.JwtData(
        username="admin@test.com",
        scope={"team1": "admin"},
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


class TestUserCreation:
    """Tests for creating users"""

    @pytest.mark.asyncio
    async def test_create_user_admin_success(self, client, admin_user_token):
        """Test that admin can create users in their team"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {"team1": "read"}
            mock_hasher.hash.return_value = "hashed_password"
            mock_c.insert_users.return_value = {
                "status": True,
                "result": {"user": "newuser@test.com"}
            }

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "newuser@test.com",
                    "password": "password123",
                    "name": "New User",
                    "scopes": "team1:read",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_users.assert_called_once()

            # Verify password was hashed
            call_args = mock_c.insert_users.call_args
            assert call_args[1]["password"] == "hashed_password"

    @pytest.mark.asyncio
    async def test_create_user_multiple_teams(self, client, root_user_token):
        """Test creating user with access to multiple teams"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {
                "team1": "admin",
                "team2": "write",
                "team3": "read"
            }
            mock_hasher.hash.return_value = "hashed_password"
            mock_c.insert_users.return_value = {
                "status": True,
                "result": {"user": "multiuser@test.com"}
            }

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "multiuser@test.com",
                    "password": "password123",
                    "name": "Multi Team User",
                    "scopes": "team1:admin,team2:write,team3:read",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_create_user_non_admin_forbidden(self, client, regular_user_token):
        """Test that non-admin user cannot create users"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {"team1": "read"}
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "newuser@test.com",
                    "password": "password123",
                    "name": "New User",
                    "scopes": "team1:read",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_create_user_missing_email_fails(self, client, admin_user_token):
        """Test that creating user without email fails"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.validate_scopes.return_value = {"team1": "read"}
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "",
                    "password": "password123",
                    "name": "User",
                    "scopes": "team1:read",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_create_user_missing_password_fails(self, client, admin_user_token):
        """Test that creating user without password fails"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x if x else None
            mock_helper.validate_scopes.return_value = {"team1": "read"}
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "user@test.com",
                    "password": "",
                    "name": "User",
                    "scopes": "team1:read",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_create_user_invalid_scopes_fails(self, client, admin_user_token):
        """Test that creating user with invalid scopes fails"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = None
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "user@test.com",
                    "password": "password",
                    "name": "User",
                    "scopes": "",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestUserRetrieval:
    """Tests for retrieving user information"""

    @pytest.mark.asyncio
    async def test_list_users_admin_success(self, client, admin_user_token):
        """Test that admin can list users"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_users.return_value = {
                "status": True,
                "result": [
                    {
                        "email": "user1@test.com",
                        "name": "User 1",
                        "is_root": False,
                        "scope": {"team1": "read"}
                    },
                    {
                        "email": "user2@test.com",
                        "name": "User 2",
                        "is_root": False,
                        "scope": {"team1": "write"}
                    }
                ]
            }

            response = await client.get(
                "/api/v1/users",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["result"]) == 2

    @pytest.mark.asyncio
    async def test_list_users_non_admin_forbidden(self, client, regular_user_token):
        """Test that non-admin user cannot list users"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/users",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_user_own_data_success(self, client, regular_user_token):
        """Test that user can retrieve their own data"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users.return_value = {
                "status": True,
                "result": [
                    {
                        "email": "user@test.com",
                        "name": "Test User",
                        "is_root": False,
                        "scope": {"team1": "write"}
                    }
                ]
            }

            response = await client.get(
                "/api/v1/user/user@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["result"][0]["email"] == "user@test.com"

    @pytest.mark.asyncio
    async def test_get_user_other_user_forbidden(self, client, regular_user_token):
        """Test that user cannot retrieve other user's data"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/user/other@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_user_root_can_see_all(self, client, root_user_token):
        """Test that root user can retrieve any user's data"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users.return_value = {
                "status": True,
                "result": [
                    {
                        "email": "other@test.com",
                        "name": "Other User",
                        "is_root": False,
                        "scope": {"team2": "admin"}
                    }
                ]
            }

            response = await client.get(
                "/api/v1/user/other@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK


class TestUserUpdate:
    """Tests for updating user information"""

    @pytest.mark.asyncio
    async def test_update_own_password_success(self, client, regular_user_token):
        """Test that user can update their own password"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_hasher.hash.return_value = "new_hashed_password"
            mock_c.update_users.return_value = {
                "status": True,
                "result": {"updated": 1}
            }

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "user@test.com",
                    "password": "new_password",
                    "name": None,
                    "scopes": None,
                    "root": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_hasher.hash.assert_called_once_with("new_password")

    @pytest.mark.asyncio
    async def test_update_own_name_success(self, client, regular_user_token):
        """Test that user can update their own name"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.update_users.return_value = {
                "status": True,
                "result": {"updated": 1}
            }

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "user@test.com",
                    "password": None,
                    "name": "Updated Name",
                    "scopes": None,
                    "root": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_update_other_user_non_root_forbidden(self, client, regular_user_token):
        """Test that non-root user cannot update other users"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "other@test.com",
                    "password": "new_password",
                    "name": None,
                    "scopes": None,
                    "root": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_update_user_scopes_root_success(self, client, root_user_token):
        """Test that root can update user scopes"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {"team1": "admin", "team2": "write"}
            mock_c.update_users.return_value = {
                "status": True,
                "result": {"updated": 1}
            }

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "other@test.com",
                    "password": None,
                    "name": None,
                    "scopes": "team1:admin,team2:write",
                    "root": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_update_user_root_status_root_success(self, client, root_user_token):
        """Test that root can update user root status"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.update_users.return_value = {
                "status": True,
                "result": {"updated": 1}
            }

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "other@test.com",
                    "password": None,
                    "name": None,
                    "scopes": None,
                    "root": True
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_update_user_empty_password_not_changed(self, client, regular_user_token):
        """Test that empty password doesn't change password"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x if x else None
            mock_c.update_users.return_value = {
                "status": True,
                "result": {"updated": 1}
            }

            response = await client.patch(
                "/api/v1/user",
                json={
                    "email": "user@test.com",
                    "password": "",
                    "name": "Updated Name",
                    "scopes": None,
                    "root": None
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            # Password hash should not be called
            mock_hasher.hash.assert_not_called()


class TestUserDeletion:
    """Tests for deleting users"""

    @pytest.mark.asyncio
    async def test_delete_user_admin_success(self, client, admin_user_token):
        """Test that admin can delete users in their team"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_user.return_value = {
                "status": True,
                "result": {"deleted": 1}
            }

            response = await client.delete(
                "/api/v1/user/user@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.delete_user.assert_called_once_with(email="user@test.com")

    @pytest.mark.asyncio
    async def test_delete_user_non_admin_forbidden(self, client, regular_user_token):
        """Test that non-admin user cannot delete users"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.delete(
                "/api/v1/user/other@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_delete_user_root_can_delete_any(self, client, root_user_token):
        """Test that root user can delete any user"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_user.return_value = {
                "status": True,
                "result": {"deleted": 1}
            }

            response = await client.delete(
                "/api/v1/user/any@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK


class TestScopeValidation:
    """Tests for scope string validation"""

    def test_validate_scopes_single_team(self):
        """Test parsing single team scope"""
        from vma.helper import validate_scopes

        result = validate_scopes("team1:read")
        assert result == {"team1": "read"}

    def test_validate_scopes_multiple_teams(self):
        """Test parsing multiple team scopes"""
        from vma.helper import validate_scopes

        result = validate_scopes("team1:admin,team2:write,team3:read")
        assert result == {"team1": "admin", "team2": "write", "team3": "read"}

    def test_validate_scopes_empty_string(self):
        """Test that empty scope string returns None"""
        from vma.helper import validate_scopes

        result = validate_scopes("")
        assert result is None

    def test_validate_scopes_none(self):
        """Test that None scope returns None"""
        from vma.helper import validate_scopes

        result = validate_scopes(None)
        assert result is None
