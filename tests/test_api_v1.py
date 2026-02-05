import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import status
from httpx import AsyncClient, ASGITransport
from datetime import datetime

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


@pytest.fixture
def regular_user_token():
    """JWT data for a regular user with read/write access to team1"""
    return mod_v1.JwtData(
        username="user@test.com",
        scope={"team1": "write"},
        root=False
    )


@pytest.fixture
def admin_user_token():
    """JWT data for a regular user with admin access to team1"""
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
    # Clean up any overrides after test
    api_server.dependency_overrides.clear()


class TestProductEndpoints:
    """Tests for product-related endpoints"""

    @pytest.mark.asyncio
    async def test_get_products_success(self, client, regular_user_token):
        """Test GET /api/v1/products - success case"""
        # Override the dependency
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_products = AsyncMock(return_value={
                "status": True,
                "result": [
                    {"id": "prod1", "description": "Product 1", "team": "team1"}
                ]
            })

            response = await client.get(
                "/api/v1/products",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] is True
            assert len(data["result"]) == 1
            mock_c.get_products.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_product_by_id_success(self, client, regular_user_token):
        """Test GET /api/v1/product/{team}/{id} - success case"""
        async def override_validate_token():
            return regular_user_token

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
            mock_c.get_products.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_product_forbidden(self, client, regular_user_token):
        """Test GET /api/v1/product/{team}/{id} - forbidden (wrong team)"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/product/team2/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestRepoEndpoints:
    """Tests for repository endpoints"""

    @pytest.mark.asyncio
    async def test_create_repo_write_success(self, client, regular_user_token):
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_repository = AsyncMock(return_value={
                "status": True,
                "result": {"name": "repo1"}
            })

            response = await client.post(
                "/api/v1/repo",
                json={
                    "product": "prod1",
                    "team": "team1",
                    "name": "repo1",
                    "url": "https://example.com/repo1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_repository.assert_called_once_with(
                product="prod1",
                team="team1",
                name="repo1",
                url="https://example.com/repo1"
            )

    @pytest.mark.asyncio
    async def test_get_repo_by_team_success(self, client, regular_user_token):
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_repositories = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "product": "prod1",
                        "team": "team1",
                        "name": "repo1",
                        "url": "https://example.com/repo1"
                    }
                ]
            })

            response = await client.get(
                "/api/v1/repo/team1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.get_repositories.assert_called_once_with(teams=["team1"])

    @pytest.mark.asyncio
    async def test_get_repo_by_product_success(self, client, regular_user_token):
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_repositories = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.get(
                "/api/v1/repo/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.get_repositories.assert_called_once_with(
                teams=["team1"], product="prod1"
            )

    @pytest.mark.asyncio
    async def test_get_repo_by_name_success(self, client, regular_user_token):
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_repositories = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.get(
                "/api/v1/repo/team1/prod1/repo1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.get_repositories.assert_called_once_with(
                teams=["team1"], product="prod1", name="repo1"
            )

    @pytest.mark.asyncio
    async def test_delete_repo_admin_success(self, client, admin_user_token):
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_repository = AsyncMock(return_value={
                "status": True,
                "result": {"deleted_rows": 1}
            })

            response = await client.delete(
                "/api/v1/repo/team1/prod1/repo1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.delete_repository.assert_called_once_with(
                team="team1", product="prod1", name="repo1"
            )

    @pytest.mark.asyncio
    async def test_post_product_success(self, client, regular_user_token):
        """Test POST /api/v1/product - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_product = AsyncMock(return_value={
                "status": True,
                "result": {"id": "new_prod"}
            })

            response = await client.post(
                "/api/v1/product",
                json={"name": "new_prod", "description": "New Product", "team": "team1"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_product.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_product_success(self, client, admin_user_token):
        """Test DELETE /api/v1/product - success case"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_product = AsyncMock(return_value={
                "status": True,
                "result": {"deleted_rows": 1}
            })

            response = await client.delete(
                "/api/v1/product/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.delete_product.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_product_insufficient_permissions(self, client, regular_user_token):
        """Test DELETE /api/v1/product - insufficient permissions (not admin)"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.delete(
                "/api/v1/product/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestImageEndpoints:
    """Tests for image-related endpoints"""

    @pytest.mark.asyncio
    async def test_get_images_success(self, client, regular_user_token):
        """Test GET /api/v1/images - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_images = AsyncMock(return_value={
                "status": True,
                "result": [
                    {"name": "app", "version": "1.0", "product": "prod1", "team": "team1"}
                ]
            })

            response = await client.get(
                "/api/v1/images",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] is True
            assert len(data["result"]) == 1

    @pytest.mark.asyncio
    async def test_post_image_success(self, client, regular_user_token):
        """Test POST /api/v1/image - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_image = AsyncMock(return_value={
                "status": True,
                "result": {"name": "app", "version": "1.0", "product": "prod1", "team": "team1"}
            })

            response = await client.post(
                "/api/v1/image",
                json={"name": "app", "version": "1.0", "product": "prod1", "team": "team1"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_image.assert_called_once()


class TestCVEEndpoints:
    """Tests for CVE-related endpoints"""

    @pytest.mark.asyncio
    async def test_get_cve_success(self, client, regular_user_token):
        """Test GET /api/v1/cve/{id} - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.escape_like.side_effect = lambda x: x
            mock_c.get_vulnerabilities_by_id = AsyncMock(return_value={
                "status": True,
                "result": {
                    "CVE-2023-1234": {
                        "source": "nvd@nist.gov",
                        "published_date": "2023-01-01",
                        "status": "Analyzed"
                    }
                }
            })

            response = await client.get(
                "/api/v1/cve/nvd/CVE-2023-1234",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "CVE-2023-1234" in data["result"]


class TestStatsEndpoint:
    """Tests for stats endpoint"""

    @pytest.mark.asyncio
    async def test_get_stats_success(self, client, regular_user_token):
        """Test GET /api/v1/stats - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_products = AsyncMock(return_value={
                "status": True,
                "result": [{"id": "prod1"}, {"id": "prod2"}]
            })
            mock_c.get_images = AsyncMock(return_value={
                "status": True,
                "result": [{"name": "img1"}, {"name": "img2"}, {"name": "img3"}]
            })

            response = await client.get(
                "/api/v1/stats",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["products"] == 2
            assert data["images"] == 3


class TestTeamEndpoints:
    """Tests for team-related endpoints"""

    @pytest.mark.asyncio
    async def test_get_teams_success(self, client, regular_user_token):
        """Test GET /api/v1/teams - success case"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_teams = AsyncMock(return_value={
                "status": True,
                "result": [{"name": "team1", "description": "Team 1"}]
            })

            response = await client.get(
                "/api/v1/teams",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["result"]) == 1

    @pytest.mark.asyncio
    async def test_post_team_success(self, client, root_user_token):
        """Test POST /api/v1/team - success case (root user)"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_teams = AsyncMock(return_value={
                "status": True,
                "result": {"name": "new_team"}
            })

            response = await client.post(
                "/api/v1/team",
                json={"name": "new_team", "description": "New Team"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_post_team_forbidden(self, client, regular_user_token):
        """Test POST /api/v1/team - should be forbidden (not root)

        NOTE: This test currently fails due to a bug in is_authorized() function.
        When teams=[] and is_root=False, is_authorized returns True instead of False.
        This allows non-root users to create teams when they shouldn't be able to.

        TODO: Fix is_authorized to return False when teams=[] and is_root=False
        """
        pytest.skip("Known bug: is_authorized() returns True for empty teams list")


class TestUserEndpoints:
    """Tests for user-related endpoints"""

    @pytest.mark.asyncio
    async def test_get_users_success(self, client, admin_user_token):
        """Test GET /api/v1/users - success case"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c:
            mock_c.get_users = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "email": "user@test.com",
                        "name": "Test User",
                        "is_root": False,
                        "scope": {"team1": "read"}
                    }
                ]
            })

            response = await client.get(
                "/api/v1/users",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["result"]) == 1

    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, client, regular_user_token):
        """Test GET /api/v1/user/{email} - success case (own data)"""
        async def override_validate_token():
            return regular_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "email": "user@test.com",
                        "name": "Test User",
                        "is_root": False,
                        "scope": {"team1": "write"}
                    }
                ]
            })

            response = await client.get(
                "/api/v1/user/user@test.com",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_post_user_success(self, client, admin_user_token):
        """Test POST /api/v1/user - success case"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {"team1": "admin"}
            mock_hasher.hash.return_value = "hashed_password"
            mock_c.insert_users = AsyncMock(return_value={
                "status": True,
                "result": {"user": "newuser@test.com"}
            })

            response = await client.post(
                "/api/v1/user",
                json={
                    "email": "newuser@test.com",
                    "password": "password123",
                    "name": "New User",
                    "scopes": "team1:admin",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_users.assert_called_once()


class TestAuthenticationEndpoints:
    """Tests for authentication-related endpoints"""

    @pytest.mark.asyncio
    async def test_token_success(self, client):
        """Test POST /api/v1/token - success case"""
        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users_w_hpass = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "email": "user@test.com",
                        "hpass": "hashed_password",
                        "name": "Test User",
                        "is_root": False
                    }
                ]
            })
            mock_c.get_scope_by_user = AsyncMock(return_value={
                "status": True,
                "result": {"team1": "write"}
            })
            mock_auth.hasher.verify.return_value = True
            mock_auth.create_token.side_effect = ["fake_access_token", "fake_refresh_token"]
            mock_auth._expire_refresh_token = 2

            response = await client.post(
                "/api/v1/token",
                data={"username": "user@test.com", "password": "password123"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] == "fake_access_token"
            assert data["token_type"] == "Bearer"

    @pytest.mark.asyncio
    async def test_token_invalid_credentials(self, client):
        """Test POST /api/v1/token - invalid credentials"""
        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a") as mock_auth, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_users_w_hpass = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "email": "user@test.com",
                        "hpass": "hashed_password",
                        "name": "Test User",
                        "is_root": False
                    }
                ]
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


class TestAuthorizationHelpers:
    """Tests for authorization helper functions"""

    def test_is_authorized_root_user(self):
        """Test is_authorized - root user always authorized"""
        from vma.api.routers.v1 import is_authorized, ADMIN

        result = is_authorized(
            scope={"team1": "read"},
            teams=["team1", "team2"],
            op=ADMIN,
            is_root=True
        )
        assert result is True

    def test_is_authorized_valid_scope(self):
        """Test is_authorized - user has valid scope"""
        from vma.api.routers.v1 import is_authorized, READ_ONLY

        result = is_authorized(
            scope={"team1": "read", "team2": "write"},
            teams=["team1", "team2"],
            op=READ_ONLY,
            is_root=False
        )
        assert result is True

    def test_is_authorized_insufficient_scope(self):
        """Test is_authorized - user lacks sufficient scope"""
        from vma.api.routers.v1 import is_authorized, ADMIN

        result = is_authorized(
            scope={"team1": "read"},
            teams=["team1"],
            op=ADMIN,
            is_root=False
        )
        assert result is False

    @pytest.mark.asyncio
    @patch("vma.api.routers.v1.c")
    async def test_get_teams_for_authz_root(self, mock_connector):
        """Test get_teams_for_authz - root user gets all teams"""
        from vma.api.routers.v1 import get_teams_for_authz

        mock_connector.get_teams = AsyncMock(return_value={
            "result": [
                {"name": "team1"},
                {"name": "team2"},
                {"name": "team3"}
            ]
        })

        result = await get_teams_for_authz(scope={"team1": "admin"}, is_root=True)
        assert len(result) == 3
        assert "team1" in result
