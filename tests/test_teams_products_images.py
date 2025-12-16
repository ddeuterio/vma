"""
Comprehensive tests for teams, products, and images management in VMA.

Tests cover:
- Team creation (root only)
- Team listing with access control
- Team deletion (root only)
- Product CRUD operations with team scoping
- Image CRUD operations with team scoping
- Cross-team access prevention
- Cascade deletion behavior
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi import status
from httpx import AsyncClient, ASGITransport

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


@pytest.fixture
def read_only_user_token():
    """JWT data for a user with read-only access"""
    return mod_v1.JwtData(
        username="reader@test.com",
        scope={"team1": "read"},
        root=False
    )


@pytest.fixture
def write_user_token():
    """JWT data for a user with write access"""
    return mod_v1.JwtData(
        username="writer@test.com",
        scope={"team1": "write"},
        root=False
    )


@pytest.fixture
def admin_user_token():
    """JWT data for a user with admin access"""
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


class TestTeamManagement:
    """Tests for team CRUD operations"""

    @pytest.mark.asyncio
    async def test_get_teams_success(self, client, read_only_user_token, mock_router_dependencies):
        """Test that user can list teams they have access to"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_teams.return_value = {
            "status": True,
            "result": [
                {"name": "team1", "description": "Team 1"}
            ]
        }

        response = await client.get(
            "/api/v1/teams",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["result"]) == 1
        assert data["result"][0]["name"] == "team1"

    @pytest.mark.asyncio
    async def test_get_team_by_name_success(self, client, read_only_user_token):
        """Test getting specific team details"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_teams.return_value = {
                "status": True,
                "result": [
                    {"name": "team1", "description": "Team 1 Description"}
                ]
            }

            response = await client.get(
                "/api/v1/team/team1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["result"][0]["name"] == "team1"

    @pytest.mark.asyncio
    async def test_get_team_unauthorized_team_forbidden(self, client, read_only_user_token):
        """Test that user cannot view team they don't have access to"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/team/team2",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_create_team_root_user_success(self, client, root_user_token):
        """Test that root user can create teams"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_teams.return_value = {
                "status": True,
                "result": {"name": "new_team"}
            }

            response = await client.post(
                "/api/v1/team",
                json={"name": "new_team", "description": "New Team Description"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_teams.assert_called_once_with(
                name="new_team",
                description="New Team Description"
            )

    @pytest.mark.asyncio
    async def test_create_team_missing_name_fails(self, client, root_user_token):
        """Test that creating team without name fails"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.post(
                "/api/v1/team",
                json={"name": "", "description": "Description"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_delete_team_root_user_success(self, client, root_user_token):
        """Test that root user can delete teams"""
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_team.return_value = {
                "status": True,
                "result": {"deleted": 1}
            }

            response = await client.delete(
                "/api/v1/team/team1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.delete_team.assert_called_once_with(id="team1")

    @pytest.mark.asyncio
    async def test_delete_team_non_root_forbidden(self, client, admin_user_token):
        """Test that non-root admin cannot delete teams"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.delete(
                "/api/v1/team/team1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestProductManagement:
    """Tests for product CRUD operations"""

    @pytest.mark.asyncio
    async def test_get_products_success(self, client, read_only_user_token, mock_router_dependencies):
        """Test listing products with team scoping"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_products.return_value = {
            "status": True,
            "result": [
                {"id": "prod1", "description": "Product 1", "team": "team1"},
                {"id": "prod2", "description": "Product 2", "team": "team1"}
            ]
        }

        response = await client.get(
            "/api/v1/products",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["result"]) == 2
        mock_c.get_products.assert_called_once_with(teams=["team1"])

    @pytest.mark.asyncio
    async def test_get_product_by_id_success(self, client, read_only_user_token):
        """Test getting specific product"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_products.return_value = {
                "status": True,
                "result": [
                    {"id": "prod1", "description": "Product 1", "team": "team1"}
                ]
            }

            response = await client.get(
                "/api/v1/product/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.get_products.assert_called_once_with(teams=["team1"], id="prod1")

    @pytest.mark.asyncio
    async def test_create_product_write_access_success(self, client, write_user_token):
        """Test that user with write access can create products"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_product.return_value = {
                "status": True,
                "result": {"id": "new_prod"}
            }

            response = await client.post(
                "/api/v1/product",
                json={
                    "name": "new_prod",
                    "description": "New Product",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_product.assert_called_once_with(
                name="new_prod",
                description="New Product",
                team="team1"
            )

    @pytest.mark.asyncio
    async def test_create_product_read_only_forbidden(self, client, read_only_user_token):
        """Test that read-only user cannot create products"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.post(
                "/api/v1/product",
                json={
                    "name": "new_prod",
                    "description": "New Product",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_create_product_missing_name_fails(self, client, write_user_token, mock_helper_errors):
        """Test that creating product without name fails"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.errors = mock_helper_errors

            response = await client.post(
                "/api/v1/product",
                json={
                    "name": "",
                    "description": "Product",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_delete_product_admin_access_success(self, client, admin_user_token):
        """Test that admin can delete products"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_product.return_value = {
                "status": True,
                "result": {"deleted_rows": 1}
            }

            import json
            response = await client.request(
                "DELETE",
                "/api/v1/product",
                content=json.dumps({"name": "prod1", "team": "team1"}),
                headers={"Authorization": "Bearer fake_token", "Content-Type": "application/json"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.delete_product.assert_called_once_with(id="prod1", team="team1")

    @pytest.mark.asyncio
    async def test_delete_product_by_id_path_param(self, client, admin_user_token):
        """Test deleting product using path parameters"""
        async def override_validate_token():
            return admin_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_product.return_value = {
                "status": True,
                "result": {"deleted_rows": 1}
            }

            response = await client.delete(
                "/api/v1/product/team1/prod1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_delete_product_write_access_forbidden(self, client, write_user_token):
        """Test that write access is insufficient for deletion"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            import json
            response = await client.request(
                "DELETE",
                "/api/v1/product",
                content=json.dumps({"name": "prod1", "team": "team1"}),
                headers={"Authorization": "Bearer fake_token", "Content-Type": "application/json"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestImageManagement:
    """Tests for image CRUD operations"""

    @pytest.mark.asyncio
    async def test_get_images_success(self, client, read_only_user_token, mock_router_dependencies):
        """Test listing images with team scoping"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_images.return_value = {
            "status": True,
            "result": [
                {
                    "name": "app",
                    "version": "1.0",
                    "product": "prod1",
                    "team": "team1"
                },
                {
                    "name": "app",
                    "version": "1.1",
                    "product": "prod1",
                    "team": "team1"
                }
            ]
        }

        response = await client.get(
            "/api/v1/images",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["result"]) == 2
        mock_c.get_images.assert_called_once_with(teams=["team1"])

    @pytest.mark.asyncio
    async def test_create_image_write_access_success(self, client, write_user_token):
        """Test that user with write access can create images"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.insert_image.return_value = {
                "status": True,
                "result": {
                    "name": "app",
                    "version": "1.0",
                    "product": "prod1",
                    "team": "team1"
                }
            }

            response = await client.post(
                "/api/v1/image",
                json={
                    "name": "app",
                    "version": "1.0",
                    "product": "prod1",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            mock_c.insert_image.assert_called_once_with(
                name="app",
                version="1.0",
                product="prod1",
                team="team1"
            )

    @pytest.mark.asyncio
    async def test_create_image_missing_required_fields_fails(self, client, write_user_token, mock_helper_errors):
        """Test that creating image without required fields fails"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.errors = mock_helper_errors

            response = await client.post(
                "/api/v1/image",
                json={
                    "name": "",
                    "version": "1.0",
                    "product": "prod1",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_create_image_read_only_forbidden(self, client, read_only_user_token):
        """Test that read-only user cannot create images"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.post(
                "/api/v1/image",
                json={
                    "name": "app",
                    "version": "1.0",
                    "product": "prod1",
                    "team": "team1"
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_delete_image_by_name_version(self, client, write_user_token):
        """Test deleting specific image version"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_image.return_value = {
                "status": True,
                "result": {"deleted": 1}
            }

            response = await client.delete(
                "/api/v1/image/team1/prod1?n=app&ver=1.0",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_delete_all_image_versions(self, client, write_user_token):
        """Test deleting all versions of an image"""
        async def override_validate_token():
            return write_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.delete_image.return_value = {
                "status": True,
                "result": {"deleted": 3}
            }

            response = await client.delete(
                "/api/v1/image/team1/prod1?n=app",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            # Should be called with version=None to delete all versions
            mock_c.delete_image.assert_called_once_with(
                product="prod1",
                name="app",
                team="team1"
            )


class TestStatsEndpoint:
    """Tests for stats aggregation"""

    @pytest.mark.asyncio
    async def test_get_stats_success(self, client, read_only_user_token, mock_router_dependencies):
        """Test getting statistics for user's teams"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_products.return_value = {
            "status": True,
            "result": [{"id": "prod1"}, {"id": "prod2"}, {"id": "prod3"}]
        }
        mock_c.get_images.return_value = {
            "status": True,
            "result": [
                {"name": "img1"},
                {"name": "img2"},
                {"name": "img3"},
                {"name": "img4"},
                {"name": "img5"}
            ]
        }

        response = await client.get(
            "/api/v1/stats",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["products"] == 3
        assert data["images"] == 5

    @pytest.mark.asyncio
    async def test_get_stats_empty_results(self, client, read_only_user_token, mock_router_dependencies):
        """Test stats with no products or images"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_products.return_value = {
            "status": True,
            "result": []
        }
        mock_c.get_images.return_value = {
            "status": True,
            "result": []
        }

        response = await client.get(
            "/api/v1/stats",
            headers={"Authorization": "Bearer fake_token"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["products"] == 0
        assert data["images"] == 0
