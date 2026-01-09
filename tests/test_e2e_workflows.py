"""
End-to-end workflow tests for VMA.

Tests complete user workflows across multiple endpoints:
- Complete onboarding flow (team → user → product → image)
- Vulnerability scanning workflow (scan → import → view)
- Image update workflow (new version → compare → analyze)
- Multi-team collaboration workflow
- API token lifecycle for CI/CD
- User permission changes and impact
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import status
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


@pytest.fixture
def root_user_token():
    """JWT data for a root user"""
    return mod_v1.JwtData(
        username="root@test.com",
        scope={"platform": "admin"},
        root=True
    )


@pytest.fixture
async def client():
    """Async test client"""
    transport = ASGITransport(app=api_server)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    api_server.dependency_overrides.clear()


class TestCompleteOnboardingWorkflow:
    """Test complete onboarding of a new team"""

    @pytest.mark.asyncio
    async def test_onboard_new_team_complete_workflow(self, client, root_user_token):
        """
        Test complete onboarding workflow:
        1. Root creates new team
        2. Root creates admin user for team
        3. Admin user creates product
        4. Admin user creates image
        """
        async def override_validate_token():
            return root_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.side_effect = lambda x: {"devops": "admin"} if x else None
            mock_hasher.hash.return_value = "hashed_password"

            # Mock get_teams for root user authorization
            mock_c.get_teams = AsyncMock(return_value={
                "status": True,
                "result": [{"name": "devops"}, {"name": "platform"}]
            })

            # Step 1: Create team
            mock_c.insert_teams = AsyncMock(return_value={
                "status": True,
                "result": {"name": "devops"}
            })

            response_team = await client.post(
                "/api/v1/team",
                json={"name": "devops", "description": "DevOps Team"},
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response_team.status_code == status.HTTP_200_OK
            assert response_team.json()["result"]["name"] == "devops"

            # Step 2: Create admin user for team
            mock_c.insert_users = AsyncMock(return_value={
                "status": True,
                "result": {"user": "devops-admin@test.com"}
            })

            response_user = await client.post(
                "/api/v1/user",
                json={
                    "email": "devops-admin@test.com",
                    "password": "secure_password",
                    "name": "DevOps Admin",
                    "scopes": "devops:admin",
                    "root": False
                },
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response_user.status_code == status.HTTP_200_OK

            # Step 3: Admin user creates product (simulate with admin token)
            admin_token = mod_v1.JwtData(
                username="devops-admin@test.com",
                scope={"devops": "admin"},
                root=False
            )
            api_server.dependency_overrides[a.validate_access_token] = lambda: admin_token

            mock_c.insert_product = AsyncMock(return_value={
                "status": True,
                "result": {"id": "web-app"}
            })

            response_product = await client.post(
                "/api/v1/product",
                json={
                    "name": "web-app",
                    "description": "Main Web Application",
                    "team": "devops"
                },
                headers={"Authorization": "Bearer admin_token"}
            )

            assert response_product.status_code == status.HTTP_200_OK

            # Step 4: Create image
            mock_c.insert_image = AsyncMock(return_value={
                "status": True,
                "result": {
                    "name": "web-app",
                    "version": "1.0.0",
                    "product": "web-app",
                    "team": "devops"
                }
            })

            response_image = await client.post(
                "/api/v1/image",
                json={
                    "name": "web-app",
                    "version": "1.0.0",
                    "product": "web-app",
                    "team": "devops"
                },
                headers={"Authorization": "Bearer admin_token"}
            )

            assert response_image.status_code == status.HTTP_200_OK

            # Verify all steps succeeded
            assert mock_c.insert_teams.called
            assert mock_c.insert_users.called
            assert mock_c.insert_product.called
            assert mock_c.insert_image.called


class TestVulnerabilityScanningWorkflow:
    """Test complete vulnerability scanning workflow"""

    @pytest.mark.asyncio
    async def test_scan_import_view_workflow(self, client, mock_router_dependencies):
        """
        Test complete scanning workflow:
        1. Create API token for scanner
        2. Import scan results
        3. View vulnerabilities
        4. Compare with previous version
        """
        # Step 1: Create API token (as root)
        root_token = mod_v1.JwtData(
            username="root@test.com",
            scope={"security": "admin"},
            root=True
        )

        async def override_root():
            return root_token

        api_server.dependency_overrides[a.validate_access_token] = override_root

        with patch("vma.api.routers.v1.a") as mock_auth:
            mock_c = mock_router_dependencies["connector"]

            # Create API token
            mock_token = "vma_scanner123456789012345678901234"
            mock_auth.generate_api_token.return_value = mock_token
            mock_auth.hasher.hash.return_value = "hashed_token"

            mock_c.insert_api_token = AsyncMock(return_value={
                "status": True,
                "result": {
                    "id": 1,
                    "created_at": datetime.now(timezone.utc)
                }
            })

            response_token = await client.post(
                "/api/v1/apitoken",
                json={
                    "username": "root@test.com",
                    "description": "CI/CD Scanner Token",
                    "expires_days": 365
                },
                headers={"Authorization": "Bearer root_token"}
            )

            assert response_token.status_code == status.HTTP_200_OK
            api_token = response_token.json()["result"]["token"]

        # Step 2: Import scan results using API token (override validate_api_token dependency)
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"security": "write"},
                    "root": False
                }
            }

        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_c = mock_router_dependencies["connector"]
        mock_c.get_images = AsyncMock(return_value={"status": False})
        mock_c.insert_image = AsyncMock(return_value={"status": True})
        mock_c.insert_image_vulnerabilities = AsyncMock(return_value={
            "status": True,
            "result": "5 vulnerabilities imported"
        })

        vuln_data = [
            ["grype", "api", "2.1.0", "backend", "security", "CVE-2023-1234",
             "2.1.1", "2023-01-01", "2023-01-01", "deb", "libssl", "1.1.1", "/usr/lib"]
        ]

        response_import = await client.post(
            "/api/v1/import",
            json={
                "scanner": "grype",
                "product": "backend",
                "image": "api",
                "version": "2.1.0",
                "team": "security",
                "data": vuln_data
            },
            headers={"Authorization": f"Bearer {api_token}"}
        )

        assert response_import.status_code == status.HTTP_200_OK

        # Step 3: View vulnerabilities (as authenticated user)
        user_token = mod_v1.JwtData(
            username="security-user@test.com",
            scope={"security": "read"},
            root=False
        )

        async def override_user():
            return user_token

        api_server.dependency_overrides[a.validate_access_token] = override_user

        mock_helper = mock_router_dependencies["helper"]
        mock_helper.format_vulnerability_rows.return_value = [
            {
                "cve": "CVE-2023-1234",
                "component": "libssl",
                "cvss": {"score": 7.5, "severity": "HIGH"}
            }
        ]

        mock_c.get_image_vulnerabilities = AsyncMock(return_value={
            "status": True,
            "result": []
        })

        response_vulns = await client.get(
            "/api/v1/image/security/backend/api/2.1.0/vuln",
            headers={"Authorization": "Bearer user_token"}
        )

        assert response_vulns.status_code == status.HTTP_200_OK


class TestImageUpdateWorkflow:
    """Test workflow for updating and comparing image versions"""

    @pytest.mark.asyncio
    async def test_new_version_compare_workflow(self, client, mock_router_dependencies):
        """
        Test image update workflow:
        1. Import new version scan
        2. Compare with old version
        3. Analyze differences
        """
        write_token = mod_v1.JwtData(
            username="dev@test.com",
            scope={"development": "write"},
            root=False
        )

        async def override_token():
            return write_token

        api_server.dependency_overrides[a.validate_access_token] = override_token

        # Step 1: Import new version (override validate_api_token for API token auth)
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"development": "write"},
                    "root": False
                }
            }

        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_c = mock_router_dependencies["connector"]
        mock_helper = mock_router_dependencies["helper"]

        mock_c.get_images = AsyncMock(return_value={"status": False})
        mock_c.insert_image = AsyncMock(return_value={"status": True})
        mock_c.insert_image_vulnerabilities = AsyncMock(return_value={
            "status": True,
            "result": "3 vulnerabilities imported"
        })

        vuln_data = [
            ["grype", "web-ui", "2.0.0", "frontend", "development", "CVE-2023-5678",
             "", "2023-01-01", "2023-01-01", "npm", "react", "17.0.0", "/app/node_modules"]
        ]

        response_import = await client.post(
            "/api/v1/import",
            json={
                "scanner": "grype",
                "product": "frontend",
                "image": "web-ui",
                "version": "2.0.0",
                "team": "development",
                "data": vuln_data
            },
            headers={"Authorization": "Bearer api_token"}
        )

        assert response_import.status_code == status.HTTP_200_OK

        # Step 2: Compare versions (switch back to JWT auth for user)
        api_server.dependency_overrides[a.validate_access_token] = override_token

        # Reset mocks for compare step - need to override side_effect, not return_value
        mock_router_dependencies["connector"].compare_image_versions.return_value = {
            "status": True,
            "result": []
        }

        # Override side_effect (fixture sets it to lambda x: x)
        mock_router_dependencies["helper"].normalize_comparison.side_effect = None
        mock_router_dependencies["helper"].normalize_comparison.return_value = {
            "stats": {
                "shared": 2,
                "only_version_a": 5,  # Fixed in new version
                "only_version_b": 1   # New vulnerability
            },
            "comparison": []
        }

        response_compare = await client.get(
            "/api/v1/image/compare/development/frontend/web-ui/1.0.0/2.0.0",
            headers={"Authorization": "Bearer user_token"}
        )

        assert response_compare.status_code == status.HTTP_200_OK
        stats = response_compare.json()["result"]["stats"]

        # Verify we can see fixed and new vulnerabilities
        assert stats["only_version_a"] == 5  # Fixed
        assert stats["only_version_b"] == 1  # New
        assert stats["shared"] == 2


class TestMultiTeamCollaboration:
    """Test workflows involving multiple teams"""

    @pytest.mark.asyncio
    async def test_multi_team_user_workflow(self, client):
        """
        Test user with access to multiple teams:
        1. Create user with multi-team access
        2. Access resources in different teams
        3. Create resources in authorized teams
        """
        # Root creates multi-team user
        root_token = mod_v1.JwtData(
            username="root@test.com",
            scope={"admin": "admin"},
            root=True
        )

        async def override_root():
            return root_token

        api_server.dependency_overrides[a.validate_access_token] = override_root

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.a.hasher") as mock_hasher, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {
                "team-a": "admin",
                "team-b": "write",
                "team-c": "read"
            }
            mock_hasher.hash.return_value = "hashed_password"

            # Mock get_teams for root user authorization
            mock_c.get_teams = AsyncMock(return_value={
                "status": True,
                "result": [
                    {"name": "admin"},
                    {"name": "team-a"},
                    {"name": "team-b"},
                    {"name": "team-c"}
                ]
            })

            mock_c.insert_users = AsyncMock(return_value={
                "status": True,
                "result": {"user": "multi@test.com"}
            })

            # Create multi-team user
            response_user = await client.post(
                "/api/v1/user",
                json={
                    "email": "multi@test.com",
                    "password": "password",
                    "name": "Multi Team User",
                    "scopes": "team-a:admin,team-b:write,team-c:read",
                    "root": False
                },
                headers={"Authorization": "Bearer root_token"}
            )

            assert response_user.status_code == status.HTTP_200_OK

            # Switch to multi-team user
            multi_token = mod_v1.JwtData(
                username="multi@test.com",
                scope={
                    "team-a": "admin",
                    "team-b": "write",
                    "team-c": "read"
                },
                root=False
            )

            async def override_multi():
                return multi_token

            api_server.dependency_overrides[a.validate_access_token] = override_multi

            # Access resources in team-a (admin)
            mock_c.get_products = AsyncMock(return_value={
                "status": True,
                "result": [{"id": "prod-a", "team": "team-a"}]
            })

            response_a = await client.get(
                "/api/v1/product/team-a/prod-a",
                headers={"Authorization": "Bearer multi_token"}
            )

            assert response_a.status_code == status.HTTP_200_OK

            # Create product in team-b (write access)
            mock_c.insert_product = AsyncMock(return_value={
                "status": True,
                "result": {"id": "prod-b"}
            })

            response_b = await client.post(
                "/api/v1/product",
                json={
                    "name": "prod-b",
                    "description": "Product B",
                    "team": "team-b"
                },
                headers={"Authorization": "Bearer multi_token"}
            )

            assert response_b.status_code == status.HTTP_200_OK

            # Try to create in team-c (read only) - should fail
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response_c = await client.post(
                "/api/v1/product",
                json={
                    "name": "prod-c",
                    "description": "Product C",
                    "team": "team-c"
                },
                headers={"Authorization": "Bearer multi_token"}
            )

            assert response_c.status_code == status.HTTP_401_UNAUTHORIZED


class TestAPITokenLifecycle:
    """Test complete API token lifecycle for CI/CD"""

    @pytest.mark.asyncio
    async def test_api_token_full_lifecycle(self, client, mock_router_dependencies):
        """
        Test API token lifecycle:
        1. Create token
        2. Use token for operations
        3. List tokens
        4. Revoke token
        5. Verify token no longer works
        """
        root_token = mod_v1.JwtData(
            username="cicd@test.com",
            scope={"devops": "admin"},
            root=True
        )

        async def override_root():
            return root_token

        api_server.dependency_overrides[a.validate_access_token] = override_root

        with patch("vma.api.routers.v1.a") as mock_auth:
            mock_c = mock_router_dependencies["connector"]

            # Step 1: Create token
            mock_token = "vma_cicd123456789012345678901234567"
            mock_auth.generate_api_token.return_value = mock_token
            mock_auth.hasher.hash.return_value = "hashed_token"

            mock_c.insert_api_token = AsyncMock(return_value={
                "status": True,
                "result": {
                    "id": 10,
                    "created_at": datetime.now(timezone.utc)
                }
            })

            response_create = await client.post(
                "/api/v1/apitoken",
                json={
                    "username": "cicd@test.com",
                    "description": "CI/CD Pipeline",
                    "expires_days": 90
                },
                headers={"Authorization": "Bearer root_token"}
            )

            assert response_create.status_code == status.HTTP_200_OK
            token_id = response_create.json()["result"]["id"]

            # Step 2: Use token (already tested in other workflows)

            # Step 3: List tokens
            mock_c.list_api_tokens = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "id": token_id,
                        "prefix": mock_token[:12],
                        "user_email": "cicd@test.com",
                        "description": "CI/CD Pipeline",
                        "revoked": False
                    }
                ]
            })

            response_list = await client.get(
                "/api/v1/tokens",
                headers={"Authorization": "Bearer root_token"}
            )

            assert response_list.status_code == status.HTTP_200_OK
            assert len(response_list.json()["result"]) == 1

            # Step 4: Revoke token
            mock_c.get_api_token_by_id = AsyncMock(return_value={
                "status": True,
                "result": {
                    "id": token_id,
                    "user_email": "cicd@test.com"
                }
            })

            mock_c.revoke_api_token = AsyncMock(return_value={
                "status": True,
                "result": "Token revoked"
            })

            response_revoke = await client.delete(
                f"/api/v1/tokens/{token_id}",
                headers={"Authorization": "Bearer root_token"}
            )

            assert response_revoke.status_code == status.HTTP_200_OK

        # Step 5: Verify token no longer works (outside the patch context)
        # Override validate_api_token dependency to return revoked status
        async def override_validate_revoked_token(authorization: str = None):
            return {
                "status": False,
                "result": "Token has been revoked"
            }

        api_server.dependency_overrides[a.validate_api_token] = override_validate_revoked_token

        response_use_revoked = await client.post(
            "/api/v1/import",
            json={
                "scanner": "grype",
                "product": "test",
                "image": "test",
                "version": "1.0",
                "team": "devops",
                "data": []
            },
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        assert response_use_revoked.status_code == status.HTTP_401_UNAUTHORIZED


class TestUserPermissionChanges:
    """Test impact of changing user permissions"""

    @pytest.mark.asyncio
    async def test_permission_upgrade_workflow(self, client, mock_helper_errors):
        """
        Test permission upgrade workflow:
        1. User has read-only access
        2. Try to create resource (fails)
        3. Admin upgrades to write access
        4. Create resource (succeeds)
        """
        # Step 1 & 2: Read-only user tries to create
        read_token = mod_v1.JwtData(
            username="junior@test.com",
            scope={"engineering": "read"},
            root=False
        )

        async def override_read():
            return read_token

        api_server.dependency_overrides[a.validate_access_token] = override_read

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = mock_helper_errors

            response_fail = await client.post(
                "/api/v1/product",
                json={
                    "name": "new-service",
                    "description": "New Service",
                    "team": "engineering"
                },
                headers={"Authorization": "Bearer read_token"}
            )

            assert response_fail.status_code == status.HTTP_401_UNAUTHORIZED

        # Step 3: Root user upgrades permission (only root can update other users)
        admin_token = mod_v1.JwtData(
            username="admin@test.com",
            scope={"engineering": "admin"},
            root=True
        )

        async def override_admin():
            return admin_token

        api_server.dependency_overrides[a.validate_access_token] = override_admin

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.validate_scopes.return_value = {"engineering": "write"}
            mock_helper.errors = mock_helper_errors

            mock_c.update_users = AsyncMock(return_value={
                "status": True,
                "result": {"updated": 1}
            })

            response_upgrade = await client.patch(
                "/api/v1/user",
                json={
                    "email": "junior@test.com",
                    "password": None,
                    "name": None,
                    "scopes": "engineering:write",
                    "root": None
                },
                headers={"Authorization": "Bearer admin_token"}
            )

            assert response_upgrade.status_code == status.HTTP_200_OK

        # Step 4: User creates resource with new permissions
        write_token = mod_v1.JwtData(
            username="junior@test.com",
            scope={"engineering": "write"},
            root=False
        )

        async def override_write():
            return write_token

        api_server.dependency_overrides[a.validate_access_token] = override_write

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = mock_helper_errors
            mock_c.insert_product = AsyncMock(return_value={
                "status": True,
                "result": {"id": "new-service"}
            })

            response_success = await client.post(
                "/api/v1/product",
                json={
                    "name": "new-service",
                    "description": "New Service",
                    "team": "engineering"
                },
                headers={"Authorization": "Bearer write_token"}
            )

            assert response_success.status_code == status.HTTP_200_OK
