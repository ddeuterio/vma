"""
Comprehensive vulnerability management tests for VMA.

Tests cover:
- CVE search and retrieval
- Image vulnerability listing
- Vulnerability import from scanner (Grype)
- Image version comparison
- Scanner output parsing
- Last seen timestamp updates
- CVSS score aggregation
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open, AsyncMock
from fastapi import status
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone
import json

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a
import vma.parser as parser


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
async def client():
    """Async test client"""
    transport = ASGITransport(app=api_server)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    api_server.dependency_overrides.clear()


@pytest.fixture
def sample_grype_report():
    """Sample Grype JSON report"""
    return {
        "distro": {
            "name": "ubuntu",
            "version": "22.04"
        },
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-1234",
                    "fix": {
                        "versions": ["1.2.3", "1.2.4"]
                    }
                },
                "artifact": {
                    "type": "deb",
                    "name": "libssl",
                    "version": "1.0.0",
                    "locations": [
                        {"path": "/usr/lib/libssl.so"},
                        {"path": "/usr/lib64/libssl.so"}
                    ]
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-5678",
                    "fix": {
                        "versions": []
                    }
                },
                "artifact": {
                    "type": "python",
                    "name": "requests",
                    "version": "2.28.0",
                    "locations": [
                        {"path": "/usr/local/lib/python3.9/site-packages/requests"}
                    ]
                }
            }
        ]
    }


class TestCVESearch:
    """Tests for CVE search and retrieval"""

    @pytest.mark.asyncio
    async def test_search_cve_by_id_success(self, client, read_only_user_token):
        """Test searching for CVE by ID"""
        async def override_validate_token():
            return read_only_user_token

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
                        "status": "Analyzed",
                        "cvss_score": 7.5,
                        "cvss_severity": "HIGH"
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

    @pytest.mark.asyncio
    async def test_search_cve_wildcard_pattern(self, client, read_only_user_token):
        """Test searching CVE with wildcard pattern"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.escape_like.side_effect = lambda x: x
            mock_c.get_vulnerabilities_by_id = AsyncMock(return_value={
                "status": True,
                "result": {
                    "CVE-2023-1234": {"source": "nvd@nist.gov"},
                    "CVE-2023-5678": {"source": "nvd@nist.gov"}
                }
            })

            response = await client.get(
                "/api/v1/cve/nvd/CVE-2023",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["result"]) == 2

    @pytest.mark.asyncio
    async def test_search_cve_missing_id_fails(self, client, read_only_user_token):
        """Test that missing CVE ID fails"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.get(
                "/api/v1/cve/",
                headers={"Authorization": "Bearer fake_token"}
            )

            # Should fail with 404 (endpoint not found) or 400
            assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND]


class TestImageVulnerabilities:
    """Tests for image vulnerability retrieval"""

    @pytest.mark.asyncio
    async def test_get_image_vulnerabilities_success(self, client, read_only_user_token):
        """Test retrieving vulnerabilities for a specific image"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_c.get_vulnerabilities_sca_by_image = AsyncMock(return_value={
                "status": True,
                "result": [
                    {
                        "vuln_id": "CVE-2023-1234",
                        "affected_component": "libssl",
                        "affected_version": "1.0.0",
                        "severity": {"level": "HIGH"}
                    }
                ]
            })

            response = await client.get(
                "/api/v1/image/team1/prod1/app/1.0/vuln-sca",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] is True

    @pytest.mark.asyncio
    async def test_get_image_vulnerabilities_unauthorized_team(self, client, read_only_user_token):
        """Test that user cannot view vulnerabilities for unauthorized team"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.get(
                "/api/v1/image/team2/prod1/app/1.0/vuln-sca",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_image_vulnerabilities_missing_params(self, client, read_only_user_token):
        """Test that missing parameters fail with 404 (FastAPI routing)"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.return_value = None
            mock_helper.errors = {"400": "One or several parameters are missing or malformed"}

            response = await client.get(
                "/api/v1/image/team1/prod1//1.0/vuln-sca",
                headers={"Authorization": "Bearer fake_token"}
            )

            # FastAPI returns 404 when path parameters are missing
            assert response.status_code == status.HTTP_404_NOT_FOUND


class TestImageComparison:
    """Tests for comparing vulnerabilities between image versions"""

    @pytest.mark.asyncio
    async def test_compare_image_versions_success(self, client, read_only_user_token):
        """Test comparing two image versions"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.normalize_comparison.return_value = {
                "stats": {
                    "shared": 5,
                    "only_version_a": 3,
                    "only_version_b": 2
                },
                "comparison": [
                    {
                        "cve_id": "CVE-2023-1234",
                        "component": "libssl",
                        "comparison": "shared",
                        "base_score": 7.5
                    }
                ]
            }
            mock_c.compare_image_versions = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.get(
                "/api/v1/image/compare/team1/prod1/app/1.0/1.1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "stats" in data["result"]
            assert "comparison" in data["result"]

    @pytest.mark.asyncio
    async def test_compare_image_versions_identifies_new_vulns(self, client, read_only_user_token):
        """Test that comparison identifies new vulnerabilities in version B"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.normalize_comparison.return_value = {
                "stats": {
                    "shared": 0,
                    "only_version_a": 0,
                    "only_version_b": 1
                },
                "comparison": [
                    {
                        "cve_id": "CVE-2023-NEW",
                        "component": "newlib",
                        "comparison": "only_version_b",
                        "base_score": 9.8
                    }
                ]
            }
            mock_c.compare_image_versions = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.get(
                "/api/v1/image/compare/team1/prod1/app/1.0/1.1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["result"]["stats"]["only_version_b"] == 1

    @pytest.mark.asyncio
    async def test_compare_image_versions_identifies_fixed_vulns(self, client, read_only_user_token):
        """Test that comparison identifies fixed vulnerabilities"""
        async def override_validate_token():
            return read_only_user_token

        api_server.dependency_overrides[a.validate_access_token] = override_validate_token

        with patch("vma.api.routers.v1.c") as mock_c, \
             patch("vma.api.routers.v1.helper") as mock_helper:

            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.normalize_comparison.return_value = {
                "stats": {
                    "shared": 0,
                    "only_version_a": 2,
                    "only_version_b": 0
                },
                "comparison": [
                    {
                        "cve_id": "CVE-2023-FIXED",
                        "component": "oldlib",
                        "comparison": "only_version_a",
                        "base_score": 7.5
                    }
                ]
            }
            mock_c.compare_image_versions = AsyncMock(return_value={
                "status": True,
                "result": []
            })

            response = await client.get(
                "/api/v1/image/compare/team1/prod1/app/1.0/1.1",
                headers={"Authorization": "Bearer fake_token"}
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["result"]["stats"]["only_version_a"] == 2


class TestVulnerabilityImport:
    """Tests for importing vulnerabilities from scanner"""

    @pytest.mark.asyncio
    async def test_import_vulnerabilities_with_api_token(self, client, mock_router_dependencies):
        """Test importing vulnerabilities using API token"""
        mock_token = "vma_test123456789012345678901234567890"

        # Override validate_api_token dependency
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"team1": "write"},
                    "root": False
                }
            }

        from vma.api.api import api_server
        import vma.auth as a
        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_c = mock_router_dependencies["connector"]

        mock_c.get_images = AsyncMock(return_value={"status": True, "result": []})
        mock_c.insert_image = AsyncMock(return_value={"status": True})
        mock_c.insert_vulnerabilities_sca_batch = AsyncMock(return_value={
            "status": True,
            "result": "2 vulnerabilities imported"
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
                        "affected_version": "1.0.0",
                        "affected_component_type": "deb",
                        "affected_path": "/usr/lib",
                        "severity": {"level": "HIGH"}
                    }
                ]
            },
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        mock_c.insert_vulnerabilities_sca_batch.assert_called_once()

    @pytest.mark.asyncio
    async def test_import_creates_image_if_not_exists(self, client, mock_router_dependencies):
        """Test that import creates image if it doesn't exist"""
        mock_token = "vma_test123456789012345678901234567890"

        # Override validate_api_token dependency
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"team1": "write"},
                    "root": False
                }
            }

        from vma.api.api import api_server
        import vma.auth as a
        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_c = mock_router_dependencies["connector"]

        # Image doesn't exist
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
                "image_name": "new_app",
                "image_version": "1.0",
                "product": "prod1",
                "team": "team1",
                "vulnerabilities": [
                    {
                        "vuln_id": "CVE-2023-9999",
                        "affected_component": "express",
                        "affected_version": "4.0.0",
                        "affected_component_type": "npm",
                        "affected_path": "/app/node_modules",
                        "severity": {"level": "HIGH"}
                    }
                ]
            },
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        mock_c.insert_image.assert_called_once_with(
            name="new_app",
            version="1.0",
            product="prod1",
            team="team1"
        )

    @pytest.mark.asyncio
    async def test_import_unauthorized_team_forbidden(self, client):
        """Test that import to unauthorized team is forbidden"""
        mock_token = "vma_test123456789012345678901234567890"

        # Override validate_api_token dependency
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"team1": "write"},
                    "root": False
                }
            }

        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        with patch("vma.api.routers.v1.helper") as mock_helper:
            mock_helper.validate_input.side_effect = lambda x: x
            mock_helper.errors = {"401": "user is not authorized to perform this action"}

            response = await client.post(
                "/api/v1/import/sca",
                json={
                    "scanner": "grype",
                    "image_name": "app",
                    "image_version": "1.0",
                    "product": "prod1",
                    "team": "team2",  # Different team
                    "vulnerabilities": []
                },
                headers={"Authorization": f"Bearer {mock_token}"}
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_import_missing_data_fails(self, client, mock_helper_errors, mock_router_dependencies):
        """Test that import without data fails"""
        mock_token = "vma_test123456789012345678901234567890"

        # Override validate_api_token dependency
        async def override_validate_api_token(authorization: str = None):
            return {
                "status": True,
                "result": {
                    "username": "scanner@test.com",
                    "teams": {"team1": "write"},
                    "root": False
                }
            }

        from vma.api.api import api_server
        import vma.auth as a
        api_server.dependency_overrides[a.validate_api_token] = override_validate_api_token

        mock_helper = mock_router_dependencies["helper"]
        mock_helper.validate_input.side_effect = lambda x: x
        mock_helper.errors = mock_helper_errors

        response = await client.post(
            "/api/v1/import/sca",
            json={
                "scanner": "grype",
                "image_name": "app",
                "image_version": "1.0",
                "product": "",
                "team": "team1",
                "vulnerabilities": []
            },
            headers={"Authorization": f"Bearer {mock_token}"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestGrypeParser:
    """Tests for Grype scanner output parsing"""

    @pytest.mark.asyncio
    async def test_grype_get_image_metadata(self, sample_grype_report, tmp_path):
        """Test extracting image metadata from Grype report"""
        report_file = tmp_path / "grype_report.json"
        report_file.write_text(json.dumps(sample_grype_report))

        metadata = await parser.grype_get_image_metadata(str(report_file))

        assert metadata[0] == "ubuntu"
        assert metadata[1] == "22.04"

    @pytest.mark.asyncio
    async def test_grype_parse_report(self, sample_grype_report, tmp_path):
        """Test parsing vulnerabilities from Grype report"""
        report_file = tmp_path / "grype_report.json"
        report_file.write_text(json.dumps(sample_grype_report))

        vulnerabilities = await parser.grype_parser(str(report_file))

        assert len(vulnerabilities) == 2

        # Check first vulnerability
        vuln1 = vulnerabilities[0]
        assert vuln1["vuln_id"] == "CVE-2023-1234"  # CVE ID
        assert vuln1["fix"]["versions"] == ["1.2.3", "1.2.4"]
        assert vuln1["affected_component_type"] == "deb"
        assert vuln1["affected_component"] == "libssl"
        assert vuln1["affected_version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_grype_parse_report_no_fix_versions(self, tmp_path):
        """Test parsing vulnerability with no fix available"""
        report = {
            "distro": {"name": "ubuntu", "version": "22.04"},
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-9999",
                        "fix": {"versions": []}
                    },
                    "artifact": {
                        "type": "python",
                        "name": "vulnerable-lib",
                        "version": "1.0.0",
                        "locations": [{"path": "/usr/lib"}]
                    }
                }
            ]
        }

        report_file = tmp_path / "grype_report.json"
        report_file.write_text(json.dumps(report))

        vulnerabilities = await parser.grype_parser(str(report_file))

        assert len(vulnerabilities) == 1
        # Fix versions should be empty string
        assert vulnerabilities[0]["fix"]["versions"] == []

    @pytest.mark.asyncio
    async def test_grype_parse_report_multiple_locations(self, tmp_path):
        """Test parsing vulnerability with multiple file locations"""
        report = {
            "distro": {"name": "alpine", "version": "3.17"},
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-1111",
                        "fix": {"versions": ["2.0.0"]}
                    },
                    "artifact": {
                        "type": "apk",
                        "name": "openssl",
                        "version": "1.1.1",
                        "locations": [
                            {"path": "/lib/libssl.so.1.1"},
                            {"path": "/lib/libcrypto.so.1.1"},
                            {"path": "/usr/lib/engines-1.1/afalg.so"}
                        ]
                    }
                }
            ]
        }

        report_file = tmp_path / "grype_report.json"
        report_file.write_text(json.dumps(report))

        vulnerabilities = await parser.grype_parser(str(report_file))

        # Locations should be comma-separated
        locations = vulnerabilities[0]["affected_path"]
        assert "/lib/libssl.so.1.1" in locations
        assert "/lib/libcrypto.so.1.1" in locations
        assert "/usr/lib/engines-1.1/afalg.so" in locations


class TestHelperFunctions:
    """Tests for vulnerability helper functions"""

    def test_format_vulnerability_rows(self):
        """Test formatting vulnerability rows for display"""
        from vma.helper import format_vulnerability_rows

        now = datetime.now()
        rows = [
            ("CVE-2023-1234", "1.2.3", "deb", "libssl", "1.0.0", "/usr/lib",
             now, now, 7.5, "HIGH", "3.1"),
            ("CVE-2023-5678", "", "python", "requests", "2.28.0", "/usr/local",
             now, now, 5.3, "MEDIUM", "3.1")
        ]

        formatted = format_vulnerability_rows(rows)

        assert len(formatted) == 2
        assert formatted[0]["cve"] == "CVE-2023-1234"
        assert formatted[0]["component"] == "libssl"
        assert formatted[0]["cvss"]["score"] == 7.5
        assert formatted[0]["cvss"]["severity"] == "HIGH"

    def test_normalize_comparison(self):
        """Test normalizing comparison results"""
        from vma.helper import normalize_comparison

        comp_data = [
            (
                "CVE-2023-1",
                "HIGH",
                "shared",
                "deb",
                "lib1",
                "/path1",
                7.5,
                0.2,
                ["http://example.com"],
                ["CWE-79"],
                {"versions": ["1.2.3"]},
            ),
            (
                "CVE-2023-2",
                "MEDIUM",
                "only_version_a",
                "deb",
                "lib2",
                "/path2",
                5.0,
                0.1,
                [],
                [],
                {"versions": []},
            ),
            (
                "CVE-2023-3",
                "CRITICAL",
                "only_version_b",
                "python",
                "lib3",
                "/path3",
                9.0,
                0.9,
                [],
                [],
                {"versions": ["2.0.0"]},
            )
        ]

        result = normalize_comparison(comp_data)

        assert result["stats"]["shared"] == 1
        assert result["stats"]["only_version_a"] == 1
        assert result["stats"]["only_version_b"] == 1
        assert len(result["comparison"]) == 3

    def test_normalize_comparison_empty(self):
        """Test normalizing empty comparison"""
        from vma.helper import normalize_comparison

        result = normalize_comparison([])

        assert result["stats"]["shared"] == 0
        assert result["stats"]["only_version_a"] == 0
        assert result["stats"]["only_version_b"] == 0
        assert result["comparison"] == []

    def test_escape_like_special_chars(self):
        """Test escaping special characters for SQL LIKE"""
        from vma.helper import escape_like

        assert escape_like("test%") == "test\\%"
        assert escape_like("test_value") == "test\\_value"
        assert escape_like("normal") == "normal"
        assert escape_like("mix%ed_chars") == "mix\\%ed\\_chars"
