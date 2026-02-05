"""
Pytest configuration and shared fixtures for VMA tests.

This file provides reusable fixtures and test utilities that can be used
across all test files.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from vma.api.api import api_server
from vma.api.models import v1 as mod_v1
import vma.auth as a


# ============================================================================
# Test Client Fixtures
# ============================================================================

@pytest.fixture
async def client():
    """
    Create an async HTTP client for testing API endpoints.

    Usage:
        async def test_endpoint(client):
            response = await client.get("/api/v1/products")
            assert response.status_code == 200
    """
    transport = ASGITransport(app=api_server)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    # Clean up any dependency overrides after each test
    api_server.dependency_overrides.clear()


# ============================================================================
# Authentication Token Fixtures
# ============================================================================

@pytest.fixture
def read_only_user_token():
    """
    JWT data for a user with read-only access to team1.

    Can view resources but cannot create/update/delete.
    """
    return mod_v1.JwtData(
        username="reader@test.com",
        scope={"team1": "read"},
        root=False
    )


@pytest.fixture
def write_user_token():
    """
    JWT data for a user with write access to team1.

    Can view and create/update resources but cannot delete.
    """
    return mod_v1.JwtData(
        username="writer@test.com",
        scope={"team1": "write"},
        root=False
    )


@pytest.fixture
def admin_user_token():
    """
    JWT data for a user with admin access to team1.

    Can perform all operations within team1.
    """
    return mod_v1.JwtData(
        username="admin@test.com",
        scope={"team1": "admin"},
        root=False
    )


@pytest.fixture
def multi_team_user_token():
    """
    JWT data for a user with access to multiple teams.

    Different permission levels across teams:
    - team1: read-only
    - team2: write access
    - team3: admin access
    """
    return mod_v1.JwtData(
        username="multi@test.com",
        scope={
            "team1": "read",
            "team2": "write",
            "team3": "admin"
        },
        root=False
    )


@pytest.fixture
def root_user_token():
    """
    JWT data for a root user.

    Root users bypass all authorization checks and can:
    - Access resources in any team
    - Create/delete teams
    - Manage any user
    - Create API tokens for any user
    """
    return mod_v1.JwtData(
        username="root@test.com",
        scope={"team1": "admin"},
        root=True
    )


# ============================================================================
# Authentication Helper Fixtures
# ============================================================================

@pytest.fixture
def override_auth_dependency():
    """
    Helper fixture to override authentication dependency.

    Usage:
        def test_endpoint(client, override_auth_dependency, admin_user_token):
            override_auth_dependency(admin_user_token)
            response = await client.get("/api/v1/endpoint")
    """
    def _override(token_data: mod_v1.JwtData):
        async def override_validate_token():
            return token_data
        api_server.dependency_overrides[a.validate_access_token] = override_validate_token
    return _override


# ============================================================================
# Sample Data Fixtures
# ============================================================================

@pytest.fixture
def sample_product_data():
    """Sample product data for testing"""
    return {
        "id": "test-product",
        "description": "Test Product Description",
        "team": "team1"
    }


@pytest.fixture
def sample_image_data():
    """Sample image data for testing"""
    return {
        "name": "test-app",
        "version": "1.0.0",
        "product": "test-product",
        "team": "team1"
    }


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "email": "testuser@test.com",
        "password": "secure_password_123",
        "name": "Test User",
        "scopes": "team1:write",
        "root": False
    }


@pytest.fixture
def sample_team_data():
    """Sample team data for testing"""
    return {
        "name": "test-team",
        "description": "Test Team Description"
    }


@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing"""
    return [
        {
            "cve": "CVE-2023-1234",
            "fix_versions": "1.2.3,1.2.4",
            "component_type": "deb",
            "component": "libssl",
            "component_version": "1.0.0",
            "component_path": "/usr/lib/libssl.so",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "cvss": {
                "score": 7.5,
                "severity": "HIGH",
                "version": "3.1"
            }
        },
        {
            "cve": "CVE-2023-5678",
            "fix_versions": "",
            "component_type": "python",
            "component": "requests",
            "component_version": "2.28.0",
            "component_path": "/usr/local/lib/python3.9",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "cvss": {
                "score": 5.3,
                "severity": "MEDIUM",
                "version": "3.1"
            }
        }
    ]


@pytest.fixture
def sample_grype_report():
    """
    Sample Grype JSON report for testing scanner import.

    Contains vulnerabilities in both deb and Python packages.
    """
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


# ============================================================================
# Mock Connector Fixtures
# ============================================================================

@pytest.fixture
def mock_connector():
    """
    Create a mock connector with common return values.

    Usage:
        def test_something(mock_connector):
            mock_connector.get_products.return_value = {
                "status": True,
                "result": [...]
            }
    """
    mock = MagicMock()

    # Set up common default return values
    mock.get_products.return_value = {"status": True, "result": []}
    mock.get_images.return_value = {"status": True, "result": []}
    mock.get_teams.return_value = {"status": True, "result": []}
    mock.get_users.return_value = {"status": True, "result": []}

    return mock


@pytest.fixture
def mock_helper():
    """
    Create a mock helper module with common return values.

    Usage:
        def test_something(mock_helper):
            mock_helper.validate_input.side_effect = lambda x: x
    """
    mock = MagicMock()

    # Common helper functions
    mock.validate_input.side_effect = lambda x: x
    mock.escape_like.side_effect = lambda x: x
    mock.errors = {
        "400": "One or several parameters are missing or malformed",
        "401": "User is not authorized to perform this action",
        "500": "Error processing data"
    }

    return mock


@pytest.fixture
def mock_auth():
    """
    Create a mock auth module with common return values.

    Usage:
        def test_something(mock_auth):
            mock_auth.hasher.verify.return_value = True
    """
    mock = MagicMock()

    # Common auth functions
    mock.hasher.hash.return_value = "hashed_password"
    mock.hasher.verify.return_value = True
    mock.create_token.return_value = "fake_jwt_token"
    mock.generate_api_token.return_value = "vma_test123456789012345678901234"

    # Token expiration settings
    mock._expire_access_token = 15  # minutes
    mock._expire_refresh_token = 2  # days
    mock._secret_key_access = "test_access_secret"
    mock._secret_key_refresh = "test_refresh_secret"
    mock._algorithm = "HS256"

    return mock


# ============================================================================
# Utility Functions
# ============================================================================

def assert_error_response(response, status_code: int, error_key: str = None):
    """
    Assert that response is an error with expected status code.

    Args:
        response: HTTP response object
        status_code: Expected HTTP status code
        error_key: Optional error message to check for in response

    Usage:
        assert_error_response(response, 401, "not authorized")
    """
    assert response.status_code == status_code

    if error_key:
        response_text = response.text.lower()
        assert error_key.lower() in response_text


def assert_success_response(response, expected_keys: list = None):
    """
    Assert that response is successful and contains expected keys.

    Args:
        response: HTTP response object
        expected_keys: Optional list of keys to check in response JSON

    Usage:
        assert_success_response(response, ["status", "result"])
    """
    assert response.status_code == 200

    if expected_keys:
        data = response.json()
        for key in expected_keys:
            assert key in data


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


# ============================================================================
# Test Database Fixtures (for integration tests)
# ============================================================================

@pytest.fixture(scope="session")
def test_database_config():
    """
    Database configuration for integration tests.

    Note: This requires a test database to be set up.
    In a real environment, you would use a separate test database.
    """
    return {
        "host": "localhost",
        "user": "vma_test",
        "password": "test_password",
        "database": "vma_test"
    }


@pytest.fixture
def clean_database(test_database_config):
    """
    Fixture to clean database before/after tests.

    Usage:
        @pytest.mark.integration
        def test_with_database(clean_database):
            # Test code here
            pass
    """
    # Setup: Clean database before test
    # In a real implementation, you would:
    # 1. Connect to test database
    # 2. Truncate all tables
    # 3. Insert any necessary seed data

    yield

    # Teardown: Clean database after test
    # Same cleanup operations
    pass


# ============================================================================
# Mock Helper Fixtures
# ============================================================================

@pytest.fixture
def mock_helper_errors():
    """
    Standard helper.errors dictionary for mocking.

    Provides all error codes used in the application:
    - 400: Bad request (missing/malformed parameters)
    - 401: Unauthorized (authentication/authorization failure)
    - 500: Internal server error
    - invalid_token_format: Invalid API token format

    Usage:
        def test_something(mock_helper_errors):
            with patch("vma.api.routers.v1.helper") as mock_helper:
                mock_helper.errors = mock_helper_errors
                mock_helper.validate_input.return_value = "validated"
                # ... rest of test

    This fixture ensures consistent mocking across all tests and prevents
    KeyError when code accesses error codes like helper.errors["401"].
    """
    return {
        "400": "One or several parameters are missing or malformed",
        "401": "User is not authorized to perform this action",
        "500": "Error procesing data",
        "invalid_token_format": "Invalid token format"
    }


@pytest.fixture
def mock_router_dependencies(mock_helper_errors):
    """
    Mock all common router dependencies together.
    Prevents MagicMock serialization errors.

    This fixture patches both connector and helper modules to ensure:
    1. helper.errors returns strings, not MagicMock objects
    2. Connector functions have sensible defaults
    3. Tests can override specific behaviors as needed

    Usage:
        def test_something(client, mock_router_dependencies):
            mock_c = mock_router_dependencies["connector"]
            mock_helper = mock_router_dependencies["helper"]

            # Override specific connector behavior
            mock_c.get_products.return_value = {"status": True, "result": [...]}

            # Test code here
    """
    from unittest.mock import patch

    with patch("vma.api.routers.v1.c") as mock_c, \
         patch("vma.api.routers.v1.helper") as mock_helper:

        # Set up helper with all error codes (sync functions)
        mock_helper.errors = mock_helper_errors
        mock_helper.validate_input.side_effect = lambda x: x
        mock_helper.escape_like.side_effect = lambda x: x
        mock_helper.format_vulnerability_rows.side_effect = lambda x: x
        mock_helper.normalize_comparison.side_effect = lambda x: x
        mock_helper.validate_scopes.side_effect = lambda x: x if x else None

        # Set up connector with sensible defaults (async functions - use AsyncMock)
        mock_c.get_products = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_images = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_teams = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_users = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_api_token_by_id = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.get_api_token_by_prefix = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_product = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_image = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_teams = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_users = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_api_token = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_image_vulnerabilities = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.insert_vulnerabilities_sca_batch = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.delete_product = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.delete_image = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.delete_team = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.delete_user = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.update_users = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.update_token_last_used = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.get_scope_by_user = AsyncMock(return_value={"status": True, "result": {}})
        mock_c.get_users_w_hpass = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_vulnerabilities_by_id = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_image_vulnerabilities = AsyncMock(return_value={"status": True, "result": []})
        mock_c.get_vulnerabilities_sca_by_image = AsyncMock(return_value={"status": True, "result": []})
        mock_c.compare_image_versions = AsyncMock(return_value={"status": True, "result": []})

        yield {"connector": mock_c, "helper": mock_helper}
