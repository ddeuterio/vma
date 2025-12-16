# VMA Test Suite

Comprehensive acceptance tests for the Vulnerability Management Application (VMA).

## Setup

Install test dependencies:

```bash
poetry install
```

## Running Tests

### Run all tests
```bash
poetry run pytest
```

### Run specific test file
```bash
poetry run pytest tests/test_auth_comprehensive.py
```

### Run with verbose output
```bash
poetry run pytest -v
```

### Run specific test class
```bash
poetry run pytest tests/test_auth_comprehensive.py::TestTokenCreation -v
```

### Run specific test function
```bash
poetry run pytest tests/test_auth_comprehensive.py::TestTokenCreation::test_create_access_token_success -v
```

### Run with coverage report
```bash
poetry run pytest --cov=src/vma --cov-report=html
```

The coverage report will be generated in `htmlcov/index.html`.

### Run with coverage report (terminal)
```bash
poetry run pytest --cov=src/vma --cov-report=term-missing
```

### Run tests by marker
```bash
# Run only integration tests
poetry run pytest -m integration

# Run only unit tests
poetry run pytest -m unit

# Skip slow tests
poetry run pytest -m "not slow"
```

### Other useful options
```bash
# Stop on first failure
poetry run pytest -x

# Run last failed tests
poetry run pytest --lf

# Show test durations
poetry run pytest --durations=10
```

## Test Structure

### test_auth_comprehensive.py - Authentication & Authorization
Comprehensive tests for authentication and authorization:

- **TestTokenCreation**: JWT token creation
- **TestTokenValidation**: Token validation and expiration
- **TestAuthenticationEndpoints**: Login, refresh, logout
- **TestRefreshTokenFlow**: Refresh token lifecycle
- **TestAuthorizationScopes**: READ_ONLY, WRITE, ADMIN scopes
- **TestCrossTeamAccess**: Cross-team access control
- **TestPasswordHashing**: Argon2 password hashing

### test_api_tokens.py - API Token Management
Tests for API token lifecycle:

- **TestAPITokenGeneration**: Token format and uniqueness
- **TestAPITokenCreation**: Creating tokens via endpoint
- **TestAPITokenValidation**: Token validation and hash verification
- **TestAPITokenListing**: Listing tokens (user-specific and root)
- **TestAPITokenRetrieval**: Getting specific token details
- **TestAPITokenRevocation**: Revoking tokens
- **TestAPITokenUsageInImport**: Using tokens in import endpoint

### test_teams_products_images.py - Resource Management
Tests for teams, products, and images:

- **TestTeamManagement**: Team CRUD operations (root only)
- **TestProductManagement**: Product CRUD with team scoping
- **TestImageManagement**: Image CRUD with team scoping
- **TestStatsEndpoint**: Statistics aggregation

### test_users_management.py - User Management
Tests for user lifecycle:

- **TestUserCreation**: Creating users with scope validation
- **TestUserRetrieval**: Listing and retrieving users
- **TestUserUpdate**: Updating user info, passwords, scopes
- **TestUserDeletion**: Deleting users
- **TestScopeValidation**: Scope format validation

### test_vulnerabilities.py - Vulnerability Management
Tests for CVE and vulnerability management:

- **TestCVESearch**: CVE search and retrieval
- **TestImageVulnerabilities**: Image vulnerability listing
- **TestImageComparison**: Comparing image versions
- **TestVulnerabilityImport**: Importing scan results
- **TestGrypeParser**: Grype scanner output parsing
- **TestHelperFunctions**: Formatting and normalization

### test_e2e_workflows.py - End-to-End Workflows
Complete workflow tests:

- **TestCompleteOnboardingWorkflow**: Team → user → product → image
- **TestVulnerabilityScanningWorkflow**: Scan → import → view
- **TestImageUpdateWorkflow**: New version → compare → analyze
- **TestMultiTeamCollaboration**: Multi-team user workflows
- **TestAPITokenLifecycle**: Token creation → use → revoke
- **TestUserPermissionChanges**: Permission upgrade workflows

### test_api_v1.py - Original API Tests
Original unit tests for API v1 endpoints (retained for compatibility)

### conftest.py - Shared Fixtures
Reusable fixtures and utilities:

- Test client fixtures
- Authentication token fixtures (read, write, admin, root)
- Sample data fixtures (products, images, users, teams)
- Mock connector and helper fixtures
- Utility functions for assertions

## Test Coverage

### Authentication (test_auth_comprehensive.py)
- ✅ JWT access and refresh token creation
- ✅ Token validation and expiration
- ✅ Login and refresh flows
- ✅ Authorization scopes (read/write/admin)
- ✅ Root user bypass
- ✅ Cross-team access control
- ✅ Password hashing with Argon2

### API Tokens (test_api_tokens.py)
- ✅ Token generation (vma_ prefix)
- ✅ Token creation with expiration
- ✅ Hash verification (Argon2)
- ✅ Token listing (user-specific and root)
- ✅ Token retrieval
- ✅ Token revocation
- ✅ Expired token handling

### Resource Management (test_teams_products_images.py)
- ✅ Team CRUD (root only)
- ✅ Product CRUD with team scoping
- ✅ Image CRUD with team scoping
- ✅ Statistics aggregation
- ✅ Authorization boundaries

### User Management (test_users_management.py)
- ✅ User creation with scope validation
- ✅ User listing (admin/root)
- ✅ User retrieval (own or admin)
- ✅ User updates (password, scopes, root)
- ✅ User deletion (admin/root)
- ✅ Scope format validation

### Vulnerabilities (test_vulnerabilities.py)
- ✅ CVE search and retrieval
- ✅ Image vulnerability listing
- ✅ Vulnerability import
- ✅ Image version comparison
- ✅ Grype parser
- ✅ Helper functions

### E2E Workflows (test_e2e_workflows.py)
- ✅ Complete onboarding
- ✅ Vulnerability scanning
- ✅ Image updates and comparison
- ✅ Multi-team collaboration
- ✅ API token lifecycle
- ✅ Permission changes

## Writing New Tests

Follow the existing patterns in the test files:

```python
@pytest.mark.asyncio
async def test_endpoint_name_scenario(self, client, write_user_token):
    """Test description"""
    # Override authentication
    async def override_validate_token():
        return write_user_token

    api_server.dependency_overrides[a.validate_access_token] = override_validate_token

    # Setup mocks
    with patch("vma.api.routers.v1.c") as mock_c, \
         patch("vma.api.routers.v1.helper") as mock_helper:

        mock_helper.validate_input.side_effect = lambda x: x
        mock_c.some_function.return_value = {"status": True, "result": {}}

        # Make request
        response = await client.get(
            "/api/v1/endpoint",
            headers={"Authorization": "Bearer fake_token"}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        mock_c.some_function.assert_called_once()
```

## Best Practices

1. **Test Names**: Use descriptive names explaining what is being tested
2. **Test Structure**: Follow Arrange-Act-Assert pattern
3. **Test Independence**: Each test should be independent
4. **Mock External Dependencies**: Mock database, APIs, etc.
5. **Test Success and Failure**: Test both happy and error paths
6. **Use Fixtures**: Share common setup via conftest.py
7. **Clear Assertions**: Use descriptive assertion messages

## Known Issues

### Authorization Bug
There is a known bug in `is_authorized()` function:
- When `teams=[]` and `is_root=False`, returns `True` instead of `False`
- Allows non-root users to perform actions when they shouldn't
- Test is skipped in test_api_v1.py line 390

## Notes

- All database operations are mocked - no real database required
- Tests use FastAPI AsyncClient
- Authentication mocked via JWT data fixtures
- Each test is isolated and independent
