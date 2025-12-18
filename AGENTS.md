# VMA - Agent Guidelines

**AI agents working with this codebase should read and follow these guidelines.**

## Project Overview

VMA (Vulnerability Management Application) is a production-ready container vulnerability tracking system with:

- **Authentication & Authorization**: JWT-based auth with OAuth2, Argon2 password hashing, and team-based access control (READ_ONLY/WRITE/ADMIN scopes)
- **API Token Management**: Programmatic API access via bearer tokens with expiration and revocation
- **CVE Database**: Full NVD CVE data sync with periodic updates
- **Container Scanning**: Import and track vulnerabilities from Grype and other scanners
- **Web Frontend**: FastAPI/Jinja2 SPA with dynamic content loading
- **Comprehensive Testing**: 151 acceptance tests covering authentication, authorization, API endpoints, and end-to-end workflows

## Current Project Status (Last Updated: 2025-12-17)

### Recent Major Features
- ✅ **Complete Authentication System** (JWT access + refresh tokens, OAuth2, Argon2)
- ✅ **Authorization & Team Scoping** (READ_ONLY, WRITE, ADMIN with cross-team validation)
- ✅ **API Token Management** (Generate, list, revoke tokens for programmatic access)
- ✅ **Comprehensive Test Suite** (151 tests with ~5,418 lines of test code)
- ✅ **Architecture Documentation** (Complete docs in `docs/` covering all components)
- ✅ **Security Hardening** (Business logic bypass fixes, input validation, secure token handling)

### Active Branch
- **Current**: `add--authN-authZ` (authentication and authorization implementation)
- **Main Branch**: `main` (use for pull requests)

### Recent Fixes (Uncommitted)
1. **Authorization Bypass Fix** (`src/vma/api/routers/v1.py:498`)
   - Fixed `delete_team` endpoint to properly validate team_id in authorization check
   - Changed from empty teams list `teams=[]` to `teams=[team_id]` for proper scope validation

2. **Exception Handling Improvements** (`src/vma/api/routers/v1.py:886,925`)
   - Added explicit `HTTPException` re-raise in `get_api_token` and `revoke_api_token`
   - Prevents HTTPException details from being masked by generic exception handler

3. **Test Suite Enhancements** (269 insertions, 220 deletions across 5 test files)
   - Improved token format validation with regex patterns
   - Enhanced dependency override patterns for better test isolation
   - More comprehensive mocking for edge cases and error conditions
   - Better test organization and clarity

### Modified Files (Uncommitted)
```
M src/vma/api/routers/v1.py          # Authorization fix + exception handling
M tests/test_api_tokens.py           # Token format validation, dependency overrides
M tests/test_e2e_workflows.py        # Test improvements and refactoring
M tests/test_teams_products_images.py # Enhanced mocking patterns
M tests/test_vulnerabilities.py      # Comprehensive error case coverage
```

## Project Structure

```
vma/
├── src/vma/                         # Main application code
│   ├── app.py                       # CLI entrypoint (argparse subcommands)
│   ├── connector.py                 # Database layer (all SQL queries)
│   ├── auth.py                      # JWT, OAuth2, password hashing, API tokens
│   ├── api/
│   │   ├── api.py                   # FastAPI app initialization
│   │   ├── models/v1.py             # Pydantic models for API v1
│   │   └── routers/v1.py            # API v1 endpoints (/api/v1/*)
│   ├── web/
│   │   ├── web.py                   # ASGI app (FastAPI) serving frontend + API
│   │   ├── templates/               # Jinja2 HTML templates
│   │   │   ├── login.html           # Login page
│   │   │   └── index.html           # Main SPA application
│   │   └── static/                  # Frontend assets (CSS, JS)
│   ├── parser.py                    # Scanner output parsers (Grype JSON)
│   ├── nvd.py                       # NVD API client and CVE sync logic
│   └── helper.py                    # Logging, validation utilities
│
├── tests/                           # Comprehensive test suite (151 tests, 7 test files)
│   ├── conftest.py                  # Pytest fixtures and test database setup
│   ├── test_auth_comprehensive.py   # Authentication & authorization tests (28 tests)
│   ├── test_api_tokens.py           # API token lifecycle tests (23 tests)
│   ├── test_api_v1.py               # API endpoint tests (16 tests)
│   ├── test_users_management.py     # User management tests (19 tests)
│   ├── test_teams_products_images.py # Resource management tests (25 tests)
│   ├── test_vulnerabilities.py      # Vulnerability tracking tests (21 tests)
│   ├── test_e2e_workflows.py        # End-to-end workflow tests (19 tests)
│   └── README.md                    # Test documentation
│
├── docs/                            # Comprehensive documentation
│   ├── architecture.md              # System architecture and design decisions
│   ├── api-reference.md             # Complete API endpoint documentation
│   ├── cli-reference.md             # CLI command reference
│   ├── user-guide.md                # End-user guide
│   └── contributing.md              # Contributing guidelines
│
├── docker/                          # Production Docker deployment
│   ├── docker-compose.yml           # Stack orchestration
│   ├── db/init/                     # PostgreSQL initialization scripts
│   └── rev_proxy/                   # Nginx reverse proxy config
│
├── dev-docker/                      # Development Docker environment
├── Dockerfile.vma                   # CLI/worker container image
├── Dockerfile.web                   # Web/API container image
├── pyproject.toml                   # Poetry dependencies and project metadata
├── CLAUDE.md                        # Claude Code project instructions
└── AGENTS.md                        # This file (agent guidelines)
```

## Core Architectural Patterns

### 1. Database Layer (`connector.py`)
- **All SQL queries** stored in `queries` dictionary
- Functions return `{"status": bool, "result": Any}` format
- Parameterized queries for SQL injection protection
- No connection pooling (creates connection per operation)

### 2. Authentication Flow (`auth.py`)
1. User submits credentials to `/api/v1/token` (OAuth2PasswordRequestForm)
2. Backend validates via `connector.get_users(email=...)` and Argon2 password verification
3. `auth.create_token()` generates JWT access token (15min) and refresh token (2 days)
4. Access token stored in JS memory, refresh token in httpOnly cookie
5. Protected endpoints use `Depends(a.validate_access_token)` to extract `JwtData(username, scope, root)`
6. On expiry, frontend calls `/api/v1/refresh` with refresh token cookie for seamless renewal

### 3. Authorization System
- **Three permission levels**: `READ_ONLY`, `WRITE`, `ADMIN`
- **Team-based scoping**: Users have `{team_name: scope}` mappings in JWT
- **Authorization check**: `is_authorized()` validates user has required scope for requested team(s)
- **Root users**: Bypass all authorization checks (super admin)

### 4. API Token Management
- **Format**: `vma_<prefix>_<token>` (base64-encoded random bytes)
- **Storage**: SHA-256 hash stored in database, plaintext returned once on creation
- **Usage**: Pass in `Authorization: Bearer vma_...` header (alternative to JWT)
- **Validation**: `validate_api_token()` dependency checks token validity, expiration, revocation

### 5. Frontend Architecture
- **Single-page application** in `src/vma/web/static/js/`
- **Modular JavaScript**: `main.js`, `sidebar.js`, `dashboard.js`, `product.js`, `image.js`, `cve.js`, `users.js`, `teams.js`, `tokens.js`
- **Dynamic content loading**: API calls to `/api/v1/*` endpoints
- **Authentication**: Access token in memory, refresh token in httpOnly cookie

## Development Workflow

### Setup
```bash
# Install dependencies (Python 3.10+)
poetry install

# Activate virtual environment
poetry shell

# Create .env file with required variables (see CLAUDE.md for full list)
cp .env.example .env
```

### Local Development

**Option 1: API Server Only** (for backend development)
```bash
poetry run uvicorn vma.api.api:api_server --reload --port 8000
# Access API at: http://localhost:8000/api/v1/*
# Auto-reloads on code changes
```

**Option 2: Full Web Application** (recommended)
```bash
poetry run gunicorn vma.web.web:create_web_app \
  --bind 0.0.0.0:8000 \
  --worker-class uvicorn.workers.UvicornWorker
# Access web UI at: http://localhost:8000/
```

### Testing

```bash
# Run all tests (151 tests)
poetry run pytest

# Run with coverage report
poetry run pytest --cov=src/vma --cov-report=html

# Run specific test file
poetry run pytest tests/test_auth_comprehensive.py

# Run specific test class
poetry run pytest tests/test_auth_comprehensive.py::TestTokenCreation -v

# Run verbose output
poetry run pytest -v

# Stop on first failure
poetry run pytest -x

# Show test durations
poetry run pytest --durations=10
```

### CLI Usage
```bash
# Initialize CVE database (full NVD history)
poetry run vma cve --init

# Update CVE data (fetch modified CVEs)
poetry run vma cve --update

# Create resources
poetry run vma create --choice product --name "my-product" --description "..."
poetry run vma create --choice image --name "app" --version "1.0" --product "my-product" --file grype.json

# Import vulnerability scan results
poetry run vma import --type grype --file grype.json --product "my-product" --host localhost --port 8000

# Query resources
poetry run vma select --choice product --name "my-product"
```

### Docker Workflow
```bash
# Build images
docker build -t vma:latest -f Dockerfile.vma .
docker build -t web:latest -f Dockerfile.web .

# Run stack (PostgreSQL, web frontend, reverse proxy)
cd docker && docker-compose up -d

# Access application
# Add to /etc/hosts: 127.0.0.1 vma.local
# Navigate to: https://vma.local:8443
```

## Coding Standards

### Python Style
- **Indentation**: 4 spaces (not tabs)
- **Naming**: `snake_case` for functions/modules, `CapWords` for classes, `UPPER_CASE` for constants
- **Type hints**: Required on all public function signatures
- **Logging**: Use Loguru exclusively (never `print()`)
- **Docstrings**: Google style for public APIs
- **Formatting**: Black and Flake8 (`poetry run black src`, `poetry run flake8`)

### Git Commit Messages
- **Format**: `<type>: <description>`
- **Types**: `add`, `fix`, `update`, `refactor`, `test`, `docs`
- **Style**: Imperative mood ("add feature" not "added feature")
- **Length**: Subject line under 72 characters
- **Examples**:
  - `add: JWT refresh token rotation`
  - `fix: SQL injection vulnerability in product query`
  - `update: NVD API rate limiting logic`

### Testing Standards
- **Framework**: pytest with asyncio support
- **Location**: Tests in `tests/` directory
- **Naming**: `test_<module>.py` for files, `test_<function_name>` for test functions
- **Organization**: Group related tests in classes (e.g., `TestTokenCreation`)
- **Coverage**: Aim for >80% coverage on new code
- **Mocking**: Mock external services (NVD API, database) in unit tests
- **Fixtures**: Reusable fixtures in `conftest.py`

## Security Guidelines

### Authentication & Authorization
- **Password Storage**: Argon2 hashing via `pwdlib` (memory-hard, GPU-resistant)
- **Token Security**:
  - Short-lived access tokens (15min) to limit exposure
  - Refresh tokens in httpOnly cookies (JavaScript cannot access)
  - Separate secrets for access and refresh tokens
  - HS256 algorithm (symmetric signing)
- **API Tokens**: SHA-256 hash storage, plaintext returned once on creation

### Critical Authorization Patterns
**IMPORTANT**: When implementing or modifying API endpoints, always follow these patterns:

1. **Team-Scoped Operations** - Always include the team_id in authorization check:
   ```python
   # ✅ CORRECT
   if not is_authorized(is_root=user_data.root, scope=user_data.scope, teams=[team_id], op=ADMIN):
       raise HTTPException(status_code=401, detail="Unauthorized")

   # ❌ WRONG - Authorization bypass vulnerability!
   if not is_authorized(is_root=user_data.root, scope=user_data.scope, teams=[], op=ADMIN):
       raise HTTPException(status_code=401, detail="Unauthorized")
   ```

2. **Exception Handling** - Always re-raise HTTPException explicitly:
   ```python
   # ✅ CORRECT
   try:
       # endpoint logic
   except HTTPException:
       raise  # Re-raise to preserve status code and detail
   except Exception as e:
       logger.error(f"Error: {e}")
       raise HTTPException(status_code=500, detail=str(e))

   # ❌ WRONG - HTTPException details masked by generic handler
   try:
       # endpoint logic
   except Exception as e:
       logger.error(f"Error: {e}")
       raise HTTPException(status_code=500, detail=str(e))
   ```

3. **Authorization Scope Validation**:
   - `READ_ONLY`: Can view resources within assigned teams only
   - `WRITE`: Can create/modify resources within assigned teams only
   - `ADMIN`: Can delete and manage users/teams within assigned teams only
   - `root=True`: Bypasses all authorization checks (super admin)

### Input Validation
- **SQL Injection**: All queries use parameterized statements (no string concatenation)
- **XSS Prevention**: `helper.validate_input()` sanitizes user inputs
- **Boundary Validation**: Validate at system boundaries (user input, external APIs)
- **Pydantic Models**: Automatic validation via FastAPI/Pydantic

### Configuration Security
- **Environment Variables**: Never commit `.env` file; use `.env.example` as template
- **Secret Keys**: Minimum 32 characters for `SECRET_KEY_ACCESS` and `SECRET_KEY_REFRESH`
- **Database Credentials**: Strong passwords and network access restrictions
- **TLS**: Nginx reverse proxy provides HTTPS (self-signed in dev, proper cert in production)

## Common Operations for AI Agents

### Adding a New API Endpoint
1. Define Pydantic model in `src/vma/api/models/v1.py`
2. Add SQL query to `queries` dict in `connector.py`
3. Implement database function in `connector.py` (returns `{"status": bool, "result": ...}`)
4. Add route to `src/vma/api/routers/v1.py`:
   - Use `Depends(a.validate_access_token)` for authentication
   - Call `is_authorized()` with appropriate scope (READ_ONLY/WRITE/ADMIN)
   - **CRITICAL**: Include actual team_id in `teams=[team_id]` parameter (see Security Guidelines)
   - Implement proper exception handling with explicit HTTPException re-raise
   - Call connector function and handle exceptions
   - Raise `HTTPException` for errors (400/401/403/500)
5. Add tests in appropriate test file (e.g., `test_api_v1.py`)
   - Test authorization with different scopes (READ_ONLY, WRITE, ADMIN)
   - Test cross-team access denial (user from team A cannot access team B resources)
   - Test exception handling paths
6. Update API documentation in `docs/api-reference.md`

### Adding a New Scanner Parser
1. Add parsing functions to `parser.py` (follow `grype_*` naming pattern)
2. Extract image metadata: `(name, version)` tuple
3. Parse vulnerabilities into list of tuples for `insert_image_vulnerabilities()`
4. Update `app.py` importer mode to support new scanner type
5. Update `/api/v1/import` endpoint in `routers/v1.py`
6. Add tests for new parser in `tests/`

### Modifying Database Schema
1. Update SQL init scripts in `docker/db/init/` (for new deployments)
2. Create migration script if needed (or add logic to `connector.py`)
3. Update corresponding `queries` dict entries in `connector.py`
4. Update Pydantic models in `api/models/v1.py`
5. Update affected frontend JavaScript modules
6. Add tests for new schema changes

### Adding New Tests
1. Choose appropriate test file or create new one (e.g., `test_<module>.py`)
2. Use fixtures from `conftest.py` for database, client, authentication
3. Follow existing test structure (classes for grouping, descriptive names)
4. Test both success and failure cases
5. Mock external dependencies (NVD API, etc.)
6. Run tests to ensure they pass: `poetry run pytest tests/test_<module>.py -v`

## Important Technical Details

### Database Connection
- Credentials loaded from `.env` via `python-dotenv`
- New connection created per operation (no connection pooling in current design)
- All queries use parameterized statements (SQL injection protection)

### NVD Sync Process
- **Initial sync**: `vma cve --init` fetches all historical CVE data year-by-year
- **Updates**: `vma cve --update` uses `lastModStartDate` parameter for modified CVEs only
- **Tracking**: `nvd_sync` table stores last fetch timestamp and checksums per year
- **API Key**: `NVD_API_KEY` required for higher rate limits (5 req/30s without key)

### Frontend Token Handling
- **Access Token**: Stored in JavaScript memory (JS variable)
- **Refresh Token**: Stored in httpOnly cookie (not accessible to JavaScript)
- **Authorization Header**: `Authorization: Bearer <access_token>`
- **Token Refresh**: Automatic refresh on 401 response via `/api/v1/refresh`

## Troubleshooting Common Issues

### Database Connection Issues
- Verify `.env` file has correct `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`
- Check PostgreSQL is running: `docker ps` or `systemctl status postgresql`
- Test connection: `psql -h localhost -U vma -d vma`

### Authentication Failures
- Verify `SECRET_KEY_ACCESS` and `SECRET_KEY_REFRESH` are set (min 32 chars)
- Check token expiration settings (`ACCESS_TOKEN_EXP_TIME`, `REFRESH_TOKEN_EXP_TIME`)
- Clear browser cookies and try logging in again
- Check user exists: `SELECT * FROM users WHERE email = 'user@example.com';`

### Test Failures
- Ensure test database is properly initialized (fixtures in `conftest.py`)
- Check for leftover test data: tests should clean up after themselves
- Run specific test with verbose output: `poetry run pytest tests/test_<module>.py::test_function -v`
- Check logs for detailed error messages

### Import/Scanning Issues
- Verify Grype JSON format matches expected schema (see `parser.py`)
- Check product exists before importing images
- Ensure database has latest CVE data: `vma cve --update`
- Review API logs for detailed error messages

## Code Modification Policy

**IMPORTANT**: AI agents working with this codebase should:

1. **Analyze and explain** code freely - provide detailed explanations of how components work
2. **Suggest changes** with detailed rationale - explain why changes are needed and what they accomplish
3. **Ask for confirmation** before making significant changes - especially for:
   - Authentication/authorization logic
   - Database schema changes
   - Security-critical code
   - API contract changes
4. **Follow existing patterns** - maintain consistency with current architecture:
   - All SQL in `connector.py` with parameterized queries
   - All API routes in `routers/v1.py` with proper auth dependencies
   - All tests in `tests/` with descriptive names and proper fixtures
5. **Update documentation** - when making changes, update:
   - Relevant docstrings
   - `docs/` markdown files
   - This AGENTS.md file if architectural patterns change
6. **Add tests** - all new features and bug fixes require tests

## Documentation Resources

- **Architecture**: `docs/architecture.md` - Complete system architecture and design decisions
- **API Reference**: `docs/api-reference.md` - All API endpoints with examples
- **CLI Reference**: `docs/cli-reference.md` - CLI command usage
- **User Guide**: `docs/user-guide.md` - End-user documentation
- **Test Documentation**: `tests/README.md` - Test suite structure and usage
- **Contributing**: `docs/contributing.md` - How to contribute to the project

## Recent Lessons Learned

### Authorization Bypass in delete_team (Fixed 2025-12-17)
**Issue**: The `delete_team` endpoint had an authorization bypass vulnerability where `teams=[]` was passed to `is_authorized()`, allowing any authenticated user to delete any team regardless of their team membership or scope.

**Root Cause**: Copy-paste error from a different endpoint where empty teams list might have been intentional (e.g., listing all teams user has access to).

**Fix**: Changed `teams=[]` to `teams=[team_id]` to properly validate user has ADMIN scope for the specific team being deleted.

**Lesson**: Always include the specific resource ID in authorization checks. Empty teams list bypasses team-scoping entirely.

**Prevention**:
- Every endpoint that operates on a team-scoped resource must include that resource's team_id
- Review all `is_authorized()` calls during code review
- Add tests for cross-team access denial scenarios

### Exception Handling Masking (Fixed 2025-12-17)
**Issue**: HTTPException raised in `get_api_token` and `revoke_api_token` endpoints were caught by generic `except Exception` handler, replacing the specific HTTP status codes (404, 401, etc.) with generic 500 errors.

**Root Cause**: Generic exception handler came before more specific HTTPException handling.

**Fix**: Added explicit `except HTTPException: raise` clause before generic exception handler.

**Lesson**: Always handle HTTPException separately to preserve status codes and error details.

**Prevention**:
- Standard exception handling pattern: `except HTTPException: raise` then `except Exception as e:`
- Test error responses to ensure correct status codes are returned

## Questions?

If you're unsure about any aspect of the codebase:
1. Check the comprehensive documentation in `docs/`
2. Review existing code patterns in similar components
3. Look at test files for usage examples
4. Review "Recent Lessons Learned" section for common pitfalls
5. Ask the human developer for clarification before making significant changes
