# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VMA (Vulnerability Management Application) is a container vulnerability tracking system that syncs CVE data from NVD (National Vulnerability Database) and tracks vulnerabilities in container images. The application consists of:

- **CLI tool** (`vma`) for database initialization, CVE sync, and manual operations
- **FastAPI backend** (`/api/v1/*`) providing REST endpoints
- **Web frontend** (FastAPI/Jinja2) with authentication and authorization
- **PostgreSQL database** storing CVE data, products, images, and vulnerability mappings

The system supports team-based access control with scopes (READ_ONLY/WRITE/ADMIN) and integrates with container scanning tools (currently Grype).

## Quick Reference

**Common Operations:**
```bash
# Initialize database with CVE data
poetry run vma cve --init

# Update CVE data from NVD
poetry run vma cve --update

# Start development server
poetry run gunicorn vma.web.web:create_web_app --bind 0.0.0.0:8000 --worker-class uvicorn.workers.UvicornWorker

# Run tests
poetry run pytest --cov=src/vma

# Import Grype scan results
poetry run vma import --type grype --file scan.json --product "my-product" --host localhost --port 8000
```

**Key Files:**
- `src/vma/app.py` - CLI entrypoint and command definitions
- `src/vma/connector.py` - All database queries and operations
- `src/vma/auth.py` - Authentication and JWT token handling
- `src/vma/api/routers/v1.py` - API endpoint definitions
- `src/vma/web/web.py` - Web server initialization and routes

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **`user-guide.md`** - End-user guide for using the web interface and CLI
- **`architecture.md`** - Detailed system architecture, data flow, and design decisions
- **`api-reference.md`** - Complete API endpoint documentation with examples
- **`cli-reference.md`** - CLI command reference and usage examples
- **`contributing.md`** - Guidelines for contributing to the project
- **`readme.md`** - Quick start and project overview

The documentation is written in Markdown and can be built with Sphinx (see `docs/conf.py` and `docs/Makefile`).

## Architecture

### Repository Structure

```
vma/
├── src/vma/                    # Main application code
│   ├── app.py                  # CLI entrypoint (argparse subcommands)
│   ├── api/
│   │   ├── api.py              # FastAPI app initialization
│   │   ├── models/v1.py        # Pydantic models for API v1
│   │   └── routers/v1.py       # API v1 endpoints (/api/v1/*)
│   ├── web/
│   │   ├── web.py              # ASGI app (FastAPI) serving frontend + API
│   │   ├── templates/          # Jinja2 HTML templates
│   │   │   ├── login.html      # Login page
│   │   │   └── index.html      # Main SPA application
│   │   └── static/             # Frontend assets
│   │       ├── css/            # Stylesheets
│   │       └── js/             # JavaScript modules
│   ├── connector.py            # Database layer (psycopg2, all SQL queries)
│   ├── auth.py                 # JWT creation/validation, password hashing
│   ├── parser.py               # Scanner output parsers (Grype JSON)
│   ├── nvd.py                  # NVD API client and CVE sync logic
│   └── helper.py               # Logging, validation utilities
│
├── tests/                      # Test suite (pytest)
│   └── authN.py                # Authentication/authorization tests
│
├── docs/                       # Comprehensive documentation
│   ├── user-guide.md           # User guide
│   ├── architecture.md         # Architecture documentation
│   ├── api-reference.md        # API documentation
│   └── cli-reference.md        # CLI documentation
│
├── docker/                     # Docker deployment configuration
│   ├── db/                     # PostgreSQL initialization scripts
│   ├── rev_proxy/              # Nginx reverse proxy config
│   ├── docker-compose.yml      # Stack orchestration
│   └── .env                    # Environment variables (not committed)
│
├── Dockerfile.vma              # CLI/worker container image
├── Dockerfile.web              # Web/API container image
├── pyproject.toml              # Poetry dependencies and project metadata
└── README.md                   # Project README
```

### Key Architectural Patterns

**Database Queries**: All SQL lives in `connector.py` in the `queries` dictionary. Functions in `connector.py` return `{"status": bool, "result": Any}` dicts.

**Authentication Flow**:
1. User submits credentials to `/api/v1/token` (OAuth2PasswordRequestForm)
2. Backend validates via `connector.get_users(email=...)` and verifies password with Argon2
3. `auth.py` creates JWT access token (15min) and refresh token (2 days)
4. Both tokens returned to client; access token stored in JS memory, refresh token in httpOnly cookie
5. Protected endpoints use `Depends(a.validate_access_token)` to extract `JwtData(username, scope, root)`
6. On access token expiry, frontend automatically calls `/api/v1/refresh` with refresh token cookie
7. New access token issued without requiring re-login (seamless token renewal)

**Authorization**:
- Three permission levels: `READ_ONLY`, `WRITE`, `ADMIN` (defined in `api/routers/v1.py`)
- Team-based scoping: users have `{team_name: scope}` mappings stored in JWT
- `is_authorized()` checks if user has required scope for requested team(s)
- Root users bypass all authorization checks

**Data Model**:
- **Hierarchy**: `Teams` → `Products` → `Images` (name + version)
- **Vulnerability Tracking**:
  - `vulnerabilities` - Full CVE data from NVD (description, published date, references)
  - `cvss_metrics` - Multiple CVSS scores per CVE (NVD, vendor sources, metrics v2/v3/v4)
  - `image_vulnerabilities` - Maps CVEs to specific images with affected components
  - `last_seen` timestamp tracks when vulnerability was last detected in scans
- **Access Control**:
  - `users` - User accounts with email, hashed password, root flag
  - `teams` - Organizational units for grouping products
  - `user_teams` - Junction table mapping users to teams with scopes (READ_ONLY/WRITE/ADMIN)
- **Audit Trail**:
  - `nvd_sync` - Tracks NVD API sync history (last fetch, checksums per year)

**Container Scanning Integration**:
- `vma import` CLI command or `/api/v1/import` endpoint accepts Grype JSON
- `parser.py` extracts image metadata and vulnerability details
- `connector.insert_image_vulnerabilities()` uses `ON CONFLICT` to update `last_seen` timestamp

## Development Commands

### Setup
```bash
poetry install                        # Install dependencies (Python 3.10+)
poetry shell                          # Activate virtual environment
```

### CLI Usage
```bash
poetry run vma --help                 # Show all subcommands
poetry run vma cve --init             # Initialize NVD database (full history)
poetry run vma cve --update           # Sync modified CVEs from NVD
poetry run vma create --choice product --name "my-product" --description "..."
poetry run vma create --choice image --name "app" --version "1.0" --product "my-product" --file grype.json
poetry run vma select --choice product --name "my-product"
poetry run vma import --type grype --file grype.json --product "my-product" --host localhost --port 8000
```

### Local Development

**Option 1: API Server Only (for backend development)**
```bash
poetry run uvicorn vma.api.api:api_server --reload --port 8000
# Access API at: http://localhost:8000/api/v1/*
# Auto-reloads on code changes
```

**Option 2: Full Web Application (recommended)**
```bash
poetry run gunicorn vma.web.web:create_web_app --bind 0.0.0.0:8000 --worker-class uvicorn.workers.UvicornWorker
# Access web UI at: http://localhost:8000/
# Serves both frontend HTML and API endpoints
```

**Running Tests**
```bash
poetry run pytest                     # Run all tests
poetry run pytest --cov=src/vma       # With coverage report
poetry run pytest tests/authN.py      # Single test file
poetry run pytest -v                  # Verbose output
poetry run pytest -k "test_login"     # Run specific test by name
```

**Development Tips**
- Use `--reload` flag with uvicorn for hot reloading during development
- Check logs in terminal for debugging (Loguru outputs to stderr)
- Frontend static files served from `src/vma/web/static/`
- Template changes require server restart (Jinja2 doesn't auto-reload by default)

### Docker Workflow
```bash
# Build images
docker build -t vma:latest -f Dockerfile.vma .
docker build -t web:latest -f Dockerfile.web .

# Create .env file in docker/ directory with:
# DB_HOST, DB_USER, DB_PASS, DB_NAME, NVD_API_KEY,
# POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB,
# SECRET_KEY_ACCESS, SECRET_KEY_REFRESH, TOKEN_ALG,
# ACCESS_TOKEN_EXP_TIME, REFRESH_TOKEN_EXP_TIME

# Run stack (PostgreSQL, web frontend, reverse proxy)
cd docker && docker-compose up -d

# Access application
# Add to /etc/hosts: 127.0.0.1 vma.local
# Navigate to: https://vma.local:8443
```

### Cron Job for CVE Updates
```bash
0 2 * * * docker run --rm --env-file /path/to/.env vma cve --update
```

## Important Technical Details

### Database Connection
- Credentials loaded from `.env` via `python-dotenv`
- `connector.py` creates new connection per operation (no connection pooling in current design)
- All queries use parameterized statements (protection against SQL injection)

### Authentication & Security
- Passwords hashed with Argon2 via `pwdlib` (see `auth.hasher`)
- JWTs use HS256 (configurable via `TOKEN_ALG` env var)
- Access tokens: 15min default (`ACCESS_TOKEN_EXP_TIME`)
- Refresh tokens: 2 days default (`REFRESH_TOKEN_EXP_TIME`)
- Refresh tokens stored in httpOnly cookies (not accessible to JS)
- Secret keys: `SECRET_KEY_ACCESS` and `SECRET_KEY_REFRESH` (must be set in `.env`)

### NVD Sync Process
- Initial sync: `vma cve --init` fetches all historical CVE data year-by-year
- Updates: `vma cve --update` uses `lastModStartDate` parameter to fetch only modified CVEs
- `nvd_sync` table tracks last fetch timestamp and checksums per year
- NVD API requires `NVD_API_KEY` for higher rate limits (recommended)

### Frontend Architecture
- Web app in `src/vma/web/` uses FastAPI to serve both HTML and API
- Login flow: POST to `/` → calls `/api/v1/token` internally → sets cookie + renders `index.html`
- Main app (`index.html`) is a single-page application that dynamically loads content from `/api/v1/*`
- HTML templates: `login.html`, `index.html` (served via Jinja2Templates)
- JavaScript modules:
  - `login.js` - Login form handling and authentication
  - `main.js` - Core app initialization and routing
  - `sidebar.js` - Navigation sidebar management
  - `dashboard.js` - Dashboard view and statistics
  - `product.js` - Product management interface
  - `image.js` - Container image vulnerability tracking
  - `cve.js` - CVE detail views and search
  - `users.js` - User management (admin)
  - `teams.js` - Team management (admin)
  - `tokens.js` - API token management
- Access token stored in memory (JS variable), passed in `Authorization: Bearer <token>` header
- Refresh token stored in httpOnly cookie for automatic token renewal

### Validation & Error Handling
- `helper.validate_input()` sanitizes user-provided strings (prevents injection)
- Standard error codes in `helper.errors` dict (e.g., `helper.errors["401"]`)
- All API endpoints return `{"status": bool, "result": ...}` format
- FastAPI automatically returns 422 for validation errors (Pydantic models)

### Testing
- **Location**: Tests in `tests/` directory
- **Framework**: pytest with asyncio support
- **Configuration**: `pyproject.toml` sets debug logging and Python path
- **Coverage**: Use `pytest --cov=src/vma` for coverage reports
- **Mocking**: Mock external services (NVD API, database) in unit tests
- **Naming**: Test files follow `test_<module>.py` pattern
- **Authentication Tests**: See `tests/authN.py` for auth/authz test examples
- **CI/CD**: GitHub Actions workflow runs tests automatically (`.github/workflows/`)

### Security Considerations
- **Password Storage**: Argon2 hashing via `pwdlib` (memory-hard, resistant to GPU attacks)
- **SQL Injection**: All queries use parameterized statements (no string concatenation)
- **XSS Prevention**: Input validation via `helper.validate_input()` sanitizes user inputs
- **CORS**: Configure CORS policies in FastAPI for production deployments
- **TLS**: Reverse proxy provides HTTPS (self-signed cert in dev, proper cert in production)
- **Token Security**:
  - Access tokens short-lived (15min) to limit exposure window
  - Refresh tokens in httpOnly cookies (not accessible to JavaScript)
  - Separate secrets for access and refresh tokens
  - HS256 algorithm (symmetric signing)
- **Environment Variables**: Never commit `.env` file; use `.env.example` as template
- **Database Credentials**: Use strong passwords and restrict network access to PostgreSQL

## Common Patterns

### Adding a New API Endpoint
1. Define Pydantic model in `src/vma/api/models/v1.py`
2. Add SQL query to `queries` dict in `connector.py`
3. Implement database function in `connector.py` (returns `{"status": bool, "result": ...}`)
4. Add route to `src/vma/api/routers/v1.py`:
   - Use `Depends(a.validate_access_token)` for authentication
   - Call `is_authorized()` with appropriate scope (READ_ONLY/WRITE/ADMIN)
   - Call connector function and handle exceptions
   - Raise `HTTPException` for errors (400/401/500)

### Adding a New Scanner Parser
1. Add parsing functions to `parser.py` (follow `grype_*` naming pattern)
2. Extract image metadata: `(name, version)` tuple
3. Parse vulnerabilities into list of tuples for `insert_image_vulnerabilities()`
4. Update `app.py` importer mode and `/api/v1/import` endpoint to support new scanner type

### Modifying Database Schema
1. Update SQL init scripts in `docker/init/` (for new deployments)
2. Add migration logic to `connector.py` (or create separate migration script)
3. Update corresponding `queries` dict entries
4. Update Pydantic models in `api/models/v1.py`
5. Update any affected frontend JavaScript

## Configuration Files

### Environment Variables (.env)
Required for both development and production:
```
DB_HOST=localhost
DB_USER=vma
DB_PASS=<password>
DB_NAME=vma
NVD_API_KEY=<nvd-api-key>
POSTGRES_USER=vma
POSTGRES_PASSWORD=<password>
POSTGRES_DB=vma
SECRET_KEY_ACCESS=<random-secret>
SECRET_KEY_REFRESH=<random-secret>
TOKEN_ALG=HS256
ACCESS_TOKEN_EXP_TIME=15
REFRESH_TOKEN_EXP_TIME=2
```

### Dockerfiles
- `Dockerfile.vma`: CLI/worker container (for cron jobs, manual operations)
- `Dockerfile.web`: Web/API container (runs Gunicorn + Uvicorn workers)
- `docker/rev_proxy/Dockerfile`: Nginx reverse proxy with self-signed TLS

## Troubleshooting

### Database Connection Issues
- Verify `.env` file has correct `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`
- Check PostgreSQL is running: `docker ps` or `systemctl status postgresql`
- Test connection: `psql -h localhost -U vma -d vma`
- Check network: if using Docker, ensure containers are on same network

### Authentication Failures
- Verify `SECRET_KEY_ACCESS` and `SECRET_KEY_REFRESH` are set in `.env`
- Check token expiration settings (`ACCESS_TOKEN_EXP_TIME`, `REFRESH_TOKEN_EXP_TIME`)
- Clear browser cookies and try logging in again
- Check user exists: `SELECT * FROM users WHERE email = 'user@example.com';`

### NVD Sync Issues
- Verify `NVD_API_KEY` is set (get from https://nvd.nist.gov/developers/request-an-api-key)
- Check rate limits: without API key, NVD limits to 5 requests per 30 seconds
- Review logs for specific NVD API errors
- Check `nvd_sync` table for last successful sync timestamp

### Import/Scanning Issues
- Verify Grype JSON format matches expected schema (see `parser.py`)
- Check product exists before importing images: `vma select --choice product --name "product-name"`
- Ensure database has latest CVE data: `vma cve --update`
- Review API logs for detailed error messages

### Frontend Issues
- Check browser console for JavaScript errors
- Verify API endpoints are accessible: `curl http://localhost:8000/api/v1/health`
- Clear browser cache and reload
- Check access token is being included in Authorization header (DevTools Network tab)

## Code Style & Guidelines

### Python Style
- **Indentation**: 4 spaces (not tabs)
- **Naming conventions**:
  - Functions/modules: `snake_case`
  - Classes: `CapWords`
  - Constants: `UPPER_CASE`
- **Type hints**: Required on all public function signatures
- **Logging**: Use Loguru exclusively (never `print()`)
- **Docstrings**: Follow Google style for public APIs

### Git Commit Messages
- **Format**: `<type>: <description>`
- **Types**: `add`, `fix`, `update`, `refactor`, `test`, `docs`
- **Style**: Imperative mood ("add feature" not "added feature")
- **Length**: Subject line under 72 characters
- **Examples**:
  - `add: JWT refresh token rotation`
  - `fix: SQL injection vulnerability in product query`
  - `update: NVD API rate limiting logic`

### Code Modification Policy
**IMPORTANT**: When working with this codebase, Claude Code should:
- **Analyze and explain** Python code freely
- **Suggest changes** with detailed explanations
- **Avoid direct modifications** to Python files unless explicitly requested
- **Ask for confirmation** before making significant architectural changes

This policy ensures human review of all code changes and prevents unintended modifications.