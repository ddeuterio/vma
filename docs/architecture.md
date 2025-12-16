# Architecture

## Overview

VMA (Vulnerability Management Application) is a full-stack container vulnerability tracking system designed to centralize CVE data and manage vulnerabilities across multiple container images and products.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Web Browser  │  │  CLI Tool    │  │  CI/CD       │     │
│  │  (JS/HTML)   │  │  (vma)       │  │  Pipeline    │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
└─────────┼──────────────────┼──────────────────┼────────────┘
          │                  │                  │
          │ HTTPS            │ HTTPS            │ HTTPS
          │                  │                  │
┌─────────▼──────────────────▼──────────────────▼────────────┐
│                    Nginx Reverse Proxy                      │
│              (TLS Termination, Load Balancing)              │
└─────────┬───────────────────────────────────────────────────┘
          │
          │ HTTP
          │
┌─────────▼───────────────────────────────────────────────────┐
│                   Application Layer                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           FastAPI Application Server                 │  │
│  │  (Gunicorn + Uvicorn Workers)                        │  │
│  │                                                       │  │
│  │  ┌──────────────┐  ┌──────────────┐                 │  │
│  │  │  Web Routes  │  │  API Routes  │                 │  │
│  │  │  (FastAPI)   │  │  (/api/v1/*) │                 │  │
│  │  └──────┬───────┘  └──────┬───────┘                 │  │
│  │         │                  │                          │  │
│  │         │  ┌───────────────┴─────────────┐           │  │
│  │         │  │  Authentication Layer       │           │  │
│  │         │  │  (JWT, OAuth2, Argon2)      │           │  │
│  │         │  └───────────────┬─────────────┘           │  │
│  │         │                  │                          │  │
│  │         └──────────────────┘                          │  │
│  │                    │                                  │  │
│  │         ┌──────────▼──────────┐                      │  │
│  │         │  Business Logic     │                      │  │
│  │         │  - Products         │                      │  │
│  │         │  - Images           │                      │  │
│  │         │  - Vulnerabilities  │                      │  │
│  │         │  - Teams            │                      │  │
│  │         │  - Users            │                      │  │
│  │         └──────────┬──────────┘                      │  │
│  │                    │                                  │  │
│  │         ┌──────────▼──────────┐                      │  │
│  │         │  Data Access Layer  │                      │  │
│  │         │  (connector.py)     │                      │  │
│  │         └──────────┬──────────┘                      │  │
│  └────────────────────┼─────────────────────────────────┘  │
└───────────────────────┼────────────────────────────────────┘
                        │ psycopg2
                        │
┌───────────────────────▼────────────────────────────────────┐
│                  PostgreSQL Database                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Tables:                                             │  │
│  │  - vulnerabilities (CVE data from NVD)               │  │
│  │  - cvss_metrics (CVSS scores)                        │  │
│  │  - products (application products)                   │  │
│  │  - images (container images)                         │  │
│  │  - image_vulnerabilities (CVE mappings)              │  │
│  │  - teams (organizational units)                      │  │
│  │  - users (authentication)                            │  │
│  │  - user_teams (team memberships)                     │  │
│  │  - nvd_sync (sync state tracking)                    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    External Services                         │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │   NVD API        │  │  Container       │                │
│  │   (NIST)         │  │  Scanners        │                │
│  │                  │  │  (Grype, etc)    │                │
│  └──────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

### CLI Tool (`vma`)

**Purpose**: Command-line interface for database management and maintenance operations.

**Key Features**:
- CVE database initialization and updates
- Manual product/image/vulnerability management
- Import vulnerability scan results
- Can be run in Docker containers for cron jobs

**Entry Point**: `src/vma/app.py`

**Commands**:
- `cve --init`: Initialize NVD database with historical data
- `cve --update`: Fetch modified CVEs from NVD
- `create`: Create products/images
- `select`: Query products/images
- `import`: Import scan results via API call

### Web Application

**Purpose**: User-facing web interface for vulnerability management.

**Technology Stack**:
- FastAPI (ASGI application server)
- Jinja2 (HTML templating)
- Vanilla JavaScript (frontend interactivity)
- Bootstrap (CSS framework)

**Key Files**:
- `src/vma/web/web.py`: ASGI app initialization
- `src/vma/web/templates/`: HTML templates
- `src/vma/web/static/`: CSS, JavaScript, assets

**Pages**:
- Login page (`/`)
- Main dashboard (`/index`)
- Product management
- Image management
- Vulnerability tracking
- User administration
- Team management

### API Layer

**Purpose**: RESTful API for programmatic access and frontend communication.

**Framework**: FastAPI (modern async Python framework)

**Key Files**:
- `src/vma/api/api.py`: API app initialization
- `src/vma/api/routers/v1.py`: Endpoint definitions
- `src/vma/api/models/v1.py`: Pydantic request/response models

**Features**:
- OpenAPI documentation (automatic)
- Request validation via Pydantic
- JWT-based authentication
- Team-based authorization
- Async request handling

### Authentication & Authorization

**Authentication Flow**:

1. User submits credentials to `/api/v1/token`
2. Backend validates against database (Argon2 password hash)
3. Generate JWT tokens:
   - Access token (15 minutes, contains user claims)
   - Refresh token (2 days, httpOnly cookie)
4. Client includes access token in Authorization header
5. Token validation on protected endpoints

**JWT Claims**:
```json
{
  "username": "user@example.com",
  "scope": {
    "engineering": "WRITE",
    "security": "READ_ONLY"
  },
  "root": false,
  "exp": 1234567890
}
```

**Authorization Model**:
- **Hierarchical permissions**: Team-scoped with three levels
  - `READ_ONLY`: View resources
  - `WRITE`: Create and modify resources
  - `ADMIN`: Full control including user management
- **Root users**: Bypass all authorization checks
- **Resource ownership**: Products belong to teams
- **Cascading permissions**: Product access grants image access

### Data Access Layer

**Purpose**: Centralized database operations with consistent error handling.

**Implementation**: `src/vma/connector.py`

**Design Pattern**:
```python
def database_operation(params):
    """All database functions follow this pattern"""
    try:
        # 1. Validate inputs
        # 2. Build SQL query from queries dict
        # 3. Execute with parameterized statements
        # 4. Process results
        return {"status": True, "result": data}
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        return {"status": False, "result": str(e)}
```

**Key Features**:
- All SQL queries stored in `queries` dictionary
- Parameterized statements (SQL injection prevention)
- Consistent return format: `{"status": bool, "result": Any}`
- Connection created per operation (no pooling)
- Comprehensive logging via Loguru

### Database Layer

**Technology**: PostgreSQL 13+

**Schema Design**:
- **Normalized structure**: Separate tables for entities
- **Foreign key constraints**: Data integrity enforcement
- **Cascading deletes**: Automatic cleanup of related records
- **JSONB columns**: Flexible storage for CVE metadata
- **Composite primary keys**: Natural keys for many-to-many relationships

**Key Tables**:
- `vulnerabilities`: CVE data from NVD
- `cvss_metrics`: CVSS scores (supports multiple sources)
- `products`: Application/service groupings
- `images`: Container image versions
- `image_vulnerabilities`: CVE-to-image mappings
- `teams`: Organizational units
- `users`: Authentication and authorization
- `user_teams`: Team membership with scopes

### NVD Sync Process

**Purpose**: Keep local CVE database synchronized with NIST NVD.

**Implementation**: `src/vma/nvd.py`

**Architecture**:
```
┌─────────────────┐
│  NVD API        │
│  (api.nvd.nist) │
└────────┬────────┘
         │ HTTPS
         │ Rate Limited
         │
┌────────▼────────────────────────────────────────┐
│  VMA Sync Process                               │
│  ┌──────────────────────────────────────────┐  │
│  │  Initial Sync (--init)                   │  │
│  │  - Fetch by year (2002-present)          │  │
│  │  - Store all CVEs and CVSS metrics       │  │
│  │  - Track checksums in nvd_sync table     │  │
│  └──────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────┐  │
│  │  Update Sync (--update)                  │  │
│  │  - Query lastModStartDate parameter      │  │
│  │  - Fetch only modified CVEs              │  │
│  │  - Upsert into database                  │  │
│  │  - Update nvd_sync timestamps            │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
         │
         │ SQL
         │
┌────────▼────────┐
│  PostgreSQL     │
│  vulnerabilities│
│  cvss_metrics   │
│  nvd_sync       │
└─────────────────┘
```

**Rate Limiting**:
- Without API key: 5 requests/30s
- With API key: 50 requests/30s
- Implemented via `ratelimit` library

**Sync State Tracking**:
```sql
CREATE TABLE nvd_sync (
    id TEXT PRIMARY KEY,        -- Year or "latest"
    last_fetched TEXT NOT NULL, -- ISO timestamp
    chcksum TEXT NOT NULL       -- Response checksum
);
```

### Parser System

**Purpose**: Extract vulnerability data from container scanner outputs.

**Implementation**: `src/vma/parser.py`

**Supported Scanners**:
- Grype (JSON format)

**Parser Functions**:
- `grype_get_image_metadata()`: Extract image name and version
- `grype_parse_report()`: Convert scan results to VMA format

**Output Format**:
```python
[
    (
        cve_id,              # str: CVE-2021-1234
        fix_versions,        # str: "1.2.3" or "None"
        component_type,      # str: "deb", "python", etc.
        component_name,      # str: "libssl"
        component_version,   # str: "1.1.1"
        component_path       # str: "/usr/lib/libssl.so"
    ),
    ...
]
```

### Deployment Architecture

**Docker Compose Services**:

1. **PostgreSQL Container**
   - Official postgres:13 image
   - Persistent volume for data
   - Init scripts for schema creation

2. **Web Container**
   - Custom image (Dockerfile.web)
   - Gunicorn + Uvicorn workers
   - Serves both web UI and API
   - Connects to PostgreSQL

3. **Nginx Reverse Proxy**
   - Custom image with self-signed TLS
   - Terminates HTTPS
   - Proxies to web container
   - Static file serving (optional)

4. **VMA CLI Container** (optional)
   - Custom image (Dockerfile.vma)
   - Used for cron jobs (CVE updates)
   - Runs in `--rm` mode

**Network Architecture**:
```
Internet
    │
    │ HTTPS (8443)
    │
┌───▼─────────────────┐
│  Nginx Container    │
│  vma.local:8443     │
└───┬─────────────────┘
    │ HTTP
    │
┌───▼─────────────────┐
│  Web Container      │
│  Internal network   │
└───┬─────────────────┘
    │ PostgreSQL protocol
    │
┌───▼─────────────────┐
│  PostgreSQL         │
│  Internal network   │
└─────────────────────┘
```

## Design Patterns

### Single Responsibility Principle

Each module has a clear, focused purpose:
- `app.py`: CLI argument parsing and routing
- `connector.py`: Database operations only
- `nvd.py`: NVD API integration only
- `parser.py`: Scanner output parsing only
- `auth.py`: Authentication/authorization only
- `helper.py`: Shared utilities

### Repository Pattern

The `connector.py` module acts as a repository layer, abstracting all database operations behind a consistent interface.

### Command Pattern

CLI commands in `app.py` route to appropriate handler functions, separating command parsing from execution.

### Dependency Injection

FastAPI's dependency injection system is used for:
- JWT validation (`Depends(validate_access_token)`)
- Database connections
- Configuration loading

### Configuration Management

Environment variables (`.env` file) provide configuration:
- Database credentials
- JWT secret keys
- API keys
- Token expiration times

Loaded via `python-dotenv` at application startup.

## Security Architecture

### Defense in Depth

Multiple security layers:
1. **Network**: HTTPS/TLS encryption
2. **Application**: JWT authentication
3. **Authorization**: Team-based access control
4. **Database**: Parameterized queries
5. **Input**: Validation and sanitization

### Secret Management

- Passwords: Argon2 hashing via pwdlib
- JWT tokens: HS256 signing with separate access/refresh keys
- Environment variables: Stored in `.env` (not in version control)
- Database credentials: PostgreSQL password authentication

### Input Validation

- **Pydantic models**: Type validation for API requests
- **helper.validate_input()**: String sanitization
- **Parameterized queries**: SQL injection prevention
- **HTTPS only**: Man-in-the-middle attack prevention

## Scalability Considerations

### Current Architecture

- Single web application instance
- Single PostgreSQL instance
- Suitable for small to medium deployments (< 1000 users)

### Scaling Strategies

**Horizontal Scaling** (web tier):
- Run multiple Gunicorn instances
- Add load balancer in front of Nginx
- Session state in JWT (stateless)

**Vertical Scaling** (database):
- Increase PostgreSQL resources
- Add connection pooling (pgBouncer)
- Optimize indexes

**Future Enhancements**:
- Redis cache for CVE lookups
- Celery for async CVE sync
- Read replicas for reporting
- S3 storage for scanner reports

## Monitoring & Observability

### Logging

- **Loguru** for structured logging
- Log levels: DEBUG, INFO, WARNING, ERROR
- Log locations:
  - Container stdout/stderr
  - Optional: centralized logging (Splunk, ELK)

### Metrics

Current implementation: None

Recommended additions:
- API request rates
- Database query performance
- CVE sync job duration
- User login events

### Health Checks

Recommended endpoints:
- `/health`: Application health
- `/ready`: Database connectivity
- `/metrics`: Prometheus metrics (future)

## Technology Stack Summary

| Layer | Technology | Version |
|-------|-----------|---------|
| Web Framework | FastAPI | 0.122.0+ |
| Template Engine | Jinja2 | (via FastAPI) |
| ASGI Server | Uvicorn | 0.38.0+ |
| Application Server | Gunicorn | 23.0.0+ |
| Database | PostgreSQL | 13+ |
| Database Driver | psycopg2-binary | 2.9.10+ |
| Authentication | JWT (PyJWT) | 2.10.1+ |
| Password Hashing | Argon2 (pwdlib) | 0.3.0+ |
| HTTP Client | Requests | 2.32.4+ |
| Logging | Loguru | 0.7.3+ |
| Rate Limiting | ratelimit | 2.2.1+ |
| Testing | pytest | 8.0.0+ |
| Reverse Proxy | Nginx | Latest |
| Container Runtime | Docker | 20.0+ |

## Future Architecture Enhancements

1. **Microservices**: Split into CVE service, scan service, reporting service
2. **Message Queue**: Kafka/RabbitMQ for async processing
3. **Caching Layer**: Redis for frequently accessed CVE data
4. **API Gateway**: Kong/Traefik for advanced routing
5. **Service Mesh**: Istio for inter-service communication
6. **Container Orchestration**: Kubernetes for production deployments
