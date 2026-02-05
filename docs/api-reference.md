# API Reference

VMA provides a RESTful API built with FastAPI for managing container vulnerabilities, products, images, users, and teams.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

VMA supports two authentication methods:

### 1. JWT Access Tokens (Web/Interactive)

Used for web browser sessions with automatic token refresh.

**Authorization Header**:
```
Authorization: Bearer <jwt_access_token>
```

**Characteristics**:
- Short-lived (15 minutes)
- Automatically refreshed via httpOnly cookie
- Best for web interface and short-lived API calls

### 2. API Tokens (CLI/CI-CD/Programmatic)

Used for long-lived programmatic access (CLI, CI/CD, scripts).

**Authorization Header**:
```
Authorization: Bearer vma_<base64_token>
```

**Characteristics**:
- Long-lived or permanent
- Inherits all permissions from creating user
- Can be revoked independently
- Best for automation and non-interactive usage

### Token Endpoints

#### POST /api/v1/token
Obtain JWT access and refresh tokens for web session.

**Request Body** (form-data):
```
username: user@example.com
password: your_password
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer"
}
```

**Note**: Refresh token is set as httpOnly cookie in response (not visible in JSON).

#### GET /api/v1/refresh_token
Refresh an expired JWT access token using refresh token cookie.

**Headers**:
```
Cookie: refresh_token=<refresh_token>
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer"
}
```

**Note**: New refresh token is also set as httpOnly cookie (token rotation).

#### GET /api/v1/logout
Logout and invalidate refresh token.

**Headers**:
```
Cookie: refresh_token=<refresh_token>
```

**Response**:
```json
{
  "status": true,
  "result": "User has logout"
}
```

**Note**: Refresh token cookie is cleared (max_age=0).

## Authorization

VMA uses team-based access control with three permission levels:

- **READ_ONLY**: View data only
- **WRITE**: Create and modify resources
- **ADMIN**: Full access including user/team management

Users have different scopes for different teams. Root users bypass all authorization checks.

## Products

### POST /product
Create a new product.

**Permission**: WRITE or ADMIN on the target team

**Request Body**:
```json
{
  "name": "my-application",
  "description": "Production application stack",
  "team": "engineering"
}
```

**Response**:
```json
{
  "status": true,
  "result": "Product created successfully"
}
```

### GET /product
Get all products or filter by team.

**Permission**: READ_ONLY or higher for requested team(s)

**Query Parameters**:
- `team` (optional): Filter by team name

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "id": "my-application",
      "description": "Production application stack",
      "team": "engineering"
    }
  ]
}
```

### PUT /product
Update an existing product.

**Permission**: WRITE or ADMIN on the product's team

**Request Body**:
```json
{
  "name": "my-application",
  "description": "Updated description",
  "team": "engineering"
}
```

### DELETE /product
Delete a product and all associated images and vulnerabilities.

**Permission**: ADMIN on the product's team

**Query Parameters**:
- `product`: Product name to delete

**Response**:
```json
{
  "status": true,
  "result": "Product deleted successfully"
}
```

## Images

### POST /image
Create a new container image record.

**Permission**: WRITE or ADMIN on the product's team

**Request Body**:
```json
{
  "name": "nginx",
  "version": "1.21.0",
  "product": "my-application"
}
```

**Response**:
```json
{
  "status": true,
  "result": "Image created successfully"
}
```

### GET /image
Get all images or filter by product/name/version.

**Permission**: READ_ONLY or higher for the product's team

**Query Parameters**:
- `product` (optional): Filter by product name
- `name` (optional): Filter by image name
- `version` (optional): Filter by image version

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "name": "nginx",
      "version": "1.21.0",
      "product": "my-application",
      "vulnerability_count": 15
    }
  ]
}
```

### PUT /image
Update an existing image.

**Permission**: WRITE or ADMIN on the product's team

**Request Body**:
```json
{
  "name": "nginx",
  "version": "1.21.0",
  "new_version": "1.21.1",
  "product": "my-application"
}
```

### DELETE /image
Delete an image and all associated vulnerabilities.

**Permission**: ADMIN on the product's team

**Query Parameters**:
- `product`: Product name
- `name`: Image name
- `version`: Image version

## Vulnerabilities

### POST /import
Import vulnerability scan results from container scanning tools.

**Authentication**: Requires API Token (not JWT access token)

**Permission**: WRITE or ADMIN on the product's team

**Authorization Header**:
```
Authorization: Bearer vma_<your_api_token>
```

**Request Body**:
```json
{
  "scanner": "grype",
  "product": "my-application",
  "image": "nginx",
  "version": "1.21.0",
  "team": "engineering",
  "data": [
    {
      "cve": "CVE-2021-1234",
      "fix_versions": "1.21.1",
      "affected_component_type": "deb",
      "affected_component": "libssl",
      "affected_version": "1.1.1",
      "affected_path": "/usr/lib/libssl.so"
    }
  ]
}
```

**Response**:
```json
{
  "status": true,
  "result": "Vulnerabilities imported successfully"
}
```

**Notes**:
- This endpoint requires an API token, not a JWT access token
- API tokens are created via `/api/v1/apitoken`
- If image doesn't exist, it will be created automatically
- `last_seen` timestamp is updated for existing vulnerabilities

### GET /vulnerabilities
Get vulnerabilities for a specific image.

**Permission**: READ_ONLY or higher for the product's team

**Query Parameters**:
- `product`: Product name
- `name`: Image name
- `version`: Image version

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "cve": "CVE-2021-1234",
      "description": "Buffer overflow in libssl",
      "severity": "HIGH",
      "base_score": 7.5,
      "fix_versions": "1.21.1",
      "affected_component": "libssl",
      "affected_version": "1.1.1",
      "first_seen": "2024-01-15T10:30:00Z",
      "last_seen": "2024-01-20T14:45:00Z"
    }
  ]
}
```

## Repositories

### POST /repo
Create a repository record.

**Permission**: WRITE or ADMIN on the product's team

**Request Body**:
```json
{
  "product": "my-application",
  "team": "engineering",
  "name": "backend-service",
  "url": "https://github.com/org/backend-service"
}
```

### GET /repo/{team}
Get all repositories for a team.

**Permission**: READ_ONLY or higher on the team

### GET /repo/{team}/{product}
Get repositories for a product.

**Permission**: READ_ONLY or higher on the team

### GET /repo/{team}/{product}/{name}
Get a repository by name.

**Permission**: READ_ONLY or higher on the team

### DELETE /repo/{team}/{product}/{name}
Delete a repository.

**Permission**: ADMIN on the team

### GET /cve/{cve_id}
Get detailed information about a specific CVE.

**Permission**: Authenticated user (any scope)

**Path Parameters**:
- `cve_id`: CVE identifier (e.g., CVE-2021-1234)

**Response**:
```json
{
  "status": true,
  "result": {
    "cve_id": "CVE-2021-1234",
    "source_identifier": "cve@mitre.org",
    "published_date": "2021-03-15T10:00:00Z",
    "last_modified": "2021-03-20T15:30:00Z",
    "vuln_status": "Analyzed",
    "descriptions": [
      {
        "lang": "en",
        "value": "Buffer overflow vulnerability in libssl..."
      }
    ],
    "cvss_metrics": [
      {
        "source": "nvd@nist.gov",
        "cvss_version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 7.5,
        "base_severity": "HIGH"
      }
    ],
    "references": [
      "https://example.com/security-advisory"
    ],
    "weakness": [
      {
        "type": "Primary",
        "description": "CWE-120: Buffer Copy without Checking Size of Input"
      }
    ]
  }
}
```

## Teams

### POST /team
Create a new team.

**Permission**: Root user only

**Request Body**:
```json
{
  "name": "engineering",
  "description": "Engineering team"
}
```

### GET /team
Get all teams or a specific team by name.

**Permission**: READ_ONLY or higher (filtered by user's teams)

**Query Parameters**:
- `name` (optional): Filter by team name

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "name": "engineering",
      "description": "Engineering team",
      "member_count": 5,
      "product_count": 12
    }
  ]
}
```

### PUT /team
Update a team's information.

**Permission**: ADMIN on the team

**Request Body**:
```json
{
  "name": "engineering",
  "description": "Updated description"
}
```

### DELETE /team
Delete a team and all associated products, images, and user associations.

**Permission**: Root user only

**Query Parameters**:
- `name`: Team name to delete

## Users

### POST /user
Create a new user.

**Permission**: Root user only (for initial creation) or ADMIN on target teams

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "secure_password",
  "teams": {
    "engineering": "WRITE",
    "security": "READ_ONLY"
  },
  "root": false
}
```

**Response**:
```json
{
  "status": true,
  "result": "User created successfully"
}
```

### GET /user
Get all users or a specific user by email.

**Permission**: Root user (see all) or ADMIN on team (see team members)

**Query Parameters**:
- `email` (optional): Filter by user email

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "email": "user@example.com",
      "teams": {
        "engineering": "WRITE",
        "security": "READ_ONLY"
      },
      "root": false,
      "created_at": "2024-01-10T08:00:00Z"
    }
  ]
}
```

### PUT /user
Update a user's information or permissions.

**Permission**: Root user or ADMIN on the teams being modified

**Request Body**:
```json
{
  "email": "user@example.com",
  "teams": {
    "engineering": "ADMIN"
  }
}
```

### DELETE /user
Delete a user account.

**Permission**: Root user only

**Query Parameters**:
- `email`: User email to delete

## API Token Management

API tokens provide long-lived authentication for CLI tools, CI/CD pipelines, and programmatic access.

### POST /apitoken
Create a new API token.

**Permission**: Root user can create for any user; regular users can create for themselves

**Authorization**: JWT access token required

**Request Body**:
```json
{
  "username": "user@example.com",
  "description": "GitHub Actions CI pipeline",
  "expires_days": 365
}
```

**Response**:
```json
{
  "status": true,
  "result": {
    "id": 1,
    "token": "vma_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "prefix": "vma_ABCDEFGH",
    "user_email": "user@example.com",
    "description": "GitHub Actions CI pipeline",
    "created_at": "2024-01-15T10:30:00Z",
    "last_used_at": null,
    "expires_at": "2025-01-15T10:30:00Z",
    "revoked": false
  }
}
```

**Important**:
- The full token is returned ONLY during creation
- Save it securely - it cannot be retrieved later
- Set `expires_days: null` for permanent tokens
- Token inherits ALL permissions from the user

### GET /tokens
List API tokens.

**Permission**: Root users see all tokens; regular users see only their own

**Authorization**: JWT access token required

**Response**:
```json
{
  "status": true,
  "result": [
    {
      "id": 1,
      "token": null,
      "prefix": "vma_ABCDEFGH",
      "user_email": "user@example.com",
      "description": "GitHub Actions CI pipeline",
      "created_at": "2024-01-15T10:30:00Z",
      "last_used_at": "2024-01-20T14:25:00Z",
      "expires_at": "2025-01-15T10:30:00Z",
      "revoked": false
    }
  ]
}
```

**Note**: Token values are never returned in list operations (only prefix shown).

### GET /tokens/{token_id}
Get details of a specific API token.

**Permission**: Root users can view any token; users can view their own tokens

**Authorization**: JWT access token required

**Path Parameters**:
- `token_id`: Token ID (integer)

**Response**:
```json
{
  "status": true,
  "result": {
    "id": 1,
    "token": null,
    "prefix": "vma_ABCDEFGH",
    "user_email": "user@example.com",
    "description": "GitHub Actions CI pipeline",
    "created_at": "2024-01-15T10:30:00Z",
    "last_used_at": "2024-01-20T14:25:00Z",
    "expires_at": "2025-01-15T10:30:00Z",
    "revoked": false
  }
}
```

### DELETE /tokens/{token_id}
Revoke an API token.

**Permission**: Root users can revoke any token; users can revoke their own tokens

**Authorization**: JWT access token required

**Path Parameters**:
- `token_id`: Token ID (integer)

**Response**:
```json
{
  "status": "success",
  "message": "Token revoked successfully"
}
```

**Notes**:
- Revoked tokens immediately stop working
- Revocation is permanent (cannot be undone)
- Token record remains in database for audit purposes

## Error Responses

All endpoints return standardized error responses:

### 400 Bad Request
```json
{
  "detail": "Invalid input: product name required"
}
```

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 403 Forbidden
```json
{
  "detail": "Insufficient permissions for this operation"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error occurred"
}
```

## Rate Limiting

The NVD API sync operations are rate-limited to comply with NIST NVD API guidelines:
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds

## API Versioning

The current API version is `v1`. Future versions will be available at `/api/v2`, etc., maintaining backward compatibility for at least one major version.
