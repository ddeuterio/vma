# API Reference

VMA provides a RESTful API built with FastAPI for managing container vulnerabilities, products, images, users, and teams.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All protected endpoints require JWT authentication via Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Token Endpoints

#### POST /token
Obtain access and refresh tokens.

**Request Body** (form-data):
```
username: user@example.com
password: your_password
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

#### POST /refresh
Refresh an expired access token using a refresh token.

**Headers**:
```
Cookie: refresh_token=<refresh_token>
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

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

**Permission**: WRITE or ADMIN on the product's team

**Request Body**:
```json
{
  "scanner": "grype",
  "product": "my-application",
  "image": "nginx",
  "version": "1.21.0",
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
