# User Guide

## Introduction

VMA (Vulnerability Management Application) helps you track and manage container vulnerabilities across your organization. This guide walks you through common workflows and features.

## Getting Started

### Accessing VMA

1. Navigate to your VMA instance: `https://vma.local:8443`
2. Log in with your credentials
3. Accept the self-signed certificate warning (production deployments should use valid certificates)

### First Login

After logging in, you'll see the main dashboard with:
- **Products** panel: Your application products
- **Navigation menu**: Access to different sections
- **User menu**: Account settings and logout

## Core Concepts

### Products

A **product** represents an application, service, or project. Products contain multiple container images.

**Example products**:
- "web-application" (your main web app)
- "api-gateway" (API service)
- "data-pipeline" (batch processing)

### Images

An **image** is a specific version of a container image. Each image belongs to one product.

**Example images**:
- nginx:1.21.0
- postgres:13.4
- myapp:v2.1.5

### Vulnerabilities

**Vulnerabilities** are CVEs (Common Vulnerabilities and Exposures) found in container images by scanning tools.

Each vulnerability record contains:
- CVE ID (e.g., CVE-2021-1234)
- Severity (LOW, MEDIUM, HIGH, CRITICAL)
- CVSS score (0-10)
- Affected component and version
- Available fixes
- First/last seen timestamps

### Teams

**Teams** are organizational units that own products. Users have different permission levels for different teams.

**Permission levels**:
- **READ_ONLY**: View products, images, and vulnerabilities
- **WRITE**: Create products and images, import scan results
- **ADMIN**: Full control including team management

## Common Workflows

### Creating a Product

1. Navigate to **Products** section
2. Click **"Create Product"**
3. Fill in the form:
   - **Name**: Unique identifier (e.g., "web-application")
   - **Description**: Human-readable description
   - **Team**: Team that owns this product
4. Click **"Create"**

**CLI alternative**:
```bash
vma create --choice product \
  --name "web-application" \
  --description "Main web application stack"
```

### Importing Vulnerability Scans

#### Using the Web Interface

1. Navigate to **Images** section
2. Click **"Import Scan"**
3. Select:
   - **Product**: Target product
   - **Scanner type**: grype (more coming soon)
   - **Scan file**: Upload Grype JSON output
4. Click **"Import"**

#### Using the CLI

```bash
# First, scan your container with Grype
grype myapp:v2.1.5 -o json > scan-results.json

# Import results into VMA
vma import \
  --type grype \
  --file scan-results.json \
  --product my-product \
  --host vma.local \
  --port 8443 \
  --secure \
  --token YOUR_ACCESS_TOKEN
```

#### Using CI/CD Pipeline

**GitHub Actions example**:
```yaml
name: Container Security Scan

on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Build container
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan with Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
          ./grype myapp:${{ github.sha }} -o json > scan.json

      - name: Import to VMA
        run: |
          docker run --rm \
            -v $(pwd)/scan.json:/scan.json \
            vma:latest import \
              --type grype \
              --file /scan.json \
              --product my-product \
              --host vma.company.com \
              --port 443 \
              --secure \
              --token ${{ secrets.VMA_TOKEN }}
```

### Viewing Vulnerabilities

#### By Product

1. Go to **Products** section
2. Click on a product name
3. See all images and their vulnerability counts

#### By Image

1. Go to **Images** section
2. Filter by product and/or image name
3. Click on an image to see detailed vulnerabilities

#### By CVE

1. Navigate to **Vulnerabilities** section
2. Search for a specific CVE ID
3. View:
   - Full CVE description
   - CVSS scores from multiple sources
   - Affected images in your environment
   - References and advisories

### Tracking Remediation

#### Vulnerability Lifecycle

Vulnerabilities in VMA are tracked with timestamps:
- **first_seen**: When the vulnerability was first detected
- **last_seen**: Most recent scan showing this vulnerability

When you update an image and re-scan:
1. Old vulnerabilities not found → `last_seen` stays unchanged (remediated)
2. Existing vulnerabilities → `last_seen` updates (still present)
3. New vulnerabilities → `first_seen` set to current time

#### Viewing Remediation Progress

Compare scan dates:
```sql
-- Example query (database access)
SELECT
    cve,
    affected_component,
    first_seen,
    last_seen,
    (NOW() - last_seen) as days_since_last_seen
FROM image_vulnerabilities
WHERE image_name = 'nginx'
  AND image_version = '1.21.0'
ORDER BY days_since_last_seen DESC;
```

Vulnerabilities with old `last_seen` dates (no recent scans showing them) are likely remediated.

### Managing Teams

**Admin users** can manage team memberships:

1. Navigate to **Teams** section
2. Select a team
3. Click **"Manage Members"**
4. Add or remove users with appropriate scopes

**CLI alternative** (root user only):
```bash
# Create team
POST /api/v1/team
{
  "name": "security",
  "description": "Security team"
}

# Add user to team
PUT /api/v1/user
{
  "email": "user@company.com",
  "teams": {
    "security": "WRITE"
  }
}
```

### Managing Users

**Root users** can create and manage user accounts:

1. Navigate to **Users** section
2. Click **"Create User"**
3. Fill in:
   - **Email**: User's email (used for login)
   - **Password**: Initial password
   - **Teams**: Team memberships with scopes
   - **Root**: Check if this is a root user
4. Click **"Create"**

**Note**: Users should change their password after first login.

## Searching and Filtering

### Product Search

- Filter by team
- Sort by name or vulnerability count
- Text search in descriptions

### Image Search

- Filter by product
- Filter by image name
- Filter by version
- Sort by last scanned date

### Vulnerability Search

- Search by CVE ID
- Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- Filter by CVSS score range
- Filter by affected component
- Filter by fix availability

## Dashboards and Reports

### Product Dashboard

Shows for each product:
- Total images
- Total vulnerabilities by severity
- Recent scan activity
- Remediation trends

### Team Dashboard

Shows for your teams:
- Products owned
- Images tracked
- Vulnerability summary
- Top CVEs

### CVE Statistics

Global view:
- Total CVEs in database
- CVEs affecting your images
- Severity distribution
- Recently published CVEs

## Best Practices

### Scanning Frequency

**Recommended schedules**:
- **Production images**: Daily scans
- **Development images**: On every build
- **Base images**: Weekly scans
- **Legacy images**: Monthly scans

### Product Organization

**Good product structure**:
```
products/
├── web-frontend (team: engineering)
│   ├── nginx-proxy
│   ├── react-app
│   └── cdn-assets
├── web-backend (team: engineering)
│   ├── api-gateway
│   ├── auth-service
│   └── user-service
└── data-platform (team: data)
    ├── postgres
    ├── redis
    └── etl-worker
```

### Team Structure

**Example teams**:
- **engineering**: Main development team (WRITE on most products)
- **security**: Security team (READ_ONLY on all, ADMIN on security tools)
- **devops**: Operations team (ADMIN on infrastructure products)
- **data**: Data team (ADMIN on data-platform)

### Vulnerability Prioritization

Focus on:
1. **CRITICAL/HIGH severity** with public exploits
2. **Network-accessible services**
3. **Production images**
4. **Components with available fixes**

De-prioritize:
5. LOW severity in non-production
6. Vulnerabilities requiring local access
7. Components with no fix available (track for future fixes)

### Automation

Automate these tasks:
- **CVE database updates**: Daily cron job
- **Container scanning**: CI/CD integration
- **Vulnerability import**: Automated after scans
- **Reports**: Weekly email summaries (future feature)

## Troubleshooting

### Login Issues

**Symptom**: "Invalid credentials" error

**Solutions**:
1. Verify username/password
2. Check if user account exists (ask admin)
3. Verify user has team membership
4. Check access token expiration (refresh)

### Import Failures

**Symptom**: Scan import returns 400 error

**Solutions**:
1. Verify scan file format (must be valid JSON)
2. Check scanner type matches file format
3. Verify product exists
4. Confirm user has WRITE permission on product's team
5. Check image metadata in scan file

**Debug CLI import**:
```bash
# Validate JSON
jq . scan.json

# Check image metadata
jq '.source' scan.json

# Test API connectivity
curl -k https://vma.local:8443/api/v1/health
```

### Missing Vulnerabilities

**Symptom**: Scan shows vulnerabilities but they don't appear in VMA

**Possible causes**:
1. Import failed silently (check logs)
2. CVE database not updated (run `vma cve --update`)
3. CVE ID not in NVD database yet (new CVEs take time)
4. Filtering applied in UI (remove filters)

### Slow Performance

**Symptom**: Web interface is slow or times out

**Solutions**:
1. Check database size (large databases need optimization)
2. Review database indexes
3. Increase Gunicorn workers
4. Add database connection pooling
5. Check PostgreSQL query performance

### CVE Sync Failures

**Symptom**: `vma cve --update` fails

**Solutions**:
1. Verify NVD_API_KEY in .env
2. Check internet connectivity
3. Review NVD API rate limits
4. Check NVD API status: https://nvd.nist.gov/

## Advanced Features

### API Access

Use the REST API for custom integrations:

```python
import requests

# Authenticate
response = requests.post(
    "https://vma.local:8443/api/v1/token",
    data={
        "username": "user@company.com",
        "password": "secure_password"
    },
    verify=False  # Only for self-signed certs
)
access_token = response.json()["access_token"]

# Get vulnerabilities for an image
response = requests.get(
    "https://vma.local:8443/api/v1/vulnerabilities",
    params={
        "product": "my-product",
        "name": "nginx",
        "version": "1.21.0"
    },
    headers={
        "Authorization": f"Bearer {access_token}"
    },
    verify=False
)
vulnerabilities = response.json()["result"]
```

### Custom Queries

Direct database queries for custom reports:

```sql
-- Top 10 most vulnerable images
SELECT
    image_name,
    image_version,
    COUNT(*) as vuln_count
FROM image_vulnerabilities
GROUP BY image_name, image_version
ORDER BY vuln_count DESC
LIMIT 10;

-- Critical vulnerabilities without fixes
SELECT DISTINCT
    iv.cve,
    v.descriptions->0->>'value' as description,
    cm.base_score
FROM image_vulnerabilities iv
JOIN vulnerabilities v ON iv.cve = v.cve_id
JOIN cvss_metrics cm ON v.cve_id = cm.cve_id
WHERE cm.base_severity = 'CRITICAL'
  AND (iv.fix_versions IS NULL OR iv.fix_versions = 'None')
ORDER BY cm.base_score DESC;

-- Vulnerability trends by week
SELECT
    DATE_TRUNC('week', first_seen) as week,
    COUNT(*) as new_vulns
FROM image_vulnerabilities
WHERE first_seen > NOW() - INTERVAL '90 days'
GROUP BY week
ORDER BY week;
```

### Webhook Notifications (Future)

Coming soon: Webhook support for events like:
- New CRITICAL vulnerability detected
- Product vulnerability count exceeds threshold
- Scan import completed
- CVE database updated

## Support

### Getting Help

- **Documentation**: https://vma-docs.readthedocs.io
- **Issues**: https://github.com/your-org/vma/issues
- **Email**: daniel.garcia.anes@gmail.com

### Reporting Bugs

Include in bug reports:
1. VMA version
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Screenshots (if applicable)
6. Browser/client details

### Feature Requests

Submit feature requests via GitHub issues with:
- Use case description
- Expected behavior
- Proposed implementation (if any)
- Priority justification
