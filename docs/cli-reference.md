# CLI Reference

## Overview

The `vma` command-line tool provides administrative functions for managing the VMA database and performing maintenance operations.

## Installation

```bash
# Install from source
git clone https://github.com/your-org/vma.git
cd vma
poetry install

# Or use via Docker
docker pull vma:latest
```

## Global Options

```bash
vma [mode] [options]
```

All commands require database connectivity. Configure via environment variables:

```bash
DB_HOST=localhost
DB_USER=vma
DB_PASS=secure_password
DB_NAME=vma
```

## Modes

### CVE Mode

Manage the NVD CVE database.

#### Initialize Database

```bash
vma cve --init
```

Downloads all historical CVE data from NVD (2002-present) and populates the local database.

**What it does**:
1. Fetches CVEs year by year from NVD API
2. Inserts vulnerability records
3. Inserts CVSS metrics from multiple sources
4. Tracks sync state in `nvd_sync` table

**Options**:
- None

**Requirements**:
- `NVD_API_KEY` environment variable (recommended for rate limits)
- Internet connectivity
- Empty or non-existent `vulnerabilities` table

**Duration**: 30-60 minutes depending on network speed and rate limits

**Example**:
```bash
# With API key
export NVD_API_KEY="your-api-key-here"
vma cve --init

# Without API key (slower due to rate limits)
vma cve --init
```

**Output**:
```
2024-01-15 10:30:00 | INFO | Initializing NVD database...
2024-01-15 10:30:05 | INFO | Fetching CVEs for year 2002...
2024-01-15 10:30:15 | INFO | Inserted 1,234 CVEs from 2002
2024-01-15 10:30:15 | INFO | Fetching CVEs for year 2003...
...
2024-01-15 11:15:30 | INFO | Initialization complete. Total CVEs: 234,567
```

#### Update Database

```bash
vma cve --update
```

Fetches recently modified CVEs from NVD and updates the local database.

**What it does**:
1. Queries `nvd_sync` table for last update timestamp
2. Fetches CVEs modified since that timestamp
3. Upserts vulnerability records (INSERT or UPDATE)
4. Updates `nvd_sync` table

**Options**:
- None

**Requirements**:
- Database must be initialized (`vma cve --init` run previously)
- `NVD_API_KEY` environment variable (recommended)
- Internet connectivity

**Recommended schedule**: Daily cron job

**Example**:
```bash
# Run manually
vma cve --update

# Cron job (runs at 2 AM daily)
0 2 * * * docker run --rm --env-file /path/to/.env vma cve --update

# Kubernetes CronJob
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vma-cve-update
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: vma
            image: vma:latest
            args: ["cve", "--update"]
            envFrom:
            - secretRef:
                name: vma-secrets
          restartPolicy: OnFailure
```

**Output**:
```
2024-01-16 02:00:00 | INFO | Checking for CVE updates...
2024-01-16 02:00:01 | INFO | Last update: 2024-01-15 02:00:00
2024-01-16 02:00:05 | INFO | Fetched 47 modified CVEs
2024-01-16 02:00:10 | INFO | Updated 45 existing CVEs
2024-01-16 02:00:10 | INFO | Inserted 2 new CVEs
2024-01-16 02:00:10 | INFO | Update complete
```

### Create Mode

Create new products or images in the database.

#### Create Product

```bash
vma create --choice product --name NAME --description DESCRIPTION
```

Creates a new product record.

**Options**:
- `--choice product`: Specify product creation
- `--name NAME`: Product identifier (unique)
- `--description DESCRIPTION`: Human-readable description

**Example**:
```bash
vma create \
  --choice product \
  --name "web-application" \
  --description "Main web application stack"
```

**Output**:
```
{'status': True, 'result': 'Product created successfully'}
```

**Notes**:
- Product name must be unique
- No team assignment in CLI (use API for team-scoped products)
- Name should be URL-safe (no spaces, special characters)

#### Create Image (Without Scan)

```bash
vma create --choice image --name NAME --version VERSION --product PRODUCT
```

Creates a new image record without importing vulnerabilities.

**Options**:
- `--choice image`: Specify image creation
- `--name NAME`: Image name (e.g., "nginx")
- `--version VERSION`: Image version/tag (e.g., "1.21.0")
- `--product PRODUCT`: Product ID to associate with

**Example**:
```bash
vma create \
  --choice image \
  --name "nginx" \
  --version "1.21.0" \
  --product "web-application"
```

**Output**:
```
{'status': True, 'result': 'Image created successfully'}
```

#### Create Image (With Scan)

```bash
vma create --choice image --name NAME --version VERSION --product PRODUCT --file SCAN_FILE
```

Creates an image and imports vulnerabilities from a Grype scan file.

**Options**:
- `--choice image`: Specify image creation
- `--name NAME`: Image name (optional if in scan file)
- `--version VERSION`: Image version (optional if in scan file)
- `--product PRODUCT`: Product ID to associate with
- `--file SCAN_FILE`: Path to Grype JSON output

**Example**:
```bash
# Scan container with Grype
grype nginx:1.21.0 -o json > nginx-scan.json

# Create image with scan results
vma create \
  --choice image \
  --product "web-application" \
  --file nginx-scan.json
```

**Output**:
```
{'status': True, 'result': 'Image created successfully'}
{'status': True, 'result': 'Imported 15 vulnerabilities'}
```

**Notes**:
- Image metadata extracted from scan file if not provided
- Vulnerabilities automatically imported
- Product must exist before creating image

### Select Mode

Query products or images from the database.

#### Select Product

```bash
vma select --choice product --name NAME
```

Retrieves product information.

**Options**:
- `--choice product`: Specify product query
- `--name NAME`: Product name to retrieve

**Example**:
```bash
vma select --choice product --name "web-application"
```

**Output**:
```json
{
  "status": true,
  "result": {
    "id": "web-application",
    "description": "Main web application stack",
    "team": "engineering",
    "image_count": 12,
    "vulnerability_count": 247
  }
}
```

#### Select Images (All for Product)

```bash
vma select --choice image --name NAME --product PRODUCT
```

Retrieves all versions of an image in a product.

**Options**:
- `--choice image`: Specify image query
- `--name NAME`: Image name
- `--product PRODUCT`: Product ID

**Example**:
```bash
vma select --choice image --name "nginx" --product "web-application"
```

**Output**:
```json
{
  "status": true,
  "result": [
    {
      "name": "nginx",
      "version": "1.21.0",
      "product": "web-application",
      "vulnerability_count": 15,
      "last_scanned": "2024-01-15T10:30:00Z"
    },
    {
      "name": "nginx",
      "version": "1.21.1",
      "product": "web-application",
      "vulnerability_count": 8,
      "last_scanned": "2024-01-16T08:15:00Z"
    }
  ]
}
```

#### Select Image (Specific Version)

```bash
vma select --choice image --name NAME --version VERSION --product PRODUCT
```

Retrieves a specific image version.

**Options**:
- `--choice image`: Specify image query
- `--name NAME`: Image name
- `--version VERSION`: Image version
- `--product PRODUCT`: Product ID

**Example**:
```bash
vma select \
  --choice image \
  --name "nginx" \
  --version "1.21.0" \
  --product "web-application"
```

**Output**:
```json
{
  "status": true,
  "result": {
    "name": "nginx",
    "version": "1.21.0",
    "product": "web-application",
    "vulnerability_count": 15,
    "critical_count": 2,
    "high_count": 5,
    "medium_count": 6,
    "low_count": 2,
    "last_scanned": "2024-01-15T10:30:00Z"
  }
}
```

### Import Mode

Import vulnerability scan results via the VMA API.

```bash
vma import --type SCANNER --file SCAN_FILE --product PRODUCT \
  --host HOST --port PORT [--secure] [--token TOKEN] [--version API_VERSION]
```

Sends scan results to VMA API for processing.

**Options**:
- `--type SCANNER`: Scanner type (`grype` currently supported)
- `--file SCAN_FILE`: Path to scan output file (JSON)
- `--product PRODUCT`: Target product ID
- `--host HOST`: VMA API hostname (default: `0.0.0.0`)
- `--port PORT`: VMA API port (default: `5000`)
- `--secure`: Use HTTPS instead of HTTP (flag)
- `--token TOKEN`: JWT access token for authentication
- `--version API_VERSION`: API version to use (e.g., `v1`)

**Example (Local)**:
```bash
# Scan container
grype myapp:v1.0.0 -o json > scan.json

# Import without authentication (dev mode)
vma import \
  --type grype \
  --file scan.json \
  --product "my-product" \
  --host localhost \
  --port 8000
```

**Example (Production)**:
```bash
# Get access token first
TOKEN=$(curl -X POST https://vma.company.com/api/v1/token \
  -d "username=scanner@company.com" \
  -d "password=secure_password" \
  | jq -r '.access_token')

# Import with authentication
vma import \
  --type grype \
  --file scan.json \
  --product "production-app" \
  --host vma.company.com \
  --port 443 \
  --secure \
  --token "$TOKEN" \
  --version v1
```

**Example (Docker)**:
```bash
docker run --rm \
  -v $(pwd)/scan.json:/scan.json \
  -e DB_HOST=postgres \
  -e DB_USER=vma \
  -e DB_PASS=password \
  -e DB_NAME=vma \
  vma:latest import \
    --type grype \
    --file /scan.json \
    --product "my-product" \
    --host vma.local \
    --port 8000
```

**Output**:
```
2024-01-15 10:45:00 | INFO | Parsing scan file: scan.json
2024-01-15 10:45:01 | INFO | Extracted image: myapp:v1.0.0
2024-01-15 10:45:01 | INFO | Found 23 vulnerabilities
2024-01-15 10:45:02 | INFO | Sending to API: https://vma.company.com:443/api/v1/import
2024-01-15 10:45:03 | INFO | Import successful
```

**Notes**:
- Requires API to be running
- Token required for authenticated endpoints
- Image will be created if it doesn't exist
- Existing vulnerabilities will be updated (last_seen timestamp)

### Delete Mode

**(Not yet implemented)**

```bash
vma delete --choice [product|image] [options]
```

Future functionality for deleting resources.

## Environment Variables

Configure VMA CLI via environment variables or `.env` file:

```bash
# Database
DB_HOST=localhost          # PostgreSQL host
DB_USER=vma               # Database user
DB_PASS=secure_password   # Database password
DB_NAME=vma               # Database name

# NVD API
NVD_API_KEY=your-api-key  # NVD API key (optional but recommended)

# JWT (for import mode)
SECRET_KEY_ACCESS=secret  # Access token secret
SECRET_KEY_REFRESH=secret # Refresh token secret
TOKEN_ALG=HS256           # JWT algorithm
```

## Exit Codes

- `0`: Success
- `1`: General error
- `2`: Database connection error
- `3`: API error
- `4`: File not found
- `5`: Invalid arguments

## Common Workflows

### Initial Setup

```bash
# 1. Initialize CVE database
vma cve --init

# 2. Create products
vma create --choice product --name "prod1" --description "Product 1"
vma create --choice product --name "prod2" --description "Product 2"

# 3. Scan and import images
grype nginx:latest -o json > nginx.json
vma create --choice image --product "prod1" --file nginx.json
```

### Daily Maintenance

```bash
#!/bin/bash
# daily-maintenance.sh

# Update CVE database
vma cve --update

# Re-scan critical images
for image in nginx:latest postgres:13 redis:6; do
  grype $image -o json > $(echo $image | tr ':' '-').json
  vma import \
    --type grype \
    --file $(echo $image | tr ':' '-').json \
    --product "production" \
    --host vma.local \
    --port 8000
done
```

### Bulk Import

```bash
#!/bin/bash
# bulk-import.sh

# Scan all images in a namespace
kubectl get pods -n production -o json \
  | jq -r '.items[].spec.containers[].image' \
  | sort -u \
  | while read image; do
      echo "Scanning $image..."
      grype $image -o json > scan.json
      vma import \
        --type grype \
        --file scan.json \
        --product "production" \
        --host vma.local \
        --port 8000 \
        --secure \
        --token "$VMA_TOKEN"
    done
```

## Troubleshooting

### Database Connection Issues

```bash
# Test connectivity
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1"

# Check environment variables
env | grep DB_

# Verify .env file
cat .env
```

### NVD API Rate Limiting

```bash
# Error: "429 Too Many Requests"

# Solution 1: Get API key from https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"

# Solution 2: Wait 30 seconds between requests
# (built into VMA automatically)
```

### Import Failures

```bash
# Validate JSON format
jq . scan.json

# Check API connectivity
curl http://localhost:8000/api/v1/health

# Verify product exists
vma select --choice product --name "my-product"

# Enable debug logging
export LOG_LEVEL=DEBUG
vma import ...
```

## Docker Usage

### Run CLI Commands in Container

```bash
# One-off command
docker run --rm \
  --env-file .env \
  vma:latest cve --update

# Interactive shell
docker run --rm -it \
  --env-file .env \
  vma:latest /bin/bash
```

### Docker Compose Service

```yaml
# docker-compose.yml
services:
  vma-cli:
    image: vma:latest
    env_file: .env
    depends_on:
      - postgres
    command: cve --update
```

## API Integration

### Python

```python
import subprocess
import json

# Run VMA CLI
result = subprocess.run(
    ["vma", "select", "--choice", "product", "--name", "my-product"],
    capture_output=True,
    text=True
)

# Parse output
data = json.loads(result.stdout)
print(f"Product has {data['result']['image_count']} images")
```

### Shell Script

```bash
#!/bin/bash

# Get product info
PRODUCT_INFO=$(vma select --choice product --name "my-product")
IMAGE_COUNT=$(echo "$PRODUCT_INFO" | jq -r '.result.image_count')

echo "Product has $IMAGE_COUNT images"
```

## See Also

- [API Reference](api-reference.md) - REST API documentation
- [User Guide](user-guide.md) - Web interface guide
- [Deployment Guide](deployment.md) - Production deployment
