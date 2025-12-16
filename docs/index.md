# VMA Documentation

**Vulnerability Management Application** - A full-stack container vulnerability tracking system.

## Overview

VMA (Vulnerability Management Application) centralizes CVE data from the National Vulnerability Database (NVD) and tracks vulnerabilities across multiple container images and products. The system provides:

- **Automated CVE Synchronization** - Keeps vulnerability data up-to-date from NVD
- **Container Scanning Integration** - Imports results from Grype and other scanning tools
- **Team-Based Access Control** - Granular permissions with READ_ONLY, WRITE, and ADMIN scopes
- **RESTful API** - FastAPI-powered endpoints for automation and integration
- **Web Interface** - User-friendly dashboard for vulnerability management
- **CLI Tool** - Command-line interface for automation and DevOps workflows

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd vma

# Install dependencies with Poetry
poetry install

# Set up environment variables
cp docker/.env.template docker/.env
# Edit docker/.env with your configuration

# Run with Docker Compose
cd docker && docker-compose up -d

# Access the application
# Add to /etc/hosts: 127.0.0.1 vma.local
# Navigate to: https://vma.local:8443
```

### First Steps

1. **Initialize CVE Database**
   ```bash
   poetry run vma cve --init
   ```

2. **Create a Product**
   ```bash
   poetry run vma create --choice product \
     --name "my-app" \
     --description "My application"
   ```

3. **Import Vulnerability Scan**
   ```bash
   grype my-image:latest -o json > scan.json
   poetry run vma import --type grype \
     --file scan.json \
     --product "my-app" \
     --host localhost \
     --port 8000
   ```

## Architecture

VMA is built with:
- **Backend**: FastAPI with Gunicorn + Uvicorn workers
- **Frontend**: Jinja2 templates with vanilla JavaScript
- **Database**: PostgreSQL with psycopg2
- **Authentication**: JWT with Argon2 password hashing
- **External Integrations**: NVD API, Grype scanner

See [Architecture Documentation](architecture.md) for detailed system design.

## Documentation Contents

```{toctree}
:maxdepth: 2

User Guide <user-guide>
Architecture <architecture>
API Reference <api-reference>
CLI Reference <cli-reference>
Contributing <contributing>
License <license>
Authors <authors>
Changelog <changelog>
```

## Key Features

### Vulnerability Tracking
- Centralized CVE database with full NVD history
- Multiple CVSS score sources (NVD, vendor-specific)
- Track vulnerabilities across products and images
- `last_seen` timestamps for vulnerability lifecycle management

### Access Control
- **Teams** - Organizational units that own products
- **Users** - Email-based authentication with Argon2 hashed passwords
- **Scopes** - Granular permissions (READ_ONLY, WRITE, ADMIN) per team
- **Root Users** - Bypass all authorization checks

### Integration
- **CLI Tool** - Automate database operations and imports
- **RESTful API** - Integrate with CI/CD pipelines
- **Scanner Support** - Currently supports Grype (more coming)
- **NVD Sync** - Automated CVE updates via NVD API

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Comprehensive guides in `docs/` directory
- **API Reference**: Interactive API documentation at `/docs` endpoint

## Indices and Tables

* {ref}`genindex`
* {ref}`modindex`
* {ref}`search`
