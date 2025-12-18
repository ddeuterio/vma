# VMA

Your Vulnerability Management Application (+ your CVE database).

## Installation

Clone

Create an .env file with the following parameters and store it inside the docker/ directory

```bash
DB_HOST=
DB_USER=
DB_PASS=
DB_NAME=
NVD_API_KEY=
POSTGRES_USER=
POSTGRES_PASSWORD=
POSTGRES_DB=
```

Create the docker images for the services described in the docker-compose file:

```bash
docker build -t vma:latest -f Dockerfile.vma .
docker build -t web:latest -f Dockerfile.web .
```

Add the following to your /etc/hosts:

```
vma.local 127.0.0.1
```

Modify the ./docker/docker-compose.yml file to your needs and run it

```bash
cd docker
docker-compose up -d
```

**NOTE:** this application is using self-signed certificates

Use your browser to get access VMA!

```
https://vma.local:8443
```

If you want to periodically update the database, I recommend creating a cron job to launch the vma image.

In the following example, the job will run at 2 am every day:

```bash
0 2 * * * docker run --rm --env-file <put here the path to your env file> vma cve --update
```

## License

This project is licensed under the **Apache License 2.0 with Commons Clause**.

This means:

* ✅ **Free to use** for personal, educational, and internal business purposes
* ✅ **Free to modify** and create derivative works
* ✅ **Free to distribute** with proper attribution
* ❌ **Cannot be sold** as a product or service (see Commons Clause restriction)

**Commercial Use Restriction:**

You cannot provide VMA to third parties as a commercial offering (SaaS, hosting, consulting)
where the value derives substantially from VMA's functionality.

For commercial licensing inquiries, please contact: daniel.garcia.anes@gmail.com

See the LICENSE.txt file for full terms and conditions.
