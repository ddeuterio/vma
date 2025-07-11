#/bin/bash
docker-compose stop db
echo "y" | docker-compose rm db
docker volume rm db_pgdata