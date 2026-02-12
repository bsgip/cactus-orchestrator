# Database Migrations

If you've updated any of the models, then a database migration will need to be created.

1. Create a docker compose file (docker-compose.yaml) that will bring up a temporary database:

```docker
services:
  db:
    image: postgres
    restart: always
    ports:
      - 5433:5432
    environment:
      POSTGRES_DB: orchestratordb
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
```

2. Start the docker container with,

```sh
docker compose up -d
```

3. Set up the minimum environment variables. Create a .env file in the project root:

```sh
ORCHESTRATOR_DATABASE_URL="postgresql+asyncpg://user:password@localhost:5433/orchestratordb"
CACTUS_PYTEST_WITHOUT_KUBERNETES="true"
TEST_EXECUTION_FQDN="foo"
JWTAUTH_JWKS_URL="a"
JWTAUTH_ISSUER="b"
JWTAUTH_AUDIENCE="c"
```

Most are these environment variables are set to dummy values. `CACTUS_PYTEST_WITHOUT_KUBERNETES` should be set to true. The credentials and port in the `ORCHESTRATOR_DATABASE_URL` environment variable should match the set in the docker compose file in step 1.

4. Apply the exisiting migrations to the database to get it into the "head" state.

If you have dotenv installed run:

```sh
dotenv run -- alembic upgrade head
```

otherwise run:

```sh
source .env && alembic upgrade head
```

5. Generate the new migration for the model changes. When generating a new migration you must supply a short description with the `-m` switch.

If you have dotenv installed run:

```sh
dotenv run -- alembic revision --autogenerate -m "INSERT YOUR MIGRATION DESCRIPTION HERE"
```

else run:

```sh
source .env && alembic revision --autogenerate -m "INSERT YOUR MIGRATION DESCRIPTION HERE"
```

If successful you should find a new .py file in `alembic/versions` directory of the project.

