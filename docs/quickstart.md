# Quickstart

In this quickstart you start PostgreSQL in Docker and let Ordivus create an application user with an automatically generated password in it. Afterwards you see how Ordivus detects deviations and foreign objects.

You need Docker and either Python 3.13+ or the Ordivus container image (see [README](../README.md#installation)).

## 1. Start PostgreSQL

```sh
docker network create ordivus-demo
docker run -d --name demo-postgres --network ordivus-demo -p 5432:5432 \
  -e POSTGRES_PASSWORD=admin-demo-pw postgres:17-alpine
```

## 2. Create a working directory

```sh
mkdir -p ordivus-demo/config ordivus-demo/secrets && cd ordivus-demo
printf 'admin-demo-pw' > secrets/admin
chmod 700 secrets && chmod 600 secrets/admin
```

`secrets/` plays the role of your secret store here. In a cluster this would be a mounted Kubernetes Secret, in production preferably OpenBao.

## 3. Write the configuration

`config/ordivus.yaml`:

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: demo-postgres
spec:
  adapter: postgresql
  endpoint:
    host: localhost          # in the container image: demo-postgres
    port: 5432
    user: postgres
  authentication:
    credentialRef: admin
---
apiVersion: ordivus.dev/v1alpha1
kind: CredentialProvider
metadata:
  name: secrets
spec:
  type: file
  directory: ./secrets       # in the container image: /work/secrets
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata:
  name: admin
spec:
  providerRef: secrets
  path: admin
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata:
  name: app-password
spec:
  providerRef: secrets
  path: app
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseRole
metadata:
  name: app_readonly
spec:
  targetRef: demo-postgres
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: app
spec:
  targetRef: demo-postgres
  memberOf: [app_readonly]
  connectionLimit: 10
  credentials:
    credentialRef: app-password
```

Validate without opening a connection:

```sh
ordivus config validate -f config
```

## 4. Plan and apply

```sh
ordivus plan -f config
```

The plan shows three actions: create the password secret `app`, the role `app_readonly` and the user `app`. Nothing has been changed yet – `secrets/app` does not exist yet either.

Ordivus also warns that the connection is not secured with TLS. For this local demo that is fine; in production you configure `endpoint.tls` (see [PostgreSQL adapter](adapters/postgresql.md)).

```sh
ordivus apply -f config
ls secrets/            # admin  app
ordivus apply -f config   # second run: nothing left to do
```

The new user can log in with the generated password:

```sh
docker exec -e PGPASSWORD="$(cat secrets/app)" demo-postgres \
  psql -h 127.0.0.1 -U app -d postgres -c 'select current_user'
```

## 5. Detect drift

Change something by hand and create a foreign user:

```sh
docker exec demo-postgres psql -U postgres -c "ALTER ROLE app CONNECTION LIMIT 99"
docker exec demo-postgres psql -U postgres -c "CREATE ROLE handmade LOGIN"
ordivus drift -f config
```

`drift` reports the changed connection limit as a fixable deviation and `handmade` as `UNMANAGED`. An `apply` resets the limit to 10 but leaves `handmade` alone – Ordivus deletes undeclared objects only within an explicitly approved `authoritative` scope.

For CI pipelines there are thresholds: `ordivus drift -f config --fail-on actionable` exits with exit code 10 as soon as fixable deviations exist.

## With the container image

Instead of installing `ordivus` locally, you can run every command in the image. To do so, set `host: demo-postgres` and `directory: /work/secrets` in the configuration:

```sh
docker run --rm --network ordivus-demo -v "$PWD":/work -w /work ordivus plan -f config
```

The image runs as a user with UID 10001; for `apply` to be able to create the secret file, `secrets/` must be writable for this UID (e.g. `docker run --user "$(id -u)" …`).

## Clean up

```sh
docker rm -f demo-postgres && docker network rm ordivus-demo
```

## Next steps

- [Concepts](concepts.md) – what additive and authoritative mean, how passwords are verified
- [Configuration](configuration.md) – all common fields, operator policy, exit codes
- [Kubernetes and CI/CD](kubernetes.md)
