# In-cluster lab

`scripts/lab.sh` sets up a reproducible lab in the local Kubernetes cluster (Docker Desktop, context
`docker-desktop`) to test Ordivus against **OpenBao** and **PostgreSQL** the way it runs in production: as
Jobs from the Helm chart, with OpenBao Kubernetes auth and secrets in KV v2. It is meant for performance
measurements with larger inventories and for experiments such as concurrent `apply` runs.

## What it is not

- **Not a production setup.** OpenBao runs in **dev mode** (in-memory, unsealed, a root token used by
  `lab.sh` for bootstrapping); every restart of the OpenBao pod loses all data until the next `lab.sh up`.
  PostgreSQL has no volume and no TLS. Certificates are self-signed by `lab.sh`.
- Not an example configuration to copy: `lab/values.yaml` works around the chart having one configuration
  for all modes (see [Credentials and identities](#credentials-and-identities)).
- Not a test suite: `lab.sh` measures and reports, it does not assert.

## Prerequisites

Docker Desktop with Kubernetes enabled, `kubectl`, `helm`, `jq`, `openssl`, `perl` and the local image:

```sh
docker build -t ordivus:dev .
```

## Commands

```sh
scripts/lab.sh up                    # create/refresh everything (idempotent), initial config: 3 databases
scripts/lab.sh run plan              # one Job via scripts/run-job.sh: exit code, duration, report summary
scripts/lab.sh run apply
scripts/lab.sh run drift
scripts/lab.sh scale 50              # regenerate the config with 50 databases and update the ConfigMap
scripts/lab.sh reset                 # drop everything the config created (databases, roles, KV secrets, policies)
scripts/lab.sh race same 20          # two apply Jobs at the same moment, same config, 20 databases
scripts/lab.sh race diff 20          # second Job uses a different config version
scripts/lab.sh check-secrets         # does every KV password log in to PostgreSQL?
scripts/lab.sh down                  # delete the namespace and the cluster-scoped ClusterRoleBinding
```

| Variable | Default | Meaning |
|---|---|---|
| `LAB_CONTEXT` | `docker-desktop` | kubectl/helm context |
| `LAB_OUT` | `$TMPDIR/ordivus-lab` | Reports (`<mode>.json`), logs and generated config |
| `LAB_PG_ADMIN` | `createrole` | Only for `up`: the Ordivus login in PostgreSQL is a non-superuser with `CREATEROLE CREATEDB` (`createrole`) or a superuser (`superuser`) |

`run` prints the wall time of the whole Job (including pod start and the 3-second polling of `run-job.sh`),
the engine duration from the report (`startedAt`–`finishedAt`) and the number of PostgreSQL sessions opened
during the run (difference of `sum(pg_stat_database.sessions)`; approximate: statistics are flushed with a
short delay, and `reset` drops the statistics of the dropped databases).

`reset` followed by `scale N` and `run apply` measures the first-run cost; a second `run apply` measures the
steady state. `race` always starts with `reset`, starts both Jobs with one `kubectl create`, prints exit code,
container start/end and summary of both, then runs `check-secrets`.

## What gets deployed

Namespace `ordivus-lab`:

- **OpenBao** 2.7.3 (pinned by digest) in dev mode. Clients use a TLS listener (`openbao.ordivus-lab.svc:8200`,
  certificate from a CA in ConfigMap `openbao-ca`); the plain-HTTP dev listener only listens on localhost in
  the pod and is used by `lab.sh` with the root token via `kubectl exec`. Bootstrap on every `up`:
  - KV v2 at `secret/`, admin password of PostgreSQL at `secret/lab/admin/postgres` (rotated on every `up`),
    generated user passwords at `secret/lab/users/<db>-app`.
  - Kubernetes auth with roles `ordivus-readonly` and `ordivus-apply`, bound to the chart's ServiceAccounts,
    audience `openbao`, policies `lab-kv-readonly` (read `secret/lab/*`) and `lab-kv-apply` (read, plus create
    on `secret/data/lab/users/*`; no update, no delete).
  - Two tokens for the `openbao` policy adapter in the Secrets `lab-openbao-token-readonly` (policy
    `lab-policy-reader`: list/read ACL policies) and `lab-openbao-token-apply` (`lab-policy-admin`: additionally
    write `app-*` policies).
  - ClusterRoleBinding `ordivus-lab-openbao-auth-delegator` (TokenReview), the only cluster-scoped object.
- **PostgreSQL 17** (`postgres:17-alpine`), login `ordivus_admin` (`CREATEROLE CREATEDB`). `template1`
  contains a table `lab_items`, so every new database has a table and `tables-in-schema` grants are observable.
- **Ordivus chart** (release `ordivus`) with `lab/values.yaml`, operator policy `lab/policy.yaml` (profile
  `standard`, additive, no deletes, no privileged grants).

Configuration (`lab/config/`, ConfigMap `ordivus-lab-config`): targets `lab-postgres` (scope `lab_*`) and
`lab-openbao`, and per database `lab_dbNNN`: roles `lab_dbNNN_ro`/`_rw`, user `lab_dbNNN_app` (member of
`_rw`, generated password in KV), grants on database, schema `public` and tables-in-schema for both roles,
and an OpenBao ACL policy `app-lab-dbNNN-read`. `race diff` uses a variant: the user is a member of `_ro`
instead, plus a role `lab_dbNNN_audit`.

### Credentials and identities

plan/drift run as `ordivus-readonly`, apply as `ordivus-apply`, each with its own projected token, OpenBao
role and policy token. The KV provider needs the OpenBao role in the configuration (`auth.role`), so the
configuration differs per mode. `lab/values.yaml` therefore adds `ordivus-lab-auth-readonly` or
`ordivus-lab-auth-apply` to `/config` per mode via `jobs.templates.<mode>.extraConfigSources`.

## Image

On Docker Desktop's kind-based Kubernetes the node has its own containerd image store; `up` loads the local
`ordivus:dev` into it. After rebuilding the image, run `up` again, otherwise the jobs keep the old image.

## Troubleshooting

- `URLError` on OpenBao in the report: TLS or network; test from a pod with the CA from ConfigMap `openbao-ca`.
- After an OpenBao pod restart everything in OpenBao is gone: run `scripts/lab.sh up`. Existing users then
  get new passwords on the next `apply` (KV secret missing → generated, `SET_PASSWORD`).
- Job logs: `$LAB_OUT/<mode>.log`; Jobs are kept for a day (`ttlSecondsAfterFinished`).
