# Kubernetes

Ordivus runs in Kubernetes as a **Job**. For this, the Helm chart `charts/ordivus` creates three **suspended CronJobs** as templates – `<release>-plan`, `<release>-drift`, `<release>-apply`. A suspended CronJob never runs on its own; every run is started from the template (`kubectl create job --from=cronjob/...`). Individual runs therefore **do not need a `helm upgrade`**.

## Image

```sh
docker build -t ordivus:dev .
docker run --rm --read-only ordivus:dev --version
```

The image contains the engine and the drivers for PostgreSQL, MySQL and Redis (ClickHouse, ArcadeDB and OpenBao need no extras). It runs as UID/GID `10001`, writes nothing to the root file system (`readOnlyRootFilesystem`) and contains neither configuration nor credentials, nor pip/setuptools. The base image is pinned by digest in the `Dockerfile`, Python dependencies come hash-verified from `requirements.lock`, and Debian security updates are applied during the build (maintenance: [development.md](development.md#dependencies-and-lock-file)). OCI labels are set via `--build-arg VERSION=…` and `--build-arg REVISION=$(git rev-parse HEAD)`.

## Installation

```sh
kubectl create namespace platform-config
kubectl -n platform-config create configmap ordivus-configuration --from-file=./config/
helm install ordivus charts/ordivus -n platform-config \
  --set image.repository=registry.example.com/ordivus \
  --set image.digest=sha256:…
```

The ConfigMap may also be created by the chart (`configuration.source: inline`, files under `configuration.files`). For GitOps, a separate ConfigMap is usually better because it can be updated independently of the chart.

The ConfigMap is mounted directly under `/config` (without `subPath`). The hidden directories Kubernetes uses to swap the files atomically (`..data`, `..<timestamp>`) are skipped by the config loader, like all paths with a leading dot.

**Limit:** a ConfigMap holds at most **1 MiB**. Split larger configurations across multiple ConfigMaps (mount them via `jobs.templates.<mode>.extraVolumes`/`extraVolumeMounts` under `/config/<subdirectory>`, per mode) or provide them as a volume from another source.

## Values overview

| Value | Default | Meaning |
|---|---|---|
| `image.repository` / `tag` / `digest` / `pullPolicy` | `ghcr.io/EXAMPLE/ordivus`, appVersion, empty, `IfNotPresent` | `digest` (`sha256:<64 hex>`) takes precedence over `tag`. For production, pin by digest: a tag can be reassigned, a digest cannot; `IfNotPresent` is then harmless |
| `configuration.source` | `configMap` | `configMap` (existing, `configuration.name`) or `inline` (`configuration.files`) |
| `policy.configMap` / `policy.secret` / `policy.key` | empty / empty / `policy.yaml` | Operator policy, separate from the configuration under `/policy`; `--policy` is passed only if set |
| `credentials.mountPath` | `/var/run/secrets/ordivus` | Directory for `CredentialProvider` `type: file`, always read-only |
| `credentials.readOnly` / `credentials.apply` | `{}` | Volume source per mode, e.g. `{secret: {secretName: …}}`; plan/drift see only `readOnly` |
| `jobs.templates.<mode>.enabled` / `suspended` | `true` / `true` | Templates for `plan`, `drift`, `apply` |
| `jobs.templates.apply.allowSchedule` | `false` | `apply.suspended: false` is accepted only with this (never in the `hardened` profile) |
| `jobs.templates.apply.namespace` | release namespace | Separate namespace for the apply CronJob, apply ServiceAccount and apply credentials (see [Security](#security)) |
| `jobs.templates.<mode>.automountServiceAccountToken` | `false` | Kubernetes token per mode |
| `jobs.templates.<mode>.projectedToken` | off | Projected, audience-bound token (e.g. OpenBao Kubernetes auth), under `mountPath/token` |
| `jobs.templates.<mode>.extraArgs` | `[]` | Additional CLI arguments, e.g. `["--fail-on", "actionable"]` |
| `jobs.templates.<mode>.env` / `extraVolumes` / `extraVolumeMounts` | `[]` | **Per mode**; there are deliberately no global variants, so that apply secrets never end up in plan/drift |
| `jobs.scheduledDrift` | off, `0 2 * * *` | Additional, **non**-suspended drift CronJob `<release>-drift-scheduled` (own `env`/`extraVolumes`/`extraVolumeMounts`) |
| `security.profile` | `standard` | `development`, `standard` or `hardened` (checks see [Security](#security)) |
| `security.readOnlyServiceAccount` / `applyServiceAccount` | `ordivus-readonly` / `ordivus-apply` | Separate identities, must differ; `createServiceAccounts: false` for existing ones |
| `security.networkPolicy` | off | Egress only to DNS (`dns.namespace`/`dns.podSelector`, default `kube-system`/`k8s-app: kube-dns`, plus `dns.cidrs`, e.g. NodeLocal DNSCache `169.254.20.10/32`) and `egress[].cidr`/`ports` (TCP); the cloud metadata address `169.254.169.254/32` or `fd00:ec2::254/128` is excluded if it lies within the block (own list: `egress[].except`) |
| `admission.enabled` | `false` | ValidatingAdmissionPolicy for pods with the apply ServiceAccount (Kubernetes ≥ 1.30) |
| `execution.timeoutSeconds` / `backoffLimit` / `ttlSecondsAfterFinished` | `1800` / `0` / `86400` | `activeDeadlineSeconds`, no retry, cleanup after one day |
| `resources` | 100m/128Mi, limits 1 CPU/512Mi/256Mi ephemeral-storage | as usual |
| `nodeSelector`, `tolerations`, `affinity`, `imagePullSecrets` | | as usual |

Every pod runs with `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, seccomp `RuntimeDefault`, `enableServiceLinks: false` and `restartPolicy: Never`; the CronJobs have `concurrencyPolicy: Forbid`. An `emptyDir` under `/tmp` is available for temporary files. The container is invoked with `<mode> -f /config --format json`: logs and report end up as JSON lines in the pod log; the report is the line with `"type":"report"`.

The `file` provider cannot create new secrets in the read-only mounted credentials directory. If `apply` is supposed to generate passwords, use an OpenBao provider for the apply credential or explicitly mount a writable volume (e.g. `emptyDir` or PVC) via `jobs.templates.apply.extraVolumes`/`extraVolumeMounts` – an `emptyDir` loses new secrets together with the pod.

## Starting runs

Directly with kubectl:

```sh
kubectl -n platform-config create job --from=cronjob/ordivus-plan ordivus-plan-$(date +%s)
```

For pipelines there is `scripts/run-job.sh`. It creates exactly one job, waits for it to finish, stores the logs under `reports/<mode>.log` and the report under `reports/<mode>.json`, and exits with the **exit code of the Ordivus container** (0, 10, 11 … as in [configuration.md](configuration.md#exit-codes)).

```sh
scripts/run-job.sh plan platform-config                                    # release "ordivus"
ORDIVUS_KUBE_CONTEXT=prod scripts/run-job.sh apply platform-config-apply my-release  # apply namespace
```

| Variable | Default | Meaning |
|---|---|---|
| `ORDIVUS_KUBE_CONTEXT` | current context | kubectl context (`--context`); **required** for `apply` (otherwise exit 2), so that no apply runs against a context that just happens to be active. Context and namespace are always printed |
| `ORDIVUS_RUN_ID` | `CI_JOB_ID`, else `BUILD_TAG`, else UTC timestamp | Part of the job name `<release>-<mode>-<id>`; made DNS-1123-compliant and truncated to 63 characters |
| `ORDIVUS_TIMEOUT` | `2100` | Seconds the script waits; afterwards exit 1, the job keeps running until `activeDeadlineSeconds` |
| `ORDIVUS_REPORT_DIR` | `reports` | Location for report and logs |
| `KUBECTL` | `kubectl` | Path to kubectl |

Before starting, the script deletes `<mode>.json` and `<mode>.log` from a previous run. The report is stored only if the log contains **exactly one** report line: with `jq`, a line that is valid JSON with `"type":"report"` and `schemaVersion`; without `jq`, a line that starts exactly with `{"type":"report","schemaVersion":"…",` and ends with `}` (engine logs never have this form; an application log line of exactly this form would be counted); otherwise the script reports this and exits with 1, unless the container has already exited with an error exit code anyway (which is preserved). Logs, report and exit code come from the job's most recent pod; if Kubernetes reports the job as `Failed` but the container exited with 0, the script exits with 1.

If the job ends without a container exit code (e.g. `activeDeadlineSeconds` exceeded, image not pullable), the script exits with 1. On abort (SIGINT/SIGTERM), it collects the logs so far and deletes the job; Ordivus then receives SIGTERM.

The CI identity needs in the respective namespace: `create` on `jobs`, `get` on `cronjobs` and `jobs`, `list` on `pods`, `get` on `pods/log`, `delete` on `jobs`. With a separate apply namespace (`jobs.templates.apply.namespace`), create **two** identities for this, each with one RoleBinding: the plan/drift identity (e.g. for merge request pipelines) only in the release namespace, the apply identity (protected branches/manual approval only) only in the apply namespace. A role with these permissions in the apply namespace is equivalent to apply permissions on all target systems.

### GitLab CI

```yaml
ordivus-plan:
  stage: plan
  image: registry.example.com/tools/kubectl:1.36
  script:
    - scripts/run-job.sh plan platform-config
  artifacts:
    when: always
    paths: [reports/]

ordivus-apply:
  stage: apply
  image: registry.example.com/tools/kubectl:1.36
  script:
    - scripts/run-job.sh apply platform-config-apply
  variables:
    ORDIVUS_KUBE_CONTEXT: prod
  artifacts:
    when: always
    paths: [reports/]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: manual
```

### Jenkins

```groovy
stage('Ordivus drift') {
  steps {
    sh 'scripts/run-job.sh drift platform-config'
  }
  post {
    always { archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true }
  }
}
```

Exit code 10 (drift above the threshold from `--fail-on`) fails the stage. If you want it only as a warning: evaluate `sh(script: '...', returnStatus: true)`.

## Configuration versions

The templates mount the ConfigMap that exists when the job starts. The pipeline must therefore first update the ConfigMap (or let GitOps sync it) and only then start the run. Which configuration a run used is recorded as `configDigest` in the report.

## Argo CD and Flux

- Argo CD or Flux (HelmRelease) manage the chart, ConfigMap and CronJob templates. A **sync does not start a run**: suspended CronJobs are neither triggered nor caught up by a reconcile. Runs are started by an external trigger (pipeline with `run-job.sh`) or `jobs.scheduledDrift`.
- Do not set `suspend` to `false` via GitOps overrides: depending on the Kubernetes version and `startingDeadlineSeconds`, missed schedules may be caught up immediately.
- Argo CD `PreSync`/`Sync` hooks with their own job manifest are possible but are not part of the chart.
- **Flux `driftDetection`** compares the Kubernetes objects of the HelmRelease with the cluster. That is **not** `ordivus drift`, which checks PostgreSQL, OpenBao etc.

## Security

- **Whoever may create jobs is part of the trust boundary.** Kubernetes RBAC cannot restrict `create jobs` to "only from this template"; `resourceNames` has no effect on `create`. Whoever may create jobs (or pods, deployments, CronJobs …) in the namespace can start their own pod with the apply ServiceAccount and its credentials.
- Therefore: grant job create permissions only to trusted CI identities; restrict workload creation across all paths. The chart offers two building blocks; the `hardened` profile requires at least one:
  - **Separate apply namespace** (`jobs.templates.apply.namespace`): the apply CronJob and apply ServiceAccount live there; the apply credentials secret, the configuration ConfigMap (with `configuration.source: configMap`) and the policy must also exist there (with `source: inline`, the chart creates the ConfigMap in both namespaces, and likewise the NetworkPolicy). Whoever may create workloads only in the release namespace can no longer reach the apply identity and credentials. Grant RoleBindings separately per namespace (see [Starting runs](#starting-runs)). The chart is still installed into the release namespace; the Helm identity needs permissions in both namespaces.
  - **ValidatingAdmissionPolicy** (`admission.enabled`, Kubernetes ≥ 1.30, cluster-wide, the Helm identity needs permissions on `admissionregistration.k8s.io`): pods with the apply ServiceAccount in the apply namespace are admitted only if they carry the labels of the apply template, are controlled by a job `<release>-apply-*` and their pod spec matches the rendered apply template:
    - **Pod spec and container contain only fields the template sets**, plus the fields that the API server and standard admission plugins add before the check – with exactly their default values (`dnsPolicy: ClusterFirst`, `schedulerName: default-scheduler`, `serviceAccount` = apply ServiceAccount, `priority`/`preemptionPolicy`, the `NoExecute` tolerations for `not-ready`/`unreachable`, `terminationMessagePath`/`terminationMessagePolicy`). This rejects: `command`, `envFrom`, `workingDir`, `ports`, probes, `lifecycle` hooks, additional containers, init and ephemeral containers (`kubectl debug`), `hostAliases`, `dnsConfig`, `nodeName`, `runtimeClassName`, `priorityClassName`, `shareProcessNamespace`, `hostNetwork`/`hostPID`/`hostIPC` etc.
    - **Exactly equal** to the template: `securityContext` of pod and container; `nodeSelector` and `affinity` are absent or exactly equal; `tolerations` only those of the template or the standard tolerations named above.
    - **At least the values of the template** (additional subkeys remain allowed so that API defaults such as `defaultMode` fit): image, arguments, `env`, `volumeMounts`, `volumes` (number and source per volume fixed; e.g. `subPath` or `items` are possible), ServiceAccount, `automountServiceAccountToken`, `restartPolicy`, `enableServiceLinks`, `terminationGracePeriodSeconds`, `imagePullSecrets`.
  - **Limits of the admission policy:** CEL cannot look up whether the owning job really comes from the CronJob; a copy of the template with a forged `ownerReference` is admitted. It starts a real `apply` run with apply credentials – at any time, also in parallel with other runs and without a pipeline. Not checked are `resources` (requests/limits), annotations and additional labels, as well as the allowed subkeys above; Pod Security Admission `restricted` on the apply namespace remains recommended as a second line of defense. Mutating webhooks or plugins that set further pod fields (e.g. sidecar injection) lead to rejection of legitimate apply pods as well. `pods/exec` and `pods/attach` are not pod changes and remain a matter for RBAC. Whoever may change the CronJob, ConfigMap or policy in the apply namespace changes what apply does. The policy reflects the state of the last Helm installation; after changes to the template outside of Helm, it rejects apply pods.
- Checks at render time in **every** profile: the read-only and apply ServiceAccounts must have different names; `jobs.templates.apply.suspended: false` only with `allowSchedule: true`.
- Additionally in the **`hardened`** profile: `image.digest` in the format `sha256:<64 hex>`, a policy, `networkPolicy.enabled`, no `automountServiceAccountToken: true` in any mode, every egress rule with `ports` and without `0.0.0.0/0`/`::/0`, apply template suspended, separate apply namespace or `admission.enabled`.
- `concurrencyPolicy: Forbid` applies only to jobs the CronJob controller starts itself, not to manually created ones. The chart does not prevent two concurrent `apply` runs.
- plan/drift run with `ordivus-readonly` and see only `credentials.readOnly`; the target system permissions of these credentials should also be read-only.
- Kubernetes tokens are not mounted by default. For OpenBao Kubernetes auth, enable `projectedToken` in the affected mode instead of `automountServiceAccountToken: true`.
- `ttlSecondsAfterFinished` deletes jobs including their logs. Reports that serve as audit evidence are archived by the pipeline (`reports/`).

## Testing locally (Docker Desktop)

Docker Desktop serves locally built images to the cluster on pull; `imagePullPolicy: Never` does **not** work there, `IfNotPresent` or `Always` does.

```sh
tests/e2e/run.sh                  # helm lint/template only
ORDIVUS_E2E=1 tests/e2e/run.sh    # additionally install in context docker-desktop, namespaces ordivus-e2e and ordivus-e2e-apply
```
