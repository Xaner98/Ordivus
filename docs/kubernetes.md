# Kubernetes

Ordivus läuft in Kubernetes als **Job**. Das Helm Chart `charts/ordivus` legt dafür drei **suspendierte CronJobs** als Vorlagen an – `<release>-plan`, `<release>-drift`, `<release>-apply`. Ein suspendierter CronJob läuft nie von selbst; jeder Lauf wird aus der Vorlage gestartet (`kubectl create job --from=cronjob/...`). Für einzelne Läufe ist also **kein `helm upgrade` nötig**.

## Image

```sh
docker build -t ordivus:dev .
docker run --rm --read-only ordivus:dev --version
```

Das Image enthält die Engine und die Treiber für PostgreSQL, MySQL und Redis (ClickHouse, ArcadeDB und OpenBao brauchen keine Extras). Es läuft als UID/GID `10001`, schreibt nichts ins Root-Dateisystem (`readOnlyRootFilesystem`) und enthält weder Konfiguration noch Credentials. Für reproduzierbare Builds das Basis-Image per Digest pinnen: `--build-arg PYTHON_IMAGE=python:3.14-slim@sha256:…`. OCI-Labels setzen `--build-arg VERSION=…` und `--build-arg REVISION=$(git rev-parse HEAD)`.

## Installation

```sh
kubectl create namespace platform-config
kubectl -n platform-config create configmap ordivus-configuration --from-file=./config/
helm install ordivus charts/ordivus -n platform-config \
  --set image.repository=registry.example.com/ordivus \
  --set image.digest=sha256:…
```

Die ConfigMap darf auch vom Chart erzeugt werden (`configuration.source: inline`, Dateien unter `configuration.files`). Für GitOps ist eine eigene ConfigMap meist besser, weil sie unabhängig vom Chart aktualisiert werden kann.

**Grenze:** Eine ConfigMap fasst höchstens **1 MiB**. Größere Konfigurationen auf mehrere ConfigMaps verteilen (über `extraVolumes`/`extraVolumeMounts` unter `/config/<unterverzeichnis>` einhängen) oder als Volume aus einer anderen Quelle bereitstellen.

## Values im Überblick

| Value | Standard | Bedeutung |
|---|---|---|
| `image.repository` / `tag` / `digest` | `ghcr.io/EXAMPLE/ordivus`, appVersion, leer | `digest` hat Vorrang vor `tag` |
| `configuration.source` | `configMap` | `configMap` (vorhandene, `configuration.name`) oder `inline` (`configuration.files`) |
| `policy.configMap` / `policy.secret` / `policy.key` | leer / leer / `policy.yaml` | Operator Policy, getrennt von der Konfiguration unter `/policy`; `--policy` wird nur übergeben, wenn gesetzt |
| `credentials.mountPath` | `/var/run/secrets/ordivus` | Verzeichnis für `CredentialProvider` `type: file` |
| `credentials.readOnly` / `credentials.apply` | `{}` | Volume-Quelle je Modus, z. B. `{secret: {secretName: …}}`; plan/drift sehen nur `readOnly` |
| `jobs.templates.<mode>.enabled` / `suspended` | `true` / `true` | Vorlagen für `plan`, `drift`, `apply` |
| `jobs.templates.<mode>.automountServiceAccountToken` | `false` | Kubernetes-Token je Modus |
| `jobs.templates.<mode>.projectedToken` | aus | projiziertes, audience-gebundenes Token (z. B. OpenBao Kubernetes Auth), unter `mountPath/token` |
| `jobs.templates.<mode>.extraArgs` | `[]` | zusätzliche CLI-Argumente, z. B. `["--fail-on", "actionable"]` |
| `jobs.scheduledDrift` | aus, `0 2 * * *` | zusätzlicher, **nicht** suspendierter Drift-CronJob `<release>-drift-scheduled` |
| `security.profile` | `standard` | `hardened` verlangt `image.digest`, eine Policy und `networkPolicy.enabled` |
| `security.readOnlyServiceAccount` / `applyServiceAccount` | `ordivus-readonly` / `ordivus-apply` | getrennte Identitäten; `createServiceAccounts: false` für vorhandene |
| `security.networkPolicy` | aus | erlaubt nur DNS (kube-system:53) und `egress[].cidr`/`ports` (TCP) |
| `execution.timeoutSeconds` / `backoffLimit` / `ttlSecondsAfterFinished` | `1800` / `0` / `86400` | `activeDeadlineSeconds`, keine Wiederholung, Aufräumen nach einem Tag |
| `resources`, `env`, `extraVolumes`, `extraVolumeMounts`, `nodeSelector`, `tolerations`, `affinity`, `imagePullSecrets` | | wie üblich |

Jeder Pod läuft mit `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, Seccomp `RuntimeDefault` und `restartPolicy: Never`; die CronJobs haben `concurrencyPolicy: Forbid`. Ein `emptyDir` unter `/tmp` steht für temporäre Dateien bereit. Der Container wird mit `<mode> -f /config --format json` aufgerufen: Logs und Report landen als JSON-Zeilen im Pod-Log, der Report ist die Zeile mit `"type":"report"`.

Der `file`-Provider kann in einem Secret-Volume keine neuen Secrets anlegen (Secret-Volumes sind immer read-only). Wenn `apply` Passwörter erzeugen soll, für das Apply-Credential einen OpenBao-Provider verwenden.

## Läufe starten

Direkt mit kubectl:

```sh
kubectl -n platform-config create job --from=cronjob/ordivus-plan ordivus-plan-$(date +%s)
```

Für Pipelines gibt es `scripts/run-job.sh`. Es erzeugt genau einen Job, wartet auf das Ende, legt die Logs unter `reports/<mode>.log` und den Report unter `reports/<mode>.json` ab und endet mit dem **Exit-Code des Ordivus-Containers** (0, 10, 11 … wie in [konfiguration.md](konfiguration.md#exit-codes)).

```sh
scripts/run-job.sh plan platform-config            # Release "ordivus"
scripts/run-job.sh apply platform-config my-release
```

| Variable | Standard | Bedeutung |
|---|---|---|
| `ORDIVUS_RUN_ID` | `CI_JOB_ID`, sonst `BUILD_TAG`, sonst UTC-Zeitstempel | Teil des Job-Namens `<release>-<mode>-<id>`; wird DNS-1123-konform gemacht und auf 63 Zeichen gekürzt |
| `ORDIVUS_TIMEOUT` | `2100` | Sekunden, die das Skript wartet; danach Exit 1, der Job läuft weiter bis `activeDeadlineSeconds` |
| `ORDIVUS_REPORT_DIR` | `reports` | Ablage für Report und Logs |
| `KUBECTL` | `kubectl` | Pfad zu kubectl |

Endet der Job ohne Exit-Code des Containers (z. B. `activeDeadlineSeconds` überschritten, Image nicht ladbar), endet das Skript mit 1. Bei Abbruch (SIGINT/SIGTERM) sammelt es die bisherigen Logs ein und löscht den Job; Ordivus erhält dann SIGTERM.

Die CI-Identität braucht im Namespace: `create` auf `jobs`, `get` auf `cronjobs` und `jobs`, `list` auf `pods`, `get` auf `pods/log`, `delete` auf `jobs`.

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
    - scripts/run-job.sh apply platform-config
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

Exit-Code 10 (Drift über der Schwelle aus `--fail-on`) lässt den Stage fehlschlagen. Wer ihn nur als Warnung will: `sh(script: '...', returnStatus: true)` auswerten.

## Konfigurationsversionen

Die Vorlagen mounten die ConfigMap, die beim Start des Jobs vorliegt. Die Pipeline muss also erst die ConfigMap aktualisieren (oder GitOps synchronisieren lassen) und danach den Lauf starten. Welche Konfiguration ein Lauf verwendet hat, steht als `configDigest` im Report.

## Argo CD und Flux

- Argo CD bzw. Flux (HelmRelease) verwalten Chart, ConfigMap und CronJob-Vorlagen. Ein **Sync startet keinen Lauf**: suspendierte CronJobs werden durch ein Reconcile weder ausgelöst noch nachgeholt. Läufe startet ein externer Trigger (Pipeline mit `run-job.sh`) oder `jobs.scheduledDrift`.
- `suspend` nicht über GitOps-Overrides auf `false` setzen: Je nach Kubernetes-Version und `startingDeadlineSeconds` können verpasste Termine sofort nachgeholt werden.
- Argo-CD-`PreSync`/`Sync`-Hooks mit eigenem Job-Manifest sind möglich, gehören aber nicht zum Chart.
- **Flux `driftDetection`** vergleicht die Kubernetes-Objekte der HelmRelease mit dem Cluster. Das ist **nicht** `ordivus drift`, das PostgreSQL, OpenBao usw. prüft.

## Sicherheit

- **Wer Jobs anlegen darf, gehört zur Trust Boundary.** Kubernetes-RBAC kann `create jobs` nicht auf „nur aus dieser Vorlage“ beschränken; `resourceNames` wirkt bei `create` nicht. Wer Jobs (oder Pods, Deployments, CronJobs …) im Namespace anlegen darf, kann einen eigenen Pod mit dem Apply-ServiceAccount und dessen Credentials starten.
- Deshalb: Job-Create-Rechte nur an vertrauenswürdige CI-Identitäten; Workload-Erstellung über alle Pfade einschränken; per Admission-Policy (z. B. Kyverno, Gatekeeper, ValidatingAdmissionPolicy) verhindern, dass fremde Pods `ordivus-apply` oder die Apply-Credentials verwenden.
- `concurrencyPolicy: Forbid` gilt nur für Jobs, die der CronJob-Controller selbst startet, nicht für manuell erzeugte. Zwei gleichzeitige `apply`-Läufe verhindert das Chart nicht.
- plan/drift laufen mit `ordivus-readonly` und sehen nur `credentials.readOnly`; die Zielsystem-Rechte dieser Credentials sollten ebenfalls nur lesend sein.
- Kubernetes-Token werden standardmäßig nicht gemountet. Für OpenBao Kubernetes Auth `projectedToken` im betroffenen Modus aktivieren statt `automountServiceAccountToken: true`.
- `ttlSecondsAfterFinished` löscht Jobs samt Logs. Reports, die als Audit-Nachweis dienen, archiviert die Pipeline (`reports/`).

## Lokal testen (Docker Desktop)

Docker Desktop liefert lokal gebaute Images beim Pull an den Cluster aus; `imagePullPolicy: Never` funktioniert dort **nicht**, `IfNotPresent` oder `Always` schon.

```sh
tests/e2e/run.sh                  # nur helm lint/template
ORDIVUS_E2E=1 tests/e2e/run.sh    # zusätzlich Installation im Kontext docker-desktop, Namespace ordivus-e2e
```
