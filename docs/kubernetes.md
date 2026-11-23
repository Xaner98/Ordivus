# Kubernetes

Ordivus läuft in Kubernetes als **Job**. Das Helm Chart `charts/ordivus` legt dafür drei **suspendierte CronJobs** als Vorlagen an – `<release>-plan`, `<release>-drift`, `<release>-apply`. Ein suspendierter CronJob läuft nie von selbst; jeder Lauf wird aus der Vorlage gestartet (`kubectl create job --from=cronjob/...`). Für einzelne Läufe ist also **kein `helm upgrade` nötig**.

## Image

```sh
docker build -t ordivus:dev .
docker run --rm --read-only ordivus:dev --version
```

Das Image enthält die Engine und die Treiber für PostgreSQL, MySQL und Redis (ClickHouse, ArcadeDB und OpenBao brauchen keine Extras). Es läuft als UID/GID `10001`, schreibt nichts ins Root-Dateisystem (`readOnlyRootFilesystem`) und enthält weder Konfiguration noch Credentials, auch kein pip/setuptools. Das Basis-Image ist im `Dockerfile` per Digest gepinnt, Python-Abhängigkeiten kommen hash-geprüft aus `requirements.lock`, Debian-Sicherheitsupdates werden beim Build eingespielt (Pflege: [entwicklung.md](entwicklung.md#abhängigkeiten-und-lock-datei)). OCI-Labels setzen `--build-arg VERSION=…` und `--build-arg REVISION=$(git rev-parse HEAD)`.

## Installation

```sh
kubectl create namespace platform-config
kubectl -n platform-config create configmap ordivus-configuration --from-file=./config/
helm install ordivus charts/ordivus -n platform-config \
  --set image.repository=registry.example.com/ordivus \
  --set image.digest=sha256:…
```

Die ConfigMap darf auch vom Chart erzeugt werden (`configuration.source: inline`, Dateien unter `configuration.files`). Für GitOps ist eine eigene ConfigMap meist besser, weil sie unabhängig vom Chart aktualisiert werden kann.

Die ConfigMap wird direkt unter `/config` eingehängt (ohne `subPath`). Die versteckten Verzeichnisse, über die Kubernetes die Dateien atomar austauscht (`..data`, `..<zeitstempel>`), überspringt der Config-Loader wie alle Pfade mit führendem Punkt.

**Grenze:** Eine ConfigMap fasst höchstens **1 MiB**. Größere Konfigurationen auf mehrere ConfigMaps verteilen (über `jobs.templates.<mode>.extraVolumes`/`extraVolumeMounts` unter `/config/<unterverzeichnis>` einhängen, je Modus) oder als Volume aus einer anderen Quelle bereitstellen.

## Values im Überblick

| Value | Standard | Bedeutung |
|---|---|---|
| `image.repository` / `tag` / `digest` / `pullPolicy` | `ghcr.io/EXAMPLE/ordivus`, appVersion, leer, `IfNotPresent` | `digest` (`sha256:<64 hex>`) hat Vorrang vor `tag`. Für Produktion per Digest pinnen: ein Tag kann neu vergeben werden, ein Digest nicht; `IfNotPresent` ist dann unkritisch |
| `configuration.source` | `configMap` | `configMap` (vorhandene, `configuration.name`) oder `inline` (`configuration.files`) |
| `policy.configMap` / `policy.secret` / `policy.key` | leer / leer / `policy.yaml` | Operator Policy, getrennt von der Konfiguration unter `/policy`; `--policy` wird nur übergeben, wenn gesetzt |
| `credentials.mountPath` | `/var/run/secrets/ordivus` | Verzeichnis für `CredentialProvider` `type: file`, immer read-only |
| `credentials.readOnly` / `credentials.apply` | `{}` | Volume-Quelle je Modus, z. B. `{secret: {secretName: …}}`; plan/drift sehen nur `readOnly` |
| `jobs.templates.<mode>.enabled` / `suspended` | `true` / `true` | Vorlagen für `plan`, `drift`, `apply` |
| `jobs.templates.apply.allowSchedule` | `false` | `apply.suspended: false` wird nur damit akzeptiert (im Profil `hardened` nie) |
| `jobs.templates.apply.namespace` | Release-Namespace | eigener Namespace für Apply-CronJob, Apply-ServiceAccount und Apply-Credentials (siehe [Sicherheit](#sicherheit)) |
| `jobs.templates.<mode>.automountServiceAccountToken` | `false` | Kubernetes-Token je Modus |
| `jobs.templates.<mode>.projectedToken` | aus | projiziertes, audience-gebundenes Token (z. B. OpenBao Kubernetes Auth), unter `mountPath/token` |
| `jobs.templates.<mode>.extraArgs` | `[]` | zusätzliche CLI-Argumente, z. B. `["--fail-on", "actionable"]` |
| `jobs.templates.<mode>.env` / `extraVolumes` / `extraVolumeMounts` | `[]` | **je Modus**; globale Varianten gibt es bewusst nicht, damit Apply-Secrets nie in plan/drift landen |
| `jobs.scheduledDrift` | aus, `0 2 * * *` | zusätzlicher, **nicht** suspendierter Drift-CronJob `<release>-drift-scheduled` (eigene `env`/`extraVolumes`/`extraVolumeMounts`) |
| `security.profile` | `standard` | `development`, `standard` oder `hardened` (Prüfungen siehe [Sicherheit](#sicherheit)) |
| `security.readOnlyServiceAccount` / `applyServiceAccount` | `ordivus-readonly` / `ordivus-apply` | getrennte Identitäten, müssen sich unterscheiden; `createServiceAccounts: false` für vorhandene |
| `security.networkPolicy` | aus | Egress nur zu DNS (`dns.namespace`/`dns.podSelector`, Standard `kube-system`/`k8s-app: kube-dns`, plus `dns.cidrs`, z. B. NodeLocal DNSCache `169.254.20.10/32`) und `egress[].cidr`/`ports` (TCP); Cloud-Metadaten-Adresse `169.254.169.254/32` bzw. `fd00:ec2::254/128` wird ausgenommen, wenn sie im Block liegt (eigene Liste: `egress[].except`) |
| `admission.enabled` | `false` | ValidatingAdmissionPolicy für Pods mit dem Apply-ServiceAccount (Kubernetes ≥ 1.30) |
| `execution.timeoutSeconds` / `backoffLimit` / `ttlSecondsAfterFinished` | `1800` / `0` / `86400` | `activeDeadlineSeconds`, keine Wiederholung, Aufräumen nach einem Tag |
| `resources` | 100m/128Mi, Limits 1 CPU/512Mi/256Mi ephemeral-storage | wie üblich |
| `nodeSelector`, `tolerations`, `affinity`, `imagePullSecrets` | | wie üblich |

Jeder Pod läuft mit `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, Seccomp `RuntimeDefault`, `enableServiceLinks: false` und `restartPolicy: Never`; die CronJobs haben `concurrencyPolicy: Forbid`. Ein `emptyDir` unter `/tmp` steht für temporäre Dateien bereit. Der Container wird mit `<mode> -f /config --format json` aufgerufen: Logs und Report landen als JSON-Zeilen im Pod-Log, der Report ist die Zeile mit `"type":"report"`.

Der `file`-Provider kann im read-only eingehängten Credentials-Verzeichnis keine neuen Secrets anlegen. Wenn `apply` Passwörter erzeugen soll, für das Apply-Credential einen OpenBao-Provider verwenden oder ausdrücklich ein beschreibbares Volume (z. B. `emptyDir` oder PVC) über `jobs.templates.apply.extraVolumes`/`extraVolumeMounts` einhängen – ein `emptyDir` verliert neue Secrets mit dem Pod.

## Läufe starten

Direkt mit kubectl:

```sh
kubectl -n platform-config create job --from=cronjob/ordivus-plan ordivus-plan-$(date +%s)
```

Für Pipelines gibt es `scripts/run-job.sh`. Es erzeugt genau einen Job, wartet auf das Ende, legt die Logs unter `reports/<mode>.log` und den Report unter `reports/<mode>.json` ab und endet mit dem **Exit-Code des Ordivus-Containers** (0, 10, 11 … wie in [konfiguration.md](konfiguration.md#exit-codes)).

```sh
scripts/run-job.sh plan platform-config                                    # Release "ordivus"
ORDIVUS_KUBE_CONTEXT=prod scripts/run-job.sh apply platform-config-apply my-release  # Apply-Namespace
```

| Variable | Standard | Bedeutung |
|---|---|---|
| `ORDIVUS_KUBE_CONTEXT` | aktueller Kontext | kubectl-Kontext (`--context`); für `apply` **Pflicht** (sonst Exit 2), damit kein Apply gegen einen zufällig aktiven Kontext läuft. Kontext und Namespace werden immer ausgegeben |
| `ORDIVUS_RUN_ID` | `CI_JOB_ID`, sonst `BUILD_TAG`, sonst UTC-Zeitstempel | Teil des Job-Namens `<release>-<mode>-<id>`; wird DNS-1123-konform gemacht und auf 63 Zeichen gekürzt |
| `ORDIVUS_TIMEOUT` | `2100` | Sekunden, die das Skript wartet; danach Exit 1, der Job läuft weiter bis `activeDeadlineSeconds` |
| `ORDIVUS_REPORT_DIR` | `reports` | Ablage für Report und Logs |
| `KUBECTL` | `kubectl` | Pfad zu kubectl |

Vor dem Start löscht das Skript `<mode>.json` und `<mode>.log` eines früheren Laufs. Der Report wird nur abgelegt, wenn das Log **genau eine** Report-Zeile enthält: mit `jq` eine Zeile, die gültiges JSON mit `"type":"report"` und `schemaVersion` ist, ohne `jq` eine Zeile, die exakt mit `{"type":"report","schemaVersion":"…",` beginnt und mit `}` endet (Logs der Engine haben diese Form nie; eine Anwendungs-Logzeile genau dieser Form würde mitgezählt); sonst meldet das Skript das und endet mit 1, außer der Container ist ohnehin mit einem Fehler-Exit-Code beendet worden (dieser bleibt erhalten). Logs, Report und Exit-Code stammen vom jüngsten Pod des Jobs; meldet Kubernetes den Job als `Failed`, der Container aber 0, endet das Skript mit 1.

Endet der Job ohne Exit-Code des Containers (z. B. `activeDeadlineSeconds` überschritten, Image nicht ladbar), endet das Skript mit 1. Bei Abbruch (SIGINT/SIGTERM) sammelt es die bisherigen Logs ein und löscht den Job; Ordivus erhält dann SIGTERM.

Die CI-Identität braucht im jeweiligen Namespace: `create` auf `jobs`, `get` auf `cronjobs` und `jobs`, `list` auf `pods`, `get` auf `pods/log`, `delete` auf `jobs`. Mit getrenntem Apply-Namespace (`jobs.templates.apply.namespace`) dafür **zwei** Identitäten mit je einer RoleBinding anlegen: die Plan-/Drift-Identität (z. B. für Merge-Request-Pipelines) nur im Release-Namespace, die Apply-Identität (nur geschützte Branches/manuelle Freigabe) nur im Apply-Namespace. Eine Rolle mit diesen Rechten im Apply-Namespace ist gleichbedeutend mit Apply-Rechten auf alle Zielsysteme.

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
- Deshalb: Job-Create-Rechte nur an vertrauenswürdige CI-Identitäten; Workload-Erstellung über alle Pfade einschränken. Das Chart bietet zwei Bausteine, das Profil `hardened` verlangt mindestens einen:
  - **Eigener Apply-Namespace** (`jobs.templates.apply.namespace`): Apply-CronJob und Apply-ServiceAccount liegen dort; Apply-Credentials-Secret, Konfigurations-ConfigMap (bei `configuration.source: configMap`) und Policy müssen ebenfalls dort existieren (bei `source: inline` legt das Chart die ConfigMap in beiden Namespaces an, die NetworkPolicy ebenso). Wer nur im Release-Namespace Workloads anlegen darf, erreicht Apply-Identität und -Credentials nicht mehr. RoleBindings getrennt je Namespace vergeben (siehe [Läufe starten](#läufe-starten)). Das Chart wird weiterhin in den Release-Namespace installiert; die Helm-Identität braucht Rechte in beiden Namespaces.
  - **ValidatingAdmissionPolicy** (`admission.enabled`, Kubernetes ≥ 1.30, cluster-weit, die Helm-Identität braucht Rechte auf `admissionregistration.k8s.io`): Pods mit dem Apply-ServiceAccount im Apply-Namespace werden nur zugelassen, wenn sie die Labels der Apply-Vorlage tragen, von einem Job `<release>-apply-*` kontrolliert werden und ihr Pod-Spec der gerenderten Apply-Vorlage entspricht:
    - **Pod-Spec und Container enthalten nur Felder, die die Vorlage setzt**, plus die Felder, die API-Server und Standard-Admission-Plugins vor der Prüfung ergänzen – mit genau deren Standardwerten (`dnsPolicy: ClusterFirst`, `schedulerName: default-scheduler`, `serviceAccount` = Apply-ServiceAccount, `priority`/`preemptionPolicy`, die `NoExecute`-Tolerations für `not-ready`/`unreachable`, `terminationMessagePath`/`terminationMessagePolicy`). Damit abgelehnt: `command`, `envFrom`, `workingDir`, `ports`, Probes, `lifecycle`-Hooks, weitere Container, Init- und Ephemeral-Container (`kubectl debug`), `hostAliases`, `dnsConfig`, `nodeName`, `runtimeClassName`, `priorityClassName`, `shareProcessNamespace`, `hostNetwork`/`hostPID`/`hostIPC` usw.
    - **Exakt gleich** der Vorlage: `securityContext` von Pod und Container; `nodeSelector` und `affinity` fehlen oder sind exakt gleich; `tolerations` nur die der Vorlage oder die oben genannten Standard-Tolerations.
    - **Mindestens die Werte der Vorlage** (zusätzliche Unterschlüssel bleiben erlaubt, damit API-Defaults wie `defaultMode` passen): Image, Argumente, `env`, `volumeMounts`, `volumes` (Anzahl und Quelle je Volume fest; z. B. `subPath` oder `items` sind möglich), ServiceAccount, `automountServiceAccountToken`, `restartPolicy`, `enableServiceLinks`, `terminationGracePeriodSeconds`, `imagePullSecrets`.
  - **Grenzen der Admission-Policy:** CEL kann nicht nachschlagen, ob der besitzende Job wirklich vom CronJob stammt; eine Kopie der Vorlage mit gefälschter `ownerReference` wird zugelassen. Sie startet einen echten `apply`-Lauf mit Apply-Credentials – zu einem beliebigen Zeitpunkt, auch parallel zu anderen Läufen und ohne Pipeline. Nicht geprüft werden `resources` (Requests/Limits), Annotations und zusätzliche Labels sowie die erlaubten Unterschlüssel oben; Pod Security Admission `restricted` auf dem Apply-Namespace bleibt als zweite Linie empfohlen. Mutierende Webhooks oder Plugins, die weitere Pod-Felder setzen (z. B. Sidecar-Injection), führen zur Ablehnung auch legitimer Apply-Pods. `pods/exec` und `pods/attach` sind keine Pod-Änderung und bleiben Sache von RBAC. Wer CronJob, ConfigMap oder Policy im Apply-Namespace ändern darf, ändert, was apply tut. Die Policy bildet den Stand der letzten Helm-Installation ab; nach Änderungen an der Vorlage außerhalb von Helm lehnt sie Apply-Pods ab.
- Prüfungen beim Rendern in **jedem** Profil: Read-only- und Apply-ServiceAccount müssen verschieden heißen; `jobs.templates.apply.suspended: false` nur mit `allowSchedule: true`.
- Zusätzlich im Profil **`hardened`**: `image.digest` im Format `sha256:<64 hex>`, eine Policy, `networkPolicy.enabled`, kein `automountServiceAccountToken: true` in irgendeinem Modus, jede Egress-Regel mit `ports` und ohne `0.0.0.0/0`/`::/0`, Apply-Vorlage suspendiert, eigener Apply-Namespace oder `admission.enabled`.
- `concurrencyPolicy: Forbid` gilt nur für Jobs, die der CronJob-Controller selbst startet, nicht für manuell erzeugte. Zwei gleichzeitige `apply`-Läufe verhindert das Chart nicht.
- plan/drift laufen mit `ordivus-readonly` und sehen nur `credentials.readOnly`; die Zielsystem-Rechte dieser Credentials sollten ebenfalls nur lesend sein.
- Kubernetes-Token werden standardmäßig nicht gemountet. Für OpenBao Kubernetes Auth `projectedToken` im betroffenen Modus aktivieren statt `automountServiceAccountToken: true`.
- `ttlSecondsAfterFinished` löscht Jobs samt Logs. Reports, die als Audit-Nachweis dienen, archiviert die Pipeline (`reports/`).

## Lokal testen (Docker Desktop)

Docker Desktop liefert lokal gebaute Images beim Pull an den Cluster aus; `imagePullPolicy: Never` funktioniert dort **nicht**, `IfNotPresent` oder `Always` schon.

```sh
tests/e2e/run.sh                  # nur helm lint/template
ORDIVUS_E2E=1 tests/e2e/run.sh    # zusätzlich Installation im Kontext docker-desktop, Namespaces ordivus-e2e und ordivus-e2e-apply
```
