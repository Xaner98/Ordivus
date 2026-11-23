#!/bin/sh
# Chart- und Launcher-Tests.
#   Teil 1 (immer, braucht nur helm): helm lint + helm template Prüfungen.
#   Teil 2 (nur mit ORDIVUS_E2E=1, braucht kubectl + docker): Installation in den Kontext
#   docker-desktop, Läufe über scripts/run-job.sh, Aufräumen des Namespace ordivus-e2e.
# Usage: tests/e2e/run.sh            (ORDIVUS_E2E=1 tests/e2e/run.sh für den Cluster-Teil)
set -eu
cd "$(dirname "$0")/../.."
chart=charts/ordivus
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
has() { printf '%s\n' "$1" | grep -q -- "$2"; }
count() { printf '%s\n' "$1" | grep -c -- "$2" || true; }

command -v helm >/dev/null || { echo "SKIP: helm not found"; exit 0; }

echo "== helm template checks"
check "helm lint" helm lint "$chart"
out=$(helm template ordivus "$chart")
check "three CronJobs" [ "$(count "$out" '^kind: CronJob')" -eq 3 ]
check "all suspended" [ "$(count "$out" 'suspend: true')" -eq 3 ]
check "concurrencyPolicy Forbid" [ "$(count "$out" 'concurrencyPolicy: Forbid')" -eq 3 ]
check "restartPolicy Never" [ "$(count "$out" 'restartPolicy: Never')" -eq 3 ]
check "backoffLimit 0" [ "$(count "$out" 'backoffLimit: 0')" -eq 3 ]
check "activeDeadlineSeconds" [ "$(count "$out" 'activeDeadlineSeconds: 1800')" -eq 3 ]
check "readOnlyRootFilesystem" [ "$(count "$out" 'readOnlyRootFilesystem: true')" -eq 3 ]
check "drop ALL" [ "$(count "$out" 'drop: \["ALL"\]')" -eq 3 ]
check "no privilege escalation" [ "$(count "$out" 'allowPrivilegeEscalation: false')" -eq 3 ]
check "seccomp RuntimeDefault" [ "$(count "$out" 'type: RuntimeDefault')" -eq 6 ]
check "token not automounted" [ "$(count "$out" 'automountServiceAccountToken: false')" -eq 5 ]
check "readonly SA twice, apply SA once" [ "$(count "$out" 'serviceAccountName: "ordivus-readonly"')" -eq 2 ] \
  && [ "$(count "$out" 'serviceAccountName: "ordivus-apply"')" -eq 1 ]
check "no --policy without policy" sh -c '! printf "%s" "$1" | grep -q -- "--policy"' sh "$out"
check "no NetworkPolicy by default" sh -c '! printf "%s" "$1" | grep -q "kind: NetworkPolicy"' sh "$out"
check "no admission policy by default" sh -c '! printf "%s" "$1" | grep -q "kind: ValidatingAdmissionPolicy"' sh "$out"
check "no service links" [ "$(count "$out" 'enableServiceLinks: false')" -eq 3 ]
check "ephemeral-storage limit" [ "$(count "$out" 'ephemeral-storage:')" -eq 3 ]

out=$(helm template ordivus "$chart" --set policy.configMap=pol --set-string "$(printf 'policy.key=p.yaml\n                - --evil')")
check "policy.key cannot inject args" sh -c '! printf "%s" "$1" | grep -q "^ *- --evil"' sh "$out"

out=$(helm template ordivus "$chart" --set jobs.templates.apply.namespace=ops --set admission.enabled=true \
  --set configuration.source=inline --set-string 'configuration.files.a\.yaml=x: 1' \
  --set security.networkPolicy.enabled=true --set credentials.apply.secret.secretName=rw \
  --set 'jobs.templates.apply.env[0].name=APPLY_ONLY' --set 'jobs.templates.apply.env[0].value=x')
check "apply CronJob, SA, ConfigMap, NetworkPolicy in apply namespace" [ "$(count "$out" 'namespace: "ops"')" -eq 4 ]
check "env only in apply" [ "$(count "$(printf '%s' "$out" | sed -n '/^kind: CronJob/,/^---/p')" 'APPLY_ONLY')" -eq 1 ]
check "credentials mounted read-only" has "$out" 'mountPath: "/var/run/secrets/ordivus", readOnly: true'
check "admission policy and binding" has "$out" 'kind: ValidatingAdmissionPolicyBinding'
check "DNS limited to kube-dns" has "$out" 'k8s-app: kube-dns'
out=$(helm template ordivus "$chart" --set security.networkPolicy.enabled=true \
  --set 'security.networkPolicy.egress[0].cidr=169.254.0.0/16' --set 'security.networkPolicy.egress[0].ports={80}')
check "metadata IP excepted" has "$out" '"169.254.169.254/32"'

out=$(helm template ordivus "$chart" --set policy.configMap=pol \
  --set credentials.readOnly.secret.secretName=ro --set credentials.apply.secret.secretName=rw)
check "--policy passed" [ "$(count "$out" '/policy/policy.yaml')" -eq 3 ]
check "credentials separated per mode" [ "$(count "$out" 'secretName: ro')" -eq 2 ] \
  && [ "$(count "$out" 'secretName: rw')" -eq 1 ]

out=$(helm template ordivus "$chart" -s templates/cronjobs.yaml --set jobs.scheduledDrift.enabled=true \
  --set jobs.templates.apply.enabled=false)
check "scheduled drift not suspended" [ "$(count "$out" 'suspend: false')" -eq 1 ] && has "$out" 'name: "ordivus-drift-scheduled"'
check "apply template disabled" sh -c '! printf "%s" "$1" | grep -q "name: \"ordivus-apply\"$"' sh "$out"

out=$(helm template ordivus "$chart" --set jobs.templates.apply.projectedToken.enabled=true \
  --set jobs.templates.apply.automountServiceAccountToken=true)
check "projected token with audience" has "$out" 'audience: "openbao"'

out=$(helm template ordivus "$chart" --set security.networkPolicy.enabled=true \
  --set 'security.networkPolicy.egress[0].cidr=10.0.0.0/8' --set 'security.networkPolicy.egress[0].ports={5432}')
check "NetworkPolicy egress" has "$out" 'cidr: "10.0.0.0/8"'
hard="--set security.profile=hardened --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
  --set policy.secret=pol --set security.networkPolicy.enabled=true --set jobs.templates.apply.namespace=ops"
rejects() { name=$1; shift; check "$name" sh -c '! helm template x "$@"' sh "$chart" "$@"; }
# shellcheck disable=SC2086 # $hard enthält mehrere Optionen
check "hardened renders when complete" helm template x "$chart" $hard
check "hardened renders with admission instead of apply namespace" helm template x "$chart" $hard \
  --set jobs.templates.apply.namespace= --set admission.enabled=true
rejects "hardened requires digest" --set security.profile=hardened
rejects "hardened rejects malformed digest" $hard --set image.digest=sha256:abc
rejects "hardened requires apply namespace or admission" $hard --set jobs.templates.apply.namespace=
rejects "hardened rejects automounted token" $hard --set jobs.templates.plan.automountServiceAccountToken=true
rejects "hardened rejects egress without ports" $hard --set 'security.networkPolicy.egress[0].cidr=10.0.0.0/8'
rejects "hardened rejects egress 0.0.0.0/0" $hard --set 'security.networkPolicy.egress[0].cidr=0.0.0.0/0' \
  --set 'security.networkPolicy.egress[0].ports={443}'
rejects "hardened rejects egress ::/0" $hard --set 'security.networkPolicy.egress[0].cidr=::/0' \
  --set 'security.networkPolicy.egress[0].ports={443}'
rejects "hardened rejects scheduled apply" $hard --set jobs.templates.apply.suspended=false \
  --set jobs.templates.apply.allowSchedule=true
rejects "apply unsuspended needs allowSchedule" --set jobs.templates.apply.suspended=false
check "apply unsuspended with allowSchedule" helm template x "$chart" --set jobs.templates.apply.suspended=false \
  --set jobs.templates.apply.allowSchedule=true
rejects "equal ServiceAccount names rejected" --set security.applyServiceAccount=ordivus-readonly
rejects "invalid profile rejected" --set security.profile=yolo
check "inline config renders ConfigMap" has "$(helm template ordivus "$chart" --set configuration.source=inline \
  --set-string 'configuration.files.a\.yaml=x: 1')" 'name: "ordivus-configuration"'

if [ "${ORDIVUS_E2E:-}" != 1 ]; then
  echo "SKIP cluster tests (set ORDIVUS_E2E=1)"
  [ "$fails" -eq 0 ] || { echo "$fails check(s) failed"; exit 1; }
  exit 0
fi
command -v kubectl >/dev/null && command -v docker >/dev/null || { echo "SKIP: kubectl/docker not found"; exit 0; }

echo "== cluster tests (context docker-desktop, namespaces ordivus-e2e and ordivus-e2e-apply)"
ns=ordivus-e2e apply_ns=ordivus-e2e-apply
export ORDIVUS_KUBE_CONTEXT=docker-desktop
kc() { kubectl --context docker-desktop "$@"; }
k() { kc -n "$ns" "$@"; }
ka() { kc -n "$apply_ns" "$@"; }
work=$(mktemp -d)
cleanup() {
  helm --kube-context docker-desktop uninstall ordivus -n "$ns" --ignore-not-found >/dev/null 2>&1 || true
  kc delete namespace "$ns" "$apply_ns" --ignore-not-found --wait=false >/dev/null; rm -rf "$work"
}
trap cleanup EXIT

[ -n "${ORDIVUS_E2E_SKIP_BUILD:-}" ] || docker build -q -t ordivus:dev . >/dev/null
helm --kube-context docker-desktop uninstall ordivus -n "$ns" --ignore-not-found >/dev/null 2>&1 || true
kc delete namespace "$ns" "$apply_ns" --ignore-not-found --wait=true >/dev/null
kc create namespace "$ns" >/dev/null
kc create namespace "$apply_ns" >/dev/null
k create secret generic ordivus-ro-creds --from-literal=dummy=ro >/dev/null
ka create secret generic ordivus-apply-creds --from-literal=dummy=rw >/dev/null

cat >"$work/values.yaml" <<'VALUES'
image: {repository: ordivus, tag: dev, pullPolicy: Always}  # Docker Desktop liefert lokale Images per Pull aus
configuration:
  source: inline
  files:
    config.yaml: |
      apiVersion: ordivus.dev/v1alpha1
      kind: Target
      metadata: {name: demo}
      spec: {adapter: fake, instance: e2e}
      ---
      apiVersion: ordivus.dev/v1alpha1
      kind: FakeItem
      metadata: {name: item1}
      spec: {targetRef: demo, attrs: {color: blue}}
credentials:
  readOnly: {secret: {secretName: ordivus-ro-creds}}
  apply: {secret: {secretName: ordivus-apply-creds}}
jobs:
  templates:
    drift: {extraArgs: ["--fail-on", "any"]}
    apply: {namespace: ordivus-e2e-apply}
admission: {enabled: true}
execution: {timeoutSeconds: 120}
VALUES
helm --kube-context docker-desktop install ordivus "$chart" -n "$ns" -f "$work/values.yaml" >/dev/null

suspended=$(k get cronjob -o 'jsonpath={range .items[*]}{.metadata.name}={.spec.suspend} {end}')
check "CronJobs suspended" [ "$suspended" = "ordivus-drift=true ordivus-plan=true " ]
check "apply CronJob in apply namespace" [ "$(ka get cronjob -o 'jsonpath={.items[*].metadata.name}={.items[*].spec.suspend}')" = "ordivus-apply=true" ]
check "no job started by install" [ -z "$(k get jobs -o name)$(ka get jobs -o name)" ]

run() {  # mode namespace expected_exit expected_identity
  rc=0
  ORDIVUS_RUN_ID="e2e-$1" ORDIVUS_REPORT_DIR="$work/reports" ORDIVUS_TIMEOUT=180 \
    scripts/run-job.sh "$1" "$2" >"$work/$1.out" 2>&1 || rc=$?
  check "$1: exit code $3 (got $rc)" [ "$rc" -eq "$3" ]
  check "$1: report extracted" grep -q "\"mode\":\"$1\"" "$work/reports/$1.json"
  pod=$(kc -n "$2" get pods -l "job-name=ordivus-$1-e2e-$1" -o 'jsonpath={.items[0].spec.serviceAccountName}/{.items[0].spec.automountServiceAccountToken}/{range .items[0].spec.volumes[*]}{.secret.secretName}{end}')
  check "$1: pod identity $4 (got $pod)" [ "$pod" = "$4" ]
  [ "$rc" -eq "$3" ] || cat "$work/$1.out"
}
run plan "$ns" 0 ordivus-readonly/false/ordivus-ro-creds
run drift "$ns" 10 ordivus-readonly/false/ordivus-ro-creds
run apply "$apply_ns" 0 ordivus-apply/false/ordivus-apply-creds
check "same template reusable (second plan run)" sh -c \
  'ORDIVUS_RUN_ID=e2e-plan-2 ORDIVUS_REPORT_DIR="$1" scripts/run-job.sh plan ordivus-e2e' sh "$work/reports"
check "apply refused without ORDIVUS_KUBE_CONTEXT" sh -c \
  '[ "$(ORDIVUS_KUBE_CONTEXT= scripts/run-job.sh apply ordivus-e2e-apply >/dev/null 2>&1; echo $?)" -eq 2 ]'

# Admission: fremder Pod mit Apply-ServiceAccount wird abgewiesen.
rogue=$(cat <<'POD'
apiVersion: v1
kind: Pod
metadata: {name: rogue, labels: {app.kubernetes.io/name: ordivus, app.kubernetes.io/instance: ordivus, ordivus.dev/mode: apply}}
spec:
  serviceAccountName: ordivus-apply
  automountServiceAccountToken: false
  restartPolicy: Never
  containers: [{name: x, image: ordivus:dev, args: ["--version"]}]
  volumes: [{name: c, secret: {secretName: ordivus-apply-creds}}]
POD
)
check "admission denies foreign pod with apply SA" sh -c \
  '! printf "%s\n" "$1" | kubectl --context docker-desktop -n ordivus-e2e-apply create --dry-run=server -f -' sh "$rogue"
if command -v jq >/dev/null; then
  tpl=$(ka get cronjob ordivus-apply -o json | jq '.spec.jobTemplate.spec.template | {apiVersion: "v1", kind: "Pod",
    metadata: (.metadata + {name: "copy", ownerReferences: [{apiVersion: "batch/v1", kind: "Job", name: "ordivus-apply-x",
    uid: "00000000-0000-0000-0000-000000000000", controller: true}]}), spec: .spec}')
  # Grenze: eine unveränderte Kopie der Vorlage mit gefälschter ownerReference wird zugelassen (docs/kubernetes.md).
  check "admission accepts unmodified template copy" sh -c \
    'printf "%s" "$1" | kubectl --context docker-desktop -n ordivus-e2e-apply create --dry-run=server -f -' sh "$tpl"
  for patch in '.spec.containers[0].command=["sh"]' '.spec.volumes[0].configMap.name="evil"' \
    '.spec.automountServiceAccountToken=true' '.spec.containers[0].env=[{name:"X",value:"y"}]'; do
    check "admission denies template copy with $patch" sh -c \
      '! printf "%s" "$1" | jq "$2" | kubectl --context docker-desktop -n ordivus-e2e-apply create --dry-run=server -f -' \
      sh "$tpl" "$patch"
  done
fi
check "admission allows other ServiceAccounts" sh -c \
  'printf "%s\n" "$1" | sed "s/serviceAccountName: ordivus-apply/serviceAccountName: default/" |
   kubectl --context docker-desktop -n ordivus-e2e-apply create --dry-run=server -f -' sh "$rogue"

# Kein Report im Lauf: alter Report wird entfernt, Exit-Code des Containers bleibt (argparse: 2).
helm --kube-context docker-desktop upgrade ordivus "$chart" -n "$ns" -f "$work/values.yaml" \
  --set 'jobs.templates.plan.extraArgs={--no-such-option}' >/dev/null
echo '{"type":"report","stale":true}' >"$work/reports/plan.json"
rc=0
ORDIVUS_RUN_ID=e2e-noreport ORDIVUS_REPORT_DIR="$work/reports" ORDIVUS_TIMEOUT=180 \
  scripts/run-job.sh plan "$ns" >"$work/noreport.out" 2>&1 || rc=$?
check "run without report: container exit code kept (got $rc)" [ "$rc" -eq 2 ]
check "run without report: stale report removed" [ ! -e "$work/reports/plan.json" ]
check "run without report: message" grep -q "expected exactly one report" "$work/noreport.out"

echo
[ "$fails" -eq 0 ] && echo "all checks passed" || { echo "$fails check(s) failed"; exit 1; }
