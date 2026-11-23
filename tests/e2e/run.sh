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
check "readonly SA twice, apply SA once" [ "$(count "$out" 'serviceAccountName: ordivus-readonly')" -eq 2 ] \
  && [ "$(count "$out" 'serviceAccountName: ordivus-apply')" -eq 1 ]
check "no --policy without policy" sh -c '! printf "%s" "$1" | grep -q -- "--policy"' sh "$out"
check "no NetworkPolicy by default" sh -c '! printf "%s" "$1" | grep -q "kind: NetworkPolicy"' sh "$out"

out=$(helm template ordivus "$chart" --set policy.configMap=pol \
  --set credentials.readOnly.secret.secretName=ro --set credentials.apply.secret.secretName=rw)
check "--policy passed" [ "$(count "$out" '/policy/policy.yaml')" -eq 3 ]
check "credentials separated per mode" [ "$(count "$out" 'secretName: ro')" -eq 2 ] \
  && [ "$(count "$out" 'secretName: rw')" -eq 1 ]

out=$(helm template ordivus "$chart" -s templates/cronjobs.yaml --set jobs.scheduledDrift.enabled=true \
  --set jobs.templates.apply.enabled=false)
check "scheduled drift not suspended" [ "$(count "$out" 'suspend: false')" -eq 1 ] && has "$out" 'name: ordivus-drift-scheduled'
check "apply template disabled" sh -c '! printf "%s" "$1" | grep -q "name: ordivus-apply$"' sh "$out"

out=$(helm template ordivus "$chart" --set jobs.templates.apply.projectedToken.enabled=true \
  --set jobs.templates.apply.automountServiceAccountToken=true)
check "projected token with audience" has "$out" 'audience: openbao'

out=$(helm template ordivus "$chart" --set security.networkPolicy.enabled=true \
  --set 'security.networkPolicy.egress[0].cidr=10.0.0.0/8' --set 'security.networkPolicy.egress[0].ports={5432}')
check "NetworkPolicy egress" has "$out" 'cidr: "10.0.0.0/8"'
check "hardened requires digest" sh -c '! helm template x "$1" --set security.profile=hardened' sh "$chart"
check "hardened renders when complete" helm template x "$chart" --set security.profile=hardened \
  --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set policy.secret=pol --set security.networkPolicy.enabled=true
check "invalid profile rejected" sh -c '! helm template x "$1" --set security.profile=yolo' sh "$chart"
check "inline config renders ConfigMap" has "$(helm template ordivus "$chart" --set configuration.source=inline \
  --set-string 'configuration.files.a\.yaml=x: 1')" 'name: ordivus-configuration'

if [ "${ORDIVUS_E2E:-}" != 1 ]; then
  echo "SKIP cluster tests (set ORDIVUS_E2E=1)"
  [ "$fails" -eq 0 ] || { echo "$fails check(s) failed"; exit 1; }
  exit 0
fi
command -v kubectl >/dev/null && command -v docker >/dev/null || { echo "SKIP: kubectl/docker not found"; exit 0; }

echo "== cluster tests (context docker-desktop, namespace ordivus-e2e)"
ns=ordivus-e2e
k() { kubectl --context docker-desktop -n "$ns" "$@"; }
work=$(mktemp -d)
cleanup() { kubectl --context docker-desktop delete namespace "$ns" --ignore-not-found --wait=false >/dev/null; rm -rf "$work"; }
trap cleanup EXIT
printf '#!/bin/sh\nexec kubectl --context docker-desktop "$@"\n' >"$work/kubectl" && chmod +x "$work/kubectl"

[ -n "${ORDIVUS_E2E_SKIP_BUILD:-}" ] || docker build -q -t ordivus:dev . >/dev/null
kubectl --context docker-desktop delete namespace "$ns" --ignore-not-found --wait=true >/dev/null
kubectl --context docker-desktop create namespace "$ns" >/dev/null
k create secret generic ordivus-ro-creds --from-literal=dummy=ro >/dev/null
k create secret generic ordivus-apply-creds --from-literal=dummy=rw >/dev/null

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
execution: {timeoutSeconds: 120}
VALUES
helm --kube-context docker-desktop install ordivus "$chart" -n "$ns" -f "$work/values.yaml" >/dev/null

suspended=$(k get cronjob -o 'jsonpath={range .items[*]}{.metadata.name}={.spec.suspend} {end}')
check "CronJobs suspended" [ "$suspended" = "ordivus-apply=true ordivus-drift=true ordivus-plan=true " ]
check "no job started by install" [ -z "$(k get jobs -o name)" ]

run() {  # mode expected_exit
  rc=0
  ORDIVUS_RUN_ID="e2e-$1" ORDIVUS_REPORT_DIR="$work/reports" ORDIVUS_TIMEOUT=180 \
    KUBECTL="$work/kubectl" scripts/run-job.sh "$1" "$ns" >"$work/$1.out" 2>&1 || rc=$?
  check "$1: exit code $2 (got $rc)" [ "$rc" -eq "$2" ]
  check "$1: report extracted" grep -q "\"mode\":\"$1\"" "$work/reports/$1.json"
  pod=$(k get pods -l "job-name=ordivus-$1-e2e-$1" -o 'jsonpath={.items[0].spec.serviceAccountName}/{.items[0].spec.automountServiceAccountToken}/{range .items[0].spec.volumes[*]}{.secret.secretName}{end}')
  check "$1: pod identity $3 (got $pod)" [ "$pod" = "$3" ]
  [ "$rc" -eq "$2" ] || cat "$work/$1.out"
}
run plan 0 ordivus-readonly/false/ordivus-ro-creds
run drift 10 ordivus-readonly/false/ordivus-ro-creds
run apply 0 ordivus-apply/false/ordivus-apply-creds
check "same template reusable (second plan run)" sh -c \
  'ORDIVUS_RUN_ID=e2e-plan-2 ORDIVUS_REPORT_DIR="$1" KUBECTL="$2" scripts/run-job.sh plan ordivus-e2e' sh "$work/reports" "$work/kubectl"

echo
[ "$fails" -eq 0 ] && echo "all checks passed" || { echo "$fails check(s) failed"; exit 1; }
