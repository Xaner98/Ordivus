#!/bin/sh
# In-Cluster-Labor: Ordivus gegen OpenBao (Kubernetes-Auth, KV v2, ACL-Policies) und PostgreSQL 17,
# Namespace ordivus-lab im Kontext docker-desktop. Doku: docs/lab.md
#
# Usage: scripts/lab.sh up | run plan|drift|apply | scale N | reset | race [same|diff] [N] | check-secrets | down
# Env:
#   LAB_CONTEXT  kubectl/helm-Kontext (Standard: docker-desktop)
#   LAB_PG_ADMIN Rolle des Ordivus-Logins in PostgreSQL bei up: createrole (Standard) | superuser
#   LAB_OUT      Ablage für Reports und Logs (Standard: ${TMPDIR:-/tmp}/ordivus-lab)
set -eu
cd "$(dirname "$0")/.."
ctx=${LAB_CONTEXT:-docker-desktop}
ns=ordivus-lab
out=${LAB_OUT:-${TMPDIR:-/tmp}/ordivus-lab}
mkdir -p "$out"
kc() { kubectl --context "$ctx" "$@"; }
k() { kc -n "$ns" "$@"; }
now() { perl -MTime::HiRes=time -e 'printf "%.1f\n", time'; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; }
# Shell-Skript von stdin im OpenBao-Pod, angemeldet mit dem Root-Token (verlässt den Pod nie).
bao_root() { k exec -i deploy/openbao -- sh -c 'export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=$BAO_DEV_ROOT_TOKEN_ID; sh -s'; }
psql_admin() { k exec -i deploy/postgres -- psql -q -U postgres -v ON_ERROR_STOP=1 "$@"; }
# create-or-update ohne Wert in argv: kubectl create --dry-run | apply
apply_cm() { name=$1; shift; k create configmap "$name" "$@" --dry-run=client -o yaml | k apply -f - >/dev/null; }

up() {
  # createrole: Least-Privilege-Login (Standard). superuser: Umgehung für PG 16+, wo jede von einem
  # CREATEROLE-Login angelegte Rolle eine implizite ADMIN-Mitgliedschaft des Logins bekommt (docs/lab.md).
  case ${LAB_PG_ADMIN:-createrole} in
    createrole) attr=NOSUPERUSER ;; superuser) attr=SUPERUSER ;;
    *) echo "LAB_PG_ADMIN must be createrole or superuser" >&2; exit 2 ;;
  esac
  kc get namespace "$ns" >/dev/null 2>&1 || kc create namespace "$ns" >/dev/null
  # Einmalige Geheimnisse und TLS: nur anlegen, wenn sie fehlen (sonst laufende Pods inkonsistent).
  k get secret openbao-root >/dev/null 2>&1 || rand | k create secret generic openbao-root --from-file=token=/dev/stdin >/dev/null
  k get secret postgres-superuser >/dev/null 2>&1 ||
    rand | k create secret generic postgres-superuser --from-file=password=/dev/stdin >/dev/null
  if ! k get secret openbao-tls >/dev/null 2>&1; then
    tls=$(mktemp -d)
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=ordivus-lab-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -keyout "$tls/ca.key" -out "$tls/ca.crt" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=openbao.ordivus-lab.svc -keyout "$tls/tls.key" -out "$tls/tls.csr" 2>/dev/null
    printf 'subjectAltName=DNS:openbao,DNS:openbao.ordivus-lab.svc,DNS:openbao.ordivus-lab.svc.cluster.local,DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' >"$tls/ext"
    openssl x509 -req -in "$tls/tls.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" -CAcreateserial -days 365 \
      -extfile "$tls/ext" -out "$tls/tls.crt" 2>/dev/null
    k create secret tls openbao-tls --cert="$tls/tls.crt" --key="$tls/tls.key" >/dev/null
    apply_cm openbao-ca --from-file=ca.crt="$tls/ca.crt"
    rm -rf "$tls"
    # Neues Zertifikat: OpenBao neu starten (in-memory, der Bootstrap unten richtet alles wieder ein).
    k rollout restart deploy/openbao >/dev/null 2>&1 || true
  fi
  k apply -f lab/openbao.yaml -f lab/postgres.yaml >/dev/null
  k rollout status deploy/openbao deploy/postgres --timeout=180s >/dev/null
  bootstrap_openbao
  bootstrap_postgres
  apply_cm ordivus-lab-policy --from-file=policy.yaml=lab/policy.yaml
  apply_cm ordivus-lab-auth-readonly --from-file=auth.yaml=lab/config/auth-readonly.yaml
  apply_cm ordivus-lab-auth-apply --from-file=auth.yaml=lab/config/auth-apply.yaml
  k get configmap ordivus-lab-config >/dev/null 2>&1 || scale 3
  helm --kube-context "$ctx" upgrade --install ordivus charts/ordivus -n "$ns" -f lab/values.yaml >/dev/null
  echo "lab up: namespace $ns, context $ctx, config scale $(k get configmap ordivus-lab-config -o 'jsonpath={.metadata.annotations.lab/scale}')"
}

# Dev-Modus ist in-memory: nach jedem Pod-Neustart fehlt alles, daher bei jedem up komplett und idempotent.
bootstrap_openbao() {
  pgpw=$(rand)
  # Neues Admin-Passwort bei jedem up: KV und PostgreSQL bleiben so auch nach einem OpenBao-Neustart konsistent.
  tokens=$(bao_root <<EOF
set -e
bao auth list -format=json | grep -q '"kubernetes/"' || bao auth enable kubernetes >/dev/null
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc >/dev/null
bao policy write lab-kv-readonly - >/dev/null <<'P'
path "secret/metadata/lab/*" { capabilities = ["read"] }
path "secret/data/lab/*"     { capabilities = ["read"] }
P
bao policy write lab-kv-apply - >/dev/null <<'P'
path "secret/metadata/lab/*"     { capabilities = ["read"] }
path "secret/data/lab/admin/*"   { capabilities = ["read"] }
path "secret/data/lab/users/*"   { capabilities = ["read", "create"] }
P
bao policy write lab-policy-reader - >/dev/null <<'P'
path "sys/policies/acl"   { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }
P
bao policy write lab-policy-admin - >/dev/null <<'P'
path "sys/policies/acl"         { capabilities = ["list"] }
path "sys/policies/acl/*"       { capabilities = ["read"] }
path "sys/policies/acl/app-*"   { capabilities = ["create", "read", "update", "delete"] }
P
for m in readonly apply; do
  p=lab-kv-readonly; [ \$m = apply ] && p=lab-kv-apply
  bao write auth/kubernetes/role/ordivus-\$m bound_service_account_names=ordivus-\$m \
    bound_service_account_namespaces=$ns audience=openbao token_policies=\$p token_ttl=15m token_max_ttl=30m >/dev/null
done
bao kv put secret/lab/admin/postgres password='$pgpw' >/dev/null
echo "readonly \$(bao token create -orphan -period=24h -policy=lab-policy-reader -field=token)"
echo "apply \$(bao token create -orphan -period=24h -policy=lab-policy-admin -field=token)"
EOF
)
  for m in readonly apply; do
    printf "%s\n" "$tokens" | awk -v m="$m" '$1 == m {printf "%s", $2}' |
      k create secret generic "lab-openbao-token-$m" --from-file=openbao-policy-token=/dev/stdin --dry-run=client -o yaml |
      k apply -f - >/dev/null
  done
}

bootstrap_postgres() {
  psql_admin <<EOF
SELECT 'CREATE ROLE ordivus_admin LOGIN CREATEROLE CREATEDB'
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ordivus_admin') \gexec
ALTER ROLE ordivus_admin $attr PASSWORD '$pgpw';
\c template1
SET client_min_messages = warning;
-- Jede neue Datenbank bekommt eine Tabelle, damit tables-in-schema-Grants beobachtbar sind (sonst ewig CREATE).
CREATE TABLE IF NOT EXISTS public.lab_items (id int PRIMARY KEY, note text);
ALTER TABLE public.lab_items OWNER TO ordivus_admin;
EOF
}

# resources.yaml für N Datenbanken; Variante b (race diff) ändert Rollenmenge und Mitgliedschaften.
gen_resources() {
  n=$1 v=${2:-a} i=1
  while [ "$i" -le "$n" ]; do
    d=$(printf 'db%03d' "$i")
    member=lab_${d}_rw
    [ "$v" = b ] && member=lab_${d}_ro
    cat <<EOF
apiVersion: ordivus.dev/v1alpha1
kind: Database
metadata: {name: lab-$d}
spec: {targetRef: lab-postgres, name: lab_$d}
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseRole
metadata: {name: lab-$d-ro}
spec: {targetRef: lab-postgres, name: lab_${d}_ro}
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseRole
metadata: {name: lab-$d-rw}
spec: {targetRef: lab-postgres, name: lab_${d}_rw}
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata: {name: lab-$d-app}
spec: {providerRef: openbao, path: lab/users/$d-app}
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata: {name: lab-$d-app}
spec:
  targetRef: lab-postgres
  name: lab_${d}_app
  memberOf: [$member]
  credentials: {credentialRef: lab-$d-app}
---
apiVersion: ordivus.dev/v1alpha1
kind: OpenBaoPolicy
metadata: {name: app-lab-$d-read}
spec:
  targetRef: lab-openbao
  policyName: app-lab-$d-read
  rules: [{path: "secret/data/lab/users/$d-*", capabilities: [read]}]
---
EOF
    for r in ro rw; do
      tables=SELECT; dbp=CONNECT
      [ "$r" = rw ] && tables="SELECT, INSERT, UPDATE, DELETE" && dbp="CONNECT, TEMPORARY"
      cat <<EOF
apiVersion: ordivus.dev/v1alpha1
kind: Grant
metadata: {name: lab-$d-$r-database}
spec: {targetRef: lab-postgres, grantee: lab_${d}_$r, database: lab_$d, on: database, privileges: [$dbp]}
---
apiVersion: ordivus.dev/v1alpha1
kind: Grant
metadata: {name: lab-$d-$r-schema}
spec: {targetRef: lab-postgres, grantee: lab_${d}_$r, database: lab_$d, on: schema, schema: public, privileges: [USAGE]}
---
apiVersion: ordivus.dev/v1alpha1
kind: Grant
metadata: {name: lab-$d-$r-tables}
spec: {targetRef: lab-postgres, grantee: lab_${d}_$r, database: lab_$d, on: tables-in-schema, schema: public, privileges: [$tables]}
---
EOF
    done
    if [ "$v" = b ]; then
      cat <<EOF
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseRole
metadata: {name: lab-$d-audit}
spec: {targetRef: lab-postgres, name: lab_${d}_audit, connectionLimit: 2}
---
EOF
    fi
    i=$((i + 1))
  done
}

write_config() {  # name n variant
  gen_resources "$2" "$3" >"$out/resources-$1.yaml"
  apply_cm "$1" --from-file=base.yaml=lab/config/base.yaml --from-file=resources.yaml="$out/resources-$1.yaml"
  k annotate configmap "$1" --overwrite "lab/scale=$2" "lab/variant=$3" >/dev/null
}

scale() {
  case ${1:-} in ''|*[!0-9]*) echo "usage: $0 scale N" >&2; exit 2 ;; esac
  write_config ordivus-lab-config "$1" a
  echo "config: $1 x (1 database, 2 roles, 1 user + KV secret, 6 grants, 1 OpenBao policy)"
}

# Entfernt alles, was die Lab-Config anlegt (Datenbanken, Rollen, KV-Secrets, app-*-Policies) – für Erstlauf-Messungen.
reset() {
  psql_admin <<'EOF'
SELECT format('DROP DATABASE %I WITH (FORCE)', datname) FROM pg_database WHERE datname LIKE 'lab\_%' \gexec
SELECT format('DROP ROLE %I', rolname) FROM pg_roles WHERE rolname LIKE 'lab\_%' ORDER BY rolcanlogin DESC \gexec
EOF
  bao_root <<'EOF'
for key in $(bao kv list -format=json secret/lab/users 2>/dev/null | tr -d '[]",' ); do bao kv metadata delete "secret/lab/users/$key" >/dev/null; done
for p in $(bao policy list | grep '^app-lab-'); do bao policy delete "$p" >/dev/null; done
EOF
  echo "reset: lab databases, roles, KV users and app-lab policies removed"
}

# Summe aller je aufgebauten PostgreSQL-Sessions (pg_stat_database.sessions, PG 14+); die Differenz um einen Lauf
# zählt dessen Verbindungen (minus 1 für diese Abfrage selbst).
sessions() { k exec deploy/postgres -- psql -Atq -U postgres -c "SELECT sum(sessions) FROM pg_stat_database"; }

# Engine-Dauer (startedAt/finishedAt des Reports), Targets, Aktionen.
summary() {  # report-file
  jq -r 'def ts: capture("^(?<s>[^.]+)(?<f>\\.[0-9]+)?Z$") | ((.s + "Z") | fromdate) + ((.f // "0") | tonumber);
    "  engine \(((.run.finishedAt | ts) - (.run.startedAt | ts)) * 10 | round / 10)s, targets: "
      + ([.targets[] | "\(.targetId)=\(.status)" + (if .reason then " (\(.reason))" else "" end)] | join(", ")),
    "  actions: " + (.summary.actions | to_entries | map(select(.value > 0) | "\(.key)=\(.value)") | join(" ")),
    "  failed=\(.summary.failed) unverified=\(.summary.unverified) targetErrors=\(.summary.targetErrors)"' "$1"
}

run() {
  mode=${1:-}
  case $mode in plan|drift|apply) ;; *) echo "usage: $0 run plan|drift|apply" >&2; exit 2 ;; esac
  s0=$(sessions) t0=$(now) rc=0
  ORDIVUS_KUBE_CONTEXT=$ctx ORDIVUS_REPORT_DIR=$out ORDIVUS_RUN_ID="lab-$(date +%H%M%S)-$$" \
    scripts/run-job.sh "$mode" "$ns" >/dev/null 2>"$out/$mode.stderr" || rc=$?
  t1=$(now)
  conns=$(( $(sessions) - s0 - 1 ))
  echo "$mode: exit $rc, wall $(echo "$t1 $t0" | awk '{printf "%.1f", $1 - $2}')s (job incl. pod start), PG sessions opened $conns, scale $(k get configmap ordivus-lab-config -o 'jsonpath={.metadata.annotations.lab/scale}')"
  if [ -s "$out/$mode.json" ]; then summary "$out/$mode.json"; else tail -n 20 "$out/$mode.stderr"; fi
  echo "  report: $out/$mode.json, logs: $out/$mode.log"
  return "$rc"
}

# Prüft für jeden App-User der Lab-Config: KV-Passwort vorhanden und Login in PostgreSQL damit möglich.
# Die Passwörter laufen nur durch die Pipe zwischen den beiden Pods, nie in Ausgabe oder Dateien.
check_secrets() {
  bao_root <<'EOF' | k exec -i deploy/postgres -- sh -c '
ok=0 bad=0
while read -r key pw; do
  u="lab_$(echo "$key" | tr - _)"
  if PGPASSWORD="$pw" psql -Atq -h 127.0.0.1 -U "$u" -d postgres -c "SELECT 1" >/dev/null 2>&1; then ok=$((ok+1)); else bad=$((bad+1)); echo "  MISMATCH $u"; fi
done
echo "secrets: $ok match, $bad mismatch (KV password vs. PostgreSQL login)"'
for key in $(bao kv list -format=json secret/lab/users 2>/dev/null | tr -d '[]",'); do
  echo "$key $(bao kv get -field=password "secret/lab/users/$key")"
done
EOF
}

# Zwei apply-Jobs gleichzeitig: same = gleiche Config, diff = zweiter Job mit Variante b (andere Rollen/Mitgliedschaften).
race() {
  variant=${1:-same} n=${2:-20}
  case $variant in same|diff) ;; *) echo "usage: $0 race [same|diff] [N]" >&2; exit 2 ;; esac
  reset >/dev/null
  write_config ordivus-lab-config "$n" a
  second=ordivus-lab-config
  if [ "$variant" = diff ]; then second=ordivus-lab-config-b; write_config "$second" "$n" b; fi
  id=$(date +%H%M%S)
  for x in a b; do
    cm=ordivus-lab-config; [ "$x" = b ] && cm=$second
    k create job "ordivus-apply-race-$id-$x" --from=cronjob/ordivus-apply --dry-run=client -o json |
      jq --arg cm "$cm" '(.spec.template.spec.volumes[] | select(.name == "lab-config") | .projected.sources[0].configMap.name) = $cm' \
      >"$out/race-$x.job.json"
  done
  s0=$(sessions) t0=$(now)
  k create -f "$out/race-a.job.json" -f "$out/race-b.job.json" >/dev/null  # ein Aufruf: Jobs Millisekunden auseinander
  echo "race ($variant, scale $n): jobs ordivus-apply-race-$id-a (ordivus-lab-config) and -b ($second) created"
  for x in a b; do
    j=ordivus-apply-race-$id-$x
    until k get job "$j" -o 'jsonpath={.status.conditions[?(@.status=="True")].type}' | grep -Eq 'Complete|Failed'; do sleep 1; done
    pod=$(k get pods -l "job-name=$j" -o 'jsonpath={.items[0].metadata.name}')
    k logs "pod/$pod" >"$out/race-$x.log" 2>&1 || true
    jq -cR 'fromjson? | select(type == "object" and .type == "report")' "$out/race-$x.log" >"$out/race-$x.json" || true
    code=$(k get pod "$pod" -o 'jsonpath={.status.containerStatuses[0].state.terminated.exitCode}')
    times=$(k get pod "$pod" -o 'jsonpath={.status.containerStatuses[0].state.terminated.startedAt} {.status.containerStatuses[0].state.terminated.finishedAt}')
    echo "job $x: exit $code, container $times"
    if [ -s "$out/race-$x.json" ]; then summary "$out/race-$x.json"; else tail -n 5 "$out/race-$x.log"; fi
  done
  echo "PG sessions opened $(( $(sessions) - s0 - 1 )) (both jobs), total wall $(echo "$(now) $t0" | awk '{printf "%.1f", $1 - $2}')s"
  check_secrets
}

down() {
  helm --kube-context "$ctx" uninstall ordivus -n "$ns" --ignore-not-found >/dev/null 2>&1 || true
  kc delete clusterrolebinding ordivus-lab-openbao-auth-delegator --ignore-not-found >/dev/null
  kc delete namespace "$ns" --ignore-not-found
}

case ${1:-} in
  up) up ;;
  run) run "${2:-}" ;;
  scale) scale "${2:-}" ;;
  reset) reset ;;
  race) race "${2:-same}" "${3:-20}" ;;
  check-secrets) check_secrets ;;
  down) down ;;
  *) echo "usage: $0 up | run plan|drift|apply | scale N | reset | race [same|diff] [N] | check-secrets | down" >&2; exit 2 ;;
esac
