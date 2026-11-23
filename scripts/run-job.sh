#!/bin/sh
# Startet genau einen Ordivus-Lauf aus der suspendierten Vorlage cronjob/<release>-<mode>,
# wartet auf das Ende, legt Logs und Report ab und endet mit dem Exit-Code des Containers.
#
# Usage: scripts/run-job.sh MODE NAMESPACE [RELEASE]
#   MODE       plan | drift | apply
#   NAMESPACE  Namespace des CronJobs (für apply ggf. der eigene Apply-Namespace)
#   RELEASE    Helm-Release-Name (Standard: ordivus)
# Env:
#   ORDIVUS_KUBE_CONTEXT  kubectl-Kontext (--context); für apply Pflicht
#   ORDIVUS_RUN_ID        Lauf-ID für den Job-Namen (Standard: CI_JOB_ID, BUILD_TAG, sonst Zeitstempel)
#   ORDIVUS_TIMEOUT       Wartezeit in Sekunden (Standard: 2100)
#   ORDIVUS_REPORT_DIR    Zielverzeichnis (Standard: reports) -> <mode>.json (Report), <mode>.log (alle Logs)
#   KUBECTL               kubectl-Binary (Standard: kubectl)
set -eu

usage() { echo "usage: $0 plan|drift|apply NAMESPACE [RELEASE]" >&2; exit 2; }
[ $# -ge 2 ] && [ $# -le 3 ] || usage
mode=$1 ns=$2 release=${3:-ordivus}
case $mode in plan|drift|apply) ;; *) usage ;; esac
dns1123='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
for v in "$ns" "$release"; do
  printf '%s\n' "$v" | grep -Eq "$dns1123" || { echo "invalid DNS-1123 name: $v" >&2; exit 2; }
done

kubectl=${KUBECTL:-kubectl}
ctx=${ORDIVUS_KUBE_CONTEXT:-}
# apply nie gegen den zufällig aktuellen Kontext.
[ "$mode" != apply ] || [ -n "$ctx" ] || { echo "apply requires ORDIVUS_KUBE_CONTEXT" >&2; exit 2; }
k() { "$kubectl" ${ctx:+--context "$ctx"} -n "$ns" "$@"; }
timeout=${ORDIVUS_TIMEOUT:-2100}
dir=${ORDIVUS_REPORT_DIR:-reports}
run_id=${ORDIVUS_RUN_ID:-${CI_JOB_ID:-${BUILD_TAG:-$(date -u +%Y%m%d%H%M%S)}}}
# Lauf-ID auf DNS-1123 bringen: klein, nur [a-z0-9-], Gesamtname max. 63 Zeichen.
run_id=$(printf '%s' "$run_id" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tr -s '-' | sed 's/^-*//')
job=$(printf '%s' "$release-$mode-$run_id" | cut -c1-63 | sed 's/-*$//')
printf '%s\n' "$job" | grep -Eq "$dns1123" || { echo "cannot build job name from run id" >&2; exit 2; }

echo "context: ${ctx:-$("$kubectl" config current-context 2>/dev/null || echo '?') (current)}, namespace: $ns" >&2
mkdir -p "$dir"
# Kein veralteter Report aus einem früheren Lauf.
rm -f "$dir/$mode.json" "$dir/$mode.log"
reports=0 pod=""
# Report-Zeile: gültiges JSON-Objekt mit type "report" und schemaVersion. Ohne jq nur das exakte Präfix der
# Engine (core/report.py) mit schließender Klammer; eine Log-Zeile genau dieser Form zählt dann ebenfalls.
report_lines() {
  if command -v jq >/dev/null; then
    jq -rR '. as $l | fromjson? | select(type == "object" and .type == "report" and has("schemaVersion")) | $l' "$1"
  else
    grep -E '^\{"type":"report","schemaVersion":"[^"]+",.*\}$' "$1"
  fi
}
collect() {
  # Jüngster Pod des Jobs (bei backoffLimit > 0 kann es mehrere geben); Logs und Exit-Code stammen beide von ihm.
  pod=$(k get pods -l "job-name=$job" --sort-by=.metadata.creationTimestamp -o 'jsonpath={.items[-1:].metadata.name}' 2>/dev/null) || pod=""
  : >"$dir/$mode.log"
  [ -z "$pod" ] || k logs "pod/$pod" >"$dir/$mode.log" 2>/dev/null || true
  cat "$dir/$mode.log" >&2
  report_lines "$dir/$mode.log" >"$dir/$mode.json.tmp" || true
  reports=$(wc -l <"$dir/$mode.json.tmp" | tr -d ' ')
  if [ "$reports" -eq 1 ]; then
    mv "$dir/$mode.json.tmp" "$dir/$mode.json"
    echo "report: $dir/$mode.json" >&2
  else
    rm -f "$dir/$mode.json.tmp"
    echo "expected exactly one report in job logs, found $reports" >&2
  fi
}
interrupted() {
  echo "interrupted, collecting logs and deleting job/$job" >&2
  collect
  k delete job "$job" --wait=false >&2 || true
  exit "$1"
}
trap 'interrupted 130' INT
trap 'interrupted 143' TERM

# concurrencyPolicy: Forbid greift nicht für manuell erzeugte Jobs: kein zweites apply aus derselben Vorlage.
# shortcut: Prüfen und Anlegen sind nicht atomar; echte Serialisierung gehört in die CI (resource_group/lock).
if [ "$mode" = apply ] && [ "${ORDIVUS_ALLOW_CONCURRENT:-}" != 1 ]; then
  running=$(k get jobs -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=apply" \
    -o 'jsonpath={range .items[*]}{.metadata.name} {.status.conditions[?(@.status=="True")].type}{"\n"}{end}') ||
    { echo "cannot list apply jobs; refusing to start (override: ORDIVUS_ALLOW_CONCURRENT=1)" >&2; exit 1; }
  running=$(printf '%s\n' "$running" | grep -Ev ' .*(Complete|Failed)' | cut -d' ' -f1 | grep . | tr '\n' ' ') || true
  if [ -n "$running" ]; then
    echo "apply job still active: $running; refusing to start (override: ORDIVUS_ALLOW_CONCURRENT=1)" >&2
    exit 1
  fi
fi

k create job "$job" --from="cronjob/$release-$mode" >&2
echo "waiting for job/$job (timeout ${timeout}s)" >&2

start=$(date +%s)
while :; do
  state=$(k get job "$job" -o 'jsonpath={.status.conditions[?(@.status=="True")].type}') || state=""  # API-Aussetzer: weiter warten
  case " $state " in *" Complete "*|*" Failed "*) break ;; esac
  if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
    echo "timeout after ${timeout}s; job/$job left running" >&2
    collect
    exit 1
  fi
  sleep 3
done

collect
code=""
# API-Aussetzer nicht als Fehlschlag werten: bis zu dreimal lesen.
[ -z "$pod" ] || for _ in 1 2 3; do
  code=$(k get pod "$pod" -o 'jsonpath={.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null) && [ -n "$code" ] && break
  code="" && sleep 2
done
if [ -z "$code" ]; then
  echo "job/$job finished without container exit code (state $state), e.g. deadline exceeded" >&2
  exit 1
fi
echo "job/$job exit code $code" >&2
case " $state " in *" Failed "*) [ "$code" -ne 0 ] || { echo "job/$job failed although exit code is 0" >&2; exit 1; } ;; esac
# Ohne genau einen Report kein Erfolg; ein Fehler-Exit-Code des Containers bleibt erhalten.
[ "$reports" -eq 1 ] || [ "$code" -ne 0 ] || exit 1
exit "$code"
