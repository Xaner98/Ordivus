#!/bin/sh
# Startet genau einen Ordivus-Lauf aus der suspendierten Vorlage cronjob/<release>-<mode>,
# wartet auf das Ende, legt Logs und Report ab und endet mit dem Exit-Code des Containers.
#
# Usage: scripts/run-job.sh MODE NAMESPACE [RELEASE]
#   MODE       plan | drift | apply
#   RELEASE    Helm-Release-Name (Standard: ordivus)
# Env:
#   ORDIVUS_RUN_ID      Lauf-ID für den Job-Namen (Standard: CI_JOB_ID, BUILD_TAG, sonst Zeitstempel)
#   ORDIVUS_TIMEOUT     Wartezeit in Sekunden (Standard: 2100)
#   ORDIVUS_REPORT_DIR  Zielverzeichnis (Standard: reports) -> <mode>.json (Report), <mode>.log (alle Logs)
#   KUBECTL             kubectl-Binary (Standard: kubectl)
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
timeout=${ORDIVUS_TIMEOUT:-2100}
dir=${ORDIVUS_REPORT_DIR:-reports}
run_id=${ORDIVUS_RUN_ID:-${CI_JOB_ID:-${BUILD_TAG:-$(date -u +%Y%m%d%H%M%S)}}}
# Lauf-ID auf DNS-1123 bringen: klein, nur [a-z0-9-], Gesamtname max. 63 Zeichen.
run_id=$(printf '%s' "$run_id" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tr -s '-' | sed 's/^-*//')
job=$(printf '%s' "$release-$mode-$run_id" | cut -c1-63 | sed 's/-*$//')
printf '%s\n' "$job" | grep -Eq "$dns1123" || { echo "cannot build job name from run id" >&2; exit 2; }

mkdir -p "$dir"
collect() {
  "$kubectl" -n "$ns" logs "job/$job" >"$dir/$mode.log" 2>/dev/null || true
  cat "$dir/$mode.log" >&2
  if grep '^{"type":"report"' "$dir/$mode.log" >"$dir/$mode.json.tmp"; then
    mv "$dir/$mode.json.tmp" "$dir/$mode.json"
    echo "report: $dir/$mode.json" >&2
  else
    rm -f "$dir/$mode.json.tmp"
    echo "no report found in job logs" >&2
  fi
}
interrupted() {
  echo "interrupted, collecting logs and deleting job/$job" >&2
  collect
  "$kubectl" -n "$ns" delete job "$job" --wait=false >&2 || true
  exit "$1"
}
trap 'interrupted 130' INT
trap 'interrupted 143' TERM

"$kubectl" -n "$ns" create job "$job" --from="cronjob/$release-$mode" >&2
echo "waiting for job/$job (timeout ${timeout}s)" >&2

start=$(date +%s)
while :; do
  state=$("$kubectl" -n "$ns" get job "$job" -o 'jsonpath={.status.conditions[?(@.status=="True")].type}') || state=""  # API-Aussetzer: weiter warten
  case " $state " in *" Complete "*|*" Failed "*) break ;; esac
  if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
    echo "timeout after ${timeout}s; job/$job left running" >&2
    collect
    exit 1
  fi
  sleep 3
done

collect
code=$("$kubectl" -n "$ns" get pods -l "job-name=$job" \
  -o 'jsonpath={.items[0].status.containerStatuses[0].state.terminated.exitCode}')
if [ -z "$code" ]; then
  echo "job/$job finished without container exit code (state $state), e.g. deadline exceeded" >&2
  exit 1
fi
echo "job/$job exit code $code" >&2
exit "$code"
