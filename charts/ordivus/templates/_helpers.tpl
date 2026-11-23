{{- define "ordivus.labels" -}}
app.kubernetes.io/name: ordivus
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "ordivus.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end }}

{{- define "ordivus.configMapName" -}}
{{- if eq .Values.configuration.source "inline" -}}
{{ .Release.Name }}-configuration
{{- else if eq .Values.configuration.source "configMap" -}}
{{ required "configuration.name is required for configuration.source=configMap" .Values.configuration.name }}
{{- else -}}
{{ fail "configuration.source must be configMap or inline" }}
{{- end -}}
{{- end }}

{{/* Namespace für CronJob, ServiceAccount und Credentials des apply-Modus (Standard: Release-Namespace). */}}
{{- define "ordivus.applyNamespace" -}}
{{ .Values.jobs.templates.apply.namespace | default .Release.Namespace }}
{{- end }}

{{/* Namespaces mit Ordivus-Pods (für ConfigMap inline und NetworkPolicy). Ausgabe: JSON-Liste. */}}
{{- define "ordivus.namespaces" -}}
{{- $l := list .Release.Namespace -}}
{{- if .Values.jobs.templates.apply.enabled }}{{ $l = append $l (include "ordivus.applyNamespace" .) }}{{ end -}}
{{ uniq $l | toJson }}
{{- end }}

{{/* ipBlock einer Egress-Regel; ohne except wird die Cloud-Metadaten-Adresse ausgenommen, wenn sie im Block liegt. */}}
{{- define "ordivus.ipBlock" -}}
{{- $cidr := required "networkPolicy cidr is required" .cidr | toString -}}
{{- if not (contains "/" $cidr) }}{{ fail (printf "networkPolicy cidr %q needs a prefix length" $cidr) }}{{ end -}}
{{- $bits := atoi (last (splitList "/" $cidr)) -}}
{{- $except := list -}}
{{- if hasKey . "except" -}}
{{- $except = .except -}}
{{- else if contains ":" $cidr -}}
{{- /* shortcut: IPv6 nur fd00::/8 oder breiter mit Präfix "fd" erkannt; bei anderen Blöcken except selbst setzen */ -}}
{{- if and (le $bits 8) (hasPrefix "fd" (lower $cidr)) }}{{ $except = list "fd00:ec2::254/128" }}{{ end -}}
{{- else if lt $bits 32 -}}
{{- $n := 0 -}}
{{- range (splitList "." (first (splitList "/" $cidr))) }}{{ $n = add (mul $n 256) (atoi .) }}{{ end -}}
{{- $size := 1 -}}
{{- range until (sub 32 $bits | int) }}{{ $size = mul $size 2 }}{{ end -}}
{{- /* 169.254.169.254 = 2852039166 */ -}}
{{- if eq (div $n $size) (div 2852039166 $size) }}{{ $except = list "169.254.169.254/32" }}{{ end -}}
{{- end -}}
ipBlock:
  cidr: {{ $cidr | quote }}
  {{- with $except }}
  except: {{- range . }}
    - {{ . | quote }}
  {{- end }}
  {{- end }}
{{- end }}

{{/* Prüfungen für alle Profile und das Profil hardened. */}}
{{- define "ordivus.validate" -}}
{{- $v := .Values -}}
{{- $apply := $v.jobs.templates.apply -}}
{{- if or $v.env $v.extraVolumes $v.extraVolumeMounts }}{{ fail "global env/extraVolumes/extraVolumeMounts were removed; set them per mode under jobs.templates.<mode> (and jobs.scheduledDrift)" }}{{ end -}}
{{- if eq $v.security.readOnlyServiceAccount $v.security.applyServiceAccount }}{{ fail "security.readOnlyServiceAccount and security.applyServiceAccount must differ" }}{{ end -}}
{{- if and $apply.enabled (not $apply.suspended) (not $apply.allowSchedule) }}{{ fail "jobs.templates.apply.suspended=false requires jobs.templates.apply.allowSchedule=true" }}{{ end -}}
{{- if eq $v.security.profile "hardened" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" ($v.image.digest | toString)) }}{{ fail "security.profile=hardened requires image.digest sha256:<64 hex>" }}{{ end -}}
{{- if not (or $v.policy.configMap $v.policy.secret) }}{{ fail "security.profile=hardened requires policy.configMap or policy.secret" }}{{ end -}}
{{- if not $v.security.networkPolicy.enabled }}{{ fail "security.profile=hardened requires security.networkPolicy.enabled" }}{{ end -}}
{{- range $mode := list "plan" "drift" "apply" }}
{{- $t := index $v.jobs.templates $mode }}
{{- if and $t.enabled $t.automountServiceAccountToken }}{{ fail (printf "security.profile=hardened forbids jobs.templates.%s.automountServiceAccountToken=true (use projectedToken)" $mode) }}{{ end -}}
{{- end -}}
{{- if and $v.jobs.scheduledDrift.enabled $v.jobs.scheduledDrift.automountServiceAccountToken }}{{ fail "security.profile=hardened forbids jobs.scheduledDrift.automountServiceAccountToken=true (use projectedToken)" }}{{ end -}}
{{- range $v.security.networkPolicy.egress }}
{{- if not .ports }}{{ fail (printf "security.profile=hardened requires ports for networkPolicy egress %v" .cidr) }}{{ end -}}
{{- if hasSuffix "/0" (toString .cidr) }}{{ fail (printf "security.profile=hardened forbids networkPolicy egress %v" .cidr) }}{{ end -}}
{{- end -}}
{{- if $apply.enabled -}}
{{- if not $apply.suspended }}{{ fail "security.profile=hardened requires jobs.templates.apply.suspended=true" }}{{ end -}}
{{- if not (or $v.admission.enabled (ne (include "ordivus.applyNamespace" .) .Release.Namespace)) }}{{ fail "security.profile=hardened requires jobs.templates.apply.namespace (other than the release namespace) or admission.enabled" }}{{ end -}}
{{- end -}}
{{- else if not (has $v.security.profile (list "development" "standard")) -}}
{{- fail "security.profile must be development, standard or hardened" -}}
{{- end -}}
{{- end }}

{{/* CronJob für einen Modus. Aufruf: dict "root" $ "name" <suffix> "mode" <plan|drift|apply> "t" <template values> "suspend" <bool> */}}
{{- define "ordivus.cronJob" -}}
{{- $v := .root.Values -}}
{{- $apply := eq .mode "apply" -}}
{{- $creds := ternary $v.credentials.apply $v.credentials.readOnly $apply -}}
{{- $policy := or $v.policy.configMap $v.policy.secret -}}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ printf "%s-%s" .root.Release.Name .name | quote }}
  namespace: {{ ternary (include "ordivus.applyNamespace" .root) .root.Release.Namespace $apply | quote }}
  labels:
    {{- include "ordivus.labels" .root | nindent 4 }}
    app.kubernetes.io/component: {{ .name | quote }}
spec:
  schedule: {{ .t.schedule | quote }}
  suspend: {{ .suspend }}
  concurrencyPolicy: Forbid
  jobTemplate:
    metadata:
      labels:
        {{- include "ordivus.labels" .root | nindent 8 }}
        app.kubernetes.io/component: {{ .name | quote }}
        ordivus.dev/mode: {{ .mode | quote }}
    spec:
      backoffLimit: {{ $v.execution.backoffLimit | int }}
      activeDeadlineSeconds: {{ $v.execution.timeoutSeconds | int }}
      ttlSecondsAfterFinished: {{ $v.execution.ttlSecondsAfterFinished | int }}
      template:
        metadata:
          labels:
            {{- include "ordivus.labels" .root | nindent 12 }}
            app.kubernetes.io/component: {{ .name | quote }}
            ordivus.dev/mode: {{ .mode | quote }}
            ordivus.dev/profile: {{ $v.security.profile | quote }}
        spec:
          restartPolicy: Never
          serviceAccountName: {{ ternary $v.security.applyServiceAccount $v.security.readOnlyServiceAccount $apply | quote }}
          automountServiceAccountToken: {{ .t.automountServiceAccountToken | toJson }}
          enableServiceLinks: false
          terminationGracePeriodSeconds: {{ $v.execution.terminationGracePeriodSeconds | int }}
          {{- with $v.imagePullSecrets }}
          imagePullSecrets: {{- toYaml . | nindent 12 }}
          {{- end }}
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            fsGroup: 10001
            seccompProfile: {type: RuntimeDefault}
          {{- with $v.nodeSelector }}
          nodeSelector: {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with $v.tolerations }}
          tolerations: {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with $v.affinity }}
          affinity: {{- toYaml . | nindent 12 }}
          {{- end }}
          containers:
            - name: ordivus
              image: {{ include "ordivus.image" .root | quote }}
              imagePullPolicy: {{ $v.image.pullPolicy | quote }}
              args:
                - {{ .mode | quote }}
                - -f
                - /config
                - --format
                - json
                {{- if $policy }}
                - --policy
                - {{ printf "/policy/%s" $v.policy.key | quote }}
                {{- end }}
                {{- range .t.extraArgs }}
                - {{ . | quote }}
                {{- end }}
              {{- with .t.env }}
              env: {{- toYaml . | nindent 16 }}
              {{- end }}
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                capabilities: {drop: ["ALL"]}
                seccompProfile: {type: RuntimeDefault}
              resources: {{- toYaml $v.resources | nindent 16 }}
              volumeMounts:
                - {name: config, mountPath: /config, readOnly: true}
                - {name: tmp, mountPath: /tmp}
                {{- if $policy }}
                - {name: policy, mountPath: /policy, readOnly: true}
                {{- end }}
                {{- if $creds }}
                - {name: credentials, mountPath: {{ $v.credentials.mountPath | quote }}, readOnly: true}
                {{- end }}
                {{- if .t.projectedToken.enabled }}
                - {name: sa-token, mountPath: {{ .t.projectedToken.mountPath | quote }}, readOnly: true}
                {{- end }}
                {{- with .t.extraVolumeMounts }}
                {{- toYaml . | nindent 16 }}
                {{- end }}
          volumes:
            - name: config
              configMap:
                name: {{ include "ordivus.configMapName" .root | quote }}
            - name: tmp
              emptyDir: {sizeLimit: 64Mi}
            {{- if $v.policy.configMap }}
            - name: policy
              configMap: {name: {{ $v.policy.configMap | quote }}}
            {{- else if $v.policy.secret }}
            - name: policy
              secret: {secretName: {{ $v.policy.secret | quote }}}
            {{- end }}
            {{- if $creds }}
            - name: credentials
              {{- toYaml $creds | nindent 14 }}
            {{- end }}
            {{- if .t.projectedToken.enabled }}
            - name: sa-token
              projected:
                sources:
                  - serviceAccountToken:
                      path: token
                      audience: {{ required "projectedToken.audience is required" .t.projectedToken.audience | quote }}
                      expirationSeconds: {{ .t.projectedToken.expirationSeconds | int }}
            {{- end }}
            {{- with .t.extraVolumes }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
{{- end }}

{{/* CEL-Ausdruck: Feld unter .path enthält mindestens die Werte aus .value (Defaults des API-Servers bleiben
     erlaubt); Listen von Objekten müssen gleich lang sein. Für die ValidatingAdmissionPolicy (admission.yaml). */}}
{{- define "ordivus.celMatch" -}}
{{- $p := .path -}}
{{- $v := .value -}}
{{- if kindIs "map" $v -}}
{{- $parts := list -}}
{{- range $k, $x := $v -}}
{{- if regexMatch "^[a-zA-Z_][a-zA-Z0-9_]*$" $k -}}
{{- $parts = append $parts (printf "has(%s.%s) && %s" $p $k (include "ordivus.celMatch" (dict "path" (printf "%s.%s" $p $k) "value" $x))) -}}
{{- else -}}
{{- $parts = append $parts (printf "%s in %s && %s" (toJson $k) $p (include "ordivus.celMatch" (dict "path" (printf "%s[%s]" $p (toJson $k)) "value" $x))) -}}
{{- end -}}
{{- end -}}
({{ $parts | join " && " | default "true" }})
{{- else if and (kindIs "slice" $v) $v (kindIs "map" (first $v)) -}}
{{- $parts := list (printf "%s.size() == %d" $p (len $v)) -}}
{{- range $i, $x := $v }}{{ $parts = append $parts (include "ordivus.celMatch" (dict "path" (printf "%s[%d]" $p $i) "value" $x)) }}{{ end -}}
({{ $parts | join " && " }})
{{- else -}}
{{ $p }} == {{ toJson $v }}
{{- end -}}
{{- end }}
