{{- define "ordivus.labels" -}}
app.kubernetes.io/name: ordivus
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
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

{{/* CronJob für einen Modus. Aufruf: dict "root" $ "name" <suffix> "mode" <plan|drift|apply> "t" <template values> "suspend" <bool> */}}
{{- define "ordivus.cronJob" -}}
{{- $v := .root.Values -}}
{{- $apply := eq .mode "apply" -}}
{{- $creds := ternary $v.credentials.apply $v.credentials.readOnly $apply -}}
{{- $policy := or $v.policy.configMap $v.policy.secret -}}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ .root.Release.Name }}-{{ .name }}
  labels:
    {{- include "ordivus.labels" .root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
spec:
  schedule: {{ .t.schedule | quote }}
  suspend: {{ .suspend }}
  concurrencyPolicy: Forbid
  jobTemplate:
    metadata:
      labels:
        {{- include "ordivus.labels" .root | nindent 8 }}
        app.kubernetes.io/component: {{ .name }}
        ordivus.dev/mode: {{ .mode }}
    spec:
      backoffLimit: {{ $v.execution.backoffLimit }}
      activeDeadlineSeconds: {{ $v.execution.timeoutSeconds }}
      ttlSecondsAfterFinished: {{ $v.execution.ttlSecondsAfterFinished }}
      template:
        metadata:
          labels:
            {{- include "ordivus.labels" .root | nindent 12 }}
            app.kubernetes.io/component: {{ .name }}
            ordivus.dev/mode: {{ .mode }}
            ordivus.dev/profile: {{ $v.security.profile }}
        spec:
          restartPolicy: Never
          serviceAccountName: {{ ternary $v.security.applyServiceAccount $v.security.readOnlyServiceAccount $apply }}
          automountServiceAccountToken: {{ .t.automountServiceAccountToken }}
          terminationGracePeriodSeconds: {{ $v.execution.terminationGracePeriodSeconds }}
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
              imagePullPolicy: {{ $v.image.pullPolicy }}
              args:
                - {{ .mode }}
                - -f
                - /config
                - --format
                - json
                {{- if $policy }}
                - --policy
                - /policy/{{ $v.policy.key }}
                {{- end }}
                {{- range .t.extraArgs }}
                - {{ . | quote }}
                {{- end }}
              {{- with $v.env }}
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
                - {name: credentials, mountPath: {{ $v.credentials.mountPath }}, readOnly: {{ not $apply }}}
                {{- end }}
                {{- if .t.projectedToken.enabled }}
                - {name: sa-token, mountPath: {{ .t.projectedToken.mountPath }}, readOnly: true}
                {{- end }}
                {{- with $v.extraVolumeMounts }}
                {{- toYaml . | nindent 16 }}
                {{- end }}
          volumes:
            - name: config
              configMap:
                name: {{ include "ordivus.configMapName" .root }}
            - name: tmp
              emptyDir: {sizeLimit: 64Mi}
            {{- if $v.policy.configMap }}
            - name: policy
              configMap: {name: {{ $v.policy.configMap }}}
            {{- else if $v.policy.secret }}
            - name: policy
              secret: {secretName: {{ $v.policy.secret }}}
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
                      audience: {{ required "projectedToken.audience is required" .t.projectedToken.audience }}
                      expirationSeconds: {{ .t.projectedToken.expirationSeconds }}
            {{- end }}
            {{- with $v.extraVolumes }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
{{- end }}
