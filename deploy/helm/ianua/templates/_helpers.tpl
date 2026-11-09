{{/* Chart name. */}}
{{- define "ianua.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "ianua.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "ianua.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "ianua.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels for a component (pass dict with root + component). */}}
{{- define "ianua.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ianua.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Service account name. */}}
{{- define "ianua.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ianua.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The namespace code runs in: the one named, or the release's own with `-code`. */}}
{{- define "ianua.codeSandboxNamespace" -}}
{{- default (printf "%s-code" .Release.Namespace) .Values.codeSandboxes.namespace -}}
{{- end -}}

{{/* The Secret holding the network filter's key. */}}
{{- define "ianua.sandboxProxySecretName" -}}
{{- printf "%s-sandbox-proxy" (include "ianua.fullname" .) -}}
{{- end -}}

{{/*
SANDBOX_PROXY_KEY: given, kept, or 32 random bytes as base64. The worker and
the filter take exactly 32 bytes, written as 64 hex characters or as base64.
*/}}
{{- define "ianua.sandboxProxyKey" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.sandboxProxySecretName" .)
    "key" "SANDBOX_PROXY_KEY"
    "given" .Values.codeSandboxes.network.key
    "generated" (randBytes 32)
) -}}
{{- end -}}

{{/* The worker's account: its own while it runs code, the deployment's otherwise. */}}
{{- define "ianua.workerServiceAccountName" -}}
{{- if .Values.codeSandboxes.enabled -}}
{{- printf "%s-worker" (include "ianua.fullname" .) -}}
{{- else -}}
{{- include "ianua.serviceAccountName" . -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding app secrets. */}}
{{- define "ianua.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "ianua.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Image pull secret name. */}}
{{- define "ianua.imagePullSecretName" -}}
{{- if .Values.imagePullSecret.existingSecret -}}
{{- .Values.imagePullSecret.existingSecret -}}
{{- else -}}
{{- printf "%s-registry" (include "ianua.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the control plane's gRPC certificate, its key, and
the authority that signs the nameservers' certificates.

Always an existing Secret. The chart never templates this material: a private
key in values.yaml is a private key in version control, and this one authorises
reading every tenant's DNS records.
*/}}
{{- define "ianua.grpcPkiSecretName" -}}
{{- if not .Values.grpc.tls.existingSecret -}}
{{- fail "grpc.tls.existingSecret must name a Secret holding tls.crt, tls.key and ca.crt — create it with `kubectl create secret generic`, do not put the key in values.yaml" -}}
{{- end -}}
{{- .Values.grpc.tls.existingSecret -}}
{{- end -}}

{{/* Fully qualified image references. */}}
{{- define "ianua.serverImage" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.server $tag -}}
{{- end -}}

{{- define "ianua.zeroImage" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.zero $tag -}}
{{- end -}}

{{- define "ianua.runnerImage" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.runner $tag -}}
{{- end -}}

{{- define "ianua.egressImage" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.egress $tag -}}
{{- end -}}

{{- define "ianua.dnsImage" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.dns $tag -}}
{{- end -}}

{{/*
The names the nameservers answer with, comma-separated for DNS_NAMESERVERS.

Refuses fewer than two. A parent zone requires at least two nameservers, so a
single one produces delegations that registrars reject and resolvers treat as
lame — a failure that surfaces at the tenant, days later, as "my domain does
not work". Better to fail the release.
*/}}
{{- define "ianua.dnsNameservers" -}}
{{- if lt (len .Values.dns.nameservers) 2 -}}
{{- fail "dns.nameservers needs at least two entries: a parent zone requires at least two nameservers, on different addresses" -}}
{{- end -}}
{{- $names := list -}}
{{- range .Values.dns.nameservers -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- join "," $names -}}
{{- end -}}

{{/* The short label a nameserver's Service is named after: ns1.ianua.io -> ns1. */}}
{{- define "ianua.dnsShortName" -}}
{{- .name | splitList "." | first -}}
{{- end -}}

{{/*
"true" when this release is one organization's own installation, empty
otherwise. Refuses an unknown mode, and trusted domains on the hosted service,
where they would let any tenant claim any name beneath them — the server
refuses the same thing at startup, and failing here says so before anything
is deployed.
*/}}
{{- define "ianua.selfHosted" -}}
{{- $mode := .Values.deployment.mode -}}
{{- if not (has $mode (list "cloud" "selfHosted")) -}}
{{- fail (printf "deployment.mode must be cloud or selfHosted, got %q" $mode) -}}
{{- end -}}
{{- if and (eq $mode "cloud") .Values.selfHosted.trustedDomains -}}
{{- fail "selfHosted.trustedDomains is only allowed with deployment.mode=selfHosted: on a shared deployment it would let any tenant claim any name beneath those domains" -}}
{{- end -}}
{{- if eq $mode "selfHosted" -}}
true
{{- end -}}
{{- end -}}

{{/*
A secret value that must not change between releases: the one given in values,
else the one an earlier release stored under `key` in `secret`, else
`generated`.

Read back from the live Secret because these values cannot be regenerated
safely. A new ENCRYPTION_KEY leaves every stored key and certificate
unreadable, a new HMAC_SECRET signs out everyone, and a new owner password
would differ from the one the server was installed with. It needs a real
cluster to read from: `helm template` piped into `kubectl apply` has none, and
would generate fresh values on every run.

Takes a dict: root, secret, key, given, generated.
*/}}
{{- define "ianua.keptSecret" -}}
{{- if .given -}}
{{- .given -}}
{{- else -}}
{{- $live := lookup "v1" "Secret" .root.Release.Namespace .secret -}}
{{- $kept := dig "data" .key "" $live -}}
{{- if $kept -}}
{{- $kept | b64dec -}}
{{- else -}}
{{- .generated -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The Secret holding INSTALL_OWNER_PASSWORD: the one named in values, else the
chart's own. Only the install Job reads it: every other command refuses the
INSTALL_* settings.
*/}}
{{- define "ianua.installSecretName" -}}
{{- .Values.selfHosted.owner.existingSecret | default (printf "%s-install" (include "ianua.fullname" .)) -}}
{{- end -}}

{{/*
The owner's first password: given, kept in the install Secret, kept from the
chart Secret where releases before it held it, or generated. Always has an
uppercase letter, a lowercase letter and a digit when generated, which the
default password policy requires.
*/}}
{{- define "ianua.ownerPassword" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.installSecretName" .)
    "key" "INSTALL_OWNER_PASSWORD"
    "given" .Values.selfHosted.owner.password
    "generated" (include "ianua.keptSecret" (dict
        "root" .
        "secret" (include "ianua.secretName" .)
        "key" "INSTALL_OWNER_PASSWORD"
        "given" ""
        "generated" (printf "%s%s%s" (randAlpha 10 | upper) (randAlpha 10 | lower) (randNumeric 6))
    ))
) -}}
{{- end -}}

{{/*
HMAC_SECRET: given, kept, or 32 random bytes as base64. The server takes
exactly 32 bytes, written as 64 hex characters or as base64.
*/}}
{{- define "ianua.hmacSecret" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.secretName" .)
    "key" "HMAC_SECRET"
    "given" .Values.secrets.hmacSecret
    "generated" (randBytes 32)
) -}}
{{- end -}}

{{/* NATS_CREDS_TOKEN: given, kept, or 48 random characters. */}}
{{- define "ianua.natsToken" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.secretName" .)
    "key" "NATS_CREDS_TOKEN"
    "given" .Values.secrets.natsToken
    "generated" (randAlphaNum 48)
) -}}
{{- end -}}

{{/* ENCRYPTION_KEY: given, kept, or 32 random bytes as base64. */}}
{{- define "ianua.encryptionKey" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.secretName" .)
    "key" "ENCRYPTION_KEY"
    "given" .Values.secrets.encryptionKey
    "generated" (randBytes 32)
) -}}
{{- end -}}

{{/*
The Secret holding zero's fallback certificate: the one named in values, else
the one the chart generates when asked to, else none.
*/}}
{{/*
The Secret holding the internal links' certificates: one named by
internalLinks.existingSecret, or the one the chart generates once.
*/}}
{{- define "ianua.internalLinksSecretName" -}}
{{- if .Values.internalLinks.existingSecret -}}
{{- .Values.internalLinks.existingSecret -}}
{{- else -}}
{{- printf "%s-internal-links" (include "ianua.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The name the gateway dials the API's relay listener by. */}}
{{- define "ianua.relayHost" -}}
{{- printf "%s-server-internal" (include "ianua.fullname" .) -}}
{{- end -}}

{{/* The name the gateway's runner listener's certificate is for. */}}
{{- define "ianua.runnerHost" -}}
{{- printf "%s-zero-internal" (include "ianua.fullname" .) -}}
{{- end -}}

{{/* The name the worker dials the gateway's workflow listener by. */}}
{{- define "ianua.workflowHost" -}}
{{- printf "%s-zero-workflow" (include "ianua.fullname" .) -}}
{{- end -}}

{{/*
A volume of the internal links' Secret holding only the files `files` names,
so each pod gets its own key and never another's.
*/}}
{{- define "ianua.internalLinksVolume" -}}
- name: internal-links
  secret:
    secretName: {{ include "ianua.internalLinksSecretName" .root }}
    # Group-readable, not owner-only: the files are owned by root and the
    # container runs as 65532, which reaches them through fsGroup.
    defaultMode: 0440
    items:
      {{- range .files }}
      - key: {{ . }}
        path: {{ . }}
      {{- end }}
{{- end -}}

{{/* Where a pod reads its internal links' files. */}}
{{- define "ianua.internalLinksMount" -}}
- name: internal-links
  mountPath: /etc/ianua/internal
  readOnly: true
{{- end -}}

{{- define "ianua.zeroTlsSecretName" -}}
{{- if .Values.zero.tls.secretName -}}
{{- .Values.zero.tls.secretName -}}
{{- else if .Values.zero.tls.generateSelfSigned -}}
{{- printf "%s-zero-default-tls" (include "ianua.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Annotations for the Traefik routes when this chart installs Traefik itself.

The route kinds are defined by the Traefik chart's CRDs, which Helm creates at
the start of the very same install. On a first install Helm checks the routes
before the cluster has registered those kinds and fails the release, though a
second attempt succeeds. Applying the routes after everything else — as
post-install and post-upgrade hooks — lets the first install work.

Empty when Traefik is installed separately, as on the hosted service, where the
routes stay ordinary release resources.
*/}}
{{- define "ianua.routeHookAnnotations" -}}
{{- if .Values.edge.enabled -}}
annotations:
  helm.sh/hook: post-install,post-upgrade
  helm.sh/hook-delete-policy: before-hook-creation
{{- end -}}
{{- end -}}

{{/*
Where a forwarded client address is believed from.

`auto` reads the pod ranges off the cluster's nodes: the proxy in front of the
API is a pod, and the clients behind it never are, so that range trusts the
proxy and nobody else. A wider range would be wrong in the other direction —
trusting a company's 10.0.0.0/8 makes every employee look like a proxy, and the
audit trail records the proxy for all of them.

Where the nodes publish no range, as with network plugins that hand out pod
addresses from the wider network, `auto` trusts nothing: the API then records
the proxy's address until the range is set by hand. That is the safe failure.
*/}}
{{- define "ianua.trustedProxies" -}}
{{- $configured := .Values.config.trustedProxies -}}
{{- if eq $configured "auto" -}}
{{- $ranges := list -}}
{{- range (lookup "v1" "Node" "" "").items -}}
{{- $ranges = concat $ranges (.spec.podCIDRs | default (compact (list .spec.podCIDR))) -}}
{{- end -}}
{{- $ranges | uniq | join "," -}}
{{- else -}}
{{- $configured -}}
{{- end -}}
{{- end -}}

{{/*
The message bus every node shares: the bundled NATS, else externalBusUrl.
The API and the worker run apart, so the server refuses to start without one.
*/}}
{{- define "ianua.busUrl" -}}
{{- if .Values.nats.enabled -}}
{{- printf "nats://%s-nats:4222" (include "ianua.fullname" .) -}}
{{- else -}}
{{- required "a bus is required, since the API and the worker run apart: enable nats or set externalBusUrl" .Values.externalBusUrl -}}
{{- end -}}
{{- end -}}

{{/*
The cache every node shares: the bundled Redis, else externalCacheUrl. The
API and the worker run apart, so the server refuses to start without one.
*/}}
{{- define "ianua.cacheUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s-redis:6379" (include "ianua.fullname" .) -}}
{{- else -}}
{{- required "a cache is required, since the API and the worker run apart: enable redis or set externalCacheUrl" .Values.externalCacheUrl -}}
{{- end -}}
{{- end -}}

{{/*
Where the database owner's login comes from: "cnpg" (the bundled cluster's
superuser), "standalone" (the bundled plain Postgres's superuser), "external"
(a Secret holding MIGRATION_DATABASE_URL), or "" when there is none.
*/}}
{{- define "ianua.ownerLoginSource" -}}
{{- if and .Values.postgresql.enabled (eq .Values.postgresql.provider "cloudnativepg") .Values.postgresql.sealAuditLog -}}
cnpg
{{- else if and .Values.postgresql.enabled (eq .Values.postgresql.provider "standalone") -}}
standalone
{{- else if and (not .Values.postgresql.enabled) (or .Values.secrets.migrationDatabaseUrl .Values.secrets.migrationExistingSecret) -}}
external
{{- end -}}
{{- end -}}

{{/*
The Secret holding MIGRATION_DATABASE_URL for an external database. Separate
from the chart Secret every pod loads: only the worker and the jobs read it.
*/}}
{{- define "ianua.migrationSecretName" -}}
{{- .Values.secrets.migrationExistingSecret | default (printf "%s-migration" (include "ianua.fullname" .)) -}}
{{- end -}}

{{/*
The Secret holding AUDIT_PURGE_DATABASE_URL: the one named in values, else the
chart's own. Like the owner's, only the worker and the jobs read it.
*/}}
{{- define "ianua.auditPurgeSecretName" -}}
{{- .Values.secrets.auditPurgeExistingSecret | default (printf "%s-audit-purge" (include "ianua.fullname" .)) -}}
{{- end -}}

{{/*
The logins only the worker and the migrate, install, operator and demo jobs
hold: the database owner's, which migrates and makes tenants' schemas, the
audit purge's, the only role that may remove audit records, the gateway's,
whose role the migration makes, and with dns.enabled the nameservers'. An API pod
never holds any of them, and the server refuses to start one that does.
*/}}
{{- define "ianua.privilegedLoginEnv" -}}
{{- if not (include "ianua.ownerLoginSource" .) }}
{{- fail "the worker needs the database owner's login: set secrets.migrationDatabaseUrl or secrets.migrationExistingSecret, or use the bundled Postgres (with postgresql.sealAuditLog=true for CloudNativePG)" }}
{{- end }}
{{- include "ianua.ownerLoginEnv" . }}
- name: AUDIT_PURGE_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.auditPurgeSecretName" . }}
      key: AUDIT_PURGE_DATABASE_URL
{{- if .Values.dns.enabled }}
{{ include "ianua.nameserverLoginEnv" . }}
{{- end }}
{{ include "ianua.gatewayLoginEnv" . }}
{{- end -}}

{{/*
The Secret holding GATEWAY_DATABASE_URL: the one named in values, else the
chart's own. The worker and the jobs read it to make the gateway's role;
the gateway and the egress gateway sign in with it.
*/}}
{{- define "ianua.gatewaySecretName" -}}
{{- .Values.secrets.gatewayExistingSecret | default (printf "%s-gateway" (include "ianua.fullname" .)) -}}
{{- end -}}

{{/* GATEWAY_DATABASE_URL, the gateway's own login. */}}
{{- define "ianua.gatewayLoginEnv" -}}
- name: GATEWAY_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.gatewaySecretName" . }}
      key: GATEWAY_DATABASE_URL
{{- end -}}

{{/*
The Secret holding NAMESERVER_DATABASE_URL: the one named in values, else the
chart's own. The worker and the jobs read it to make the nameservers' role;
the nameserver pods sign in with it.
*/}}
{{- define "ianua.nameserverSecretName" -}}
{{- .Values.secrets.nameserverExistingSecret | default (printf "%s-nameserver" (include "ianua.fullname" .)) -}}
{{- end -}}

{{/* NAMESERVER_DATABASE_URL, the nameservers' own login. */}}
{{- define "ianua.nameserverLoginEnv" -}}
- name: NAMESERVER_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.nameserverSecretName" . }}
      key: NAMESERVER_DATABASE_URL
{{- end -}}

{{/* MIGRATION_DATABASE_URL, from wherever the owner's login comes from. */}}
{{- define "ianua.ownerLoginEnv" -}}
{{- $source := include "ianua.ownerLoginSource" . }}
{{- if eq $source "cnpg" }}
- name: PG_SUPERUSER_NAME
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.fullname" . }}-pg-superuser
      key: username
- name: PG_SUPERUSER_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.fullname" . }}-pg-superuser
      key: password
- name: MIGRATION_DATABASE_URL
  value: "postgresql://$(PG_SUPERUSER_NAME):$(PG_SUPERUSER_PASSWORD)@{{ include "ianua.fullname" . }}-pg-rw:5432/{{ .Values.postgresql.database }}"
{{- else if eq $source "standalone" }}
- name: MIGRATION_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.fullname" . }}-pg-app
      key: superuserUri
{{- else if eq $source "external" }}
- name: MIGRATION_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.migrationSecretName" . }}
      key: MIGRATION_DATABASE_URL
{{- end }}
{{- end -}}

{{/*
Whether the server and worker refuse to start against an audit log the
platform's own role could change or remove records from. Required by default.
*/}}
{{- define "ianua.auditSealEnv" -}}
- name: AUDIT_REQUIRE_SEALED
  value: {{ ternary "true" "false" .Values.audit.requireSealed | quote }}
{{- end -}}

{{/*
DATABASE_URL env entry. With a bundled database it reads the `uri` key of its
app secret; otherwise DATABASE_URL comes from the chart Secret via envFrom and
this emits nothing.
*/}}
{{- define "ianua.databaseUrlEnv" -}}
{{- if .Values.postgresql.enabled }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.fullname" . }}-pg-app
      key: uri
{{- end }}
{{- end -}}

{{/* Shared envFrom (non-secret config + secrets). */}}
{{- define "ianua.envFrom" -}}
- configMapRef:
    name: {{ include "ianua.fullname" . }}-config
- secretRef:
    name: {{ include "ianua.secretName" . }}
{{- end -}}

{{/*
Whether the egress gateway runs: on by default wherever agents run in
sandboxes, since the services they call are a way out otherwise. Turning it
off is a choice made in values, not a default nobody noticed.
*/}}
{{- define "ianua.egressGatewayOn" -}}
{{- if and .Values.agentSandboxes.egressGateway.enabled .Values.agentSandboxes.agents -}}
true
{{- end -}}
{{- end -}}

{{/*
The Secret holding EVENT_SIGNING_SECRET. Apart from the chart Secret every pod
loads: the proxy and the egress gateway must not be able to sign platform
events, so only the server-side processes read it.
*/}}
{{- define "ianua.eventSigningSecretName" -}}
{{- printf "%s-event-signing" (include "ianua.fullname" .) -}}
{{- end -}}

{{/* EVENT_SIGNING_SECRET: given, kept, or 32 random bytes as base64. */}}
{{- define "ianua.eventSigningSecret" -}}
{{- include "ianua.keptSecret" (dict
    "root" .
    "secret" (include "ianua.eventSigningSecretName" .)
    "key" "EVENT_SIGNING_SECRET"
    "given" .Values.secrets.eventSigningSecret
    "generated" (randBytes 32)
) -}}
{{- end -}}

{{/* The EVENT_SIGNING_SECRET env entry, for server-side processes only. */}}
{{- define "ianua.eventSigningEnv" -}}
- name: EVENT_SIGNING_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "ianua.eventSigningSecretName" . }}
      key: EVENT_SIGNING_SECRET
{{- end -}}

{{/* Where the disk file store is mounted in the server's pods. */}}
{{- define "ianua.filesDir" -}}
/var/lib/ianua/files
{{- end -}}

{{/* "true" when files are kept on the chart's volume, empty otherwise. */}}
{{- define "ianua.filesOnDisk" -}}
{{- $store := .Values.files.store -}}
{{- if not (has $store (list "disk" "objects")) -}}
{{- fail (printf "files.store must be disk or objects, got %q" $store) -}}
{{- end -}}
{{- if eq $store "disk" -}}
true
{{- end -}}
{{- end -}}

{{/* The file store's volume mount, for a server-side container. */}}
{{- define "ianua.filesVolumeMount" -}}
{{- if include "ianua.filesOnDisk" . }}
- name: files
  mountPath: {{ include "ianua.filesDir" . }}
{{- end }}
{{- end -}}

{{/* The file store's volume, for a server-side pod. */}}
{{- define "ianua.filesVolume" -}}
{{- if include "ianua.filesOnDisk" . }}
- name: files
  persistentVolumeClaim:
    claimName: {{ include "ianua.fullname" . }}-files
{{- end }}
{{- end -}}

{{/*
A one-off command of the server binary, run as a Helm hook Job: it builds
the platform as a worker would, with the owner's and the audit purge's logins,
does its one task and exits. Each command runs again safely. None of them
writes a file, so none mounts the file store: a pre-upgrade hook could not
wait for a volume the upgrade itself makes.

Takes a dict: root, name (also the component), args, hook, weight,
backoffLimit, and env (extra env entries, already rendered).
*/}}
{{- define "ianua.commandJob" -}}
{{- $root := .root -}}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "ianua.fullname" $root }}-{{ .name }}
  labels:
    {{- include "ianua.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
  annotations:
    "helm.sh/hook": {{ .hook }}
    "helm.sh/hook-weight": {{ .weight | quote }}
    # Keep the finished Job, so its log stays readable until the next run.
    "helm.sh/hook-delete-policy": before-hook-creation
spec:
  backoffLimit: {{ .backoffLimit }}
  template:
    metadata:
      labels:
        {{- include "ianua.selectorLabels" (dict "root" $root "component" .name) | nindent 8 }}
    spec:
      restartPolicy: OnFailure
      automountServiceAccountToken: false
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      containers:
        - name: {{ .name }}
          image: {{ include "ianua.serverImage" $root }}
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          args: {{ toJson .args }}
          env:
            {{- include "ianua.databaseUrlEnv" $root | nindent 12 }}
            {{- include "ianua.eventSigningEnv" $root | nindent 12 }}
            {{- include "ianua.auditSealEnv" $root | nindent 12 }}
            {{- include "ianua.privilegedLoginEnv" $root | nindent 12 }}
            {{- with .env }}
            {{- . | nindent 12 }}
            {{- end }}
          envFrom:
            {{- include "ianua.envFrom" $root | nindent 12 }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            {{- toYaml $root.Values.worker.resources | nindent 12 }}
{{- end -}}
