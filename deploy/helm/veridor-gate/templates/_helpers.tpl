{{/*
Naming. Job names become the job-name label on the pod, and label values are
capped at 63 characters, so the fullname is cut to 52 to leave room for the
"-r<revision>" suffix hook.mode=none adds.
*/}}
{{- define "veridor-gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "veridor-gate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "veridor-gate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "veridor-gate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "veridor-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gate
{{- end -}}

{{- define "veridor-gate.labels" -}}
helm.sh/chart: {{ include "veridor-gate.chart" . }}
{{ include "veridor-gate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The Job name. A helm hook keeps one stable name: Helm deletes the previous Job
before creating the next (before-hook-creation, which veridor-gate.validate
requires in the delete policy: without it a Job an earlier run left behind is
reused, and the gate does not run again). A plain Job's pod template is
immutable, so with hook.mode=none every Helm revision gets its own Job and
Helm prunes the old one.

An argocd hook has no name: job.yaml renders metadata.generateName with
veridor-gate.argocdJobPrefix, and Argo CD names each sync's Job
<prefix><first 7 characters of the revision, none for an Application with
several sources>-postsync-<the operation's start, Unix seconds>. With one fixed name and BeforeHookCreation, Argo CD v3.5.3
reported some syncs from the previous sync's Job, in both directions; with
generateName each sync was reported from its own Job (measured on kind:
deploy/argocd/README.md, "Each sync reads its own Job"). A Job name is a pod
label value, at most 63 characters, and Argo CD adds up to 27 (7 +
"-postsync-" + 10 digits), so the prefix is cut to 36.
*/}}
{{- define "veridor-gate.jobName" -}}
{{- if eq .Values.hook.mode "none" -}}
{{- printf "%s-r%d" (include "veridor-gate.fullname" .) (int .Release.Revision) -}}
{{- else -}}
{{- include "veridor-gate.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "veridor-gate.argocdJobPrefix" -}}
{{- printf "%s-" (include "veridor-gate.fullname" . | trunc 35 | trimSuffix "-") -}}
{{- end -}}

{{- define "veridor-gate.configMapName" -}}
{{- if .Values.existingConfigMap.name -}}
{{- .Values.existingConfigMap.name -}}
{{- else -}}
{{- printf "%s-config" (include "veridor-gate.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "veridor-gate.configMapKey" -}}
{{- if .Values.existingConfigMap.name -}}
{{- .Values.existingConfigMap.key | default "veridor.json" -}}
{{- else -}}
veridor.json
{{- end -}}
{{- end -}}

{{- define "veridor-gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "veridor-gate.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The hook annotation values as the tool that reads them reads them, so
     what veridor-gate.validate checks is what job.yaml renders. Helm splits
     hook events and delete policies on commas and lower-cases and trims each
     one (its manifest sorter), so "post-install,PRE-UPGRADE" ran as a
     pre-upgrade hook; Argo CD splits on commas and trims, and matches each
     value case-sensitively. */}}
{{- define "veridor-gate.helmList" -}}
{{- $out := list -}}
{{- range splitList "," (toString .) -}}{{- $out = append $out (lower (trim .)) -}}{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{- define "veridor-gate.argoList" -}}
{{- $out := list -}}
{{- range splitList "," (toString .) -}}{{- $out = append $out (trim .) -}}{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{- define "veridor-gate.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
Render-time refusals. Each one names the value at fault and the fix. They run
from job.yaml and configmap.yaml, so no manifest is produced when any fails.
*/}}
{{- define "veridor-gate.validate" -}}
{{- $mode := .Values.hook.mode | default "" -}}
{{- if not (has $mode (list "argocd" "helm" "none")) -}}
{{- fail (printf "veridor-gate: hook.mode is %q. Set it to argocd (Argo CD PostSync hook, rendered by Argo CD, with a Job of its own each sync that runs hooks: the sync operation fails when the gate fails), helm (post-install,post-upgrade hook, for the Helm CLI: the release fails), or none (a plain Job that whatever applies it must watch). There is no default: a Job with Argo CD annotations installed by plain `helm install` fails without failing anything." $mode) -}}
{{- end -}}
{{- /* Argo CD renders the chart with `helm template`, where lookup returns
       nothing. A non-empty answer means the render reached a cluster: `helm
       install` / `helm upgrade` (or a server-side dry run), which does not run
       Argo CD hooks. Measured with Helm 4.2.2 before this refusal existed:
       the argocd-mode Job, which has no name, failed a server-side install
       ("resource name may not be empty"), but with --server-side=false (the
       way Helm 3 applies) the install exited 0, the release was deployed, and
       the API server named the Job g-veridor-gate-mn9q2; nothing waited for
       it. The list is of ConfigMaps in the release namespace, which the
       release writes anyway; its answer is non-empty even with no items. */ -}}
{{- if and (eq $mode "argocd") (lookup "v1" "ConfigMap" .Release.Namespace "") -}}
{{- fail "veridor-gate: hook.mode is argocd, and this render reached a cluster, so it is `helm install` or `helm upgrade`, not Argo CD. The Helm CLI does not run Argo CD hooks: it would apply the gate Job as a plain resource, not wait for it, and report the release deployed whatever the gate finds. In argocd mode the Job has no fixed name (metadata.generateName, so that each Argo CD sync reads its own Job). Deploy the chart through an Argo CD Application (deploy/argocd/application-example.yaml), or use hook.mode helm with the Helm CLI." -}}
{{- end -}}
{{- /* The mirror case. Argo CD also renders a helm-mode chart, and turns
       helm.sh/hook post-install,post-upgrade into a PostSync hook and
       before-hook-creation into BeforeHookCreation (gitops-engine v3.5.3,
       pkg/sync/hook/helm): one fixed Job name for every sync, the shape
       argocd mode left. Measured in a gate-only Application with the target
       alternating: 14 of 80 syncs were reported from the previous sync's
       Job, 6 of the 40 vulnerable ones Succeeded while their own gate exited
       1; argocd mode, 0 of 50. A render that reaches no cluster cannot tell
       Argo CD from `helm template` or a client-side dry run, so all of them
       are refused unless the user opens it for the Helm CLI. The opt-in is
       read first, and only a boolean true opens it; an opened render never
       calls lookup. */ -}}
{{- $renderWithoutCluster := and (kindIs "bool" .Values.hook.helm.allowRenderWithoutCluster) .Values.hook.helm.allowRenderWithoutCluster -}}
{{- if and (eq $mode "helm") (not $renderWithoutCluster) (not (lookup "v1" "ConfigMap" .Release.Namespace "")) -}}
{{- fail "veridor-gate: hook.mode is helm, and this render reached no cluster: `helm template`, a client-side --dry-run, or Argo CD, which renders with `helm template`. Argo CD runs a helm-mode Job as a PostSync hook with this one fixed name and BeforeHookCreation, and Argo CD v3.5.3 then reported syncs from the previous sync's Job: vulnerable syncs Succeeded while their own gate exited 1 (measured). Under Argo CD use hook.mode argocd, which gives each sync that runs hooks a Job of its own. To render helm mode for the Helm CLI without a cluster (helm template, --dry-run=client), set hook.helm.allowRenderWithoutCluster to true; never set it under Argo CD." -}}
{{- end -}}
{{- /* values.schema.json refuses every value below; these are the same
       refusals for a render that skips the schema (--skip-schema-validation,
       or Argo CD's spec.source.helm.skipSchemaValidation), made on the values
       as Helm and Argo CD read them (veridor-gate.helmList / argoList). */ -}}
{{- $events := splitList "," (include "veridor-gate.helmList" (.Values.hook.helm.events | default "")) -}}
{{- $helmPolicies := splitList "," (include "veridor-gate.helmList" (.Values.hook.helm.deletePolicy | default "")) -}}
{{- $phases := splitList "," (include "veridor-gate.argoList" (.Values.hook.argocd.phase | default "")) -}}
{{- $argoPolicies := splitList "," (include "veridor-gate.argoList" (.Values.hook.argocd.deletePolicy | default "")) -}}
{{- $prePhase := "" -}}
{{- if eq $mode "helm" -}}
{{- range $events -}}
{{- if hasPrefix "pre-" . -}}{{- $prePhase = printf "hook.helm.events %s" . -}}{{- end -}}
{{- end -}}
{{- else if and (eq $mode "argocd") (has "PreSync" $phases) -}}
{{- $prePhase = "hook.argocd.phase PreSync" -}}
{{- end -}}
{{- if $prePhase -}}
{{- fail (printf "veridor-gate: a pre-phase hook (%s) is not supported. It runs before this release's ConfigMap (and ServiceAccount) is created or updated: a first install cannot mount its configuration, and an upgrade runs the previous revision's configuration against the version that is about to be replaced. Use hook.helm.events post-install,post-upgrade or hook.argocd.phase PostSync." $prePhase) -}}
{{- end -}}
{{- if eq $mode "helm" -}}
{{- range $events -}}
{{- if not (has . (list "post-install" "post-upgrade" "post-rollback" "test")) -}}
{{- fail (printf "veridor-gate: hook.helm.events names %q, which is not one of post-install, post-upgrade, post-rollback, test. Helm creates the Job only on an event it knows, so an unknown one gates nothing. Use post-install,post-upgrade." .) -}}
{{- end -}}
{{- end -}}
{{- if not (and (has "post-install" $events) (has "post-upgrade" $events)) -}}
{{- fail (printf "veridor-gate: hook.helm.events is %q. Helm creates the gate Job only on the events listed, so without both post-install and post-upgrade a `helm install` or `helm upgrade` runs no gate and exits 0 with the release deployed (measured: with test alone, install and upgrade created no Job). List post-install,post-upgrade; post-rollback and test may be added to them, not used instead." (.Values.hook.helm.events | default "" | toString)) -}}
{{- end -}}
{{- range $helmPolicies -}}
{{- if not (has . (list "before-hook-creation" "hook-succeeded" "hook-failed")) -}}
{{- fail (printf "veridor-gate: hook.helm.deletePolicy names %q, which is not one of before-hook-creation, hook-succeeded, hook-failed." .) -}}
{{- end -}}
{{- end -}}
{{- if not (has "before-hook-creation" $helmPolicies) -}}
{{- fail (printf "veridor-gate: hook.helm.deletePolicy is %q, which does not include before-hook-creation. The gate Job keeps one name per release, so a Job an earlier run left behind (hook-failed keeps one that passed) is what the next `helm upgrade` finds: Helm reports the release deployed without running the gate again (measured: the upgrade exited 0 on the install's Complete Job). Include before-hook-creation, e.g. before-hook-creation,hook-failed." (.Values.hook.helm.deletePolicy | default "" | toString)) -}}
{{- end -}}
{{- else if eq $mode "argocd" -}}
{{- if has "Sync" $phases -}}
{{- fail "veridor-gate: hook.argocd.phase Sync is not supported. Argo CD runs a Sync hook together with the apply of the application's manifests, not once they are Healthy, so the gate probes whatever the Service still routes to: the version being replaced. Use hook.argocd.phase PostSync." -}}
{{- end -}}
{{- if ne (join "," $phases) "PostSync" -}}
{{- fail (printf "veridor-gate: hook.argocd.phase is %q. The only supported phase is PostSync (exactly: Argo CD matches the hook phase case-sensitively, and a Job whose phase it does not recognise, or SyncFail, Skip or PostDelete, does not run after each sync that runs hooks)." (.Values.hook.argocd.phase | default "" | toString)) -}}
{{- end -}}
{{- range $argoPolicies -}}
{{- if not (has . (list "BeforeHookCreation" "HookSucceeded" "HookFailed")) -}}
{{- fail (printf "veridor-gate: hook.argocd.deletePolicy names %q, which is not one of BeforeHookCreation, HookSucceeded, HookFailed (Argo CD matches them case-sensitively)." .) -}}
{{- end -}}
{{- end -}}
{{- /* Each sync's Job has a name of its own (generateName), so
       BeforeHookCreation never finds an earlier one to delete (measured: 16
       Jobs after 16 syncs). Only HookSucceeded and HookFailed (Argo CD, once
       it has recorded the result) and ttlSecondsAfterFinished remove them. */ -}}
{{- if and (kindIs "invalid" .Values.job.ttlSecondsAfterFinished) (not (and (has "HookSucceeded" $argoPolicies) (has "HookFailed" $argoPolicies))) -}}
{{- fail (printf "veridor-gate: job.ttlSecondsAfterFinished is null with hook.mode argocd and hook.argocd.deletePolicy %q. Every Argo CD sync creates a gate Job with a name of its own, and BeforeHookCreation never finds an earlier one to delete, so without a TTL each sync's Job and pod stay in the namespace for good. Set job.ttlSecondsAfterFinished to a number of seconds (3600 is the default), or list both HookSucceeded and HookFailed, which delete every Job (and its log) once Argo CD has read it." (include "veridor-gate.argoList" .Values.hook.argocd.deletePolicy)) -}}
{{- end -}}
{{- end -}}
{{- /* The kubelet pulls repository@digest and ignores the tag beside it
       (measured on kind: a nonexistent tag with a real digest ran that
       digest's image). The published chart sets image.digest to its own
       release's image, the one tagged appVersion, so `--set image.tag=X`
       alone rendered repository:X@<that digest> and kept running the release
       image while the manifest named X. A digest is used only with the tag it
       belongs to: image.digestTag, or appVersion when that is empty. */ -}}
{{- if .Values.image.digest -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- $digestTag := .Values.image.digestTag | default .Chart.AppVersion | toString -}}
{{- if ne $tag $digestTag -}}
{{- fail (printf "veridor-gate: image.tag is %q, but image.digest is the digest of tag %q (%s). The kubelet pulls by digest and ignores the tag, so the Job would run that image while its manifest names %s; the published chart sets image.digest to its release's image. Set image.digest to \"\" to pull %s by tag, or set image.digest to the digest of %s and image.digestTag to %q." $tag $digestTag (ternary "image.digestTag" "the chart's appVersion, as image.digestTag is empty" (not (empty .Values.image.digestTag))) $tag $tag $tag $tag) -}}
{{- end -}}
{{- end -}}
{{- $inline := and .Values.config (gt (len .Values.config) 0) -}}
{{- $existing := .Values.existingConfigMap.name -}}
{{- if and $inline $existing -}}
{{- fail "veridor-gate: both config and existingConfigMap.name are set. Use one: config renders the configuration into a ConfigMap this chart owns; existingConfigMap.name mounts one you manage." -}}
{{- end -}}
{{- if not (or $inline $existing) -}}
{{- fail "veridor-gate: no Veridor configuration. Set config to the configuration object (the same JSON `veridor run --config` reads, written as YAML), or existingConfigMap.name to a ConfigMap holding it under existingConfigMap.key." -}}
{{- end -}}
{{- if not (hasPrefix "/work" .Values.output.dir) -}}
{{- fail (printf "veridor-gate: output.dir is %q. It must be under /work, the only writable directory besides /tmp (the root filesystem is read-only)." .Values.output.dir) -}}
{{- end -}}
{{- $baseUrl := .Values.target.baseUrl | default "" | toString -}}
{{- if $inline -}}
{{- /* Veridor refuses a configuration without a target object ("target must
       be an object", exit 2) before it applies --base-url, so target.baseUrl
       alone rendered a Job that could never pass (measured on kind). */ -}}
{{- if not (kindIs "map" .Values.config.target) -}}
{{- fail "veridor-gate: config has no target object. Veridor refuses a configuration without one (exit 2, \"target must be an object\") even when --base-url is passed. Add config.target: {} (target.baseUrl fills in base_url) or set config.target.base_url." -}}
{{- end -}}
{{- if and (not $baseUrl) (not .Values.config.target.base_url) -}}
{{- fail "veridor-gate: no target. Set target.baseUrl (passed as --base-url, e.g. http://invoices-api.shop.svc.cluster.local:8080) or config.target.base_url." -}}
{{- end -}}
{{- end -}}
{{- include "veridor-gate.refuseUserinfo" (dict "where" "target.baseUrl" "url" $baseUrl) -}}
{{- include "veridor-gate.scanBaseUrl" $baseUrl -}}
{{- include "veridor-gate.refuseOwnedArgs" .Values.extraArgs -}}
{{- if $inline -}}
{{- $target := .Values.config.target | default dict -}}
{{- if kindIs "map" $target -}}
{{- include "veridor-gate.refuseUserinfo" (dict "where" "config.target.base_url" "url" ($target.base_url | default "" | toString)) -}}
{{- end -}}
{{- end -}}
{{- $names := list -}}
{{- range $index, $entry := .Values.secretEnv -}}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]*$" ($entry.name | default "" | toString)) -}}
{{- fail (printf "veridor-gate: secretEnv[%d].name %q is not an environment variable name ([A-Za-z_][A-Za-z0-9_]*)." $index ($entry.name | default "" | toString)) -}}
{{- end -}}
{{- if not (and $entry.secretName $entry.key) -}}
{{- fail (printf "veridor-gate: secretEnv[%d] (%s) needs both secretName and key: credentials come only from an existing Secret." $index $entry.name) -}}
{{- end -}}
{{- if has $entry.name $names -}}
{{- fail (printf "veridor-gate: secretEnv lists %s twice." $entry.name) -}}
{{- end -}}
{{- $names = append $names $entry.name -}}
{{- end -}}
{{- if $inline -}}
{{- $allow := list -}}
{{- range .Values.allowLiteralHeaders -}}
{{- if regexMatch "(?i)(auth|cookie|token|secret|key|session|passw|credential)" (toString .) -}}
{{- fail (printf "veridor-gate: allowLiteralHeaders lists %q, which names a credential. It exists for headers that are not credentials (X-Tenant-Id, Accept); a credential goes in a Secret and is referenced as ${NAME} through secretEnv." (toString .)) -}}
{{- end -}}
{{- $allow = append $allow (lower (toString .)) -}}
{{- end -}}
{{- include "veridor-gate.scanCredentials" (dict "path" "config" "value" .Values.config "allow" $allow "captureNames" false) -}}
{{- /* Every ${NAME} Veridor will expand from the environment must be provided.
       `sequences` is skipped: names there may be capture references, which
       Veridor resolves at run time rather than from the environment. */ -}}
{{- $scanned := omit .Values.config "sequences" | toJson -}}
{{- range $ref := regexFindAll "\\$\\{[A-Za-z_][A-Za-z0-9_]*\\}" $scanned -1 | uniq -}}
{{- $var := trimSuffix "}" (trimPrefix "${" $ref) -}}
{{- if not (has $var $names) -}}
{{- fail (printf "veridor-gate: config references ${%s}, and no secretEnv entry provides %s. Add {name: %s, secretName: <Secret>, key: <key>} to secretEnv; Veridor would otherwise refuse the configuration at run time (exit 2)." $var $var $var) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- include "veridor-gate.refuseHookAnnotations" .Values.job.annotations -}}
{{- /* The selector labels are the NetworkPolicy's podSelector. A podLabels
       entry for one of them replaced the pod's label (rendered after it), so
       the policy selected no pod and constrained nothing (measured on kind). */ -}}
{{- $selector := include "veridor-gate.selectorLabels" . | fromYaml -}}
{{- range $key, $_ := .Values.job.podLabels -}}
{{- if hasKey $selector $key -}}
{{- fail (printf "veridor-gate: job.podLabels sets %s, a selector label the chart owns. It is the NetworkPolicy's podSelector: overriding it leaves the policy selecting no pod, constraining nothing. Remove it from job.podLabels (nameOverride changes app.kubernetes.io/name)." $key) -}}
{{- end -}}
{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- if not (and .Values.networkPolicy.targetPeers .Values.networkPolicy.targetPorts) -}}
{{- fail "veridor-gate: networkPolicy.enabled is true but networkPolicy.targetPeers or networkPolicy.targetPorts is empty. A policy with no target denies the gate its own target and every run would exit 3; name the target's pods (targetPeers) and the port they listen on (targetPorts)." -}}
{{- end -}}
{{- /* A NetworkPolicy rule with no peers allows every destination, and a port
       entry with no port every port of its protocol (measured on kind: 53/tcp
       of a pod that is not DNS, and a target peer's port no entry named). */ -}}
{{- range $index, $port := .Values.networkPolicy.targetPorts -}}
{{- if not (and (kindIs "map" $port) $port.port) -}}
{{- fail (printf "veridor-gate: networkPolicy.targetPorts[%d] has no port. A NetworkPolicyPort without a port allows every port of its protocol; set port to the port the target's pods listen on." $index) -}}
{{- end -}}
{{- end -}}
{{- if .Values.networkPolicy.dns.enabled -}}
{{- if not (and .Values.networkPolicy.dns.peers .Values.networkPolicy.dns.ports) -}}
{{- fail "veridor-gate: networkPolicy.dns.enabled is true but networkPolicy.dns.peers or networkPolicy.dns.ports is empty. An egress rule with no peers allows every destination, and one with no ports every port, so the DNS rule would open egress beyond DNS. Name the DNS pods and ports, or set networkPolicy.dns.enabled: false." -}}
{{- end -}}
{{- range $index, $port := .Values.networkPolicy.dns.ports -}}
{{- if not (and (kindIs "map" $port) $port.port) -}}
{{- fail (printf "veridor-gate: networkPolicy.dns.ports[%d] has no port. A NetworkPolicyPort without a port allows every port of its protocol, to every DNS peer." $index) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* target.baseUrl is passed as --base-url, which Veridor applies after it
     expands the configuration: a ${NAME} in it is sent as written. It was
     checked for user:password@ only, so a literal ";token=..." or
     "?api_key=..." rendered into the Job's arguments (measured in the pod
     spec on kind), readable by anyone who can read the Job or its pod. */}}
{{- define "veridor-gate.scanBaseUrl" -}}
{{- $url := . -}}
{{- if contains "${" $url -}}
{{- fail "veridor-gate: target.baseUrl contains ${...}. It is passed as --base-url, which Veridor does not expand, so the reference would be sent as written. Put the URL in config.target.base_url, or send the credential as a header referencing a Secret (secretEnv)." -}}
{{- end -}}
{{- range $match := regexFindAll (include "veridor-gate.pairPattern" "") $url -1 -}}
{{- $pair := splitn "=" 2 (regexReplaceAll "^[?&;]?[\\t\\n\\f\\r ]*" $match "") -}}
{{- $name := include "veridor-gate.unquotePlus" $pair._0 -}}
{{- if and (or (eq (include "veridor-gate.credentialName" $name) "true") (regexMatch (include "veridor-gate.pairOnlyKey" "") (include "veridor-gate.fold" $name))) (eq (include "veridor-gate.isLiteral" (include "veridor-gate.unquotePlus" $pair._1)) "true") -}}
{{- fail (printf "veridor-gate: target.baseUrl carries a literal value for the credential-named parameter %q (not printed). It is passed as --base-url and would sit in the Job's arguments, readable by anyone who can read the Job or its pod. Send the credential as a header referencing a Secret (secretEnv)." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* extraArgs are appended after the chart's own arguments. Veridor's parser
     keeps the last value of a flag and reads any unambiguous prefix of a
     flag as the flag (argparse's allow_abbrev), so `--base-u URL` replaced
     target.baseUrl without its credential check (measured: the Job's
     arguments carried a literal ;token= and Veridor probed that URL), and
     `--fail none` would turn the gate off. Every flag the chart passes from a
     value is refused here in every spelling argparse reads as it: an element
     "--x..." (before any "=") that is a prefix of the flag, with or without
     "=value". No other `veridor run` option is a prefix of one of these
     (tests/test_helm_chart.py checks it), so none is refused by this.
     --help and -h are refused too: `veridor run --help` exits 0 having run
     nothing. So is every single-dash token with an h in it: argparse reads a
     cluster that starts with -h as -h (measured: -hx, -hq, -h1 exit 0 having
     run nothing), and -h is the only single-dash option `run` has, so a
     cluster without an h is a parse error, exit 2. The value after the flag
     is never printed. */}}
{{- define "veridor-gate.refuseOwnedArgs" -}}
{{- $owned := dict "--config" "config (or existingConfigMap)" "--output-dir" "output.dir" "--fail-on" "gate.failOn" "--base-url" "target.baseUrl" "--require-complete" "gate.requireComplete" "--require-clean-teardown" "gate.requireCleanTeardown" "--read-only" "gate.readOnly" "--no-prove-liveness" "gate.proveLiveness" "--sarif" "gate.sarif" "--wait-for-target" "gate.waitForTargetSeconds" "--help" "" -}}
{{- range $index, $arg := . -}}
{{- $shown := (splitn "=" 2 (toString $arg))._0 -}}
{{- $flag := ternary "--help" $shown (and (regexMatch "^-[^-]" $shown) (contains "h" $shown)) -}}
{{- if regexMatch "^--[^-=]" $flag -}}
{{- range $name := keys $owned | sortAlpha -}}
{{- if and (hasPrefix $flag $name) (eq $name "--help") (hasPrefix "--" $shown) -}}
{{- fail (printf "veridor-gate: extraArgs[%d] is %s, which Veridor reads as --help: `veridor run --help` prints its usage and exits 0 having run nothing, so the Job would complete as a pass. Remove it." $index $shown) -}}
{{- else if and (hasPrefix $flag $name) (eq $name "--help") -}}
{{- fail (printf "veridor-gate: extraArgs[%d] is %s, a single-dash token with an h in it, which Veridor reads as --help when it starts with -h (measured: -hx exits 0 having run nothing, as -h does), so the Job would complete as a pass; -h is the only single-dash option `veridor run` has. Remove it." $index $shown) -}}
{{- else if hasPrefix $flag $name -}}
{{- fail (printf "veridor-gate: extraArgs[%d] starts with %s, a prefix of %s. Veridor reads a flag's unambiguous prefix as the flag and keeps its last value, and extraArgs come after the chart's own arguments, so this would replace what the chart passes from its values (a --base-url there skips the target.baseUrl credential check). Set %s instead. The value is not printed." $index $shown $name (get $owned $name)) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* job.annotations are rendered after the hook annotations the chart
     checks, as duplicate keys, and Helm keeps the last one: `helm.sh/hook:
     test` there made install and upgrade create no Job, `helm.sh/hook:
     pre-install` made a hook.mode none Job a pre-install hook, and
     `argocd.argoproj.io/hook: Sync` rendered past the Sync refusal (measured
     with helm template). Every key that makes the Job a hook, or that the
     chart sets from hook.*, is refused in every mode. So is every other key
     under helm.sh/ or argocd.argoproj.io/: they decide when the Job is
     created, kept or deleted, and `helm.sh/resource-policy: keep` kept a
     passing Job through `helm uninstall`, after which `helm install` adopted
     it, Complete, and ran no gate against a target that had turned
     vulnerable (measured on kind, hook.mode none). Pod template annotations
     are not read by Helm or Argo CD, so job.podAnnotations is left alone. */}}
{{- define "veridor-gate.refuseHookAnnotations" -}}
{{- range $key, $_ := . -}}
{{- if or (hasPrefix "helm.sh/hook" $key) (hasPrefix "argocd.argoproj.io/hook" $key) (eq $key "argocd.argoproj.io/sync-wave") -}}
{{- fail (printf "veridor-gate: job.annotations sets %s, a hook annotation. The chart renders its own hook annotations from hook.mode and hook.* after checking them, and a duplicate key in job.annotations replaces the checked one (Helm keeps the last): `helm.sh/hook: test` there runs no gate on install or upgrade. Set hook.helm.* or hook.argocd.* (hook.argocd.syncWave for the sync wave) instead, and remove it from job.annotations." $key) -}}
{{- else if or (hasPrefix "helm.sh/" $key) (hasPrefix "argocd.argoproj.io/" $key) -}}
{{- fail (printf "veridor-gate: job.annotations sets %s. No key under helm.sh/ or argocd.argoproj.io/ is accepted there: they decide when the Job is created, kept or deleted, and the chart sets the ones the gate needs from hook.*. `helm.sh/resource-policy: keep` kept a passing Job through `helm uninstall`, and the next `helm install` adopted it, still Complete, and ran no gate against a target that had since turned vulnerable. Remove it from job.annotations." $key) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "veridor-gate.refuseUserinfo" -}}
{{- if regexMatch "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*@" .url -}}
{{- fail (printf "veridor-gate: %s carries user:password@ credentials in the URL. Remove them and send the credential as a header referencing a Secret (secretEnv)." .where) -}}
{{- end -}}
{{- end -}}

{{/*
The literal-credential refusal. The same rule as capsule.literal_credentials
(src/veridor/capsule.py), so a value one of them refuses the other does not
publish: tests/fixtures/credential_parity.json is evaluated by both. Its two
deliberate differences are cases there with their reasons; the known
differences that need inputs no configuration should contain are listed in
tests/test_credential_parity.py, and in each this side refuses more. Applied
to the whole configuration object:

  * headers maps (the key in any case) and session inject entries: a header
    value must be only
    ${NAME} references, or one auth-scheme word and one reference ("Bearer
    ${VERIDOR_OWNER_TOKEN}"). A Cookie header is read one cookie at a time,
    so "sid=${VERIDOR_SID}" is a reference. Unlike the capsule, EVERY header
    is held to this unless allowLiteralHeaders lists it, and that list may
    not name a credential.
  * a credential-named key ($credKey: a key ending in password (also with
    a digit or a confirmation word after it), passwd, passphrase, passwort,
    kennwort, contrasena/contraseña, mot_de_passe, secret, token, jwt,
    credential(s), api key, private key, secret key, access key, passcode,
    pin code, otp code, mfa code, verification code or client assertion,
    with or without a separator before it, so accessToken and
    aws_secret_access_key; or pass / pwd / senha / pin / otp / totp / hotp
    as a word of their own; userpass, userpwd, dbpass, adminpwd; and the
    last [segment] of a bracketed name such as user[password])
    must hold references only in every string and number beneath it, in
    lists and objects at any depth ({password: {value: L}} too); a key
    beneath it that describes the credential ($credentialDescriptors: type,
    username, ...) is walked by the ordinary rules. "x-${NAME}" is refused.
  * an object with a `value` whose name, key, field or type ($pairLabels)
    holds a credential name ({name: password, value: L}): its value is held
    to the same rule.
  * under a `capture` map, a credential-named key is a capture name only
    when its value is an extractor (veridor-gate.isExtractor); otherwise it
    is held to the rule like any other.
  * every string: user:password@ in any URL, credential-named parameters in
    query strings and form bodies (plus- and percent-decoded, ASCII), where
    the whole names in $pairOnlyKey (key, auth, code, sig, sessionid, ...)
    count as well, and
    JSON text, which is parsed and walked by these same rules (when Go's
    parser refuses the text, parsed again with NaN, Infinity and every number
    outside a string read as 0, since Python's parser reads them).

Empty strings carry nothing. ${capture.NAME} and sequence captures count as
references. The offending value is never printed: it may be the secret.
*/}}
{{- define "veridor-gate.credKey" -}}
{{- $credKey := "(?i)^(?:.*(?:password(?:[_-]?(?:confirm(?:ation)?|again|repeat|[0-9]))?|passwd|passphrase|passwort|kennwort|contrase(?:n|[^\\x00-\\x7f]{1,2})a|mot[_-]?de[_-]?passe|secret|token|jwt|credentials?|api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?key|pass[_-]?code|pin[_-]?code|otp[_-]?code|mfa[_-]?code|verification[_-]?code|client[_-]?assertion)|(?:.*[_.-])?(?:pwd|pass|senha|pin|otp|totp|hotp)|.*(?-i:[a-z0-9]P)(?:wd|ass|in)|.*(?-i:[a-z0-9](?:O|T[Oo]))tp|(?:user|db|admin)(?:pass|pwd))$" -}}
{{- $credKey -}}
{{- end -}}

{{- define "veridor-gate.credentialDescriptors" -}}
{{- $credentialDescriptors := "type temporary username user email id name" -}}
{{- $credentialDescriptors -}}
{{- end -}}

{{- define "veridor-gate.pairLabels" -}}
{{- $pairLabels := "name key field type" -}}
{{- $pairLabels -}}
{{- end -}}

{{- define "veridor-gate.captureExtractor" -}}
{{- $captureExtractor := "^(\\$(\\.[A-Za-z_][A-Za-z0-9_-]*|\\[(0|[1-9][0-9]*)\\])+|header:[!#$%&'*+.^_`|~0-9A-Za-z-]+)$" -}}
{{- $captureExtractor -}}
{{- end -}}

{{- define "veridor-gate.pairOnlyKey" -}}
{{- $pairOnlyKey := "(?i)^(?:key|auth|sig|signature|code|j?session[_-]?id|sid)$" -}}
{{- $pairOnlyKey -}}
{{- end -}}

{{- define "veridor-gate.headerOk" -}}
{{- $headerOk := "^[\\t\\n\\f\\r ]*([A-Za-z][A-Za-z0-9._~+/-]*[\\t\\n\\f\\r ]+)?\\$\\{[A-Za-z_][A-Za-z0-9_.]*\\}[\\t\\n\\f\\r ]*$" -}}
{{- $headerOk -}}
{{- end -}}

{{- define "veridor-gate.anyReference" -}}
{{- $anyReference := "\\$\\{[A-Za-z_][A-Za-z0-9_.]*\\}" -}}
{{- $anyReference -}}
{{- end -}}

{{- define "veridor-gate.pairPattern" -}}
{{- $pairPattern := "(?:^|[?&;])[\\t\\n\\f\\r ]*([^=&;?#\\t\\n\\f\\r ]+)=([^&;#\\t\\n\\f\\r ]*)" -}}
{{- $pairPattern -}}
{{- end -}}

{{- define "veridor-gate.userinfoPattern" -}}
{{- $userinfoPattern := "[A-Za-z][A-Za-z0-9+.-]*://([^/?#@\\t\\n\\f\\r ]*)@" -}}
{{- $userinfoPattern -}}
{{- end -}}

{{/* "true" when the value carries anything but ${...} references: a number,
     or a string with text left once every reference and surrounding
     whitespace is removed. Booleans and null carry nothing. */}}
{{- define "veridor-gate.isLiteral" -}}
{{- if or (kindIs "float64" .) (kindIs "float32" .) (kindIs "int64" .) (kindIs "int32" .) (kindIs "int" .) -}}
true
{{- else if kindIs "string" . -}}
{{- if trim (regexReplaceAll (include "veridor-gate.anyReference" "") . "") -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/* The four characters Go's and Python's case rules relate to an ASCII
     letter differently, read as that letter: measured over every code point,
     Python's (?i) matches U+0130 and U+0131 as i and RE2 does not, Go's
     lower makes U+0130 "i" and Python's "i" plus U+0307, and both relate
     U+017F to s and U+212A to k; nothing else is related to an ASCII letter
     by either. The chart rendered apİ_key and credentİals holding a literal
     that the capsule refused, and read İd under password as a descriptor.
     Applied wherever a match makes the scan STRICTER (a credential name, a
     parameter-only name, the headers key); where a match EXEMPTS (a
     descriptor, a Cookie read one cookie at a time) only an ASCII key
     matches. capsule._ASCII_FOLD, pinned equal. */}}
{{- define "veridor-gate.fold" -}}
{{- toString . | replace "\u0130" "i" | replace "\u0131" "i" | replace "\u017f" "s" | replace "\u212a" "k" -}}
{{- end -}}

{{/* "true" for a credential-named field, including the last [segment] of a
     bracketed form name such as user[password]. */}}
{{- define "veridor-gate.credentialName" -}}
{{- $name := include "veridor-gate.fold" . -}}
{{- $credKey := include "veridor-gate.credKey" "" -}}
{{- $last := "" -}}
{{- range regexSplit "[\\[\\]]" $name -1 -}}
{{- if . -}}{{- $last = . -}}{{- end -}}
{{- end -}}
{{- if or (regexMatch $credKey $name) (and $last (regexMatch $credKey $last)) -}}true{{- end -}}
{{- end -}}

{{/* "true" for a capture's extractor: an object whose `from` is a capture
     source, or a sequence capture's JSON path / header:NAME. */}}
{{- define "veridor-gate.isExtractor" -}}
{{- if kindIs "map" . -}}
{{- $from := get . "from" -}}
{{- if and (kindIs "string" $from) (has $from (list "cookie" "header" "json_pointer" "html_meta")) -}}true{{- end -}}
{{- else if kindIs "string" . -}}
{{- if regexMatch (include "veridor-gate.captureExtractor" "") . -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/* The credential name a name/value object labels its `value` with
     ({name: password, value: ...}, {type: password, value: ...}), or "". */}}
{{- define "veridor-gate.pairLabel" -}}
{{- $map := . -}}
{{- $found := "" -}}
{{- if hasKey $map "value" -}}
{{- range $label := splitList " " (include "veridor-gate.pairLabels" "") -}}
{{- $named := get $map $label -}}
{{- if and (not $found) (kindIs "string" $named) (eq (include "veridor-gate.credentialName" $named) "true") -}}{{- $found = $named -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $found -}}
{{- end -}}

{{/* urllib.parse.unquote_plus for ASCII: "+" is a space, %XX a byte. Python
     decodes UTF-8; here the escapes of the four characters veridor-gate.fold
     reads are decoded to them (so ap%C4%B0_key is a credential name on both
     sides), every other escaped sequence of two to four bytes, or the start
     of one, becomes ONE U+FFFD, and any other byte of 0x80 or more one U+FFFD
     each. A literal stays a literal either way. The count matters only to
     $credKey's one-or-two non-ASCII slot in contraseña: with a U+FFFD per
     byte, contrase%E2%82%ACa (three bytes) matched in Python and not here,
     and rendered (measured); now it is never more characters here than in
     Python. Decoded in one pass: %2541 is "%41", not "A". */}}
{{- define "veridor-gate.unquotePlus" -}}
{{- $text := replace "+" " " (toString .) -}}
{{- $text = regexReplaceAll "%[Cc]4%[Bb]0" $text "\u0130" -}}
{{- $text = regexReplaceAll "%[Cc]4%[Bb]1" $text "\u0131" -}}
{{- $text = regexReplaceAll "%[Cc]5%[Bb][Ff]" $text "\u017f" -}}
{{- $text = regexReplaceAll "%[Ee]2%84%[Aa][Aa]" $text "\u212a" -}}
{{- $text = regexReplaceAll "%[Ff][0-7](?:%[89ABab][0-9A-Fa-f]){1,3}|%[Ee][0-9A-Fa-f](?:%[89ABab][0-9A-Fa-f]){1,2}|%[CDcd][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]" $text "\ufffd" -}}
{{- if not (regexMatch "%[0-9A-Fa-f]{2}" $text) -}}
{{- $text -}}
{{- else -}}
{{- $bytes := dict -}}
{{- range $code := until 256 -}}
{{- $_ := set $bytes (printf "%02x" $code) (ternary (printf "%c" $code) "�" (lt $code 128)) -}}
{{- end -}}
{{- $codes := regexFindAll "%[0-9A-Fa-f]{2}" $text -1 -}}
{{- range $index, $part := regexSplit "%[0-9A-Fa-f]{2}" $text -1 -}}
{{- $part -}}
{{- if lt $index (len $codes) -}}{{- get $bytes (lower (substr 1 3 (index $codes $index))) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* One header (or one session inject header). Every header is held to the
     reference rule unless allowLiteralHeaders lists it; a Cookie is read one
     cookie at a time. */}}
{{- define "veridor-gate.scanHeader" -}}
{{- $path := .path -}}
{{- $name := toString .name -}}
{{- $lower := lower $name -}}
{{- if and (eq (include "veridor-gate.isLiteral" .value) "true") (not (has $lower .allow)) -}}
{{- $text := toString .value -}}
{{- if and (regexMatch "^[\\x00-\\x7f]*$" $name) (has $lower (list "cookie" "set-cookie")) -}}
{{- range $part := splitList ";" $text -}}
{{- $cookie := splitn "=" 2 $part -}}
{{- $named := contains "=" $part -}}
{{- if eq (include "veridor-gate.isLiteral" (ternary $cookie._1 $part $named)) "true" -}}
{{- fail (printf "veridor-gate: %s carries a literal value for cookie %q (not printed). Write each cookie's value as a ${NAME} reference (e.g. \"sid=${VERIDOR_SESSION}\") and map NAME with secretEnv: [{name: NAME, secretName: <Secret>, key: <key>}]." $path (ternary (trim $cookie._0) $name $named)) -}}
{{- end -}}
{{- end -}}
{{- else if not (regexMatch (include "veridor-gate.headerOk" "") $text) -}}
{{- fail (printf "veridor-gate: %s carries a literal value (not printed). The chart never renders a credential into a ConfigMap. Put the value in a Secret, write the header as \"${NAME}\" or \"<Scheme> ${NAME}\" (e.g. \"Bearer ${VERIDOR_OWNER_TOKEN}\"), and map NAME with secretEnv: [{name: NAME, secretName: <Secret>, key: <key>}]. If %s is not a credential, list it in allowLiteralHeaders." $path $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* One string: user:password@ in a URL, credential-named name=value pairs,
     and JSON text, parsed and walked. */}}
{{- define "veridor-gate.scanString" -}}
{{- $path := .path -}}
{{- $text := .text -}}
{{- $allow := .allow -}}
{{- range $match := regexFindAll (include "veridor-gate.userinfoPattern" "") $text -1 -}}
{{- $userinfo := trimSuffix "@" (regexReplaceAll "^[A-Za-z][A-Za-z0-9+.-]*://" $match "") -}}
{{- if eq (include "veridor-gate.isLiteral" (replace ":" "" $userinfo)) "true" -}}
{{- fail (printf "veridor-gate: %s carries user:password@ in a URL (not printed). Remove it and send the credential as a header referencing a Secret (secretEnv)." $path) -}}
{{- end -}}
{{- end -}}
{{- range $match := regexFindAll (include "veridor-gate.pairPattern" "") $text -1 -}}
{{- $pair := splitn "=" 2 (regexReplaceAll "^[?&;]?[\\t\\n\\f\\r ]*" $match "") -}}
{{- $name := include "veridor-gate.unquotePlus" $pair._0 -}}
{{- if and (or (eq (include "veridor-gate.credentialName" $name) "true") (regexMatch (include "veridor-gate.pairOnlyKey" "") (include "veridor-gate.fold" $name))) (eq (include "veridor-gate.isLiteral" (include "veridor-gate.unquotePlus" $pair._1)) "true") -}}
{{- fail (printf "veridor-gate: %s carries a literal value for the credential-named parameter %q (not printed). Write it as ${NAME} and map NAME with secretEnv: [{name: NAME, secretName: <Secret>, key: <key>}]." $path $name) -}}
{{- end -}}
{{- end -}}
{{- $stripped := trim $text -}}
{{- if or (hasPrefix "{" $stripped) (hasPrefix "[" $stripped) -}}
{{- $parsed := fromJsonArray (printf "[%s]" $stripped) -}}
{{- if and (eq (len $parsed) 1) (kindIs "string" (index $parsed 0)) -}}
{{- /* Go's encoding/json refused the text (fromJsonArray returns the error
       as the one element). Python's json, which the capsule parses with,
       also reads NaN, Infinity, -Infinity and every number however large,
       where Go refuses one beyond float64, and a literal password next to
       one was refused there and rendered here (measured, including numbers a
       narrower pattern missed: a 251-digit mantissa with e60, 301 digits
       glued to e9). So on this failure path, parse again with every NaN,
       Infinity and JSON number OUTSIDE strings read as 0. The text is split
       at its string literals, which are kept byte for byte: rewriting inside
       them could merge two keys or turn "${A-1}" into a reference. A number
       is a literal under a credential-named key whatever its value, so this
       only lets the walk below run where Python's would. */ -}}
{{- $stringPattern := "\"(?:[^\"\\\\]|\\\\.)*\"" -}}
{{- $strings := regexFindAll $stringPattern $stripped -1 -}}
{{- $normalised := "" -}}
{{- range $index, $part := regexSplit $stringPattern $stripped -1 -}}
{{- $normalised = print $normalised (regexReplaceAll "-?Infinity|NaN|-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?" $part "0") -}}
{{- if lt $index (len $strings) -}}{{- $normalised = print $normalised (index $strings $index) -}}{{- end -}}
{{- end -}}
{{- $parsed = fromJsonArray (printf "[%s]" $normalised) -}}
{{- end -}}
{{- if and (eq (len $parsed) 1) (or (kindIs "map" (index $parsed 0)) (kindIs "slice" (index $parsed 0))) -}}
{{- include "veridor-gate.scanCredentials" (dict "path" (printf "%s (JSON text)" $path) "value" (index $parsed 0) "allow" $allow "captureNames" false) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "veridor-gate.scanCredentials" -}}
{{- $path := .path -}}
{{- $allow := .allow -}}
{{- $captureNames := .captureNames -}}
{{- if kindIs "string" .value -}}
{{- include "veridor-gate.scanString" (dict "path" $path "text" .value "allow" $allow) -}}
{{- else if kindIs "slice" .value -}}
{{- range $index, $item := .value -}}
{{- include "veridor-gate.scanCredentials" (dict "path" (printf "%s[%d]" $path $index) "value" $item "allow" $allow "captureNames" false) -}}
{{- end -}}
{{- else if kindIs "map" .value -}}
{{- $label := include "veridor-gate.pairLabel" .value -}}
{{- range $key, $item := .value -}}
{{- $here := printf "%s.%s" $path $key -}}
{{- if and $label (eq $key "value") -}}
{{- include "veridor-gate.scanCredentialValue" (dict "path" $here "value" $item "allow" $allow) -}}
{{- else -}}
{{- if and (eq (lower (include "veridor-gate.fold" $key)) "headers") (kindIs "map" $item) -}}
{{- range $header, $headerValue := $item -}}
{{- include "veridor-gate.scanHeader" (dict "path" (printf "%s.%s" $here $header) "name" $header "value" $headerValue "allow" $allow) -}}
{{- end -}}
{{- else if and (eq $key "inject") (kindIs "slice" $item) -}}
{{- range $index, $entry := $item -}}
{{- if kindIs "map" $entry -}}
{{- $at := printf "%s[%d].value" $here $index -}}
{{- if kindIs "string" $entry.header -}}
{{- include "veridor-gate.scanHeader" (dict "path" (printf "%s (header %s)" $at $entry.header) "name" $entry.header "value" $entry.value "allow" $allow) -}}
{{- end -}}
{{- range $slot := list "form_field" "json_field" -}}
{{- $field := get $entry $slot -}}
{{- if and (kindIs "string" $field) (eq (include "veridor-gate.credentialName" $field) "true") (eq (include "veridor-gate.isLiteral" $entry.value) "true") -}}
{{- fail (printf "veridor-gate: %s (%s %s) carries a literal value for a credential-named field (not printed). Reference a capture (${capture.NAME}) or a Secret-backed ${NAME} from secretEnv instead." $at $slot $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and (eq (include "veridor-gate.credentialName" $key) "true") (not (and $captureNames (eq (include "veridor-gate.isExtractor" $item) "true"))) -}}
{{- include "veridor-gate.scanCredentialValue" (dict "path" $here "value" $item "allow" $allow) -}}
{{- else -}}
{{- include "veridor-gate.scanCredentials" (dict "path" $here "value" $item "allow" $allow "captureNames" (eq $key "capture")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The value of a credential-named key, at any depth: a scalar must carry
     no literal, and so must every scalar beneath it, through lists and
     objects ({password: {value: L}}, Okta's credentials.password.value, was
     walked by the ordinary rules and rendered, measured). Only a key that
     describes the credential ($credentialDescriptors: type, username, ...)
     is walked by the ordinary rules. */}}
{{- define "veridor-gate.scanCredentialValue" -}}
{{- $path := .path -}}
{{- $allow := .allow -}}
{{- if kindIs "slice" .value -}}
{{- range $index, $item := .value -}}
{{- include "veridor-gate.scanCredentialValue" (dict "path" (printf "%s[%d]" $path $index) "value" $item "allow" $allow) -}}
{{- end -}}
{{- else if kindIs "map" .value -}}
{{- $descriptors := splitList " " (include "veridor-gate.credentialDescriptors" "") -}}
{{- range $inner, $item := .value -}}
{{- $here := printf "%s.%s" $path $inner -}}
{{- if and (regexMatch "^[\\x00-\\x7f]*$" $inner) (has (lower $inner) $descriptors) -}}
{{- include "veridor-gate.scanCredentials" (dict "path" $here "value" $item "allow" $allow "captureNames" false) -}}
{{- else -}}
{{- include "veridor-gate.scanCredentialValue" (dict "path" $here "value" $item "allow" $allow) -}}
{{- end -}}
{{- end -}}
{{- else if eq (include "veridor-gate.isLiteral" .value) "true" -}}
{{- fail (printf "veridor-gate: %s is a credential-named field with a literal value (not printed). Put the value in a Secret, write it as \"${NAME}\" (the reference alone, nothing around it), and map NAME with secretEnv." $path) -}}
{{- end -}}
{{- end -}}

{{/* The arguments after `veridor`. One list, so the Job and the tests agree. */}}
{{- define "veridor-gate.args" -}}
- run
- --config
- /config/veridor.json
- --output-dir
- {{ .Values.output.dir | quote }}
- --fail-on
- {{ .Values.gate.failOn | quote }}
{{- with .Values.target.baseUrl }}
- --base-url
- {{ . | quote }}
{{- end }}
{{- if .Values.gate.requireComplete }}
- --require-complete
{{- end }}
{{- if .Values.gate.requireCleanTeardown }}
- --require-clean-teardown
{{- end }}
{{- if .Values.gate.readOnly }}
- --read-only
{{- end }}
{{- if not .Values.gate.proveLiveness }}
- --no-prove-liveness
{{- end }}
{{- if .Values.gate.sarif }}
- --sarif
- {{ printf "%s/veridor.sarif" (trimSuffix "/" .Values.output.dir) | quote }}
{{- end }}
{{- if gt (int .Values.gate.waitForTargetSeconds) 0 }}
- --wait-for-target
- {{ int .Values.gate.waitForTargetSeconds | toString | quote }}
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | toString | quote }}
{{- end }}
{{- end -}}
