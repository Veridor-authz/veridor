#!/usr/bin/env bash
# Fetch the published JSON schemas the CI checks validate against, each from a
# URL pinned to a commit and checked against a sha256, into DIR:
#
#   bash .github/scripts/fetch-schemas.sh DIR
#
#   DIR/sast-report-format.json  GitLab security-report-schemas v15.2.5
#                                (tag v15.2.5 is commit 94999aa4), the schema
#                                `veridor report --format gitlab-sast` targets
#   DIR/gitlab-ci.json           GitLab's CI/CD YAML schema (gitlab-org/gitlab,
#                                app/assets/javascripts/editor/schema/ci.json)
#   DIR/azure-pipelines.json     Azure Pipelines' service-schema.json
#                                (microsoft/azure-pipelines-vscode)
#
# The digests were computed on 2026-09-24 from these exact URLs. Each schema
# was also fetched a second way and compared: the SAST schema by its tag URL,
# and all three against the copies these checks were first run with here;
# every pair was byte-identical. A mismatch exits 1 naming the file and
# deletes what was downloaded for it.
set -euo pipefail

dest="${1:?usage: fetch-schemas.sh DIR}"
mkdir -p "$dest"

fetch() {  # name url sha256
  local name=$1 url=$2 expected=$3 actual
  curl -fsSL --retry 3 -o "${dest}/${name}.part" "$url"
  actual="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${dest}/${name}.part")"
  if [[ "$actual" != "$expected" ]]; then
    rm -f "${dest}/${name}.part"
    echo "::error::${name}: sha256 is ${actual}, expected ${expected} (${url})" >&2
    exit 1
  fi
  mv "${dest}/${name}.part" "${dest}/${name}"
  echo "${name}  sha256:${actual}  ${url}"
}

fetch sast-report-format.json \
  https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/94999aa479bd7607fb28e28701754021fe3a6723/dist/sast-report-format.json \
  1d2d2717fe7bd7bc5f3428bcfc4c3f2b7d60dbe27482602f99041da57afc33d8
fetch gitlab-ci.json \
  https://gitlab.com/gitlab-org/gitlab/-/raw/ea739d4df6c8be2fe674757d976920280de86b29/app/assets/javascripts/editor/schema/ci.json \
  a4dc2b155aa574575fbfd51dcca99388db5ba1b563ab5e05ce8df005e7eb9ced
fetch azure-pipelines.json \
  https://raw.githubusercontent.com/microsoft/azure-pipelines-vscode/9e40e814abd20917f273dd587497086f0476a563/service-schema.json \
  f00a9630f6550204148634d9a13f634b5750a225559886effe09a751482f0459
