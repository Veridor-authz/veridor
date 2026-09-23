#!/usr/bin/env bash
# Install kubectl v1.34.1 from dl.k8s.io, checked against a pinned sha256,
# into $RUNNER_TEMP/kubectl and put it on GITHUB_PATH. tests/test_kustomize.py
# renders the Kustomize overlays with `kubectl kustomize` (the kustomize v5.7.1
# embedded in this kubectl is the version its parity tests were measured with)
# and, under VERIDOR_REQUIRE_KUBECTL=1, fails instead of skipping without it.
# A runner image's own kubectl changes with the image, and a parity test
# should not depend on which one it got. The digests are the ones dl.k8s.io
# publishes beside each binary (kubectl.sha256); on 2026-09-24 both matched
# the sha256 of the downloaded binaries.
set -euo pipefail

version=v1.34.1
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    platform=linux/amd64
    digest=7721f265e18709862655affba5343e85e1980639395d5754473dafaadcaa69e3
    ;;
  Darwin/arm64)
    platform=darwin/arm64
    digest=d80e5fa36f2b14005e5bb35d3a72818acb1aea9a081af05340a000e5fbdb2f76
    ;;
  *)
    echo "::error::no pinned kubectl for $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

destination="${RUNNER_TEMP:?RUNNER_TEMP is not set}/kubectl"
mkdir -p "$destination"
curl -fsSL --retry 3 -o "${destination}/kubectl" "https://dl.k8s.io/release/${version}/bin/${platform}/kubectl"
actual="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${destination}/kubectl")"
if [[ "$actual" != "$digest" ]]; then
  rm -f "${destination}/kubectl"
  echo "::error::kubectl ${version} ${platform} sha256 is ${actual}, expected ${digest}" >&2
  exit 1
fi
chmod +x "${destination}/kubectl"
"${destination}/kubectl" version --client
echo "$destination" >> "${GITHUB_PATH:?GITHUB_PATH is not set}"
