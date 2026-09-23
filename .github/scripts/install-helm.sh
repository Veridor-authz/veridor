#!/usr/bin/env bash
# Install helm v4.2.2 from get.helm.sh, checked against a pinned sha256, into
# $RUNNER_TEMP/helm and put it on GITHUB_PATH. It replaces azure/setup-helm,
# which downloads the same tarball and runs it with no digest comparison and
# no input to add one; the release chart job runs helm next to a ghcr login
# and an OIDC token that signs the chart. The digests are the ones get.helm.sh
# publishes beside each tarball (helm-v4.2.2-<platform>.tar.gz.sha256sum),
# which the v4.2.2 release notes on github.com/helm/helm repeat; on 2026-09-24
# both matched the sha256 of the downloaded tarballs. There is deliberately no
# download-URL override: the pinned digest is the control.
set -euo pipefail

version=v4.2.2
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    platform=linux-amd64
    digest=9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6
    ;;
  Darwin/arm64)
    platform=darwin-arm64
    digest=5410a0dae3d5d91f45653b161260d9301aabc4ae80ae50a6605d66884b6df8ea
    ;;
  *)
    echo "::error::no pinned helm for $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

asset="helm-${version}-${platform}.tar.gz"
destination="${RUNNER_TEMP:?RUNNER_TEMP is not set}/helm"
mkdir -p "$destination"
curl -fsSL --retry 3 -o "${destination}/${asset}" "https://get.helm.sh/${asset}"
actual="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${destination}/${asset}")"
if [[ "$actual" != "$digest" ]]; then
  rm -f "${destination}/${asset}"
  echo "::error::${asset} sha256 is ${actual}, expected ${digest}" >&2
  exit 1
fi
tar -xzf "${destination}/${asset}" -C "$destination" --strip-components=1 "${platform}/helm"
rm -f "${destination}/${asset}"
"${destination}/helm" version
echo "$destination" >> "${GITHUB_PATH:?GITHUB_PATH is not set}"
