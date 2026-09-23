#!/usr/bin/env bash
# Install syft v1.51.1 from its GitHub release, checked against a pinned
# sha256, into $RUNNER_TEMP/syft and put it on GITHUB_PATH. It replaces
# anchore/sbom-action, which (read at 3ad72834, v0.24.2) downloads syft's
# install.sh from raw.githubusercontent.com at the release tag and runs it;
# that script checks the binary only against the same release's checksums, so
# nothing in this repository pinned what ran. syft runs in the release build
# job after dist/ is built and before SHA256SUMS, provenance and the PyPI
# upload, so a substituted syft could have changed the files that are then
# attested and published. The digests are the ones in
# syft_1.51.1_checksums.txt on the v1.51.1 release; on 2026-09-24 both matched
# the sha256 of the downloaded tarballs, and `cosign verify-blob` accepted that
# checksums file's signature for the identity
# https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main
# (a one-line change to the file failed it). There is deliberately no
# download-URL override: the pinned digest is the control.
set -euo pipefail

version=1.51.1
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    platform=linux_amd64
    digest=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3
    ;;
  Darwin/arm64)
    platform=darwin_arm64
    digest=ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1
    ;;
  *)
    echo "::error::no pinned syft for $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

asset="syft_${version}_${platform}.tar.gz"
destination="${RUNNER_TEMP:?RUNNER_TEMP is not set}/syft"
mkdir -p "$destination"
curl -fsSL --retry 3 -o "${destination}/${asset}" \
  "https://github.com/anchore/syft/releases/download/v${version}/${asset}"
actual="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${destination}/${asset}")"
if [[ "$actual" != "$digest" ]]; then
  rm -f "${destination}/${asset}"
  echo "::error::${asset} sha256 is ${actual}, expected ${digest}" >&2
  exit 1
fi
tar -xzf "${destination}/${asset}" -C "$destination" syft
rm -f "${destination}/${asset}"
SYFT_CHECK_FOR_APP_UPDATE=false "${destination}/syft" version
echo "$destination" >> "${GITHUB_PATH:?GITHUB_PATH is not set}"
