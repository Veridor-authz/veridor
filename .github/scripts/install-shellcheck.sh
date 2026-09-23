#!/usr/bin/env bash
# Install shellcheck 0.11.0 from its GitHub release, checked against a pinned
# sha256, into $RUNNER_TEMP/shellcheck and put it on GITHUB_PATH. The project
# publishes no checksum file; the digests below were recorded from the release
# assets on 2026-09-24. A runner image's own shellcheck varies by image version,
# and a test that REQUIRES shellcheck should not depend on which one it got.
set -euo pipefail

version=0.11.0
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    asset="shellcheck-v${version}.linux.x86_64.tar.xz"
    digest=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
    ;;
  Darwin/arm64)
    asset="shellcheck-v${version}.darwin.aarch64.tar.xz"
    digest=56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
    ;;
  *)
    echo "::error::no pinned shellcheck for $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

destination="${RUNNER_TEMP:?RUNNER_TEMP is not set}/shellcheck"
mkdir -p "$destination"
curl -fsSL -o "${destination}/${asset}" \
  "https://github.com/koalaman/shellcheck/releases/download/v${version}/${asset}"
actual="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${destination}/${asset}")"
if [[ "$actual" != "$digest" ]]; then
  echo "::error::${asset} sha256 is ${actual}, expected ${digest}" >&2
  exit 1
fi
tar -xJf "${destination}/${asset}" -C "$destination" --strip-components=1 "shellcheck-v${version}/shellcheck"
"${destination}/shellcheck" --version
echo "$destination" >> "${GITHUB_PATH:?GITHUB_PATH is not set}"
