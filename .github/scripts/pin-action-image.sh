#!/usr/bin/env bash
# Usage: pin-action-image.sh pin|verify
#
# Makes the container pypa/gh-action-pypi-publish runs the one pinned by
# digest, and afterwards checks that it was. Reads ACTION_IMAGE (the image
# name), ACTION_REF (the action's commit SHA, the tag the action runs) and
# ACTION_DIGEST (sha256:...) from the environment.
#
# The action writes a docker action at run time whose image is
# docker://ghcr.io/pypa/gh-action-pypi-publish:<the SHA it was pinned at>, a
# tag, and that container makes the OIDC exchange that mints the PyPI token.
# A tag is whatever was last pushed to it. The runner starts a docker action
# it meets during a job with `docker run` and no pull (actions/runner,
# ContainerActionHandler.cs and DockerCommandManager.DockerRun), and docker run
# uses a local image of that name when one exists. So:
#
#   pin     pulls the image by digest and tags it with the name the action
#           will run, then checks that the name resolves to that digest's image.
#   verify  runs after the upload. It checks that the generated action named
#           that image, and that the name still resolves to the digest's
#           image, and fails the job otherwise.
#
# verify runs after the upload, so a failure there cannot undo one. It stops
# the jobs after it (image, chart, GitHub release) and makes the run fail.
set -euo pipefail

: "${ACTION_IMAGE:?}" "${ACTION_REF:?}" "${ACTION_DIGEST:?}"
if [[ ! "$ACTION_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "::error::ACTION_DIGEST '${ACTION_DIGEST}' is not a sha256 digest"
  exit 1
fi
pinned="${ACTION_IMAGE}@${ACTION_DIGEST}"
named="${ACTION_IMAGE}:${ACTION_REF}"
generated=.github/.tmp/.generated-actions/run-pypi-publish-in-docker-container/action.yml

same_image() {
  local want got
  want="$(docker image inspect --format '{{.Id}}' "$pinned")" || want=""
  got="$(docker image inspect --format '{{.Id}}' "$named")" || got=""
  if [[ -z "$want" || "$want" != "$got" ]]; then
    echo "::error::${named} is image '${got}', not ${pinned} ('${want}')$1"
    return 1
  fi
}

case "${1:-}" in
  pin)
    docker pull "$pinned"
    docker tag "$pinned" "$named"
    same_image ""
    echo "${named} is ${pinned}"
    ;;
  verify)
    if [[ ! -f "$generated" ]]; then
      echo "::error::${generated} is missing, so what the publish step ran cannot be checked; the action may have changed how it runs its container"
      exit 1
    fi
    image="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["runs"]["image"])' "$generated")"
    if [[ "$image" != "docker://${named}" ]]; then
      echo "::error::the publish step ran '${image}', not docker://${named}, so the digest pinned before it did not apply"
      exit 1
    fi
    same_image ": the publish step may have run something else"
    echo "the publish step ran ${named}, which is ${pinned}"
    ;;
  *)
    echo "usage: pin-action-image.sh pin|verify" >&2
    exit 2
    ;;
esac
