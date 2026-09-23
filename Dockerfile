# The release image: the interpreter plus one wheel. The runtime imports
# nothing but the standard library, so there is no dependency tree to audit.
#
#   docker build -t veridor:local .
#   docker run --rm veridor:local --version
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" veridor:local \
#     run --config veridor.json
#
# Both stages use the same base, pinned by digest (python:3.12-alpine, a
# multi-arch index; Dependabot's docker ecosystem proposes digest updates).
# Alpine rather than slim: the same CPython 3.12 on musl, less than half the
# download. It has no bash, so a GitLab job in this image runs under sh, and
# its CA bundle is Alpine's, which lacks some legacy roots Debian still ships.
# The build stage makes the wheel; the runtime stage installs it with
# --no-index from a read-only mount of the build stage, so nothing but the
# installed wheel reaches the image: no tests, docs, fixtures or demo server,
# and no layer holding the wheel file. The mount needs BuildKit.

FROM python:3.12-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111 AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/
# The build backend is pinned by version and hash, and the wheel is built
# without build isolation or an index, so this stage fetches exactly one file.
RUN printf '%s\n' 'setuptools==84.0.0 --hash=sha256:51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670' \
      > /tmp/build-requirements.txt \
 && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: \
      -r /tmp/build-requirements.txt \
 && python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --no-index \
      --wheel-dir /dist .

FROM python:3.12-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111
ARG VERSION=0.0.0+local
ARG REVISION=unknown
ARG CREATED=unknown
# Non-root, uid and gid 10001 -- the ids the Helm chart's securityContext
# names. /work is the working directory and the default --output-dir parent;
# it is owned by 10001 in the image, but a bind mount replaces it with the
# host directory and its ownership (see the docker run line above).
RUN addgroup -S -g 10001 veridor \
 && adduser -S -D -H -u 10001 -G veridor -h /work -s /sbin/nologin veridor \
 && mkdir /work && chown 10001:10001 /work
# One layer, so what it deletes is never committed: install the wheel, then
# remove pip and ensurepip's bundled wheels (the image never installs anything
# again), then compile what the CLI's verbs import: veridor.cli, the modules
# they import lazily, the codecs a run looks up by name, and what `serve`
# imports to read its pages. The base ships no bytecode, and uid 10001 cannot
# write any, so a module left uncompiled here is compiled from source every
# time it is imported. tests/test_packaging.py runs every verb and fails when
# one imports a module this step does not reach; the CI image job checks that
# `--version` and a `run` in the image compile nothing. `env -u` keeps the
# step writing bytecode wherever PYTHONDONTWRITEBYTECODE is set, including for
# the modules the interpreter imports before the command runs.
RUN --mount=type=bind,from=build,source=/dist,target=/tmp/wheels \
    python -m pip install --no-cache-dir --no-index --no-deps /tmp/wheels/*.whl \
 && python -m pip uninstall --yes --no-cache-dir pip \
 && rm -rf /usr/local/lib/python3.12/ensurepip /usr/local/bin/pip* \
 && env -u PYTHONDONTWRITEBYTECODE python -c "import veridor.cli, veridor.capsule, veridor.mutation, veridor.sequence, veridor.web, encodings.idna, encodings.utf_16_be, encodings.utf_16_le, importlib.resources; [f.read_bytes() for f in importlib.resources.files(veridor.web).iterdir() if f.is_file()]"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["veridor"]
CMD ["--help"]

LABEL org.opencontainers.image.title="Veridor" \
      org.opencontainers.image.description="Authorization regression testing for CI" \
      org.opencontainers.image.source="https://github.com/Veridor-authz/veridor" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
