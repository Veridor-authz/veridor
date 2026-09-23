# One side of the datasette pair, built from the published wheel of a single
# release. Datasette publishes no image for its 1.0 alphas -- Docker Hub carries
# only 0.x, and ghcr and quay carry nothing (measured 2026-09-27) -- so the pin
# is the wheel's own sha256 from PyPI, which names published bytes as exactly as
# a registry digest does.
#
# Both sides install the SAME hash-pinned dependency set (requirements.txt), so
# the only difference between the two images is the release under test. pip runs
# with --require-hashes, which refuses any file whose hash is not listed, and
# --only-binary, so nothing is built from source at image-build time.
ARG BASE
FROM ${BASE}
ARG PACKAGE
ARG VERSION
ARG SHA256
COPY requirements.txt /tmp/requirements.txt
RUN printf '%s==%s --hash=sha256:%s\n' "$PACKAGE" "$VERSION" "$SHA256" > /tmp/pin.txt \
 && cat /tmp/requirements.txt >> /tmp/pin.txt \
 && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/pin.txt \
 && rm /tmp/pin.txt /tmp/requirements.txt \
 # Proves the image holds the release the fixture named, from inside the image,
 # before any pair runs against it.
 && python -c "import importlib.metadata, sys; \
found = importlib.metadata.version(sys.argv[1]); \
sys.exit(0) if found == sys.argv[2] else sys.exit(f'built {sys.argv[1]} {found}, not {sys.argv[2]}')" \
      "$PACKAGE" "$VERSION"
COPY serve.py /opt/veridor/serve.py
# Not root: the vulnerable side is a known-vulnerable server, and nothing it
# does needs more than its own tmpfs.
USER 65534:65534
CMD ["python", "/opt/veridor/serve.py"]
