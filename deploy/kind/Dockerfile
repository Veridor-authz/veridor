# Veridor demo image.
#
# The runtime is the Python standard library only, so there is no dependency
# layer to install and no lockfile to keep honest -- `pip install .` pulls in
# nothing but Veridor itself. tests/test_stdlib_only.py (fast tier) asserts
# both halves: an AST scan of every import in src/veridor/**, and no runtime
# dependency in pyproject.toml. This image is where it pays off.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Non-root by default. The viewer only ever reads files, but a container that
# does not need root should not have it.
RUN useradd --create-home --uid 10001 veridor

WORKDIR /app
COPY pyproject.toml README.pypi.md LICENSE NOTICE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && pip check

# Fixtures and the demo target are needed to SEED the demo, not to run Veridor.
# They are copied separately so it is obvious which parts of this image exist
# only for the demonstration.
COPY fixtures/ ./fixtures/
COPY scripts/demo_server.py ./scripts/demo_server.py
COPY deploy/kind/seed.sh ./seed.sh
RUN chmod +x ./seed.sh && mkdir -p /data && chown veridor:veridor /data

USER veridor
EXPOSE 8787
# 0.0.0.0 is the only bind a published container port can reach, so the
# acknowledgement `serve` demands is given here; publish it to loopback only:
#   docker run -p 127.0.0.1:8787:8787 ...
CMD ["veridor", "serve", "--output-dir", "/data/.veridor", "--host", "0.0.0.0", "--i-understand-this-is-unauthenticated", "--port", "8787"]
