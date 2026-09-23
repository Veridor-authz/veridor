#!/bin/sh
# Seed the demo with REAL artifacts, by running all three verbs against a real
# target. Nothing here is fabricated: the finding the viewer shows is one this
# container actually measured, seconds earlier, against the demo server running
# beside it.
#
# Runs as an initContainer so the viewer starts with history already present.
# A first-time user opening an empty UI learns nothing about the product.
set -eu

OUT=/data/.veridor
PORT=8765
BASE="http://127.0.0.1:${PORT}"

# The demo server exits 2 rather than starting if the port is taken, so a
# failure to come up here means something is genuinely wrong -- not that we
# should carry on and probe whatever else answered. Every verb below is
# `|| true`, so this is the one place the seed can stop: the port must be free
# before the target starts, and the target must answer, still running, within
# 10s. Otherwise the init container fails and the viewer never starts, rather
# than starting over runs that measured something else or nothing.
port_answers() {
  python -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',${PORT}))==0 else 1)"
}
refuse_if_port_taken() {
  if port_answers; then
    echo "seed: something already answers on ${BASE}; refusing to probe it as the demo target" >&2
    exit 1
  fi
}
wait_for_target() {
  for _ in $(seq 1 40); do
    if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
      break
    fi
    if port_answers; then
      return 0
    fi
    sleep 0.25
  done
  echo "seed: the demo target did not answer on ${BASE}; its output above says why. Nothing more is seeded" >&2
  exit 1
}

refuse_if_port_taken
echo "==> starting the vulnerable demo target on ${BASE}"
python /app/scripts/demo_server.py --vulnerable --port "${PORT}" &
TARGET_PID=$!
trap 'kill "${TARGET_PID}" 2>/dev/null || true' EXIT
wait_for_target

echo "==> run: does the boundary hold?  (expects exit 1 -- a confirmed finding)"
veridor run --config /app/fixtures/veridor.demo.json --base-url "${BASE}" \
  --output-dir "${OUT}" --sarif "${OUT}/veridor.sarif" || true

echo "==> map: what would a compromise reach?"
veridor map --config /app/fixtures/veridor.map-demo.json \
  --openapi /app/fixtures/openapi.demo.json --base-url "${BASE}" \
  --output-dir "${OUT}" || true

echo "==> mutate: would the suite catch a regression?"
veridor mutate --config /app/fixtures/veridor.demo.json --base-url "${BASE}" \
  --output-dir "${OUT}" --min-interval 0 || true

kill "${TARGET_PID}" 2>/dev/null || true
wait "${TARGET_PID}" 2>/dev/null || true
trap - EXIT

# A second run against the PATCHED target, so the viewer has a baseline diff to
# show rather than a single run with nothing to compare against. This is the
# regression story the product exists for: the same declaration, the same
# command, a different answer.
refuse_if_port_taken
echo "==> starting the patched demo target"
python /app/scripts/demo_server.py --port "${PORT}" &
TARGET_PID=$!
trap 'kill "${TARGET_PID}" 2>/dev/null || true' EXIT
wait_for_target

echo "==> run: the same declaration against the fixed target (expects exit 0)"
veridor run --config /app/fixtures/veridor.demo.json --base-url "${BASE}" \
  --output-dir "${OUT}" || true

kill "${TARGET_PID}" 2>/dev/null || true
trap - EXIT

echo "==> seeded artifacts:"
find "${OUT}" -type f | sort
