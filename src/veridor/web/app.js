const state = {
  verb: "run",
  runs: [],
  maps: [],
  mutations: [],
  selected: null,
  activeDiff: "new",
  filter: "",
  // The route a link opened the page on, held until applyRoute() has read it.
  // Loading a list auto-selects its newest entry, and selecting rewrites the
  // hash, so without this a link to any older run opened the newest instead.
  pendingRoute: null,
};

// Fallbacks only. Every run document written by this Veridor carries its own
// `interpretation` block, and that is what gets rendered; these keep a v1 run
// -- written before the block existed -- from displaying counts with no scope
// at all. They are verified against core.DECLARATION_SCOPE / core.PASS_SCOPE
// by tests/test_ui.py, so they cannot drift from the strings the CLI prints.

// How a run's own status renders. `inconclusive` is neither: nothing was
// measured, which is not a pass and is not a finding about the target.
const STATUS_TONE = { passed: "safe", failed: "danger", inconclusive: "warn" };

// Green means what mutation.exit_code means by 0: mutants were generated and
// every one was killed. Keyed on `survived` alone, a report that generated
// nothing, or whose only unkilled mutants were aberrant or errored -- exit 2,
// "the engine does not know whether these checks discriminate" -- went green.
// Takes a report summary or a list entry; both carry these four counts.
function mutationTone(summary) {
  return summary.generated &&
    !summary.survived &&
    !summary.aberrant &&
    !summary.errored
    ? "safe"
    : "warn";
}

// The score, or null when it is not defined. mutation.score is null when no
// generated mutant was evaluated, and a report written before it was carries
// 0.0 for a run whose every mutant errored -- the target was down, and the
// list read "0.00 · 0/13 killed" as if thirteen checks had failed to
// discriminate. Recomputed from the counts so both render as no score.
function mutationScore(summary) {
  const value = summary.score;
  if (value === null || value === undefined) return null;
  const evaluated = (summary.generated ?? 0) - (summary.errored ?? 0);
  return evaluated > 0 ? value : null;
}

// The one-line tally under a list entry. Without a score there is no "killed
// of generated" worth printing: say what happened instead.
function mutationTally(summary) {
  if (mutationScore(summary) === null) {
    return summary.errored
      ? `none evaluated · ${summary.errored} errored`
      : "no mutant evaluated";
  }
  return `${summary.killed}/${summary.generated} killed · ${summary.survived ?? 0} surviving`;
}

// `status` is computed from findings alone, so a run the gate failed for a
// reason that is not a finding -- unproven liveness, an unclean teardown, an
// expectation that asserts nothing -- stays `passed`. Painted from `status`
// alone it got the green of a run that exited 0. Amber instead: CI failed it,
// and nothing about the target was found.
function runTone(status, gateExit) {
  const tone = STATUS_TONE[status] ?? "warn";
  return tone === "safe" && Number.isInteger(gateExit) && gateExit !== 0
    ? "warn"
    : tone;
}

// A capsule verification (`veridor verify`) exits with the capsule's verdict,
// not with a gate over findings, and was listed as an ordinary run: its status
// is computed from findings, so an INCONCLUSIVE verification -- exit 2, nothing
// established -- read FAILED in red. These say the verdict instead. The exit
// code each verdict means is checked against the gate's, and anything that
// does not agree, or a verdict this viewer does not know, is amber: never the
// green of NOT_REPRODUCED, which itself says "not reproduced", never "safe".
const CAPSULE_EXIT = { CONFIRMED: 1, NOT_REPRODUCED: 0, INCONCLUSIVE: 2 };
const CAPSULE_TONE = { CONFIRMED: "danger", NOT_REPRODUCED: "safe", INCONCLUSIVE: "warn" };

function capsuleStatus(capsule, gateExit) {
  // null for an ordinary run, including every run document written before
  // `verify` recorded its verdict.
  if (!capsule || typeof capsule !== "object") return null;
  const verdict = typeof capsule.verdict === "string" ? capsule.verdict : "";
  const agrees =
    Object.prototype.hasOwnProperty.call(CAPSULE_EXIT, verdict) &&
    CAPSULE_EXIT[verdict] === gateExit;
  return {
    verdict,
    tone: agrees ? CAPSULE_TONE[verdict] : "warn",
    label: `capsule · ${verdict ? verdict.replace(/_/g, " ") : "no verdict"}`,
  };
}

const DECLARATION_SCOPE =
  "Veridor evaluates the expectations you declared. A finding means observed " +
  "behaviour differed from your declaration; it does not establish that the " +
  "declaration is correct.";
const PASS_SCOPE =
  "A matched probe means the target agreed with your declaration for that " +
  "one request. It is not evidence that the boundary is enforced, and an " +
  "expectation that accepts both access and denial matches trivially.";

// The one sentence that keeps `map` honest. A candidate is an inconsistency in
// observations; promoting it to a finding is a human act that happens in a
// config file, never here. Rendered above the list, not below it.
const CANDIDATE_DISCIPLINE =
  "These are hypotheses, not findings. Each one is an inconsistency Veridor " +
  "observed and cannot interpret: it does not know what your boundary should " +
  "be. A candidate becomes a finding only when you declare an expectation for " +
  "it and `veridor run` measures a difference.";
// Drift's two halves, used only if the document does not carry its own. Both
// matter: the first stops a change reading as a verdict, and the second stops
// "nothing moved" reading as "nothing is wrong". A diff can only ever speak
// about what changed.
const DRIFT_DISCIPLINE =
  "A change is an observation, not a verdict. Reach that opened may be a " +
  "feature you shipped; reach that closed may be a broken deploy rather than " +
  "a fix. Veridor reports what moved between two runs and cannot tell you " +
  "which of those it is looking at.";
const DRIFT_BLINDNESS =
  "Blind to anything that did not change. An endpoint that has been open to " +
  "everyone since the first run never moves, so it never appears here.";
// And the one that keeps `mutate` honest.
const MUTANT_DISCIPLINE =
  "A surviving mutant means this check MAY BE VACUOUS -- it may pass whatever " +
  "the target does. It is not a report about your target, and a score of 1.00 " +
  "does not mean the boundary is enforced.";

const VERB_LABELS = {
  map: {
    heading: "Map history",
    empty: "No maps yet. Execute <code>veridor map</code> to create one.",
    title: "Select a map",
    blurb: "Observed reach per identity, and the inconsistencies worth declaring a check for.",
    command: "veridor map --config veridor.json --openapi openapi.json",
  },
  run: {
    heading: "Run history",
    empty: "No runs yet. Execute <code>veridor run</code> to create one.",
    title: "Select a run",
    blurb: "Findings, evidence grades, and what changed since your baseline.",
    command: "veridor run --config veridor.json",
  },
  mutate: {
    heading: "Mutation history",
    empty: "No mutation reports yet. Execute <code>veridor mutate</code> to create one.",
    title: "Select a mutation report",
    blurb: "Which of your checks would still pass if the boundary broke.",
    command: "veridor mutate --config veridor.json",
  },
};

const runsElement = document.querySelector("#runs");
const emptyElement = document.querySelector("#empty-runs");
const detailElement = document.querySelector("#run-detail");
const connectionElement = document.querySelector("#connection");
const headingElement = document.querySelector("#list-heading");
const noMatchesElement = document.querySelector("#no-matches");
const filterElement = document.querySelector("#filter");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatDate(value) {
  if (!value) return "Unknown time";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function targetLabel(target) {
  if (!target) return "unknown target";
  if (typeof target === "string") return target;
  return target.base_url || target.host || "unknown target";
}

function setConnection(text, kind) {
  connectionElement.textContent = text;
  connectionElement.className = `status ${kind}`;
}

async function request(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

// ---------------------------------------------------------------- loading

async function loadRuns() {
  setConnection("Syncing", "neutral");
  loadedAt = Date.now();
  try {
    if (state.verb === "map") {
      const payload = await request("/api/maps");
      state.maps = payload.maps;
      renderRuns();
      setConnection("Local", "safe");
      if (!state.selected && !state.pendingRoute && state.maps.length) {
        await selectMap(state.maps[0].map_id);
      }
    } else if (state.verb === "mutate") {
      const payload = await request("/api/mutations");
      state.mutations = payload.mutations;
      renderRuns();
      setConnection("Local", "safe");
      if (!state.selected && !state.pendingRoute && state.mutations.length) {
        await selectMutation(state.mutations[0].stem);
      }
    } else {
      const payload = await request("/api/runs");
      state.runs = payload.runs;
      renderRuns();
      setConnection("Local", "safe");
      if (!state.selected && !state.pendingRoute && state.runs.length) {
        await selectRun(state.runs[0].run_id);
      }
    }
  } catch (error) {
    setConnection("Unavailable", "danger");
    showError(error);
  }
}

function placeholder(verb) {
  const labels = VERB_LABELS[verb];
  const box = element("div", "placeholder");
  box.append(element("h2", "", labels.title));
  box.append(element("p", "muted", labels.blurb));
  // The command that produces one. An empty pane that only says "select
  // something" is useless to the person who has nothing to select.
  box.append(element("code", "placeholder-hint", labels.command));
  return box;
}

function showSkeleton() {
  const bones = element("div", "skeleton");
  for (let index = 0; index < 4; index += 1) {
    bones.append(element("div", "skeleton-row"));
  }
  runsElement.replaceChildren(bones);
}

function selectVerb(verb) {
  if (state.verb === verb) return;
  switchVerb(verb);
  loadRuns();
}

// Everything a change of verb changes on screen, for a tab click and for a
// link alike. A link that opened a map used to flip state.verb alone, so the
// map was drawn under the "run" tab and a "Run history" heading.
function switchVerb(verb) {
  state.verb = verb;
  state.selected = null;
  // A filter typed against runs means nothing against maps, and silently
  // carrying it over would look like an empty history.
  state.filter = "";
  filterElement.value = "";
  noMatchesElement.hidden = true;
  headingElement.textContent = VERB_LABELS[verb].heading;
  emptyElement.innerHTML = VERB_LABELS[verb].empty;
  emptyElement.hidden = true;
  for (const button of document.querySelectorAll("[data-verb]")) {
    button.setAttribute("aria-selected", button.dataset.verb === verb ? "true" : "false");
  }
  detailElement.replaceChildren(placeholder(verb));
  showSkeleton();
}

// ------------------------------------------------------------------ list

function listButton(id, selected, lines) {
  const button = element("button", "run-button");
  button.type = "button";
  button.dataset.runId = id;
  if (selected) button.classList.add("selected");
  for (const line of lines) button.append(line);
  return button;
}

function matchesFilter(entry) {
  const needle = state.filter.trim().toLowerCase();
  if (!needle) return true;
  // Match on everything the row displays, so what a reader can see is what
  // they can search: identifier, target, status, tier.
  const haystack = [
    entry.run_id,
    entry.map_id,
    entry.stem,
    entry.status,
    capsuleStatus(entry.capsule, entry.gate_exit_code)?.label,
    entry.capsule?.check_id,
    entry.tier === undefined ? "" : `tier ${entry.tier}`,
    targetLabel(entry.target),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function renderRuns() {
  runsElement.replaceChildren();
  const all =
    state.verb === "map"
      ? state.maps
      : state.verb === "mutate"
        ? state.mutations
        : state.runs;
  const items = all.filter(matchesFilter);
  // "No artifacts at all" and "none match your filter" are different problems
  // with different fixes, so they get different messages.
  emptyElement.hidden = all.length !== 0;
  noMatchesElement.hidden = !(all.length !== 0 && items.length === 0);

  for (const entry of items) {
    let button;
    if (state.verb === "map") {
      const top = element("span", "run-top");
      top.append(element("strong", "", entry.map_id));
      top.append(element("span", "dot neutral", "observed"));
      const count = entry.candidate_count ?? 0;
      // `drift` is null when no baseline was given, and that is a third state,
      // not zero: "not compared" must not read as "compared, nothing moved".
      // Only the former is silent here.
      let summary =
        `${entry.inventory?.operations ?? 0} operations · ` +
        `${count} candidate${count === 1 ? "" : "s"}`;
      if (entry.drift) {
        const moved = entry.drift.changes ?? 0;
        summary += ` · ${moved} change${moved === 1 ? "" : "s"} vs baseline`;
        if (entry.drift.significant) {
          top.append(
            element("span", "dot warn", `${entry.drift.significant} more access`),
          );
        }
      }
      button = listButton(entry.map_id, state.selected?.map_id === entry.map_id, [
        top,
        element("span", "muted", targetLabel(entry.target)),
        element("span", "run-summary", summary),
      ]);
      button.addEventListener("click", () => selectMap(entry.map_id));
    } else if (state.verb === "mutate") {
      const top = element("span", "run-top");
      top.append(element("strong", "", `tier ${entry.tier ?? 1}`));
      top.append(
        element(
          "span",
          `dot ${mutationTone(entry)}`,
          mutationScore(entry) === null ? "no score" : entry.score.toFixed(2),
        ),
      );
      button = listButton(entry.stem, state.selected?.stem === entry.stem, [
        top,
        element("span", "muted", formatDate(entry.completed_at)),
        element("span", "run-summary", mutationTally(entry)),
      ]);
      button.addEventListener("click", () => selectMutation(entry.stem));
    } else {
      const top = element("span", "run-top");
      top.append(element("strong", "", entry.run_id));
      const capsule = capsuleStatus(entry.capsule, entry.gate_exit_code);
      top.append(
        capsule
          ? element("span", `dot ${capsule.tone}`, capsule.label)
          : element(
              "span",
              `dot ${runTone(entry.status, entry.gate_exit_code)}`,
              entry.status,
            ),
      );
      button = listButton(entry.run_id, state.selected?.run_id === entry.run_id, [
        top,
        element("span", "muted", formatDate(entry.started_at)),
        element(
          "span",
          "run-summary",
          capsule
            ? `check ${entry.capsule.check_id ?? "unnamed"} · ${entry.summary?.probes ?? 0} probes`
            : `${entry.summary?.probes ?? 0} probes · ${entry.summary?.new ?? 0} new`,
        ),
      ]);
      button.addEventListener("click", () => selectRun(entry.run_id));
    }
    const item = document.createElement("li");
    item.append(button);
    runsElement.append(item);
  }
}

async function selectRun(runId, options = {}) {
  try {
    state.selected = await request(`/api/runs/${encodeURIComponent(runId)}`);
    state.activeDiff = "new";
    if (!options.fromHash) writeHash("run", runId);
    renderRuns();
    renderDetail();
  } catch (error) {
    showError(error);
  }
}

async function selectMap(mapId, options = {}) {
  try {
    state.selected = await request(`/api/maps/${encodeURIComponent(mapId)}`);
    if (!options.fromHash) writeHash("map", mapId);
    renderRuns();
    renderMapDetail();
  } catch (error) {
    showError(error);
  }
}

async function selectMutation(stem, options = {}) {
  try {
    const report = await request(`/api/mutations/${encodeURIComponent(stem)}`);
    if (!options.fromHash) writeHash("mutate", stem);
    report.stem = stem;
    state.selected = report;
    renderRuns();
    renderMutateDetail();
  } catch (error) {
    showError(error);
  }
}

// ----------------------------------------------------------------- parts

function metric(label, value, tone = "") {
  // A zero is dimmed rather than dropped. Six equally-loud numbers of which
  // four are zero is a row the eye cannot triage, but removing the zeros would
  // be worse: "0 inconclusive" is a real result, and a metric that disappears
  // when empty makes the reader wonder whether it was measured at all.
  const empty = Number(value) === 0 ? " zero" : "";
  const card = element("div", `metric ${tone}${empty}`);
  card.append(element("span", "metric-value", String(value)));
  card.append(element("span", "muted", label));
  return card;
}

function splitLead(text) {
  /* Return [first sentence, remainder]. Used only for presentation: not one
     word is dropped, reordered or rewritten -- the claim paragraphs are the
     product's credibility and a viewer that edited them would be lying. The
     split is on the first sentence boundary that leaves a usable lead, so a
     "1.0" or an abbreviation mid-sentence does not cut it in half. */
  const match = String(text).match(/^([\s\S]{40,240}?[.!?])\s+(?=[A-Z])/);
  if (!match) return [String(text), ""];
  return [match[1], String(text).slice(match[0].length)];
}

function shortId(value) {
  // The trailing hash is what distinguishes two artifacts; the timestamp prefix
  // is the same twenty characters on every one of them. Leading with the digest
  // makes a list scannable, and the full id stays one line below.
  if (!value) return "unknown";
  const tail = String(value).split("-").pop();
  return tail && tail.length >= 4 ? tail : String(value);
}

function rawLink(href, label) {
  // A security tool that will not show you its own JSON is asking for trust it
  // has not earned. Every view links to the exact document it rendered.
  const link = element("a", "raw-link", label);
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener";
  return link;
}

function proportionBar(reached, refused, unmeasured, total) {
  /* Reach is a proportion and was rendered only as prose. The bar is a second
     encoding of the same numbers, never a new claim: the unmeasured slice is
     drawn in its own neutral tone precisely so a small reach bar cannot be
     misread as "this identity reaches little" when most cells were never
     probed. */
  const bar = element("div", "bar");
  bar.setAttribute("role", "img");
  bar.setAttribute(
    "aria-label",
    `${reached} reached, ${refused} refused, ${unmeasured} unmeasured of ${total}`,
  );
  const denominator = Math.max(total, 1);
  for (const [kind, value] of [
    ["reached", reached],
    ["refused", refused],
    ["unmeasured", unmeasured],
  ]) {
    if (!value) continue;
    const part = element("span", `bar-part bar-${kind}`);
    part.style.width = `${(value / denominator) * 100}%`;
    bar.append(part);
  }
  return bar;
}

function gateBanner(run) {
  /* The run's outcome in one line, the way CI acts on it: the gate's exit code
     and the counts behind it. Every value is read from the run document and
     the tone comes from runTone(), the same rule the status badge uses -- a run
     the gate failed for a reason that is not a finding stays amber, never red
     and never green. A document without a gate (an old schema) gets no banner
     rather than a guessed one. A capsule verification is headed by its verdict
     and toned by capsuleStatus(): its exit code is the capsule's, and "Gate
     passes" over NOT_REPRODUCED would say more than one claim not reproducing
     establishes. */
  const gate = run.gate || {};
  if (!Number.isInteger(gate.exit_code)) return null;
  const summary = run.summary || {};
  const capsule = capsuleStatus(run.capsule, gate.exit_code);
  const tone = capsule ? capsule.tone : runTone(run.status, gate.exit_code);
  const banner = element("div", `gate-banner ${tone}`);
  const passed = gate.exit_code === 0;
  const head = element("div", "gate-head");
  head.append(
    element(
      "span",
      "gate-word",
      capsule
        ? `Capsule ${capsule.verdict ? capsule.verdict.replace(/_/g, " ") : "without a verdict"}`
        : passed
          ? "Gate passes"
          : "Gate fails",
    ),
    element("span", "gate-exit", `exit ${gate.exit_code}`),
  );
  banner.append(head);
  const facts = [];
  if (capsule) {
    facts.push(`check ${run.capsule.check_id ?? "unnamed"}`);
    if (typeof run.capsule.reason === "string" && run.capsule.reason) {
      facts.push(run.capsule.reason);
    }
  }
  if (summary.vulnerable) {
    const confirmed = summary.confirmed ?? 0;
    facts.push(
      `${summary.vulnerable} vulnerable` +
        (confirmed ? ` (${confirmed} confirmed by marker)` : ""),
    );
  }
  if (Number.isInteger(summary.probes)) {
    facts.push(`${summary.safe ?? 0}/${summary.probes} probes matched their declaration`);
  }
  // "new" and "resolved" are relative to a baseline. Without one every finding
  // counts as new, so naming a baseline would claim a comparison that never ran.
  if ((run.regression || {}).baseline_run_id) {
    if (summary.resolved) facts.push(`${summary.resolved} resolved since the baseline`);
    if (summary.new) facts.push(`${summary.new} new since the baseline`);
  }
  // A capsule's own reason is the verdict in the head, already said.
  const reasons = capsule
    ? []
    : (gate.reasons || []).filter((reason) => reason.code !== "findings");
  if (!passed && reasons.length) {
    facts.push(`failed for: ${reasons.map((reason) => reason.code).join(", ")}`);
  }
  if (gate.fail_on) facts.push(`fail-on ${gate.fail_on}`);
  banner.append(element("p", "gate-facts", facts.join(" · ")));
  return banner;
}

function accessMatrix(matrix) {
  /* The map as the grid it is: one row per operation (and specimen), one
     column per identity, each cell the status Veridor measured. Colour encodes
     reach exactly as the matrix document records it; a cell whose response
     carried ANOTHER identity's planted marker is ringed in amber, not red,
     because in a map that is an observation to declare and test, never a
     finding. Cells that were not probed say so instead of looking refused. */
  const cells = matrix.cells || [];
  const identities = matrix.identities || [];
  const rows = matrix.rows || [];
  if (!cells.length || !identities.length || !rows.length) return null;
  const key = (operation, specimen, identity) =>
    `${operation}\u0000${specimen ?? ""}\u0000${identity}`;
  const index = new Map(
    cells.map((cell) => [key(cell.operation, cell.specimen, cell.identity), cell]),
  );
  const wrap = element("div", "matrix-scroll");
  const grid = element("div", "matrix");
  grid.setAttribute("role", "table");
  grid.setAttribute("aria-label", "Access matrix: each operation as each identity");
  grid.style.setProperty("--columns", identities.length);
  const header = element("div", "matrix-row");
  header.setAttribute("role", "row");
  header.append(element("span", "matrix-corner", "operation"));
  for (const identity of identities) {
    const cell = element("span", "matrix-identity", identity);
    cell.setAttribute("role", "columnheader");
    header.append(cell);
  }
  grid.append(header);
  let crossed = 0;
  for (const row of rows) {
    const line = element("div", "matrix-row");
    line.setAttribute("role", "row");
    const [method, ...rest] = String(row.operation).split(" ");
    const label = element("span", "matrix-op");
    label.setAttribute("role", "rowheader");
    label.append(element("b", "", method), document.createTextNode(` ${rest.join(" ")}`));
    if (row.specimen) label.append(element("small", "", row.specimen));
    line.append(label);
    for (const identity of identities) {
      const cell = index.get(key(row.operation, row.specimen, identity));
      const reach = cell?.reach || "unknown";
      const box = element("span", `matrix-cell ${reach}`);
      box.setAttribute("role", "cell");
      const status = Number.isInteger(cell?.status) ? String(cell.status) : "·";
      box.append(element("span", "", status));
      let description = `${identity}, ${row.operation}: ${reach}`;
      if (Number.isInteger(cell?.status)) description += `, HTTP ${cell.status}`;
      if (cell?.unknown_reason) description += ` (${cell.unknown_reason})`;
      // The panel says a dot's tooltip says why; for a cell the document
      // does not hold at all, the why is that it holds none.
      else if (!cell) description += " (no cell recorded)";
      if (cell?.marker_scan === "present" && cell.marker_owner) {
        const own = cell.marker_owner === identity;
        box.append(element("i", own ? "matrix-marker own" : "matrix-marker"));
        if (!own) {
          box.classList.add("crossed");
          crossed += 1;
        }
        description += own
          ? ", carries its own marker"
          : `, carries ${cell.marker_owner}'s marker`;
      }
      box.title = description;
      box.setAttribute("aria-label", description);
      line.append(box);
    }
    grid.append(line);
  }
  wrap.append(grid);
  const legend = element("div", "matrix-legend");
  legend.append(
    element("span", "key-reached", "reached"),
    element("span", "key-refused", "refused"),
    element("span", "key-unknown", "not probed or unknown"),
    element("span", "key-marker", "planted marker in the response"),
  );
  if (crossed) {
    legend.append(
      element("span", "key-crossed", `${crossed} cell${crossed === 1 ? "" : "s"} carried another identity's marker: a candidate below, not a finding`),
    );
  }
  const container = element("div", "matrix-block");
  container.append(wrap, legend);
  return container;
}

//: How many findings render before the list offers to show the rest. A run
//: with hundreds -- a first run against a large suite -- rendered every one,
//: so the page a reader opens to triage the first finding stalls on the last.
const FINDING_PAGE = 50;

function findingCard(finding, resolved = false) {
  const card = element("article", `finding ${resolved ? "resolved" : finding.level}`);
  // The anchor a deep link targets. `finding.id` IS the SARIF
  // partialFingerprint, so a link survives a re-run.
  if (finding.id) card.dataset.fingerprint = finding.id;
  const heading = element("div", "finding-heading");
  heading.append(element("strong", "", finding.title || finding.id));
  const chips = element("span", "finding-chips");
  // The evidence grade travels with the verdict: "confirmed" means the
  // response carried another identity's planted marker, which is what makes
  // a 200 more than a status-code disagreement.
  if (finding.evidence_grade && !resolved) {
    chips.append(element("span", `grade ${finding.evidence_grade}`, finding.evidence_grade));
  }
  chips.append(element("span", "verdict", resolved ? "resolved" : finding.verdict));
  heading.append(chips);
  card.append(heading);
  card.append(element("p", "", finding.message));
  card.append(
    element(
      "p",
      "muted mono",
      `${finding.check_id} · identity: ${finding.identity}`,
    ),
  );
  if (finding.remediation && !resolved) {
    card.append(element("p", "remediation", `Fix: ${finding.remediation}`));
  }
  return card;
}

function disclosureList(run) {
  // Each block describes outcomes that produce NO finding: an expectation that
  // accepts both access and denial, an exclusion licensed by an identity
  // marker_probe rather than by a control at the path under test, and a
  // request that went out without a declared form_field or json_field its body
  // could not carry. They were recorded only in the raw run JSON, so a reviewer
  // reading a green dashboard could not distinguish any of them from a
  // same-path-proven pass.
  // oracle_disclosures holds two kinds: a marker_probe licence, and a
  // request whose fabricated credential the target served. Each gets its own
  // heading, so a target that accepts a forged credential is not described as
  // a marker live elsewhere.
  const served = (entry) => entry.control_source === "fabricated_credential";
  const groups = [
    ["non_asserting_expectations", "Expectations that assert nothing"],
    ["oracle_disclosures", "Exclusions licensed away from the tested path",
      (entry) => !served(entry)],
    ["oracle_disclosures", "Requests that served a fabricated credential", served],
    ["injection_disclosures", "Requests sent without a declared body field"],
  ];
  const container = element("div", "disclosure-list");
  let rendered = 0;
  for (const [key, heading, keep] of groups) {
    const entries = (run[key] || []).filter(keep || (() => true));
    if (!entries.length) continue;
    rendered += 1;
    container.append(element("h4", "", `${heading} (${entries.length})`));
    const list = element("ul", "disclosure-items");
    for (const entry of entries) {
      const item = document.createElement("li");
      // An injection disclosure names a sequence step, a teardown entry or a
      // marker probe as often as a check, so it carries its own label.
      const label = entry.where || entry.check_id;
      item.append(element("span", "mono", `${label} · ${entry.identity}`));
      item.append(element("span", "", ` ${entry.statement}`));
      list.append(item);
    }
    container.append(list);
  }
  return rendered ? container : null;
}

function renderScope(fragment, run) {
  const interpretation = run.interpretation || {};
  const finding = fragment.querySelector('[data-field="scope-finding"]');
  const pass = fragment.querySelector('[data-field="scope-pass"]');
  finding.textContent = `Findings: ${
    interpretation.summary || DECLARATION_SCOPE
  }`;
  pass.textContent = `Passes: ${interpretation.pass_means || PASS_SCOPE}`;
  const disclosures = disclosureList(run);
  if (disclosures) {
    fragment.querySelector('[data-field="disclosures"]').append(disclosures);
  }
}

function findingList(findings, emptyText, resolved = false) {
  if (!findings.length) return element("p", "empty", emptyText);
  const list = element("div", "finding-list");
  const shown = findings.slice(0, FINDING_PAGE);
  for (const finding of shown) list.append(findingCard(finding, resolved));
  if (findings.length > shown.length) {
    // A first run against a large suite can carry hundreds. Rendering every
    // one stalls the page a reader opened to triage the FIRST.
    const more = element(
      "button", "more", `Show ${findings.length - shown.length} more`,
    );
    more.type = "button";
    more.addEventListener("click", () => {
      more.remove();
      for (const finding of findings.slice(FINDING_PAGE)) {
        list.append(findingCard(finding, resolved));
      }
    });
    list.append(more);
  }
  return list;
}

// -------------------------------------------------------------- run view

function renderDetail() {
  const run = state.selected;
  const template = document.querySelector("#detail-template");
  const fragment = template.content.cloneNode(true);
  fragment.querySelector('[data-field="run-id"]').textContent =
    `Run ${shortId(run.run_id)}`;
  const meta = fragment.querySelector('[data-field="metadata"]');
  meta.textContent = `${formatDate(run.started_at)} · ${run.target} · `;
  meta.append(
    element("span", "mono", run.run_id),
    document.createTextNode(" · "),
    rawLink(`/api/runs/${encodeURIComponent(run.run_id)}`, "raw JSON"),
  );

  const status = fragment.querySelector('[data-field="run-status"]');
  const gate = run.gate || {};
  const gateFailed = Number.isInteger(gate.exit_code) && gate.exit_code !== 0;
  const capsule = capsuleStatus(run.capsule, gate.exit_code);
  status.textContent = capsule
    ? capsule.label
    : gateFailed && run.status === "passed"
      ? `${run.status} · gate exit ${gate.exit_code}`
      : run.status;
  // Three states, not two. `inconclusive` is a run that measured nothing --
  // amber, because a red FAILED badge over a green exit code told a reader the
  // opposite of what happened, and a green one would be worse. A capsule
  // verification is toned by its verdict, for the same reason.
  status.classList.add(capsule ? capsule.tone : runTone(run.status, gate.exit_code));

  const summary = run.summary;
  const metrics = fragment.querySelector('[data-field="metrics"]');
  // "Matched", not "Safe": the measurement compared a status against a list
  // the operator wrote. `summary.safe` keeps its key for schema stability.
  // "Unexpected denial" is separated from "Vulnerable" for the same reason the
  // grader separates the verdicts -- a probe the target REFUSED returned no
  // data at all, and painting it red contradicts Veridor's own model.
  metrics.append(
    metric("Probes", summary.probes),
    metric("Matched", summary.safe, "safe"),
    metric("Vulnerable", summary.vulnerable, summary.vulnerable ? "danger" : ""),
    metric("Unexpected denial", summary.unexpected_denial ?? 0),
    metric("Inconclusive", summary.inconclusive),
    metric(
      "Escalated",
      summary.escalated ?? 0,
      summary.escalated ? "danger" : "",
    ),
  );

  const banner = gateBanner(run);
  if (banner) fragment.querySelector('[data-field="gate"]').append(banner);

  renderScope(fragment, run);

  fragment.querySelector('[data-field="finding-count"]').textContent =
    `${run.findings.length} total`;
  const findingsField = fragment.querySelector('[data-field="findings"]');
  // Said above the findings: the gate failed this run for a reason that is
  // not a finding, so "no active findings" is true and is not a pass.
  // A capsule verification's reason is its verdict, said on the badge and
  // the banner; it is not a gate condition to explain here.
  const gateReasons = capsule
    ? []
    : (gate.reasons || []).filter((reason) => reason.code !== "findings");
  if (gateFailed && gateReasons.length) {
    findingsField.append(
      element(
        "p",
        "warn-note",
        `The gate failed this run with exit ${gate.exit_code} for a reason that ` +
          "is not a finding: " +
          gateReasons
            .map((reason) =>
              reason.count === undefined
                ? reason.code
                : `${reason.code} (${reason.count})`,
            )
            .join(", ") +
          ". The status above describes the findings only.",
      ),
    );
  }
  findingsField.append(
    findingList(run.findings, "No active findings. All probes matched expectations."),
  );
  fragment.querySelector('[data-field="baseline"]').textContent =
    run.regression.baseline_run_id
      ? `vs ${run.regression.baseline_run_id}`
      : "No baseline";

  for (const button of fragment.querySelectorAll("[data-tab]")) {
    const tab = button.dataset.tab;
    // `escalated` is absent from v1 run documents, which the viewer still
    // loads, so every category is read defensively.
    const entries = run.regression[tab] || [];
    button.textContent = `${button.textContent} (${entries.length})`;
    button.setAttribute("aria-selected", tab === state.activeDiff ? "true" : "false");
    button.addEventListener("click", () => {
      state.activeDiff = tab;
      renderDetail();
    });
  }
  const selected = run.regression[state.activeDiff] || [];
  fragment
    .querySelector('[data-field="diff"]')
    .append(
      findingList(
        selected,
        `No ${state.activeDiff} findings in this comparison.`,
        state.activeDiff === "resolved",
      ),
    );
  detailElement.replaceChildren(fragment);
}

// -------------------------------------------------------------- map view

function reachRow(entry) {
  const row = element("article", "reach");
  const heading = element("div", "finding-heading");
  heading.append(element("strong", "", entry.identity));
  const counts = entry.counts || {};
  heading.append(
    element("span", "verdict neutral", `${counts.reached ?? 0} reached`),
  );
  row.append(heading);
  row.append(
    proportionBar(
      counts.reached ?? 0,
      counts.refused ?? 0,
      counts.unmeasured ?? 0,
      counts.inventory ?? 0,
    ),
  );
  // The document's own headline says "at least N of M", because unmeasured
  // cells make every reach count a lower bound. Rendering it verbatim is what
  // keeps the number from being read as a total.
  row.append(element("p", "", entry.headline || ""));
  // The counts line doubles as the bar's key. Three colours with no legend are
  // decoration; colouring the words that name them costs nothing and means the
  // bar explains itself without adding a second row of chrome.
  const detail = element("p", "muted mono bar-key");
  const parts = [
    ["reached", counts.reached ?? 0, "reached"],
    ["refused", counts.refused ?? 0, "refused"],
    ["indeterminate", counts.indeterminate ?? 0, null],
    ["unmeasured", counts.unmeasured ?? 0, "unmeasured"],
  ];
  parts.forEach(([label, value, kind], index) => {
    if (index) detail.append(document.createTextNode(" · "));
    const span = element("span", kind ? `key key-${kind}` : "");
    span.textContent = `${label} ${value}`;
    detail.append(span);
  });
  detail.append(
    document.createTextNode(` of ${counts.inventory ?? 0} inventoried`),
  );
  row.append(detail);
  const reached = entry.reached_operations || [];
  if (reached.length) {
    const list = element("ul", "disclosure-items");
    for (const operation of reached) {
      const item = document.createElement("li");
      item.append(element("span", "mono", operation.operation));
      item.append(element("span", "muted", ` → ${operation.status}`));
      list.append(item);
    }
    row.append(list);
  }
  return row;
}

// Drift changes carry the SAME amber as candidates and survivors, and for the
// same reason: amber means "you cannot conclude anything from this yet". A
// change that means more access is a measured difference between two runs, not
// a verdict on either -- reach that opened may be a feature that shipped this
// week. Red here would say Veridor knows which, and it does not.
function driftCard(change) {
  const card = element(
    "article",
    `finding ${change.significant ? "drift-significant" : "drift-change"}`,
  );
  const heading = element("div", "finding-heading");
  const where = [change.operation, change.identity, change.specimen ? `[${change.specimen}]` : ""]
    .filter(Boolean)
    .join(" · ");
  heading.append(element("strong", "", where || change.kind));
  heading.append(
    element(
      "span",
      `verdict ${change.significant ? "warn" : "neutral"}`,
      change.kind,
    ),
  );
  card.append(heading);
  card.append(
    element("p", "muted mono", `${change.before ?? "—"} → ${change.after ?? "—"}`),
  );
  // The note is the honest half: every kind carries its own caveat in the
  // document, so the reader gets "this may be a fix, or a feature that broke"
  // rather than a bare label they have to interpret alone.
  card.append(element("p", "", change.note || ""));
  return card;
}

function candidateCard(candidate) {
  const card = element("article", "finding candidate");
  const heading = element("div", "finding-heading");
  heading.append(
    element("strong", "", `${candidate.identity} · ${candidate.operation}`),
  );
  heading.append(element("span", "verdict neutral", candidate.rule));
  card.append(heading);
  card.append(element("p", "", candidate.explanation || ""));

  const meta = [
    candidate.evidence_tier ? `evidence: ${candidate.evidence_tier}` : null,
    candidate.ranking?.consensus ? `consensus: ${candidate.ranking.consensus}` : null,
    ...(candidate.tags || []),
  ].filter(Boolean);
  if (meta.length) card.append(element("p", "muted mono", meta.join(" · ")));

  // Every rule declares the shapes it is known to get wrong, and those live in
  // the document already. Showing them next to the candidate is the difference
  // between a hypothesis an operator can evaluate and a bare accusation they
  // have to take on trust -- and it is the same reason `run` prints what it
  // could not exclude rather than only what it found.
  const modes = candidate.false_positive_modes || [];
  if (modes.length) {
    const wrapper = element("details", "fp-modes");
    wrapper.append(
      element("summary", "", `When this rule is wrong (${modes.length})`),
    );
    const list = element("ul", "disclosure-items");
    for (const mode of modes) {
      const item = document.createElement("li");
      item.textContent = mode;
      list.append(item);
    }
    wrapper.append(list);
    card.append(wrapper);
  }

  if (candidate.promotion?.id) {
    card.append(
      element(
        "p",
        "remediation",
        `Promote with \`veridor map --promote\`, then declare it: ${candidate.promotion.id}`,
      ),
    );
  }
  return card;
}

// `counts.cells` is every cell in the grid, probed or not. It was labelled
// "Cells probed" beside "8 Unknown" and "8 of 20 cell(s) WERE NEVER PROBED".
// No probed count is shown: the document does not record one. "unknown" mixes
// cells never sent (skipped_mutating, skipped_no_specimen) with cells sent and
// not answered (transport_error, rate_limited), so cells minus unknown is the
// measured count, not the probed one.
function mapMetrics(inventory, counts) {
  return [
    metric("Operations", inventory.operations ?? 0),
    metric("Identities", inventory.identities ?? 0),
    metric("Cells in grid", counts.cells ?? 0),
    metric("Reached", counts.reached ?? 0),
    metric("Refused", counts.refused ?? 0),
    metric("Unknown", counts.unknown ?? 0),
  ];
}

function renderMapDetail() {
  const map = state.selected;
  const blast = map.blast_radius || {};
  const candidates = map.candidates || {};
  const matrix = map.matrix || {};
  const template = document.querySelector("#map-template");
  const fragment = template.content.cloneNode(true);

  fragment.querySelector('[data-field="map-id"]').textContent =
    `Map ${shortId(map.map_id)}`;
  const inventory = blast.inventory || {};
  const mapMeta = fragment.querySelector('[data-field="map-metadata"]');
  mapMeta.textContent =
    `${targetLabel(blast.target || matrix.target)} · ` +
    `${inventory.operations ?? 0} operations × ${inventory.identities ?? 0} identities · `;
  mapMeta.append(
    element("span", "mono", map.map_id),
    document.createTextNode(" · "),
    rawLink(`/api/maps/${encodeURIComponent(map.map_id)}`, "raw JSON"),
  );

  const grid = accessMatrix(matrix);
  if (grid) {
    fragment.querySelector('[data-field="matrix"]').append(grid);
    fragment.querySelector('[data-field="matrix-panel"]').hidden = false;
  }

  const claim = blast.claim || candidates.claim || matrix.claim || {};
  const [claimLead, claimBody] = splitLead(claim.statement || "");
  fragment.querySelector('[data-field="map-claim"]').textContent = claimLead;
  const limitation = blast.limitation || candidates.limitation || "";
  fragment.querySelector('[data-field="map-limitation"]').textContent =
    [claimBody, limitation].filter(Boolean).join("\n\n");
  const safety = blast.safety || matrix.safety || {};
  fragment.querySelector('[data-field="map-safety"]').textContent =
    safety.posture || "";

  // A partial map is announced, not quietly rendered as if complete: rules
  // that need a quorum simply did not reach it, so an empty candidate list
  // here means "not measured", not "nothing to see".
  const incomplete = fragment.querySelector('[data-field="map-incomplete"]');
  if (safety.aborted) {
    incomplete.append(
      element(
        "p",
        "warn-note",
        `This map is INCOMPLETE: the run aborted after ${safety.issued ?? "?"} of ` +
          `${safety.planned ?? "?"} requests (${safety.abort_reason || "unknown reason"}). ` +
          "Counts below are lower bounds and rules that need a quorum may not have run.",
      ),
    );
  }
  if ((map.missing || []).length) {
    incomplete.append(
      element(
        "p",
        "warn-note",
        `Missing document(s): ${map.missing.join(", ")}. ` +
          "An absent document is not the same as an empty one.",
      ),
    );
  }

  fragment
    .querySelector('[data-field="map-metrics"]')
    .append(...mapMetrics(inventory, matrix.counts || {}));

  const reachContainer = fragment.querySelector('[data-field="blast-radius"]');
  const identities = blast.identities || [];
  if (!identities.length) {
    reachContainer.append(element("p", "empty", "No blast radius recorded."));
  } else {
    const list = element("div", "finding-list");
    for (const entry of identities) list.append(reachRow(entry));
    reachContainer.append(list);
  }

  const entries = candidates.candidates || [];
  fragment.querySelector('[data-field="candidate-count"]').textContent =
    `${entries.length} hypothes${entries.length === 1 ? "is" : "es"}`;
  // `discipline` is a plain string in the document, not an object. Reading it
  // as `.statement` silently produced undefined and fell through to the
  // fallback below, so the UI showed a paraphrase while the canonical sentence
  // sat unused in the JSON -- the exact drift these fallbacks exist to prevent.
  fragment.querySelector('[data-field="candidate-discipline"]').textContent =
    candidates.discipline || CANDIDATE_DISCIPLINE;
  const candidateContainer = fragment.querySelector('[data-field="candidates"]');
  if (!entries.length) {
    candidateContainer.append(
      element(
        "p",
        "empty",
        "No candidates. Consistency is not authorization: this says the rules " +
          "found no asymmetry to ask you about, not that the target is sound.",
      ),
    );
  } else {
    const list = element("div", "finding-list");
    for (const candidate of entries) list.append(candidateCard(candidate));
    candidateContainer.append(list);
  }
  fragment.querySelector('[data-field="candidate-footer"]').textContent =
    candidates.footer || "";

  renderDrift(fragment, map.drift);

  detailElement.replaceChildren(fragment);
}

// The panel stays HIDDEN when no baseline was given. Rendering "0 changes"
// there would answer a question nobody asked, and it reads as "nothing moved"
// -- which is a measurement, and none was taken.
function renderDrift(fragment, drift) {
  const panel = fragment.querySelector('[data-field="drift-panel"]');
  if (!drift) return;
  panel.hidden = false;

  const changes = drift.changes || [];
  const significant = drift.significant || 0;
  fragment.querySelector('[data-field="drift-count"]').textContent =
    `${changes.length} change${changes.length === 1 ? "" : "s"}` +
    (significant ? ` · ${significant} mean more access` : "");

  const claim = drift.claim || {};
  fragment.querySelector('[data-field="drift-discipline"]').textContent =
    claim.does_not_measure
      ? `Veridor does not measure ${claim.does_not_measure}.`
      : DRIFT_DISCIPLINE;

  // A diff across two different targets compares deployments, not changes.
  // Silently rendering it as drift would be the most misleading thing this
  // panel could do, so it is called out above the changes rather than below.
  const targets = fragment.querySelector('[data-field="drift-targets"]');
  const before = drift.baseline?.target;
  const after = drift.current?.target;
  if (before && after && before !== after) {
    targets.append(
      element(
        "p",
        "warn-note",
        `Baseline and current name DIFFERENT targets: ${before} vs ${after}. ` +
          "A diff across two targets compares deployments, not changes.",
      ),
    );
  }

  // What the comparison could see, said above the changes in the words
  // drift.render uses. The viewer used to read none of these counts, so a
  // comparison that measured nothing rendered exactly like a quiet one.
  const comparable = drift.comparable_cells || 0;
  const incomparable = drift.incomparable_cells || 0;
  const redirected = drift.redirect_cells || 0;
  const blind = (drift.blind_cells || 0) - (drift.blind_cells_not_probed || 0);
  const blindNotProbed = drift.blind_cells_not_probed || 0;
  // drift.measured_in_both: read when recorded, derived for an older report.
  const measuredInBoth = Number.isInteger(drift.measured_in_both_cells)
    ? drift.measured_in_both_cells
    : comparable - (drift.unmeasured_cells || 0) - redirected;
  const nothingMeasured = comparable > 0 && measuredInBoth <= 0;
  const notes = [];
  if (nothingMeasured) {
    notes.push(
      `NOT ONE CELL WAS MEASURED IN BOTH RUNS (${comparable} appear in both). ` +
        "No policy can fire on this comparison: under --fail-on-drift it exits 3, " +
        "not 0. It is not a pass.",
    );
  }
  if (incomparable) {
    notes.push(
      `${incomparable} cell(s) EXIST IN ONLY ONE OF THE TWO RUNS and were not ` +
        "compared at all. A re-seeded specimen changes the cell's identity, so " +
        "neither the old cell nor the new one is a change.",
    );
  }
  // How much of the grid the comparison saw, counted as drift.render counts
  // it: cells in both runs that were not measured in both. Without it a
  // comparison that measured half its grid showed an unqualified "Nothing
  // moved". Floored and never 100 while anything went unseen, as there.
  const share = comparable || 1;
  const unseen = comparable - Math.max(measuredInBoth, 0);
  if (unseen) {
    const seen = Math.min(99, Math.floor((100 * (share - unseen)) / share));
    notes.push(
      `drift saw ${seen}% of the grid: ${share - unseen} of ${share} comparable ` +
        "cell(s) were measured in BOTH runs. A quiet report below is quiet about " +
        "the rest of it, not evidence about it.",
    );
  }
  if (redirected) {
    notes.push(
      `${redirected} of ${comparable} comparable cell(s) were answered with a ` +
        "redirect in at least one run. Veridor does not follow redirects, so they " +
        "do not count as measured.",
    );
  }
  if (blind) {
    notes.push(
      `THE BASELINE NEVER MEASURED ${blind} of ${comparable} cell(s). Drift is ` +
        "BLIND there: a regression on those cells cannot be reported as more " +
        "access. Re-record the baseline against a quiet target before trusting " +
        "a clean report.",
    );
  }
  if (blindNotProbed) {
    notes.push(
      `${blindNotProbed} of ${comparable} cell(s) WERE NEVER PROBED, by this ` +
        "plan's own rules. Drift is blind there and will stay blind until the " +
        "plan is widened.",
    );
  }
  const notProbed = drift.unmeasured_cells_not_probed || 0;
  const lost = (drift.unmeasured_cells || 0) - notProbed;
  if (lost) {
    notes.push(
      `${lost} of ${share} comparable cell(s) could not be measured in one of the ` +
        "two runs — a rate limit, a server error, a timeout, or a proxy that " +
        "answered 407 before the target saw the request.",
    );
  }
  if (notProbed - blindNotProbed) {
    notes.push(
      `${notProbed - blindNotProbed} further comparable cell(s) were never ` +
        "probed. That is structural, not noise: the same cells every run, and no " +
        "target behaviour will change it.",
    );
  }
  for (const note of notes) targets.append(element("p", "warn-note", note));

  const container = fragment.querySelector('[data-field="drift-changes"]');
  if (!changes.length && (incomparable || !comparable || nothingMeasured)) {
    // The reassuring sentence, withheld, as drift.render withholds it: zero
    // changes over zero compared cells is not "nothing moved".
    container.append(
      element(
        "p",
        "warn-note",
        `Nothing to compare. ${comparable} cell(s) appear in both runs, ` +
          `${Math.max(measuredInBoth, 0)} measured in both. This is not ` +
          "'nothing moved': cells that were not compared cannot change.",
      ),
    );
  } else if (!changes.length) {
    container.append(
      element(
        "p",
        "empty",
        "Nothing moved. Every comparable cell reads the same as the baseline — " +
          "which is not a clean bill of health, only an absence of change.",
      ),
    );
  } else {
    const list = element("div", "finding-list");
    // Significant first: the reader should meet "more access than before"
    // ahead of a status code that changed shape.
    for (const change of [...changes].sort(
      (a, b) => Number(b.significant) - Number(a.significant),
    )) {
      list.append(driftCard(change));
    }
    container.append(list);
  }

  fragment.querySelector('[data-field="drift-blindness"]').textContent =
    claim.blind_to
      ? `Blind to ${claim.blind_to}.`
      : DRIFT_BLINDNESS;
}

// ----------------------------------------------------------- mutate view

function survivorCard(survivor) {
  const card = element("article", "finding survivor");
  const heading = element("div", "finding-heading");
  // The IDENTITY belongs in the heading, not buried in the footer line. One
  // check mutated under one operator for two identities produced two cards
  // whose headings were character-for-character identical -- which reads as the
  // double-listing bug this view had, rather than as two real results.
  const subject = [survivor.check_id || survivor.id || "mutant", survivor.identity]
    .filter(Boolean)
    .join(" · ");
  heading.append(element("strong", "", subject));
  heading.append(
    element(
      "span",
      "verdict warn",
      survivor.operator_label || survivor.operator || "",
    ),
  );
  card.append(heading);
  // The diagnosis is the whole value of a survivor: it says WHY the check may
  // be vacuous and what to confirm. mutation.py bans the vocabulary that would
  // let it read as a defect report, so it is rendered verbatim.
  card.append(element("p", "", survivor.diagnosis || ""));
  if (survivor.mutation) {
    card.append(element("p", "muted", `Mutation: ${survivor.mutation}`));
  }
  if (survivor.observed) {
    card.append(element("p", "muted", `Observed: ${survivor.observed}`));
  }
  if (survivor.id) card.append(element("p", "muted mono", survivor.id));
  return card;
}

function renderMutateDetail() {
  const report = state.selected;
  const summary = report.summary || {};
  const interpretation = report.interpretation || {};
  const scoring = report.scoring || {};
  const template = document.querySelector("#mutate-template");
  const fragment = template.content.cloneNode(true);

  fragment.querySelector('[data-field="mutate-id"]').textContent =
    `Mutation · tier ${report.tier ?? 1}`;
  const mutateMeta = fragment.querySelector('[data-field="mutate-metadata"]');
  mutateMeta.textContent =
    `${formatDate(report.completed_at)} · ${targetLabel(report.target)} · `;
  mutateMeta.append(
    rawLink(`/api/mutations/${encodeURIComponent(report.stem)}`, "raw JSON"),
  );

  // The score is the headline of this verb and was rendered as a chip smaller
  // than the identifier beside it. It gets the hero treatment, with the claim
  // attached to it rather than three paragraphs away -- a bare 0.83 invites
  // exactly the reading the report text spends a page preventing.
  const score = fragment.querySelector('[data-field="mutate-score"]');
  const value = mutationScore(summary);
  const undefinedScore = value === null;
  const allKilled = mutationTone(summary) === "safe";
  score.classList.add(allKilled ? "safe" : "warn");
  score.append(
    element("span", "hero-value", undefinedScore ? "--" : value.toFixed(2)),
    element("span", "hero-label", "mutation score"),
    element(
      "span",
      "hero-note",
      undefinedScore
        ? "no mutant was evaluated"
        : `${summary.killed ?? 0} of ${summary.generated ?? 0} mutants killed`,
    ),
  );

  // The mutation report names this key `statement`, not `summary` -- run
  // documents use `summary`, and assuming they matched meant the report's own
  // wording was never rendered.
  const statement = interpretation.statement || MUTANT_DISCIPLINE;
  // ...and it is ~940 characters of run-on prose. Setting the whole thing as
  // the lead paragraph made the wall LARGER, which is the opposite of the
  // point. Split off the opening sentence to carry the claim and let the rest
  // qualify it: same words, in an order a reader can enter.
  const [lead, body] = splitLead(statement);
  fragment.querySelector('[data-field="mutate-claim"]').textContent = lead;
  // `statement` already ENDS with the relationship paragraph, so rendering both
  // printed the coverage-versus-mutation-score explanation twice in a row. Show
  // it separately only when the statement did not already carry it -- the point
  // of the paragraph is that the two numbers are different claims, and saying
  // that twice makes the block look automated rather than considered.
  const relationship = interpretation.relationship || "";
  const extra =
    relationship && !statement.includes(relationship) ? `\n\n${relationship}` : "";
  fragment.querySelector('[data-field="mutate-relationship"]').textContent =
    `${body}${extra}`.trim();
  fragment.querySelector('[data-field="mutate-formula"]').textContent =
    scoring.formula ? `Score = ${scoring.formula}. ${scoring.excluded || ""}` : "";

  fragment
    .querySelector('[data-field="mutate-metrics"]')
    .append(
      metric("Generated", summary.generated ?? 0),
      metric("Killed", summary.killed ?? 0, "safe"),
      metric("Survived", summary.survived ?? 0, summary.survived ? "warn" : ""),
      metric("Aberrant", summary.aberrant ?? 0),
      metric("Errored", summary.errored ?? 0),
      metric("Not applicable", summary.not_applicable ?? 0),
    );

  const survivors = report.survivors || [];
  fragment.querySelector('[data-field="survivor-count"]').textContent =
    `${survivors.length} total`;
  const container = fragment.querySelector('[data-field="survivors"]');
  if (!survivors.length && allKilled) {
    container.append(
      element(
        "p",
        "empty",
        "Every mutant was killed. Your checks would notice this class of " +
          "regression; that is a statement about your declaration, not about " +
          "whether the boundary is enforced.",
      ),
    );
  } else if (!survivors.length && !summary.generated) {
    // "Every mutant was killed" is vacuously true of an empty set; the text
    // renderer prints nothing here and the report exits 2.
    container.append(
      element(
        "p",
        "empty",
        "No mutant was generated, so nothing was measured. This is not an " +
          "all-clear: it says nothing about whether your checks discriminate.",
      ),
    );
  } else if (!survivors.length) {
    // Nothing survived, but something could not be evaluated: the panel
    // below lists it, and the all-clear is false while one exists.
    container.append(
      element(
        "p",
        "empty",
        "No mutant survived, but not every mutant was evaluated (listed " +
          "below). This is not an all-clear until they are.",
      ),
    );
  } else {
    const list = element("div", "finding-list");
    for (const survivor of survivors) list.append(survivorCard(survivor));
    container.append(list);
  }

  // `unresolved` is survivors PLUS errored, by design -- the text renderer uses
  // it instead of `survivors` so nothing unmeasured escapes the report. A
  // viewer that has already listed the survivors above must therefore show only
  // the REMAINDER, or it lists every survivor twice and a reader counts four
  // problems where there are two.
  const survivorIds = new Set(survivors.map((item) => item.id));
  const errored = (report.unresolved || []).filter(
    (item) => !survivorIds.has(item.id),
  );
  const panel = fragment.querySelector('[data-field="unresolved-panel"]');
  fragment.querySelector('[data-field="unresolved-count"]').textContent =
    `${errored.length} total`;
  if (!errored.length) {
    panel.hidden = true;
  } else {
    const list = element("div", "finding-list");
    for (const item of errored) list.append(survivorCard(item));
    fragment.querySelector('[data-field="unresolved"]').append(list);
  }

  detailElement.replaceChildren(fragment);
}

function showError(error) {
  const box = element("div", "placeholder");
  box.append(element("h2", "", "Could not load Veridor data"));
  box.append(element("p", "muted", error.message));
  box.append(
    element(
      "p",
      "muted",
      "The viewer reads artifacts from the directory it was pointed at. If you " +
        "expected something here, check that directory exists and holds a run.",
    ),
  );
  box.append(element("code", "placeholder-hint", "veridor serve --output-dir .veridor"));
  detailElement.replaceChildren(box);
}

// --------------------------------------------------------------- chrome

function currentTheme() {
  const forced = document.documentElement.getAttribute("data-theme");
  if (forced) return forced;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("veridor-theme", next);
  } catch (error) {
    // Storage can be disabled; the toggle still works for this page view.
  }
}

// Deep links. A finding is the unit of a disclosure conversation, and until
// now the only way to point somebody at one was "open the viewer, pick the
// third run, scroll". Fingerprints are already stable across runs, so a link
// to a finding survives a re-run -- which is exactly what the workflow needs.
//
//   #/run/<run_id>
//   #/run/<run_id>/finding/<fingerprint>
//   #/map/<map_id>          #/mutate/<stem>
function routeFromHash() {
  const parts = decodeURIComponent(location.hash.replace(/^#\/?/, "")).split("/");
  const [kind, id, section, anchor] = parts;
  if (!kind || !id) return null;
  return { kind, id, anchor: section === "finding" ? anchor : null };
}

function writeHash(kind, id, anchor) {
  const path = anchor
    ? `#/${kind}/${encodeURIComponent(id)}/finding/${encodeURIComponent(anchor)}`
    : `#/${kind}/${encodeURIComponent(id)}`;
  if (location.hash !== path) history.replaceState(null, "", path);
}

async function applyRoute() {
  const route = routeFromHash();
  if (!route) return;
  const verb = { run: "run", map: "map", mutate: "mutate" }[route.kind];
  if (!verb) return;
  if (state.verb !== verb) {
    switchVerb(verb);
    await loadRuns();
  }
  if (verb === "run") await selectRun(route.id, { fromHash: true });
  else if (verb === "map") await selectMap(route.id, { fromHash: true });
  else await selectMutation(route.id, { fromHash: true });
  if (route.anchor) {
    const target = document.querySelector(
      `[data-fingerprint="${CSS.escape(route.anchor)}"]`,
    );
    if (target) target.scrollIntoView({ block: "center" });
  }
}

window.addEventListener("hashchange", applyRoute);

// How old what you are looking at is. The viewer reads a directory that a `run`
// in another terminal is still writing to, and it never polls -- so a reader
// could be triaging a run three commits stale with nothing on screen saying so.
// A cue, not a poll: reloading is the operator's decision, and a page that
// refetched under them while they read a finding would be worse.
let loadedAt = null;

function renderFreshness() {
  const element_ = document.querySelector("#loaded-at");
  if (!element_ || !loadedAt) return;
  const seconds = Math.round((Date.now() - loadedAt) / 1000);
  element_.textContent =
    seconds < 60
      ? "loaded just now"
      : `loaded ${Math.round(seconds / 60)} min ago — Refresh for newer runs`;
  element_.classList.toggle("stale", seconds >= 300);
}

setInterval(renderFreshness, 15000);

// A tablist that cannot be driven from the keyboard is a tablist in name only.
// `role="tablist"` tells a screen reader to expect Left/Right; without the
// handler the announcement is a promise the page does not keep.
function wireTablist(container) {
  const tabs = [...container.querySelectorAll('[role="tab"]')];
  container.addEventListener("keydown", (event) => {
    const step = { ArrowRight: 1, ArrowLeft: -1, Home: -Infinity, End: Infinity }[
      event.key
    ];
    if (step === undefined) return;
    event.preventDefault();
    const current = tabs.indexOf(document.activeElement);
    const next =
      step === -Infinity
        ? 0
        : step === Infinity
          ? tabs.length - 1
          : (current + step + tabs.length) % tabs.length;
    tabs[next]?.focus();
    tabs[next]?.click();
  });
}

function markSelected(tabs, isActive) {
  for (const tab of tabs) {
    const active = isActive(tab);
    tab.setAttribute("aria-selected", active ? "true" : "false");
    // Roving tabindex: one stop for the whole group, as the pattern requires.
    tab.tabIndex = active ? 0 : -1;
  }
}

const verbTabs = [...document.querySelectorAll("[data-verb]")];
for (const button of verbTabs) {
  button.addEventListener("click", () => selectVerb(button.dataset.verb));
}
const verbList = verbTabs[0]?.parentElement;
if (verbList) {
  verbList.setAttribute("role", "tablist");
  wireTablist(verbList);
  markSelected(verbTabs, (tab) => tab.dataset.verb === state.verb);
}
document.querySelector("#theme-toggle").addEventListener("click", toggleTheme);
document.querySelector("#refresh").addEventListener("click", loadRuns);
filterElement.addEventListener("input", () => {
  state.filter = filterElement.value;
  renderRuns();
});
function boot() {
  showSkeleton();
  state.pendingRoute = routeFromHash();
  return loadRuns()
    .then(() => {
      renderFreshness();
      return applyRoute();
    })
    .finally(() => {
      // Only the link the page was opened on is held; a later Refresh or verb
      // switch selects the newest entry as before. A link to an entry that is
      // not there falls back to the newest, and the hash then names it.
      const linked = state.pendingRoute;
      state.pendingRoute = null;
      if (linked && !state.selected) return loadRuns();
      return undefined;
    });
}

boot();
