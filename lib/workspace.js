'use strict';
/**
 * Local "workspace" storage — the offline equivalent of jsmon-cli's
 * server-side workspaces. Every scan is saved as a timestamped "run" under
 * ~/.jsrecon/workspaces/<name>/runs/<runId>.json (override root with
 * JSRECON_STORE or --store). This is what makes -count, --urls, --domains,
 * --files, -issues, and cross-run -rsearch possible without a server.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

function storeRoot(overrideDir) {
  return overrideDir || process.env.JSRECON_STORE || path.join(os.homedir(), '.jsrecon');
}

function workspaceDir(root, name) {
  return path.join(root, 'workspaces', name);
}

function ensureWorkspace(root, name) {
  const dir = workspaceDir(root, name);
  fs.mkdirSync(path.join(dir, 'runs'), { recursive: true });
  return dir;
}

function listWorkspaces(root) {
  const wsRoot = path.join(root, 'workspaces');
  if (!fs.existsSync(wsRoot)) return [];
  return fs.readdirSync(wsRoot).filter((n) => fs.statSync(path.join(wsRoot, n)).isDirectory());
}

/** Permanently deletes a whole workspace (every run, its dashboard.html, and
 *  its cached source snapshots) — backs the dashboard's "Delete workspace"
 *  action. Refuses to delete outside the workspaces root, just in case a
 *  crafted name ever reached here. */
function deleteWorkspace(root, name) {
  const wsRoot = path.join(root, 'workspaces');
  const dir = path.join(wsRoot, name);
  const resolved = path.resolve(dir);
  if (!resolved.startsWith(path.resolve(wsRoot) + path.sep)) {
    throw new Error('Refusing to delete outside the workspaces directory');
  }
  if (!fs.existsSync(dir)) return { deleted: false };
  fs.rmSync(dir, { recursive: true, force: true });
  return { deleted: true };
}

function makeRunId() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

/** Saves a completed scan as a new run and returns its runId. */
function saveRun(root, workspace, { targets, checks, findings, meta }) {
  const dir = ensureWorkspace(root, workspace);
  const runId = makeRunId();
  const timestamp = new Date().toISOString();
  const run = {
    runId,
    workspace,
    timestamp,
    targets,
    checks,
    meta: meta || {},
    findings: annotateNewVsSeen(root, workspace, findings, runId, timestamp),
  };
  fs.writeFileSync(path.join(dir, 'runs', `${runId}.json`), JSON.stringify(run, null, 2));
  fs.writeFileSync(path.join(dir, 'latest.json'), JSON.stringify({ runId }));
  return runId;
}

/**
 * Removes one scanned target (asset) and all of its findings from a
 * workspace — what backs the dashboard's "Remove" button on an asset card.
 * Rewrites every run file in the workspace: strips the target from its
 * `targets` list and drops any finding whose `file` matches it. A run that
 * ends up with no targets left at all is deleted outright (it was entirely
 * about the removed asset); otherwise it's rewritten in place. Returns how
 * many runs were touched and how many findings were removed, so the caller
 * can report something concrete back to the UI.
 */
function deleteAsset(root, workspace, target) {
  const dir = path.join(workspaceDir(root, workspace), 'runs');
  if (!fs.existsSync(dir)) return { runsTouched: 0, runsDeleted: 0, findingsRemoved: 0 };

  let runsTouched = 0;
  let runsDeleted = 0;
  let findingsRemoved = 0;

  const runFiles = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  for (const rf of runFiles) {
    const filePath = path.join(dir, rf);
    const run = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!run.targets.includes(target) && !run.findings.some((f) => f.file === target)) continue;

    const beforeCount = run.findings.length;
    run.targets = run.targets.filter((t) => t !== target);
    run.findings = run.findings.filter((f) => f.file !== target);
    findingsRemoved += beforeCount - run.findings.length;
    runsTouched++;

    if (run.targets.length === 0) {
      fs.unlinkSync(filePath);
      runsDeleted++;
    } else {
      fs.writeFileSync(filePath, JSON.stringify(run, null, 2));
    }
  }

  // If the deleted run happened to be "latest", repoint latest.json at
  // whatever run now sorts last, or remove it if nothing is left.
  const latestPath = path.join(workspaceDir(root, workspace), 'latest.json');
  if (runsDeleted > 0 && fs.existsSync(latestPath)) {
    const remaining = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
    if (remaining.length === 0) {
      fs.unlinkSync(latestPath);
    } else {
      const { runId: currentLatestId } = JSON.parse(fs.readFileSync(latestPath, 'utf8'));
      if (!remaining.includes(`${currentLatestId}.json`)) {
        const newest = remaining.sort().pop().replace(/\.json$/, '');
        fs.writeFileSync(latestPath, JSON.stringify({ runId: newest }));
      }
    }
  }

  return { runsTouched, runsDeleted, findingsRemoved };
}

function listRuns(root, workspace) {
  const dir = path.join(workspaceDir(root, workspace), 'runs');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => {
      const run = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      return { runId: run.runId, timestamp: run.timestamp, targets: run.targets.length, findings: run.findings.length };
    })
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

/**
 * Stable identity for a finding, used to collapse duplicates. Mirrors the
 * intra-file dedup analyzeRecon already does within one scan (same
 * type+file+value counts as the same finding regardless of exact position),
 * extended to positional findings (postmessage/sourcemap) that have no single
 * "value" — those collapse on type+file+line+column instead. This is what
 * keeps re-scanning the same target (e.g. from the dashboard's Assets tab,
 * or just re-running the CLI) from piling up one duplicate row per re-scan
 * once runs are merged.
 */
function dedupeKeyFor(f) {
  if (f.value != null) return `${f.type}|${f.file}|v:${f.value}`;
  if (f.line != null) return `${f.type}|${f.file}|l:${f.line}:${f.column != null ? f.column : ''}`;
  return `${f.type}|${f.file}|s:${f.snippet || ''}`;
}

/** Collapses duplicate findings, keeping the last (most recent) occurrence
 *  of each — so a fresher re-scan's snippet/context wins over a stale one. */
function dedupeFindings(findings) {
  const byKey = new Map();
  for (const f of findings) byKey.set(dedupeKeyFor(f), f);
  return [...byKey.values()];
}

// --- "New vs seen" ledger --------------------------------------------------
// A tiny per-workspace JSON file (dedupeKey -> {firstSeenRunId, firstSeenAt,
// lastSeenRunId, lastSeenAt, seenCount}) that survives across runs. This is
// what lets a re-scan answer "did anything actually change here?" without a
// human diffing two finding lists by eye — every finding gets tagged, at
// save time, with whether its dedupe key has ever been seen in this
// workspace before.
function ledgerPath(root, workspace) {
  return path.join(workspaceDir(root, workspace), 'ledger.json');
}

function loadLedger(root, workspace) {
  const p = ledgerPath(root, workspace);
  if (!fs.existsSync(p)) return {};
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return {}; }
}

function saveLedger(root, workspace, ledger) {
  ensureWorkspace(root, workspace);
  fs.writeFileSync(ledgerPath(root, workspace), JSON.stringify(ledger, null, 2));
}

/** Tags each finding about to be saved with isNew/firstSeenAt/seenCount
 *  against the workspace's ledger, updating the ledger as it goes. Called
 *  from saveRun so every persisted run already carries this — no separate
 *  pass needed at read time. */
function annotateNewVsSeen(root, workspace, findings, runId, timestamp) {
  const ledger = loadLedger(root, workspace);
  const annotated = findings.map((f) => {
    const key = dedupeKeyFor(f);
    let entry = ledger[key];
    if (!entry) {
      entry = { firstSeenRunId: runId, firstSeenAt: timestamp, lastSeenRunId: runId, lastSeenAt: timestamp, seenCount: 1 };
      ledger[key] = entry;
      return { ...f, isNew: true, firstSeenAt: timestamp, seenCount: 1 };
    }
    entry.lastSeenRunId = runId;
    entry.lastSeenAt = timestamp;
    entry.seenCount = (entry.seenCount || 1) + 1;
    return { ...f, isNew: false, firstSeenAt: entry.firstSeenAt, seenCount: entry.seenCount };
  });
  saveLedger(root, workspace, ledger);
  return annotated;
}

// --- Persistent triage (mark-as-reviewed) ----------------------------------
// A per-workspace JSON file (dedupeKey -> {status, note, at}) so once you
// mark a finding as a false positive (or confirmed) it stays that way on
// every future scan/view of the same value — instead of the exact same
// noise reappearing every time you rescan a target.
function triagePath(root, workspace) {
  return path.join(workspaceDir(root, workspace), 'triage.json');
}

function loadTriage(root, workspace) {
  const p = triagePath(root, workspace);
  if (!fs.existsSync(p)) return {};
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return {}; }
}

function saveTriageMap(root, workspace, map) {
  ensureWorkspace(root, workspace);
  fs.writeFileSync(triagePath(root, workspace), JSON.stringify(map, null, 2));
}

/** Sets (status truthy) or clears (status falsy/'clear') the triage decision
 *  for one exact finding, identified by its dedupe key. Returns the new
 *  entry, or null if cleared. */
function setTriage(root, workspace, dedupeKey, status, note) {
  const map = loadTriage(root, workspace);
  if (!status || status === 'clear') {
    delete map[dedupeKey];
    saveTriageMap(root, workspace, map);
    return null;
  }
  map[dedupeKey] = { status, note: note || '', at: new Date().toISOString() };
  saveTriageMap(root, workspace, map);
  return map[dedupeKey];
}

// --- Allowlist (user-known safe values) -------------------------------------
// A per-workspace JSON file of values Sam already knows are safe — cache-
// busting hashes, internal build IDs, an internal domain that isn't secret,
// etc. — so they stop being reported at all on every future scan, instead of
// having to re-triage the same known-noise value again each time it reappears
// under a new dedupe key (a fresh line/file/hash). Two match modes:
//   values:   exact string match against finding.value
//   patterns: regex source strings tested against finding.value
function allowlistPath(root, workspace) {
  return path.join(workspaceDir(root, workspace), 'allowlist.json');
}

function loadAllowlist(root, workspace) {
  const p = allowlistPath(root, workspace);
  if (!fs.existsSync(p)) return { values: [], patterns: [] };
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    return {
      values: Array.isArray(parsed.values) ? parsed.values : [],
      patterns: Array.isArray(parsed.patterns) ? parsed.patterns : [],
    };
  } catch (e) {
    return { values: [], patterns: [] };
  }
}

function saveAllowlist(root, workspace, allowlist) {
  ensureWorkspace(root, workspace);
  fs.writeFileSync(allowlistPath(root, workspace), JSON.stringify(allowlist, null, 2));
}

function addToAllowlist(root, workspace, value, kind = 'value') {
  const allowlist = loadAllowlist(root, workspace);
  const bucket = kind === 'pattern' ? 'patterns' : 'values';
  if (!allowlist[bucket].includes(value)) allowlist[bucket].push(value);
  saveAllowlist(root, workspace, allowlist);
  return allowlist;
}

function removeFromAllowlist(root, workspace, value, kind = 'value') {
  const allowlist = loadAllowlist(root, workspace);
  const bucket = kind === 'pattern' ? 'patterns' : 'values';
  allowlist[bucket] = allowlist[bucket].filter((v) => v !== value);
  saveAllowlist(root, workspace, allowlist);
  return allowlist;
}

/** Builds a fast matcher function from a loaded allowlist. Invalid regex
 *  patterns are skipped rather than throwing, so one typo'd pattern in the
 *  file can't take down an entire scan. */
function buildAllowlistMatcher(allowlist) {
  const valueSet = new Set(allowlist.values || []);
  const compiled = [];
  for (const src of allowlist.patterns || []) {
    try { compiled.push(new RegExp(src)); } catch (e) { /* skip invalid pattern */ }
  }
  return (value) => {
    if (value == null) return false;
    if (valueSet.has(value)) return true;
    return compiled.some((re) => re.test(value));
  };
}

// --- Cross-target correlation -----------------------------------------------
// Builds, straight from every run file on disk (not the deduped/merged view),
// a map of "this exact value, for this finding type" -> the set of scanned
// files it showed up in. This is what lets a single-target view still say
// "this same secret/endpoint also appears in 3 other files you've scanned in
// this workspace" — something no single run's findings list could know on
// its own.
function buildValueIndex(root, workspace) {
  const dir = path.join(workspaceDir(root, workspace), 'runs');
  const index = new Map();
  if (!fs.existsSync(dir)) return index;
  const runFiles = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  for (const rf of runFiles) {
    let run;
    try { run = JSON.parse(fs.readFileSync(path.join(dir, rf), 'utf8')); } catch (e) { continue; }
    for (const f of run.findings || []) {
      if (f.value == null || !f.file) continue;
      const key = `${f.type}|v:${f.value}`;
      if (!index.has(key)) index.set(key, new Set());
      index.get(key).add(f.file);
    }
  }
  return index;
}

/** Same idea as buildValueIndex, but sweeps every workspace under this store
 *  root instead of just one — a map of "type|v:value" -> Set of
 *  "workspace::file" pairs. This is what lets a finding say "this same key
 *  also turned up scanning a completely different target" (a different
 *  program, a different client's app, whatever else you've scanned), not
 *  just other files inside the current workspace. Skipped entirely when
 *  there's only one workspace to begin with, since there's nothing else to
 *  correlate against. */
function buildGlobalValueIndex(root, excludeWorkspace) {
  const index = new Map();
  const workspaces = listWorkspaces(root).filter((w) => w !== excludeWorkspace);
  for (const wsName of workspaces) {
    const dir = path.join(workspaceDir(root, wsName), 'runs');
    if (!fs.existsSync(dir)) continue;
    const runFiles = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
    for (const rf of runFiles) {
      let run;
      try { run = JSON.parse(fs.readFileSync(path.join(dir, rf), 'utf8')); } catch (e) { continue; }
      for (const f of run.findings || []) {
        if (f.value == null || !f.file) continue;
        const key = `${f.type}|v:${f.value}`;
        if (!index.has(key)) index.set(key, new Set());
        index.get(key).add(`${wsName}::${f.file}`);
      }
    }
  }
  return index;
}

/** Applies triage state, same-workspace correlation, and cross-workspace
 *  correlation to a findings array read back from disk. Every finding gets
 *  a stable `dedupeKey` (so the dashboard/CLI can act on it without
 *  re-deriving the same logic client-side), a `triage` object when one is
 *  on file, `seenInOtherFiles`/`seenInFileCount` when the same value+type
 *  shows up in more than one scanned target in this workspace, and
 *  `seenInOtherWorkspaces`/`seenInWorkspaceCount` when it also shows up in
 *  a *different* workspace entirely. */
function enrichFindings(root, workspace, findings) {
  const triageMap = loadTriage(root, workspace);
  const valueIndex = buildValueIndex(root, workspace);
  const allWorkspaces = listWorkspaces(root);
  const globalIndex = allWorkspaces.length > 1 ? buildGlobalValueIndex(root, workspace) : null;

  return findings.map((f) => {
    const key = dedupeKeyFor(f);
    let out = { ...f, dedupeKey: key };
    if (triageMap[key]) out.triage = triageMap[key];

    if (f.value != null && f.file) {
      const vkey = `${f.type}|v:${f.value}`;

      const files = valueIndex.get(vkey);
      if (files && files.size > 1) {
        const otherFiles = [...files].filter((file) => file !== f.file);
        if (otherFiles.length) {
          out.seenInOtherFiles = otherFiles;
          out.seenInFileCount = files.size;
        }
      }

      if (globalIndex) {
        const globalEntries = globalIndex.get(vkey);
        if (globalEntries && globalEntries.size) {
          const byWorkspace = {};
          for (const entry of globalEntries) {
            const sep = entry.indexOf('::');
            const wsName = entry.slice(0, sep);
            const file = entry.slice(sep + 2);
            (byWorkspace[wsName] = byWorkspace[wsName] || []).push(file);
          }
          out.seenInOtherWorkspaces = Object.entries(byWorkspace).map(([wsName, files]) => ({ workspace: wsName, files }));
          out.seenInWorkspaceCount = out.seenInOtherWorkspaces.length;
        }
      }
    }
    return out;
  });
}

/** Loads one run, or 'latest', or 'all' (merges every run's findings). */
function loadRun(root, workspace, runId) {
  const dir = path.join(workspaceDir(root, workspace), 'runs');
  if (!fs.existsSync(dir)) return null;

  if (runId === 'all') {
    const runs = fs.readdirSync(dir).filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')))
      .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    if (runs.length === 0) return null;
    const merged = runs.flatMap((r) => r.findings.map((f) => ({ ...f, runId: r.runId, runTimestamp: r.timestamp })));
    return {
      runId: 'all',
      workspace,
      timestamp: new Date().toISOString(),
      targets: [...new Set(runs.flatMap((r) => r.targets))],
      checks: [...new Set(runs.flatMap((r) => r.checks))],
      findings: enrichFindings(root, workspace, dedupeFindings(merged)),
    };
  }

  let file;
  if (!runId || runId === 'latest') {
    const latestPath = path.join(workspaceDir(root, workspace), 'latest.json');
    if (!fs.existsSync(latestPath)) return null;
    const { runId: latestId } = JSON.parse(fs.readFileSync(latestPath, 'utf8'));
    file = path.join(dir, `${latestId}.json`);
  } else {
    file = path.join(dir, `${runId}.json`);
  }
  if (!fs.existsSync(file)) return null;
  const run = JSON.parse(fs.readFileSync(file, 'utf8'));
  run.findings = enrichFindings(
    root,
    workspace,
    dedupeFindings(run.findings.map((f) => ({ ...f, runId: run.runId, runTimestamp: run.timestamp })))
  );
  return run;
}

/** Parses jsmon-style "page=1 limit=100 severity=high,medium dateFrom=2026-01-01" strings. */
function parseKV(str) {
  const out = {};
  if (!str) return out;
  for (const part of str.trim().split(/\s+/)) {
    const [k, v] = part.split('=');
    if (k && v !== undefined) out[k] = v;
  }
  return out;
}

function paginate(list, page, limit) {
  const p = Math.max(1, parseInt(page || '1', 10));
  const l = Math.max(1, parseInt(limit || '100', 10));
  const start = (p - 1) * l;
  return { page: p, limit: l, total: list.length, items: list.slice(start, start + l) };
}

module.exports = {
  storeRoot,
  workspaceDir,
  ensureWorkspace,
  listWorkspaces,
  deleteWorkspace,
  saveRun,
  listRuns,
  loadRun,
  deleteAsset,
  dedupeFindings,
  dedupeKeyFor,
  loadTriage,
  setTriage,
  loadAllowlist,
  saveAllowlist,
  addToAllowlist,
  removeFromAllowlist,
  buildAllowlistMatcher,
  parseKV,
  paginate,
};
