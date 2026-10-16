#!/usr/bin/env node
/**
 * jsrecon — local static analysis CLI for JS recon during authorized security testing.
 *
 * Scans one file, a directory, or a glob/list of JavaScript files and reports:
 *   - postMessage findings (listeners missing origin checks, sends using '*')
 *   - sourceMappingURL references, resolving/fetching the .map to list exposed
 *     original source paths
 *   - recon data: emails, domains, IPs, API/endpoint-looking paths, S3 buckets
 *   - likely secrets: AWS keys, Google API keys, Slack tokens, JWTs, generic
 *     key/secret/token assignments, private key blocks
 *
 * This tool only reads files you point it at (local disk, or a URL you pass
 * explicitly with --fetch-maps). It does not scan the network on its own,
 * brute force anything, evade any protections, or exploit findings — it just
 * flags patterns for you to review manually. Use only on targets/code you are
 * authorized to test.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { globSync } = require('glob');
const chalk = require('chalk');
const ws = require('../lib/workspace');
const { crawl } = require('../lib/crawl');
const { buildDashboardHtml } = require('../lib/ui');
const {
  lineAndColumn,
  analyzePostMessage,
  analyzeRecon,
  analyzeSecrets,
  analyzeCrossFileTaint,
} = require('../lib/analyzers');

function usage() {
  console.log(`
${chalk.bold('jsrecon')} — local JS recon scanner (postMessage, source maps, recon data, secrets)

Scan targets (pick one):
  -u <file|url|list.txt>  Scan a single JS file (local path OR http(s):// URL),
                          or point it at a local .txt file listing several
                          targets — one per line, local paths and http(s)://
                          URLs freely mixed, e.g.:
                            https://example.com/test.js
                            /home/you/projects/app/test.js
  -d <dir|domain>         Scan all matching files under a local directory, OR
                          (if not an existing directory) crawl a live domain
  -f <list.txt>           Same as passing a .txt list to -u — kept as its own
                          flag too since some scripts already call it that way

Domain crawl options (used with -d <domain>):
  -depth <1..4>           Crawl depth (default: 2)
  -keywords <a,b>         Only report URLs containing one of these keywords
  -extensions <a,b>       File extensions to collect while crawling (default: js,mjs)
  --max-pages <n>         Safety cap on pages visited while crawling (default: 200)

What to look for (default: all):
  --checks <list>         Comma list from: postmessage,sourcemap,recon,secrets
                          e.g. --checks secrets,recon
                          postmessage also covers WebSocket/BroadcastChannel
                          message listeners, importScripts, document.domain,
                          and window.open(...) missing noopener — plus, when
                          more than one file is scanned in the same run (e.g.
                          -d on a directory), a cross-file pass that follows
                          event.data through require()/import into another
                          scanned file's exported function and flags it if
                          that function's own body reaches a dangerous sink.

Request options:
  -H "Header: value"      Custom HTTP header, repeatable, applied to every fetch
  --waf-bypass            Rotate a realistic browser User-Agent + jittered
                          delay between requests (does not evade auth/IP
                          blocks or exploit anything — just avoids looking
                          like a naive scripted scanner during authorized testing)
  --timeout <ms>          Timeout for remote fetches (default: 15000)
  --fetch-maps            Attempt to fetch remote sourceMappingURLs (http/https)
  --save-dir <dir>        Also save a local copy of every fetched JS/map file

Local workspace (persists every scan so results can be queried later):
  -wksp <name>            Workspace to save this scan / query into (default: "default")
  --store <dir>           Where workspaces live (default: ~/.jsrecon)
  --no-save               Don't persist this scan to a workspace
  -cw, --create-workspace <name>   Create an (empty) workspace
  --workspaces            List local workspaces
  --runs                  List runs in a workspace (-wksp)
  -count                  Show recon/secret/issue counts for a run (-wksp [-run <id|latest|all>]),
                          including how many findings are new since they first
                          appeared and how many are hidden as triaged false positives
  --urls "page=1 limit=100"      List extracted recon-url values from a run
  --domains "page=1 limit=100"   List extracted recon-domain values from a run
  --files "page=1 limit=100"     List every target scanned in a run
  -issues "page=1 limit=100 severity=high,medium dateFrom=YYYY-MM-DD dateTo=YYYY-MM-DD"
                          List medium/high severity findings (postmessage +
                          source-map + secret findings) from a run. Findings
                          marked as a false positive are hidden by default
                          (--show-suppressed brings them back).
  --new-only              With -issues: only show findings new since they
                          first appeared in this workspace (a quick "what
                          changed since my last scan" view)
  --show-suppressed       With -issues/-count: include findings that were
                          triaged as false-positive instead of hiding them

Triage (persists across future scans of the same value):
  --triage-key <key>      The finding's "dedupeKey" (shown by -issues, or in
                          the dashboard) to mark/clear
  --triage-status <s>     false-positive | confirmed | clear
  --triage-note <text>    Optional note to attach (default: none)

Allowlist (user-known safe values — suppressed from every future scan,
in this workspace, instead of reappearing as noise every time):
  --allowlist-add <value>     Add an exact value (or, with --allowlist-pattern,
                               a regex source) to this workspace's allowlist
  --allowlist-remove <value>  Remove one
  --allowlist-pattern         Modifier for --allowlist-add/--allowlist-remove:
                               treat <value> as a regex tested against each
                               finding's value, instead of an exact match
  --allowlist-list            Show this workspace's current allowlist

Reverse search:
  -rsearch <value>        Find which file/line a value came from.
                          Uses --in <findings.json> if given, else the
                          current workspace's runs (-wksp, -run).

Result analysis UI:
  --ui                    Build a local HTML dashboard for a run (-wksp [-run])
  --ui-out <file.html>    Where to write it (default: <workspace>/dashboard.html)
  --serve [port]          Also serve that dashboard at http://127.0.0.1:<port> (default 5757)

General options:
  --ext <a,b,c>           Extensions to include when scanning a local dir (default: js,mjs,cjs)
  --filter <text>         Only show recon/secret findings whose value contains <text>
  --out <file.json>       Also write this scan's findings as JSON to this path
  --no-color              Disable colored output

Examples:
  jsrecon -u ./app.bundle.js
  jsrecon -u https://auth.hiring.amazon.com/main.prod.js -wksp amazon
  jsrecon -u ./targets.txt -wksp amazon    # .txt of mixed URLs/local paths
  jsrecon -d example.com -depth 3 -keywords api,admin -extensions js,json -wksp example
  jsrecon -H "Cookie: session=abc" -u https://app.example.com/main.js
  jsrecon -count -wksp amazon
  jsrecon -issues "severity=high,medium" -wksp amazon
  jsrecon -issues "severity=high,medium" --new-only -wksp amazon   # only what's new since last scan
  jsrecon --triage-key "recon-domain|..." --triage-status false-positive -wksp amazon
  jsrecon --ui --serve -wksp amazon
  jsrecon -rsearch "AIzaSyD..." -wksp amazon
`);
}

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
  usage();
  process.exit(args.length === 0 ? 1 : 0);
}

function getFlagValue(flag) {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : null;
}
function getAllFlagValues(flag) {
  const out = [];
  args.forEach((a, i) => { if (a === flag) out.push(args[i + 1]); });
  return out;
}
const hasFlag = (flag) => args.includes(flag);

const singleFile = getFlagValue('-u');
const dir = getFlagValue('-d');
const listFile = getFlagValue('-f');
const extArg = getFlagValue('--ext') || 'js,mjs,cjs';
const outFile = getFlagValue('--out');
const fetchMaps = hasFlag('--fetch-maps');
const filterText = getFlagValue('--filter');
const rsearchValue = getFlagValue('-rsearch');
const inFile = getFlagValue('--in');
const checksArg = getFlagValue('--checks');
const saveDir = getFlagValue('--save-dir');
const fetchTimeout = parseInt(getFlagValue('--timeout') || '15000', 10);
if (saveDir) fs.mkdirSync(saveDir, { recursive: true });
const enabledChecks = new Set(
  (checksArg ? checksArg.split(',') : ['postmessage', 'sourcemap', 'recon', 'secrets']).map((c) => c.trim())
);
if (hasFlag('--no-color')) chalk.level = 0;

// Request customization
const customHeaders = {};
getAllFlagValues('-H').forEach((h) => {
  if (!h) return;
  const idx = h.indexOf(':');
  if (idx === -1) return;
  customHeaders[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
});
const wafBypass = hasFlag('--waf-bypass');
const WAF_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
];
function buildHeaders() {
  const h = { ...customHeaders };
  if (wafBypass) {
    h['User-Agent'] = h['User-Agent'] || WAF_USER_AGENTS[Math.floor(Math.random() * WAF_USER_AGENTS.length)];
    h['Accept'] = h['Accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
    h['Accept-Language'] = h['Accept-Language'] || 'en-US,en;q=0.9';
  }
  return h;
}
async function politeDelay() {
  if (!wafBypass) return;
  const ms = 250 + Math.floor(Math.random() * 500);
  await new Promise((r) => setTimeout(r, ms));
}

// Workspace / storage flags
const storeDir = ws.storeRoot(getFlagValue('--store'));
const workspaceName = getFlagValue('-wksp') || 'default';
const noSave = hasFlag('--no-save');
const runArg = getFlagValue('-run');

// --- Standalone commands that don't run a scan -------------------------------

const createWorkspaceName = getFlagValue('-cw') || getFlagValue('--create-workspace');
if (createWorkspaceName) {
  ws.ensureWorkspace(storeDir, createWorkspaceName);
  console.log(chalk.green(`Created workspace "${createWorkspaceName}" at ${ws.workspaceDir(storeDir, createWorkspaceName)}`));
  process.exit(0);
}

if (hasFlag('--workspaces')) {
  const names = ws.listWorkspaces(storeDir);
  console.log(chalk.bold(`\nWorkspaces (${storeDir}):\n`));
  if (names.length === 0) console.log('  (none yet — they are created automatically on first scan, or with -cw <name>)');
  names.forEach((n) => console.log(`  - ${n}`));
  process.exit(0);
}

if (hasFlag('--runs')) {
  const runs = ws.listRuns(storeDir, workspaceName);
  console.log(chalk.bold(`\nRuns in workspace "${workspaceName}":\n`));
  if (runs.length === 0) console.log('  (no runs yet)');
  runs.forEach((r) => console.log(`  ${r.runId}  ${r.timestamp}  targets=${r.targets}  findings=${r.findings}`));
  process.exit(0);
}

if (hasFlag('-count')) {
  const run = ws.loadRun(storeDir, workspaceName, runArg || 'latest');
  if (!run) { console.error(chalk.red(`No run found for workspace "${workspaceName}" (run: ${runArg || 'latest'})`)); process.exit(1); }
  const byField = {};
  let secrets = 0, isNewCount = 0, suppressedCount = 0, crossWorkspaceCount = 0;
  run.findings.forEach((f) => {
    if (f.field) byField[f.field] = (byField[f.field] || 0) + 1;
    if (f.type && f.type.startsWith('secret-')) secrets++;
    if (f.isNew) isNewCount++;
    if (f.triage && f.triage.status === 'false-positive') suppressedCount++;
    if (f.seenInOtherWorkspaces && f.seenInOtherWorkspaces.length) crossWorkspaceCount++;
  });
  console.log(chalk.bold(`\nCounts for workspace "${workspaceName}" (run: ${run.runId}):\n`));
  console.log(`  targets scanned: ${run.targets.length}`);
  console.log(`  total findings:  ${run.findings.length}`);
  console.log(`  secrets:         ${secrets}`);
  console.log(`  new since first seen (this run/view): ${isNewCount}`);
  console.log(`  triaged as false-positive:            ${suppressedCount}`);
  console.log(`  also seen in other workspaces:        ${crossWorkspaceCount}`);
  console.log(chalk.bold('\n  recon fields:'));
  Object.entries(byField).sort((a, b) => b[1] - a[1]).forEach(([field, n]) => console.log(`    ${field}: ${n}`));
  process.exit(0);
}

if (hasFlag('--triage-key')) {
  const key = getFlagValue('--triage-key');
  const status = getFlagValue('--triage-status');
  const note = getFlagValue('--triage-note') || '';
  if (!key || !status || !['false-positive', 'confirmed', 'clear'].includes(status)) {
    console.error(chalk.red('Usage: jsrecon --triage-key <dedupeKey> --triage-status <false-positive|confirmed|clear> [--triage-note "..."] -wksp <name>'));
    process.exit(1);
  }
  const entry = ws.setTriage(storeDir, workspaceName, key, status === 'clear' ? null : status, note);
  console.log(chalk.green(entry ? `Marked as ${entry.status}: ${key}` : `Cleared triage for: ${key}`));
  process.exit(0);
}

// --- Allowlist management: user-known safe values (cache-busting hashes,
// internal build IDs, an internal domain that isn't sensitive, etc.) that
// should stop being reported at all, in every workspace scan from now on.
// Persisted per-workspace at <workspaceDir>/allowlist.json — separate from
// triage (triage marks a *specific past finding* reviewed; the allowlist
// says a *value* itself is never worth reporting, however it resurfaces).
if (hasFlag('--allowlist-add')) {
  const value = getFlagValue('--allowlist-add');
  const kind = hasFlag('--allowlist-pattern') ? 'pattern' : 'value';
  if (!value) {
    console.error(chalk.red('Usage: jsrecon --allowlist-add <value> [--allowlist-pattern] -wksp <name>'));
    process.exit(1);
  }
  ws.addToAllowlist(storeDir, workspaceName, value, kind);
  console.log(chalk.green(`Added ${kind} to allowlist for workspace "${workspaceName}": ${value}`));
  process.exit(0);
}
if (hasFlag('--allowlist-remove')) {
  const value = getFlagValue('--allowlist-remove');
  const kind = hasFlag('--allowlist-pattern') ? 'pattern' : 'value';
  if (!value) {
    console.error(chalk.red('Usage: jsrecon --allowlist-remove <value> [--allowlist-pattern] -wksp <name>'));
    process.exit(1);
  }
  ws.removeFromAllowlist(storeDir, workspaceName, value, kind);
  console.log(chalk.green(`Removed ${kind} from allowlist for workspace "${workspaceName}": ${value}`));
  process.exit(0);
}
if (hasFlag('--allowlist-list')) {
  const allowlist = ws.loadAllowlist(storeDir, workspaceName);
  console.log(chalk.bold(`\nAllowlist — workspace "${workspaceName}"\n`));
  console.log(chalk.dim('Values:'));
  (allowlist.values.length ? allowlist.values : ['(none)']).forEach((v) => console.log(`  ${v}`));
  console.log(chalk.dim('\nPatterns:'));
  (allowlist.patterns.length ? allowlist.patterns : ['(none)']).forEach((v) => console.log(`  ${v}`));
  process.exit(0);
}

function listReconField(flagValue, field) {
  const run = ws.loadRun(storeDir, workspaceName, runArg || 'latest');
  if (!run) { console.error(chalk.red(`No run found for workspace "${workspaceName}"`)); process.exit(1); }
  const kv = ws.parseKV(flagValue);
  const values = [...new Set(run.findings.filter((f) => f.field === field).map((f) => f.value))];
  const { page, limit, total, items } = ws.paginate(values, kv.page, kv.limit);
  console.log(chalk.bold(`\n${field} — page ${page}, ${items.length} of ${total}\n`));
  items.forEach((v) => console.log(`  ${v}`));
  process.exit(0);
}
if (hasFlag('--urls')) listReconField(getFlagValue('--urls'), 'url');
if (hasFlag('--domains')) listReconField(getFlagValue('--domains'), 'domain');

if (hasFlag('--files')) {
  const run = ws.loadRun(storeDir, workspaceName, runArg || 'latest');
  if (!run) { console.error(chalk.red(`No run found for workspace "${workspaceName}"`)); process.exit(1); }
  const kv = ws.parseKV(getFlagValue('--files'));
  const { page, limit, total, items } = ws.paginate(run.targets, kv.page, kv.limit);
  console.log(chalk.bold(`\nfiles — page ${page}, ${items.length} of ${total}\n`));
  items.forEach((v) => console.log(`  ${v}`));
  process.exit(0);
}

if (hasFlag('-issues')) {
  const run = ws.loadRun(storeDir, workspaceName, runArg || 'latest');
  if (!run) { console.error(chalk.red(`No run found for workspace "${workspaceName}"`)); process.exit(1); }
  const kv = ws.parseKV(getFlagValue('-issues'));
  const severities = kv.severity ? kv.severity.split(',') : ['high', 'medium'];
  const showSuppressed = hasFlag('--show-suppressed');
  const newOnly = hasFlag('--new-only');
  let issues = run.findings.filter((f) => severities.includes(f.severity));
  if (!showSuppressed) issues = issues.filter((f) => !(f.triage && f.triage.status === 'false-positive'));
  if (newOnly) issues = issues.filter((f) => f.isNew);
  if (kv.dateFrom) issues = issues.filter((f) => f.runTimestamp >= kv.dateFrom);
  if (kv.dateTo) issues = issues.filter((f) => f.runTimestamp <= kv.dateTo + 'T23:59:59Z');
  const { page, limit, total, items } = ws.paginate(issues, kv.page, kv.limit);
  console.log(chalk.bold(`\nIssues — page ${page}, ${items.length} of ${total}\n`));
  items.forEach((f) => {
    const color = f.severity === 'high' ? chalk.red.bold : chalk.yellow.bold;
    const tags = [f.isNew ? chalk.green.bold('[NEW]') : null, f.triage ? chalk.dim(`[${f.triage.status}]`) : null].filter(Boolean).join(' ');
    console.log(`${color(`[${f.severity.toUpperCase()}]`)}${tags ? ' ' + tags : ''} ${f.type} ${chalk.dim(`${f.file}:${f.line || ''}`)}`);
    if (f.note) console.log(`    ${f.note}`);
    if (f.seenInOtherFiles && f.seenInOtherFiles.length) {
      console.log(chalk.dim(`    ↳ also found in ${f.seenInFileCount - 1} other file(s): ${f.seenInOtherFiles.slice(0, 3).join(', ')}${f.seenInOtherFiles.length > 3 ? ', ...' : ''}`));
    }
    if (f.seenInOtherWorkspaces && f.seenInOtherWorkspaces.length) {
      const summary = f.seenInOtherWorkspaces
        .map((w) => `${w.workspace} (${w.files.length} file${w.files.length > 1 ? 's' : ''})`)
        .join(', ');
      console.log(chalk.cyan.dim(`    ↳ also found in ${f.seenInWorkspaceCount} other workspace(s): ${summary}`));
    }
    console.log(chalk.dim(`    key: ${f.dedupeKey}`));
  });
  process.exit(0);
}

let skipScan = false;
if (hasFlag('--ui')) {
  const initialRun = ws.loadRun(storeDir, workspaceName, runArg || 'all');
  if (!initialRun) { console.error(chalk.red(`No run found for workspace "${workspaceName}"`)); process.exit(1); }
  const uiOut = getFlagValue('--ui-out') || path.join(ws.workspaceDir(storeDir, workspaceName), 'dashboard.html');
  fs.mkdirSync(path.dirname(uiOut), { recursive: true });
  fs.writeFileSync(uiOut, buildDashboardHtml(initialRun));
  console.log(chalk.green(`\nDashboard written to ${uiOut} (open it directly in a browser)`));

  if (hasFlag('--serve')) {
    const port = parseInt(getFlagValue('--serve'), 10) || 5757;

    function readJsonBody(req, maxBytes = 2 * 1024 * 1024) {
      return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) { reject(new Error('body too large')); req.destroy(); return; }
          chunks.push(chunk);
        });
        req.on('end', () => {
          try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
          catch (e) { reject(new Error('invalid JSON body')); }
        });
        req.on('error', reject);
      });
    }

    // A valid, filesystem-safe workspace name — same rule the client applies
    // before offering "create new workspace", so the two stay in sync.
    const isValidWorkspaceName = (n) => typeof n === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(n);

    const server = http.createServer(async (req, res) => {
      const reqUrl = new URL(req.url, `http://${req.headers.host}`);
      // Every route honors ?wksp=<name> so the dashboard can switch workspaces
      // live; falls back to the one the server was started with.
      const reqWksp = reqUrl.searchParams.get('wksp') || workspaceName;
      const reqRun = reqUrl.searchParams.get('run') || runArg || 'all';

      // Always rebuilds from the live workspace so newly-added scans show up
      // without restarting the server — the dashboard is never a stale snapshot.
      if (req.method === 'GET' && reqUrl.pathname === '/') {
        const run = ws.loadRun(storeDir, reqWksp, reqRun);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(run ? buildDashboardHtml(run) : buildDashboardHtml({ workspace: reqWksp, findings: [], targets: [] }));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/run') {
        const run = ws.loadRun(storeDir, reqWksp, reqRun);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(run || { workspace: reqWksp, findings: [], targets: [] }));
        return;
      }

      // Lists every local workspace so the dashboard's sidebar switcher has
      // something to populate, without needing a page reload to discover one
      // created from the CLI in another terminal.
      if (req.method === 'GET' && reqUrl.pathname === '/api/workspaces') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ workspaces: ws.listWorkspaces(storeDir), current: reqWksp }));
        return;
      }

      // Add-asset API: scans new local paths and/or URLs from the dashboard's
      // "Add JS file(s)" form. Saves into body.workspace when given (letting
      // the dashboard start a brand-new workspace for this scan) or reqWksp
      // otherwise, using the same analyzers as the CLI.
      if (req.method === 'POST' && reqUrl.pathname === '/api/scan') {
        try {
          const body = await readJsonBody(req);
          const targets = Array.isArray(body.targets)
            ? body.targets.map((t) => String(t).trim()).filter(Boolean)
            : [];
          if (targets.length === 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'No targets provided' }));
            return;
          }
          let targetWorkspace = reqWksp;
          if (body.workspace) {
            if (!isValidWorkspaceName(body.workspace)) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Workspace name may only contain letters, numbers, dot, dash, underscore' }));
              return;
            }
            targetWorkspace = body.workspace;
          }
          const checksSet = Array.isArray(body.checks) && body.checks.length
            ? new Set(body.checks)
            : enabledChecks;

          console.log(chalk.dim(`\n[serve] scanning ${targets.length} new target(s) from dashboard into workspace "${targetWorkspace}": ${targets.join(', ')}`));
          const { allFindings, scanned, errors } = await scanTargets(targets, checksSet, { print: false, workspace: targetWorkspace });

          const runId = ws.saveRun(storeDir, targetWorkspace, {
            targets,
            checks: [...checksSet],
            findings: allFindings,
            meta: { addedFromUi: true },
          });
          console.log(chalk.dim(`[serve] saved run "${runId}" — ${scanned} scanned, ${errors} error(s), ${allFindings.length} finding(s)`));

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ runId, workspace: targetWorkspace, scanned, errors, findingCount: allFindings.length }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }

      // Removes one scanned asset (and every finding attributed to it) from
      // a workspace — backs the dashboard's per-asset "Remove" button.
      if (req.method === 'POST' && reqUrl.pathname === '/api/delete-asset') {
        try {
          const body = await readJsonBody(req);
          const target = typeof body.target === 'string' ? body.target.trim() : '';
          const targetWorkspace = body.workspace && isValidWorkspaceName(body.workspace) ? body.workspace : reqWksp;
          if (!target) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'No target specified' }));
            return;
          }
          const result = ws.deleteAsset(storeDir, targetWorkspace, target);
          console.log(chalk.dim(`[serve] removed asset "${target}" from workspace "${targetWorkspace}" — ${result.findingsRemoved} finding(s), ${result.runsDeleted} empty run(s) deleted`));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ workspace: targetWorkspace, target, ...result }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }

      // Permanently deletes an entire workspace (every run, its cached
      // sources, everything) — backs the dashboard sidebar's "Delete
      // workspace" action.
      if (req.method === 'POST' && reqUrl.pathname === '/api/delete-workspace') {
        try {
          const body = await readJsonBody(req);
          const targetWorkspace = typeof body.workspace === 'string' ? body.workspace.trim() : '';
          if (!targetWorkspace || !isValidWorkspaceName(targetWorkspace)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'No valid workspace specified' }));
            return;
          }
          const result = ws.deleteWorkspace(storeDir, targetWorkspace);
          console.log(chalk.dim(`[serve] deleted workspace "${targetWorkspace}"`));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ workspace: targetWorkspace, ...result }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }

      // Marks or clears a triage decision (false-positive / confirmed) on one
      // exact finding, identified by its dedupeKey — backs the dashboard's
      // per-finding "Mark as false positive" / "Confirm" / "Clear" buttons.
      // The decision is keyed on the finding's value+type+location, so it
      // stays applied on every future scan/view of that same value, not just
      // the run it was clicked in.
      if (req.method === 'POST' && reqUrl.pathname === '/api/triage') {
        try {
          const body = await readJsonBody(req);
          const key = typeof body.dedupeKey === 'string' ? body.dedupeKey : '';
          const status = body.status;
          const note = typeof body.note === 'string' ? body.note : '';
          const targetWorkspace = body.workspace && isValidWorkspaceName(body.workspace) ? body.workspace : reqWksp;
          if (!key || !['false-positive', 'confirmed', 'clear'].includes(status)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'dedupeKey and a valid status (false-positive|confirmed|clear) are required' }));
            return;
          }
          const entry = ws.setTriage(storeDir, targetWorkspace, key, status === 'clear' ? null : status, note);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ workspace: targetWorkspace, dedupeKey: key, triage: entry }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }

      // Serves the exact source of one scanned target — from the snapshot
      // cached at scan time when available, otherwise a best-effort live
      // re-read/re-fetch — so the dashboard can show the WHOLE file with the
      // flagged line jumped to and highlighted in place, with no dependency
      // on an editor URI handler or a browser's text-fragment support.
      if (req.method === 'GET' && reqUrl.pathname === '/api/source') {
        try {
          const target = reqUrl.searchParams.get('file');
          if (!target) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'No file specified' }));
            return;
          }
          const MAX_SOURCE_BYTES = 3 * 1024 * 1024; // cap so a huge bundle can't hang the browser tab
          const cachePath = path.join(sourceCacheDir(reqWksp), sourceCacheFilename(target));
          let content = null;
          let source = 'cache';

          if (fs.existsSync(cachePath)) {
            content = fs.readFileSync(cachePath, 'utf8');
          } else if (isUrl(target)) {
            try {
              const r = await fetchWithTimeout(target, fetchTimeout);
              if (r.ok) {
                content = await r.text();
                cacheSource(reqWksp, target, content);
                source = 'live-refetch';
              }
            } catch (e) { /* falls through to the 404 below */ }
          } else if (fs.existsSync(target)) {
            content = fs.readFileSync(target, 'utf8');
            cacheSource(reqWksp, target, content);
            source = 'live-read';
          }

          if (content == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Original source is no longer available (file moved/deleted locally, or the URL no longer reaches it). The snippet and code-context shown in the finding are still what was captured at scan time.' }));
            return;
          }

          const truncated = content.length > MAX_SOURCE_BYTES;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ content: truncated ? content.slice(0, MAX_SOURCE_BYTES) : content, truncated, source }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    });

    server.listen(port, '127.0.0.1', () => {
      console.log(chalk.green(`Serving dashboard at http://127.0.0.1:${port} (Ctrl+C to stop)`));
      console.log(chalk.dim(`  Add new JS files/URLs to scan directly from the Assets tab in the dashboard.`));
      console.log(chalk.dim(`  Switch or create workspaces from the sidebar without restarting this server.`));
    });
    skipScan = true;
  } else {
    process.exit(0);
  }
} else if (rsearchValue) {
  // --- Reverse search mode (doesn't need a fresh scan) -----------------------
  let data;
  if (inFile) {
    data = JSON.parse(fs.readFileSync(inFile, 'utf8'));
  } else {
    const run = ws.loadRun(storeDir, workspaceName, runArg || 'all');
    if (!run) { console.error(chalk.red(`No findings to search: pass --in <file.json> or scan into a workspace first`)); process.exit(1); }
    data = run.findings;
  }
  // Supports jsmon-style "field=value" as well as a bare value.
  let field = null, needle = rsearchValue;
  const kvMatch = rsearchValue.match(/^([a-zA-Z0-9_-]+)=(.*)$/);
  if (kvMatch) { field = kvMatch[1]; needle = kvMatch[2]; }

  const matches = data.filter((f) => {
    if (field && f.field !== field && f.type !== field) return false;
    const haystacks = [f.value, f.snippet, f.note, ...(f.sources || [])].filter(Boolean);
    return haystacks.some((h) => String(h).includes(needle));
  });
  console.log(chalk.bold(`\nReverse search for "${rsearchValue}" — ${matches.length} match(es)\n`));
  matches.forEach((f) => {
    console.log(`${chalk.bold(f.type)} ${chalk.dim(`${f.file}:${f.line || ''}`)}`);
    if (f.value) console.log(`    value: ${f.value}`);
    if (f.snippet) console.log(`    ${chalk.dim(f.snippet)}`);
    console.log('');
  });
  process.exit(0);
}

const isUrl = (target) => /^https?:\/\//i.test(target);

/** Reads a target-list file: one entry per line, local paths and/or
 *  http(s):// URLs freely mixed, blank lines and `#`-comments ignored. */
function parseTargetListFile(file) {
  return fs.readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .filter((l) => !l.startsWith('#'));
}

/**
 * Returns the scan targets, resolving -d into either a local directory
 * listing or a live domain crawl (jsmon's `-d <domain> -depth -keywords
 * -extensions`), depending on whether the value is an existing directory.
 */
async function collectFiles() {
  if (singleFile) {
    // -u also doubles as "scan whatever this list file points at" when it's
    // handed a local .txt file instead of a single JS file/URL — so a
    // single flag covers both "one target" and "a file of targets" the way
    // it reads naturally, without having to remember -f is the other flag.
    if (!isUrl(singleFile) && /\.txt$/i.test(singleFile) && fs.existsSync(singleFile) && fs.statSync(singleFile).isFile()) {
      return parseTargetListFile(singleFile);
    }
    return [singleFile];
  }
  if (listFile) {
    return parseTargetListFile(listFile);
  }
  if (dir) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      const exts = extArg.split(',').map((e) => e.trim());
      const pattern = `**/*.{${exts.join(',')}}`;
      return globSync(pattern, { cwd: dir, nodir: true, absolute: true });
    }
    // Not a local directory — treat it as a domain/URL to crawl.
    const seed = /^https?:\/\//i.test(dir) ? dir : `https://${dir}`;
    const depth = parseInt(getFlagValue('-depth') || getFlagValue('-scan-depth') || '2', 10);
    const keywords = (getFlagValue('-keywords') || getFlagValue('-scan-keywords') || '')
      .split(',').map((k) => k.trim()).filter(Boolean);
    const extensions = (getFlagValue('-extensions') || getFlagValue('-scan-extensions') || 'js,mjs')
      .split(',').map((e) => e.trim());
    const maxPages = parseInt(getFlagValue('--max-pages') || '200', 10);

    console.log(chalk.bold(`\nCrawling ${seed} (depth ${depth}, extensions: ${extensions.join(',')}${keywords.length ? `, keywords: ${keywords.join(',')}` : ''})...\n`));

    const { pages, visited } = await crawl(seed, {
      depth, keywords, extensions, maxPages,
      fetchFn: async (url) => {
        await politeDelay();
        const res = await fetchWithTimeout(url, fetchTimeout);
        return { ok: res.ok, text: res.ok ? await res.text() : '' };
      },
      onLog: (msg) => console.log(chalk.dim(`  ${msg}`)),
    });

    console.log(chalk.dim(`Visited ${visited} page(s), found ${pages.length} matching file(s)\n`));
    return pages.map((p) => p.url);
  }
  console.error(chalk.red('Error: specify one of -u <file|url>, -d <dir|domain>, -f <list.txt>, or -rsearch with --in'));
  process.exit(1);
}

/** Turns a URL into a safe local filename for --save-dir. */
function urlToFilename(url) {
  const u = new URL(url);
  const base = (u.hostname + u.pathname).replace(/[^a-zA-Z0-9._-]/g, '_');
  return base || 'download.js';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Every remote fetch in the tool (single-target scan, source-map follow,
 * and the domain crawler's per-page fetch) goes through this one function,
 * so retry/backoff lives in exactly one place. A 429 (rate limited) or 5xx
 * (server-side hiccup) is often transient — bailing out on the first one
 * turns a brief blip into a missed file and a confusing "HTTP 503" error for
 * what would have succeeded on a second try a moment later. 4xx other than
 * 429 (404, 403, 401...) is not retried — that's a real, stable answer from
 * the server, and hammering it again wastes time and looks more like an
 * attack during authorized testing than a normal client would.
 * Backoff: 500ms, 1000ms, 2000ms (capped), plus up to 250ms of jitter so a
 * batch of parallel-ish requests against the same host don't all retry in
 * lockstep. A Retry-After response header (seconds or an HTTP-date), when
 * present, overrides the computed delay for that attempt.
 */
async function fetchWithTimeout(url, timeoutMs, { retries = 2 } = {}) {
  let lastRes = null;
  let lastErr = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { signal: controller.signal, headers: buildHeaders() });
      clearTimeout(t);
      const retryable = res.status === 429 || (res.status >= 500 && res.status < 600);
      if (!retryable || attempt === retries) return res;
      lastRes = res;
    } catch (e) {
      clearTimeout(t);
      // Network-level failures (DNS, connection reset, our own abort on
      // timeout) are retried too — same transient-failure reasoning as a 5xx.
      lastErr = e;
      if (attempt === retries) throw e;
    }
    let delayMs = Math.min(2000, 500 * 2 ** attempt) + Math.floor(Math.random() * 250);
    const retryAfter = lastRes && lastRes.headers ? lastRes.headers.get('retry-after') : null;
    if (retryAfter) {
      const asSeconds = Number(retryAfter);
      if (!Number.isNaN(asSeconds)) delayMs = asSeconds * 1000;
      else {
        const asDate = Date.parse(retryAfter);
        if (!Number.isNaN(asDate)) delayMs = Math.max(0, asDate - Date.now());
      }
    }
    await sleep(delayMs);
  }
  // Unreachable in practice (the loop always returns/throws on the last
  // attempt), but keeps the function's return type honest for any caller.
  if (lastRes) return lastRes;
  throw lastErr || new Error(`fetchWithTimeout: exhausted retries for ${url}`);
}

/**
 * Resolves a single scan target (local path or http(s) URL) into
 * { content, filePath, baseUrl }. filePath is used for display/output and,
 * for local files, for resolving relative source maps; baseUrl (set only for
 * URL targets) is used instead to resolve a relative sourceMappingURL back
 * into a fetchable absolute URL.
 */
async function readTarget(target) {
  if (isUrl(target)) {
    await politeDelay();
    const res = await fetchWithTimeout(target, fetchTimeout);
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const content = await res.text();
    if (saveDir) {
      fs.writeFileSync(path.join(saveDir, urlToFilename(target)), content);
    }
    return { content, filePath: target, baseUrl: target };
  }
  const content = fs.readFileSync(target, 'utf8');
  return { content, filePath: target, baseUrl: null };
}

// --- Analyzers ---------------------------------------------------------------
// analyzePostMessage / analyzeRecon / analyzeSecrets live in lib/analyzers.js
// (pure functions, imported at the top of this file) so they can be unit
// tested directly — see test/analyzers.test.js. analyzeSourceMaps stays here
// since it does real I/O (fetching/reading .map files).

async function analyzeSourceMaps(content, filePath, baseUrl) {
  const findings = [];
  const re = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const { line, column } = lineAndColumn(content, m.index);
    const target = m[1];
    // Reused on every follow-on finding below so each one still points back
    // to the exact line/column in the JS file that referenced the map, even
    // though the interesting content (leaked paths, fetch errors) lives elsewhere.
    const refSnippet = `sourceMappingURL=${target}`;

    findings.push({
      type: 'sourcemap-reference',
      severity: 'info',
      file: filePath,
      line,
      column,
      snippet: refSnippet,
      note: 'File references a source map.',
    });

    let mapContent = null;
    let mapSource = null;

    if (target.startsWith('data:')) {
      // inline base64/JSON map — decode directly, no fetch needed
      const b64Match = target.match(/base64,(.*)$/);
      if (b64Match) {
        try {
          mapContent = Buffer.from(b64Match[1], 'base64').toString('utf8');
          mapSource = '(inline data: URI)';
        } catch (e) {
          // ignore malformed inline map
        }
      }
    } else if (/^https?:\/\//i.test(target) || baseUrl) {
      // Either an absolute URL, or a relative path that needs resolving
      // against the URL the JS file itself was fetched from.
      mapSource = /^https?:\/\//i.test(target) ? target : new URL(target, baseUrl).toString();
      if (fetchMaps) {
        try {
          const res = await fetchWithTimeout(mapSource, fetchTimeout);
          if (res.ok) {
            mapContent = await res.text();
            if (saveDir) {
              fs.writeFileSync(path.join(saveDir, urlToFilename(mapSource)), mapContent);
            }
          }
        } catch (e) {
          findings.push({
            type: 'sourcemap-fetch-error',
            severity: 'info',
            file: filePath,
            line,
            column,
            snippet: refSnippet,
            note: `Could not fetch ${mapSource}: ${e.message}`,
          });
        }
      }
    } else {
      const resolved = path.resolve(path.dirname(filePath), target);
      mapSource = resolved;
      if (fs.existsSync(resolved)) {
        mapContent = fs.readFileSync(resolved, 'utf8');
      }
    }

    if (mapContent) {
      try {
        const mapJson = JSON.parse(mapContent);
        const sources = mapJson.sources || [];
        // Every source map that resolves exposes *some* path, but "exposes
        // vendor/build-tool internals only" and "exposes your own app's
        // source tree" are very different findings to triage — a map whose
        // sources are entirely node_modules/webpack/vendor noise is still
        // worth noting but shouldn't compete for attention at the same
        // severity as one that hands over your actual source layout.
        // NOT included: a bare "webpack://" prefix or "webpack/" path segment
        // — webpack labels EVERY module that way, including the app's own
        // source, so matching on that alone would misclassify real app code
        // as vendor noise. Only match webpack's own internal runtime files
        // and actual dependency trees.
        const VENDOR_SOURCE_RE = /node_modules|\(webpack\)|webpack\/bootstrap|webpack\/runtime|[\\/]vendor[\\/]/i;
        const ownSources = sources.filter((s) => !VENDOR_SOURCE_RE.test(s));
        const severity = ownSources.length > 0 ? 'high' : sources.length > 0 ? 'low' : 'low';
        findings.push({
          type: 'sourcemap-exposed',
          severity,
          file: filePath,
          line,
          column,
          snippet: refSnippet,
          note: sources.length === 0
            ? `Source map at ${mapSource} resolved but lists no source paths.`
            : ownSources.length > 0
              ? `Source map at ${mapSource} exposes ${sources.length} original source path(s), including ${ownSources.length} that look like this app's own code (not vendor/node_modules).`
              : `Source map at ${mapSource} exposes ${sources.length} original source path(s), but all of them look like vendor/build-tool internals (node_modules, webpack runtime) rather than this app's own source.`,
          sources,
        });
      } catch (e) {
        findings.push({
          type: 'sourcemap-parse-error',
          severity: 'info',
          file: filePath,
          line,
          column,
          snippet: refSnippet,
          note: `Found map at ${mapSource} but could not parse JSON: ${e.message}`,
        });
      }
    } else if (mapSource) {
      findings.push({
        type: 'sourcemap-unresolved',
        severity: 'info',
        file: filePath,
        line,
        column,
        snippet: refSnippet,
        note: `Map reference points to ${mapSource} but it was not fetched/found (pass --fetch-maps for remote URLs, or ensure the .map file is present locally).`,
      });
    }
  }
  return findings;
}
// --- Runner -----------------------------------------------------------------

const severityColor = {
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan,
  info: chalk.gray,
};

function printFinding(f) {
  const color = severityColor[f.severity] || chalk.white;
  const loc = `${f.file}:${f.line || ''}${f.column != null ? `:${f.column}` : ''}`;
  console.log(
    `${color(`[${f.severity.toUpperCase()}]`)} ${chalk.bold(f.type)} ${chalk.dim(loc)}`
  );
  if (f.value) console.log(`    value: ${f.value}`);
  // Always show the match-centered snippet when present — it's what lets you
  // jump straight to the spot in a minified/single-line bundle where line
  // number alone tells you almost nothing.
  if (f.snippet) console.log(`    ${chalk.dim(f.snippet)}`);
  if (f.note) console.log(`    ${f.note}`);
  if (f.sources && f.sources.length) {
    f.sources.slice(0, 20).forEach((s) => console.log(`      - ${s}`));
    if (f.sources.length > 20) console.log(`      ... and ${f.sources.length - 20} more`);
  }
  console.log('');
}

/**
 * Scans a list of targets (local paths or URLs) with the given checks.
 * Shared by the CLI's main() and the --serve "add asset" API, so a file
 * added from the dashboard goes through exactly the same analyzers.
 */
/**
 * Every scanned target's exact source, as fetched/read at scan time, is
 * cached to disk under the workspace — this is what lets the dashboard's
 * "Open full file" view jump straight to the flagged line later, even if a
 * remote bundle gets redeployed or a local file gets moved/edited before you
 * come back to verify it manually. Keyed by a hash of the target string so
 * no separate manifest is needed — the server route recomputes the same
 * hash from the `file` it's asked for.
 */
function sourceCacheFilename(target) {
  return crypto.createHash('sha1').update(target).digest('hex') + '.src';
}

function sourceCacheDir(workspace) {
  return path.join(ws.workspaceDir(storeDir, workspace), 'sources');
}

function cacheSource(workspace, target, content) {
  try {
    const dir = sourceCacheDir(workspace);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, sourceCacheFilename(target)), content);
  } catch (e) {
    // Best-effort — a failed cache write shouldn't fail the scan itself;
    // the dashboard just falls back to a live re-fetch/read for this target.
  }
}

async function scanTargets(targets, checksSet, { print = false, workspace = workspaceName } = {}) {
  const allFindings = [];
  let scanned = 0;
  let errors = 0;
  let allowlistedCount = 0;
  // Loaded once per scan (not per file) — an exact-value/regex matcher for
  // this workspace's saved allowlist.json (see --allowlist-add/-remove/-list).
  const isAllowlisted = ws.buildAllowlistMatcher(ws.loadAllowlist(storeDir, workspace));
  // Every successfully-read file's content, retained for the cross-file
  // taint pass below (analyzeCrossFileTaint needs every file in the batch
  // in hand at once — it can't run per-file like the other analyzers).
  const scannedSources = [];

  for (const target of targets) {
    let content, filePath, baseUrl;
    try {
      ({ content, filePath, baseUrl } = await readTarget(target));
    } catch (e) {
      if (print) console.log(chalk.red(`Could not fetch/read ${target}: ${e.message}`));
      errors++;
      continue;
    }
    scanned++;
    cacheSource(workspace, target, content);
    scannedSources.push({ filePath, content });

    let fileFindings = [];
    if (checksSet.has('postmessage')) fileFindings.push(...analyzePostMessage(content, filePath));
    if (checksSet.has('sourcemap')) fileFindings.push(...(await analyzeSourceMaps(content, filePath, baseUrl)));
    if (checksSet.has('recon')) fileFindings.push(...analyzeRecon(content, filePath));
    if (checksSet.has('secrets')) fileFindings.push(...analyzeSecrets(content, filePath));

    const beforeAllowlist = fileFindings.length;
    fileFindings = fileFindings.filter((f) => !isAllowlisted(f.value));
    allowlistedCount += beforeAllowlist - fileFindings.length;

    if (filterText) {
      fileFindings = fileFindings.filter((f) =>
        (f.value && f.value.includes(filterText)) ||
        (f.snippet && f.snippet.includes(filterText)) ||
        (f.note && f.note.includes(filterText))
      );
    }

    if (print) fileFindings.forEach(printFinding);
    allFindings.push(...fileFindings);
  }

  // Cross-file taint: needs every file's content in hand at once, so it runs
  // once after the per-file loop rather than inside it. Scoped to this
  // scan's own batch of files — see the comment on analyzeCrossFileTaint in
  // lib/analyzers.js for why that's a deliberate limit, not an oversight.
  if (checksSet.has('postmessage') && scannedSources.length > 1) {
    let crossFileFindings = analyzeCrossFileTaint(scannedSources);
    if (filterText) {
      crossFileFindings = crossFileFindings.filter((f) =>
        (f.snippet && f.snippet.includes(filterText)) || (f.note && f.note.includes(filterText))
      );
    }
    if (print) crossFileFindings.forEach(printFinding);
    allFindings.push(...crossFileFindings);
  }

  if (print && allowlistedCount > 0) {
    console.log(chalk.dim(`(${allowlistedCount} finding(s) suppressed by workspace allowlist — see --allowlist-list)`));
  }

  return { allFindings, scanned, errors, allowlistedCount };
}

function printSummary(allFindings, scanned, errors) {
  const summary = { high: 0, medium: 0, low: 0, info: 0 };
  allFindings.forEach((f) => summary[f.severity] = (summary[f.severity] || 0) + 1);

  const byType = {};
  allFindings.forEach((f) => byType[f.type] = (byType[f.type] || 0) + 1);

  console.log(chalk.bold('--- Summary ---'));
  console.log(`Files scanned: ${scanned}${errors ? chalk.red(` (${errors} errors)`) : ''}`);
  console.log(
    `Severity: ${chalk.red.bold(summary.high || 0)} high, ` +
    `${chalk.yellow.bold(summary.medium || 0)} medium, ` +
    `${chalk.cyan(summary.low || 0)} low, ` +
    `${chalk.gray(summary.info || 0)} info`
  );
  Object.entries(byType).forEach(([type, count]) => console.log(`  ${type}: ${count}`));
}

async function main() {
  const files = await collectFiles();
  console.log(chalk.bold(`\njsrecon — scanning ${files.length} file(s) [checks: ${[...enabledChecks].join(', ')}]\n`));

  const { allFindings, scanned, errors } = await scanTargets(files, enabledChecks, { print: true });

  console.log('');
  printSummary(allFindings, scanned, errors);

  if (outFile) {
    fs.writeFileSync(outFile, JSON.stringify(allFindings, null, 2));
    console.log(`\nWrote ${allFindings.length} findings to ${outFile}`);
  }

  if (!noSave) {
    const runId = ws.saveRun(storeDir, workspaceName, {
      targets: files,
      checks: [...enabledChecks],
      findings: allFindings,
    });
    console.log(chalk.dim(`Saved as run "${runId}" in workspace "${workspaceName}" (${storeDir})`));
    console.log(chalk.dim(`  jsrecon -count -wksp ${workspaceName}   |   jsrecon --ui --serve -wksp ${workspaceName}`));
  }
}

if (!skipScan) {
  main().catch((e) => {
    console.error(chalk.red(`Fatal error: ${e.message}`));
    process.exit(1);
  });
}
