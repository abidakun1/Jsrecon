'use strict';
/**
 * Local result-analysis UI — a jsmon-style security dashboard: sidebar
 * navigation by finding category (Overview / Issues / PostMessage / Source
 * Maps / Secrets / Recon Data / Assets), stat cards, severity breakdown, and
 * a filterable table. Everything is a single self-contained HTML file with
 * the findings embedded as JSON — no server or network required to view it.
 *
 * Recon Data is further split by field (recon-api-path, recon-port-url,
 * recon-url, etc. all stay distinct via clickable chips) instead of one flat
 * dump. When opened through `jsrecon --ui --serve` (detected client-side via
 * location.protocol), the Assets tab also gets a form to add new local
 * files/URLs and scan them via the server's /api/scan endpoint, without
 * leaving the dashboard.
 */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function buildDashboardHtml(run) {
  const findings = run.findings || [];
  const dataJson = JSON.stringify(findings).replace(/</g, '\\u003c');
  const targetsJson = JSON.stringify(run.targets || []).replace(/</g, '\\u003c');
  const checksJson = JSON.stringify(run.checks || ['postmessage', 'sourcemap', 'recon', 'secrets']);
  const severities = ['high', 'medium', 'low', 'info'];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jsrecon — ${escapeHtml(run.workspace || 'results')}</title>
<style>
  :root {
    --bg: #0a0d12; --panel: #10141b; --panel-2: #161b24; --border: #232a35; --text: #e6edf3; --muted: #7d8590;
    --high: #f85149; --medium: #d29922; --low: #58a6ff; --info: #6e7681; --accent: #3fb950; --accent-dim: rgba(63,185,80,.12);
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f3f4f6; --panel:#fff; --panel-2:#f6f8fa; --border:#d0d7de; --text:#1f2328; --muted:#57606a; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 14px; }
  a { color: inherit; }

  .shell { display: flex; min-height: 100vh; }

  /* --- Sidebar --- */
  .sidebar { width: 232px; flex-shrink: 0; background: var(--panel); border-right: 1px solid var(--border); display:flex; flex-direction: column; }
  .brand { padding: 18px 20px; border-bottom: 1px solid var(--border); display:flex; align-items:center; gap:10px; }
  .brand .dot { width:10px; height:10px; border-radius:50%; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
  .brand .dot.offline { background: var(--muted); box-shadow:none; }
  .brand .name { font-weight:700; font-size:15px; letter-spacing:.02em; }
  .brand .name span { color: var(--accent); }
  .ws-meta { padding: 12px 20px 16px; border-bottom: 1px solid var(--border); }
  .ws-meta .label { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-bottom:2px; }
  .ws-meta .val { font-size: 13px; font-weight:600; word-break: break-word; }
  .ws-meta .sub { font-size: 11px; color: var(--muted); margin-top: 6px; }
  #workspaceSelect { width:100%; background: var(--panel-2); border:1px solid var(--border); color: var(--text); padding: 6px 8px; border-radius:6px; font-size: 13px; font-weight:600; cursor:pointer; }
  .ws-row { display:flex; gap:6px; align-items:stretch; }
  .ws-row #workspaceSelect { flex:1; min-width:0; }
  #deleteWorkspaceBtn { flex:0 0 auto; background: var(--panel-2); color: var(--high); border:1px solid var(--border); border-radius:6px; padding: 6px 9px; font-size: 13px; cursor:pointer; line-height:1; }
  #deleteWorkspaceBtn:hover { background: var(--high); color:#1a0505; border-color: var(--high); }
  #deleteWorkspaceBtn:disabled { opacity:.4; cursor:default; background: var(--panel-2); color: var(--muted); }

  nav { padding: 10px 10px; flex: 1; }
  nav .navitem { display:flex; align-items:center; justify-content:space-between; gap:8px; padding: 9px 12px; border-radius:7px; cursor:pointer; color: var(--muted); font-size: 13px; font-weight:500; margin-bottom: 2px; }
  nav .navitem:hover { background: var(--panel-2); color: var(--text); }
  nav .navitem.active { background: var(--accent-dim); color: var(--accent); }
  nav .navitem .count { font-size: 11px; background: var(--panel-2); padding: 1px 7px; border-radius: 999px; color: var(--muted); }
  nav .navitem.active .count { background: rgba(63,185,80,.2); color: var(--accent); }
  nav .navitem .ic { width:16px; text-align:center; margin-right: 4px; opacity: .85; }
  nav .navgroup-label { font-size: 10px; text-transform: uppercase; letter-spacing:.07em; color: var(--muted); padding: 14px 12px 6px; }

  .sidebar-footer { padding: 12px 20px; border-top: 1px solid var(--border); font-size: 11px; color: var(--muted); }

  /* --- Main --- */
  main { flex:1; min-width:0; display:flex; flex-direction:column; }
  .topbar { padding: 16px 28px; border-bottom: 1px solid var(--border); display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; background: var(--panel); }
  .topbar h1 { font-size: 17px; margin:0; }
  .topbar .desc { font-size:12px; color:var(--muted); margin-top:2px; }
  .controls { display:flex; gap: 8px; flex-wrap: wrap; align-items:center; }
  .controls input, .controls select { background: var(--panel-2); border:1px solid var(--border); color: var(--text); padding: 7px 10px; border-radius:6px; font-size: 12px; }
  .toggle-label { display:flex; align-items:center; gap:5px; font-size: 12px; color: var(--muted); white-space:nowrap; cursor:pointer; }
  .toggle-label input { padding:0; }
  .controls input[type=text] { min-width: 240px; }

  .content { padding: 24px 28px; flex:1; }

  .stats-row { display:flex; gap: 12px; flex-wrap: wrap; margin-bottom: 22px; }
  .stat-card { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 14px 18px; min-width: 120px; flex: 1; }
  .stat-card .n { font-size: 26px; font-weight: 800; line-height: 1.1; }
  .stat-card .l { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-top:4px; }
  .stat-card.sev-high .n { color: var(--high); } .stat-card.sev-medium .n { color: var(--medium); }
  .stat-card.sev-low .n { color: var(--low); } .stat-card.sev-info .n { color: var(--info); }
  .stat-card.sev-total .n { color: var(--text); }

  .bar-wrap { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 22px; }
  .bar-wrap .bt { font-size: 11px; text-transform:uppercase; letter-spacing:.05em; color: var(--muted); margin-bottom: 10px; }
  .bar-track { display:flex; height: 10px; border-radius: 999px; overflow:hidden; background: var(--panel-2); }
  .bar-seg.high { background: var(--high); } .bar-seg.medium { background: var(--medium); }
  .bar-seg.low { background: var(--low); } .bar-seg.info { background: var(--info); }
  .bar-legend { display:flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; }
  .bar-legend .li { display:flex; align-items:center; gap:6px; font-size: 12px; color: var(--muted); }
  .bar-legend .sw { width:9px; height:9px; border-radius:2px; }
  .sw.high { background: var(--high); } .sw.medium { background: var(--medium); } .sw.low { background: var(--low); } .sw.info { background: var(--info); }

  table { width: 100%; table-layout: fixed; border-collapse: collapse; background: var(--panel); border:1px solid var(--border); border-radius: 10px; overflow: hidden; }
  thead th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); border-bottom:1px solid var(--border); padding: 10px 16px; background: var(--panel-2); }
  thead th:nth-child(1) { width: 80px; } thead th:nth-child(2) { width: 15%; } thead th:nth-child(3) { width: 190px; }
  tbody td { padding: 11px 16px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; overflow-wrap: break-word; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--panel-2); }
  .badge { display:inline-block; padding:2px 9px; border-radius: 999px; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }
  .badge.high { background: rgba(248,81,73,.15); color: var(--high); }
  .badge.medium { background: rgba(210,153,34,.15); color: var(--medium); }
  .badge.low { background: rgba(88,166,255,.15); color: var(--low); }
  .badge.info { background: rgba(110,118,129,.15); color: var(--info); }
  .file { color: var(--muted); font-size: 11.5px; word-break: break-all; }
  a.file.loclink { color: var(--low); text-decoration: none; cursor: pointer; }
  a.file.loclink:hover { text-decoration: underline; }
  a.file.loclink::after { content: ' \\2197'; font-size: 10px; opacity: .7; }
  .val { font-family: ui-monospace, Menlo, Consolas, monospace; word-break: break-all; font-size: 12.5px; }
  .method-badge { display:inline-block; padding:2px 8px; border-radius:5px; font-size:10.5px; font-weight:700; letter-spacing:.03em; font-family: ui-monospace, Menlo, Consolas, monospace; background: var(--accent-dim); color: var(--accent); margin-bottom: 5px; }
  .method-badge.none { background: var(--panel-2); color: var(--muted); font-weight:600; text-transform:none; letter-spacing:0; }
  .new-badge { display:inline-block; padding:2px 8px; border-radius:5px; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; background: rgba(63,185,80,.15); color: #3fb950; margin-right:6px; margin-bottom: 5px; }
  .corr-note { color: var(--low); font-size: 11.5px; margin-top: 4px; }
  .corr-note.cross-ws { color: var(--accent); }
  .triage-row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-top: 6px; }
  .triage-badge { display:inline-block; padding:2px 8px; border-radius:5px; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }
  .triage-badge.false-positive { background: var(--panel-2); color: var(--muted); text-decoration: line-through; }
  .triage-badge.confirmed { background: rgba(248,81,73,.15); color: var(--high); }
  .triage-note { color: var(--muted); font-size: 11.5px; }
  .triage-btn { border:1px solid var(--border); background: var(--panel-2); color: var(--muted); border-radius:5px; padding:2px 8px; font-size:11px; cursor:pointer; }
  .triage-btn:hover { color: var(--text); border-color: var(--accent); }
  tr.suppressed-row { opacity: .5; }
  .note { color: var(--muted); font-size: 12px; margin-top: 3px; }
  .count-line { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
  .sources { margin: 4px 0 0; padding-left: 16px; color: var(--muted); font-size: 11.5px; }
  #empty { padding: 48px; text-align:center; color: var(--muted); display:none; background: var(--panel); border:1px solid var(--border); border-radius: 10px; }

  /* --- Inline code context (the actual handler body, not just a short snippet) --- */
  .ctx { margin-top: 8px; }
  .ctx summary { cursor:pointer; font-size: 11.5px; color: var(--accent); user-select:none; }
  .ctx summary:hover { text-decoration: underline; }
  .ctx-toolbar { display:flex; align-items:center; gap:8px; margin: 6px 0; }
  .ctx-toolbar .copy-ctx-btn { padding: 3px 10px; font-size: 11px; }
  .ctx-toolbar .copy-status { font-size: 11px; color: var(--low); }
  .ctx-code { background: #0d1117; border:1px solid var(--border); border-radius: 8px; padding: 12px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; line-height:1.5; color: #c9d1d9; overflow-x:auto; white-space:pre; max-height: 420px; overflow-y:auto; }
  .ctx-code mark { background: rgba(248,81,73,.35); color: #fff; border-radius:3px; padding: 0 2px; }

  /* --- Full-file viewer: one-click, in-dashboard navigation straight to the
     flagged line, with no dependency on an editor URI handler or a
     browser's text-fragment support. --- */
  .open-in-viewer-btn { display:block; width: fit-content; max-width:100%; padding: 4px 10px; font-size: 10.5px; margin-top: 6px; white-space: nowrap; }
  .viewer-overlay { display:none; position:fixed; inset:0; background: rgba(0,0,0,.6); z-index: 1000; align-items:center; justify-content:center; padding: 24px; }
  .viewer-overlay.open { display:flex; }
  .viewer-panel { background: var(--bg); border:1px solid var(--border); border-radius: 12px; width: 100%; max-width: 1100px; height: 85vh; display:flex; flex-direction:column; overflow:hidden; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
  .viewer-header { display:flex; align-items:center; justify-content:space-between; gap:12px; padding: 12px 16px; border-bottom:1px solid var(--border); flex-shrink:0; }
  .viewer-title { font-size: 13px; font-weight:700; word-break: break-all; }
  .viewer-header-actions { display:flex; align-items:center; gap:10px; flex-shrink:0; }
  .viewer-source-note { font-size: 11px; color: var(--muted); }
  .viewer-close { background:none; border:none; color: var(--muted); font-size: 22px; line-height:1; cursor:pointer; padding: 0 4px; }
  .viewer-close:hover { color: var(--text); }
  .viewer-body { flex:1; overflow:auto; background: #0d1117; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; line-height:1.6; }
  .viewer-body .vline { display:flex; white-space:pre; }
  .viewer-body .vline-no { flex-shrink:0; width: 56px; text-align:right; padding-right: 14px; color: #6e7681; user-select:none; position:sticky; left:0; background: #0d1117; }
  .viewer-body .vline-content { color: #c9d1d9; padding-right: 24px; }
  .viewer-body .vline-hit { background: rgba(248,81,73,.12); }
  .viewer-body .vline-hit .vline-no { background: rgba(248,81,73,.25); color: #fff; font-weight:700; }
  .viewer-body mark { background: rgba(248,81,73,.5); color:#fff; border-radius:2px; }
  .viewer-body .viewer-error { padding: 40px; text-align:center; color: var(--muted); white-space:normal; }

  .asset-list { display:flex; flex-direction:column; gap:8px; }
  .asset-card { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 12px 16px; font-size: 12.5px; display:flex; flex-wrap:wrap; justify-content:space-between; gap:10px; align-items:center; }
  .asset-card-main { display:flex; flex-direction:column; gap:6px; min-width:0; flex:1 1 260px; }
  .asset-card-name { word-break: break-all; font-weight:600; }
  .asset-card-badges { display:flex; flex-wrap:wrap; gap:5px; }
  .asset-card-actions { display:flex; align-items:center; gap:8px; flex-shrink:0; }
  .asset-card .n { color: var(--muted); font-size: 11px; flex-shrink:0; }
  .asset-card-actions .btn { padding: 5px 12px; font-size: 11.5px; }
  .sev-badge { border-radius:999px; padding: 2px 9px; font-size: 10.5px; font-weight:700; }
  .sev-badge.high { background: rgba(248,81,73,.15); color: var(--high); }
  .sev-badge.medium { background: rgba(210,153,34,.15); color: var(--medium); }
  .sev-badge.low { background: rgba(88,166,255,.15); color: var(--low); }
  .sev-badge.info { background: rgba(110,118,129,.15); color: var(--info); }
  .sev-badge.none { background: var(--panel-2); color: var(--muted); }
  .btn.danger { background: rgba(248,81,73,.15); color: #f85149; border:1px solid rgba(248,81,73,.4); }
  .btn.danger:hover { background: rgba(248,81,73,.25); }

  /* --- Field chips (Recon Data grouping) --- */
  .chip-row { display:flex; gap:8px; flex-wrap:wrap; margin-bottom: 18px; }
  .chip { background: var(--panel); border:1px solid var(--border); border-radius: 999px; padding: 6px 14px; font-size: 12px; color: var(--muted); cursor:pointer; display:flex; align-items:center; gap:7px; }
  .chip:hover { color: var(--text); border-color: var(--muted); }
  .chip.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent); }
  .chip .n { background: var(--panel-2); border-radius:999px; padding: 0 7px; font-size: 11px; }
  .chip.active .n { background: rgba(63,185,80,.2); }

  /* --- Per-asset grouping (keeps different domains/files from blending together) --- */
  .asset-group { margin-bottom: 22px; }
  .asset-group:last-child { margin-bottom: 0; }
  .asset-group-header { display:flex; align-items:center; justify-content:space-between; gap:10px; padding: 8px 12px; background: var(--panel-2); border:1px solid var(--border); border-bottom:none; border-radius: 8px 8px 0 0; }
  .asset-group-header .agh-name { font-size: 13px; font-weight:600; color: var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .asset-group-header .agh-count { font-size: 11px; color: var(--muted); flex-shrink:0; }
  .asset-group table { border-radius: 0 0 8px 8px; margin-top:0; }

  /* --- Add-asset form --- */
  .add-asset { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 20px; }
  .add-asset .t { font-size: 12.5px; font-weight:700; margin-bottom: 4px; }
  .add-asset .d { font-size: 11.5px; color: var(--muted); margin-bottom: 10px; }
  .add-asset textarea { width:100%; min-height: 74px; background: var(--panel-2); border:1px solid var(--border); color: var(--text); border-radius:6px; padding: 8px 10px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; resize: vertical; }
  .add-asset .row { display:flex; gap:10px; align-items:center; margin-top: 10px; flex-wrap: wrap; }
  .add-asset .checks { display:flex; gap:12px; flex-wrap:wrap; font-size:12px; color: var(--muted); }
  .add-asset .checks label { display:flex; align-items:center; gap:5px; cursor:pointer; }
  .btn { background: var(--accent); color: #04170a; border:none; border-radius:6px; padding: 8px 16px; font-size: 12.5px; font-weight:700; cursor:pointer; }
  .btn:disabled { opacity:.5; cursor:default; }
  .btn.secondary { background: var(--panel-2); color: var(--text); border:1px solid var(--border); }
  .add-asset .status { font-size: 12px; margin-top: 8px; }
  .add-asset .status.ok { color: var(--accent); }
  .add-asset .status.err { color: var(--high); }
  .add-asset .offline-note { font-size: 12px; color: var(--muted); background: var(--panel-2); border-radius: 6px; padding: 10px 12px; }
  .add-asset .offline-note code { color: var(--text); }
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand"><div class="dot" id="statusDot"></div><div class="name">js<span>recon</span></div></div>
    <div class="ws-meta">
      <div class="label">Workspace</div>
      <div class="ws-row">
        <select id="workspaceSelect"><option value="${escapeHtml(run.workspace || 'default')}">${escapeHtml(run.workspace || 'default')}</option></select>
        <button id="deleteWorkspaceBtn" title="Delete this workspace">🗑</button>
      </div>
      <div class="sub" id="wsRun">run: ${escapeHtml(run.runId || '-')}</div>
      <div class="sub" id="wsTimestamp">${escapeHtml(run.timestamp || '')}</div>
      <div class="sub" id="targetCount">${(run.targets || []).length} target(s) scanned</div>
    </div>
    <nav id="nav"></nav>
    <div class="sidebar-footer" id="sidebarFooter">Local scan · no data leaves this machine</div>
  </aside>

  <main>
    <div class="topbar">
      <div>
        <h1 id="sectionTitle">Overview</h1>
        <div class="desc" id="sectionDesc"></div>
      </div>
      <div class="controls">
        <input type="text" id="search" placeholder="Search value, file, snippet, note...">
        <select id="severityFilter"><option value="">All severities</option>${severities.map(s => `<option value="${s}">${s}</option>`).join('')}</select>
        <label class="toggle-label"><input type="checkbox" id="newOnlyFilter"> New only</label>
        <label class="toggle-label"><input type="checkbox" id="showSuppressedFilter"> Show suppressed</label>
      </div>
    </div>
    <div class="content" id="content"></div>
  </main>
</div>

<div class="viewer-overlay" id="viewerOverlay">
  <div class="viewer-panel">
    <div class="viewer-header">
      <div class="viewer-title" id="viewerTitle">File</div>
      <div class="viewer-header-actions">
        <span class="viewer-source-note" id="viewerSourceNote"></span>
        <button type="button" class="btn secondary" id="viewerBeautifyBtn" style="display:none">Beautify</button>
        <button type="button" class="btn secondary" id="viewerCopyBtn">Copy full file</button>
        <button type="button" class="viewer-close" id="viewerCloseBtn" aria-label="Close">&times;</button>
      </div>
    </div>
    <div class="viewer-body" id="viewerBody"></div>
  </div>
</div>

<script>
let DATA = ${dataJson};
let TARGETS = ${targetsJson};
let CURRENT_WORKSPACE = ${JSON.stringify(run.workspace || 'default')};
const DEFAULT_CHECKS = ${checksJson};
const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

// Stable per-finding index so the "Copy code" button can find its own
// finding's full context back on DATA, independent of whatever filtered/
// grouped/re-sorted array a table row happens to be rendered from.
function tagIndices(arr) { arr.forEach((f, i) => { f.__idx = i; }); return arr; }
tagIndices(DATA);

// Served via \`jsrecon --ui --serve\` (http://) vs opened as a plain file
// (file://) — only the served case has a backend that can run new scans.
const SERVED = location.protocol.indexOf('http') === 0;

const RECON_FIELD_LABELS = {
  'email': 'Emails', 'ipv4': 'IPs', 'domain': 'Domains', 'url': 'URLs',
  'social-url': 'Social URLs', 'api-path': 'API Paths', 'aws-s3-bucket': 'S3 Buckets',
  'port-url': 'Host:Port', 'gql-query': 'GraphQL Queries', 'gql-mutation': 'GraphQL Mutations',
  'gql-fragment': 'GraphQL Fragments', 'npm-package': 'npm Packages', 'param': 'URL Params',
};

const SECTIONS = [
  { id: 'overview',   label: 'Overview',     ic: '&#9673;', match: null,
    desc: 'Summary across every finding in this run.' },
  { id: 'issues',     label: 'Issues',       ic: '&#9888;', match: f => f.severity === 'high' || f.severity === 'medium',
    desc: 'Medium and high severity findings worth a manual look.' },
  { id: 'postmessage',label: 'PostMessage',  ic: '&#8644;', match: f => f.type.startsWith('postmessage'),
    desc: 'window.postMessage senders and message-event listeners.' },
  { id: 'sourcemap',  label: 'Source Maps',  ic: '&#9636;', match: f => f.type.startsWith('sourcemap'),
    desc: 'sourceMappingURL references and any source paths they expose.' },
  { id: 'secrets',    label: 'Secrets',      ic: '&#128273;', match: f => f.type.startsWith('secret-'),
    desc: 'Likely API keys, tokens and credentials found in the code.' },
  { id: 'recon',      label: 'Recon Data',   ic: '&#128269;', match: f => f.type.startsWith('recon-'),
    desc: 'Extracted data, grouped by field — pick a chip below to isolate one kind (e.g. just API paths, or just host:port references).' },
  { id: 'assets',     label: 'Assets',       ic: '&#128193;', match: 'assets',
    desc: 'Every file / URL scanned in this run.' },
];

let currentSection = 'overview';
let reconFieldFilter = '';
// Which single asset (exact scanned target) to isolate — '' shows every
// asset's findings, grouped and separated rather than blended into one list.
let assetFilter = '';
try {
  const saved = localStorage.getItem('jsrecon:lastSection');
  if (saved && SECTIONS.some(s => s.id === saved)) currentSection = saved;
} catch (e) { /* private browsing etc — ignore */ }

/** Same new-only / show-suppressed filtering render() applies to the table,
 *  reused here so the sidebar's per-tab count always matches what you'd
 *  actually see clicking into that tab — previously this counted every raw
 *  finding regardless of triage state, so a tab kept showing its original
 *  total (e.g. "Secrets 20") even after every one of them was marked as a
 *  false positive and hidden from the list. */
function visibleForCounting(rows) {
  const newOnlyEl = document.getElementById('newOnlyFilter');
  const showSuppressedEl = document.getElementById('showSuppressedFilter');
  if (newOnlyEl && newOnlyEl.checked) rows = rows.filter(f => f.isNew);
  if (!showSuppressedEl || !showSuppressedEl.checked) {
    rows = rows.filter(f => !(f.triage && f.triage.status === 'false-positive'));
  }
  return rows;
}

function countFor(section) {
  if (section.id === 'assets') return TARGETS.length;
  const rows = section.match ? DATA.filter(section.match) : DATA.slice();
  return visibleForCounting(rows).length;
}

function renderNav() {
  const nav = document.getElementById('nav');
  let html = '';
  SECTIONS.forEach((s, i) => {
    if (i === 1) html += '<div class="navgroup-label">Findings</div>';
    if (i === 6) html += '<div class="navgroup-label">Scope</div>';
    html += \`<div class="navitem \${s.id === currentSection ? 'active' : ''}" data-id="\${s.id}">
      <span><span class="ic">\${s.ic}</span>\${s.label}</span>
      <span class="count">\${countFor(s)}</span>
    </div>\`;
  });
  nav.innerHTML = html;
  nav.querySelectorAll('.navitem').forEach(el => {
    el.addEventListener('click', () => {
      currentSection = el.dataset.id;
      reconFieldFilter = '';
      assetFilter = '';
      try { localStorage.setItem('jsrecon:lastSection', currentSection); } catch (e) {}
      render();
    });
  });
}

function escapeHtmlJs(s) {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

/**
 * Turns a finding's file/line/column into a clickable link that jumps
 * straight to that spot:
 *  - local file → a vscode://file/<path>:<line>:<col> deep link (opens VS
 *    Code at the exact line, if it's installed and registered for that URI
 *    scheme — the common case for a dev machine).
 *  - remote URL → the URL itself with a Chrome/Edge "text fragment"
 *    (#:~:text=...) built from the match snippet, so the browser scrolls to
 *    and highlights the matched code when it opens the file.
 * Falls back to plain (non-clickable) text when there's nothing to link to.
 */
function buildLocationCell(f) {
  const loc = (f.file || '') + (f.line ? ':' + f.line : '') + (f.column != null ? ':' + f.column : '');
  if (!f.file) return '<span class="file">' + escapeHtmlJs(loc) + '</span>';

  const isUrl = /^https?:\\/\\//i.test(f.file);
  let href = null, title = '';

  if (isUrl) {
    let text = (f.snippet || '').replace(/^…/, '').replace(/…$/, '').trim();
    if (text.length > 120) text = text.slice(0, 120);
    if (text) {
      href = f.file + '#:~:text=' + encodeURIComponent(text);
      title = 'Opens the file in a new tab and jumps to/highlights this text (Chrome/Edge support text fragments; other browsers just open the file).';
    } else {
      href = f.file;
      title = 'Opens the file in a new tab.';
    }
  } else if (f.line) {
    const col = (f.column != null ? f.column : 0) + 1;
    href = 'vscode://file/' + encodeURI(f.file) + ':' + f.line + ':' + col;
    title = 'Opens in VS Code at this exact line (requires VS Code installed and the vscode:// handler registered).';
  }

  // Primary, always-reliable way to get to the exact line: an in-dashboard
  // viewer that fetches the full file (from the scan-time snapshot, or a
  // fresh read as a fallback) and scrolls straight to it, highlighted — no
  // editor, no external site, no browser text-fragment support required.
  const viewerBtn = (SERVED && f.line != null)
    ? '<button type="button" class="btn secondary open-in-viewer-btn" data-idx="' + f.__idx + '">Jump to line</button>'
    : '';

  const locHtml = href
    ? '<a class="file loclink" target="_blank" rel="noopener noreferrer" href="' + href.replace(/"/g, '&quot;') + '" title="' + title.replace(/"/g, '&quot;') + '">' + escapeHtmlJs(loc) + '</a>'
    : '<span class="file">' + escapeHtmlJs(loc) + '</span>';

  return locHtml + viewerBtn;
}

/** Escapes code for display, wrapping the exact matched substring (when known)
 *  in <mark> so the dangerous part jumps out inside a long handler body. */
function escapeForContext(text, matchOffset, matchLen) {
  if (matchOffset == null || !matchLen) return escapeHtmlJs(text);
  const before = escapeHtmlJs(text.slice(0, matchOffset));
  const match = escapeHtmlJs(text.slice(matchOffset, matchOffset + matchLen));
  const after = escapeHtmlJs(text.slice(matchOffset + matchLen));
  return before + '<mark>' + match + '</mark>' + after;
}

/**
 * The whole point of this block: put the actual code being flagged directly
 * in the dashboard, expandable in place, with a one-click copy — so tracing
 * a postmessage (or any) finding back to real code never depends on an
 * external editor, a live re-fetch of a remote bundle, or a browser feature
 * that may not be available.
 */
function buildContextBlock(f) {
  if (!f.context) return '';
  const html = escapeForContext(f.context, f.contextMatchOffset, f.contextMatchLen);
  const lineCount = f.context.split('\\n').length;
  const startNote = f.contextLine ? ', starts at line ' + f.contextLine : '';
  return '<details class="ctx">' +
    '<summary>Show code (' + lineCount + (lineCount === 1 ? ' line' : ' lines') + startNote + ')</summary>' +
    '<div class="ctx-toolbar"><button type="button" class="btn secondary copy-ctx-btn" data-idx="' + f.__idx + '">Copy code</button>' +
    '<span class="copy-status" data-idx-status="' + f.__idx + '"></span></div>' +
    '<pre class="ctx-code"><code>' + html + '</code></pre>' +
  '</details>';
}

/** Clipboard write with a document.execCommand fallback for contexts (e.g.
 *  a dashboard opened as a plain file://) where the async Clipboard API
 *  isn't available. */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e2) {
      return false;
    }
  }
}

let viewerLastFocused = null;

// --- Beautifier (lib/beautify.js, inlined) -----------------------------
// Dependency-free JS "unminifier" for the jump-to-line viewer below. Never
// rewrites token text, only whitespace between tokens, so an original
// offset can be mapped forward into the beautified output (mapOffset) and
// the flagged line/column re-highlighted correctly after reformatting.
/**
 * Lightweight, dependency-free JS "unminifier" for the jump-to-line viewer.
 * It never rewrites token text — only inserts/removes whitespace between
 * tokens — so every original character offset can be mapped forward to an
 * offset in the beautified output, which is what lets the flagged line be
 * re-highlighted correctly after reformatting. Not a full pretty-printer
 * (no real parser), just heuristics good enough to turn a wall of minified
 * JS into something a human can visually scan.
 */

const MULTI_CHAR_OPS = [
  '>>>=', '===', '!==', '**=', '...', '>>>', '<<=', '>>=', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
];

const REGEX_ALLOWED_WORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await',
]);

const SPACE_BOTH_SIDES_OPS = new Set([
  '=', '==', '===', '!=', '!==', '<=', '>=', '&&', '||', '??',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**=', '>>>=', '<<=', '>>=',
  '&&=', '||=', '??=', '**', '<<', '>>', '>>>', '=>',
  '+', '-', '*', '/', '%', '<', '>', '&', '|', '^', '?',
]);

const CONTROL_KEYWORDS_SPACE_BEFORE_PAREN = new Set(['if', 'for', 'while', 'switch', 'catch']);

function tokenize(src) {
  const n = src.length;
  let i = 0;
  const tokens = [];
  const isIdentStart = (c) => /[A-Za-z_$]/.test(c);
  const isIdentPart = (c) => /[A-Za-z0-9_$]/.test(c);
  const isDigit = (c) => c >= '0' && c <= '9';

  function prevTok() {
    return tokens.length ? tokens[tokens.length - 1] : null;
  }

  while (i < n) {
    const c = src[i];

    if (c === ' ' || c === '\\t' || c === '\\r' || c === '\\n' || c === '\\f' || c === '\\v') {
      i++;
      continue;
    }

    if (c === '/' && src[i + 1] === '/') {
      const start = i;
      i += 2;
      while (i < n && src[i] !== '\\n') i++;
      tokens.push({ type: 'linecomment', start, end: i });
      continue;
    }

    if (c === '/' && src[i + 1] === '*') {
      const start = i;
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i = Math.min(n, i + 2);
      tokens.push({ type: 'blockcomment', start, end: i });
      continue;
    }

    if (c === '"' || c === "'") {
      const q = c;
      const start = i;
      i++;
      while (i < n && src[i] !== q) {
        if (src[i] === '\\\\') i++;
        i++;
      }
      i = Math.min(n, i + 1);
      tokens.push({ type: 'string', start, end: i });
      continue;
    }

    if (c === '\`') {
      const start = i;
      i++;
      let depth = 0;
      while (i < n) {
        if (src[i] === '\\\\') { i += 2; continue; }
        if (src[i] === '\`' && depth === 0) { i++; break; }
        if (src[i] === '$' && src[i + 1] === '{') { depth++; i += 2; continue; }
        if (src[i] === '}' && depth > 0) { depth--; i++; continue; }
        i++;
      }
      tokens.push({ type: 'template', start, end: i });
      continue;
    }

    if (c === '/') {
      const prev = prevTok();
      const prevText = prev ? src.slice(prev.start, prev.end) : '';
      const regexAllowed = !prev
        || ['brace-open', 'paren-open', 'op', 'comma', 'semi', 'colon'].includes(prev.type)
        || (prev.type === 'word' && REGEX_ALLOWED_WORDS.has(prevText));
      if (regexAllowed) {
        const start = i;
        let j = i + 1;
        let inClass = false;
        let ok = false;
        while (j < n) {
          const ch = src[j];
          if (ch === '\\\\') { j += 2; continue; }
          if (ch === '[') { inClass = true; j++; continue; }
          if (ch === ']') { inClass = false; j++; continue; }
          if (ch === '\\n') { ok = false; break; }
          if (ch === '/' && !inClass) { j++; ok = true; break; }
          j++;
        }
        if (ok) {
          while (j < n && /[a-z]/i.test(src[j])) j++;
          tokens.push({ type: 'regex', start, end: j });
          i = j;
          continue;
        }
        // fell through: not actually a regex (unterminated) — treat '/' as an operator below
      }
    }

    if (isIdentStart(c)) {
      const start = i;
      i++;
      while (i < n && isIdentPart(src[i])) i++;
      tokens.push({ type: 'word', start, end: i });
      continue;
    }

    if (isDigit(c) || (c === '.' && isDigit(src[i + 1]))) {
      const start = i;
      i++;
      while (i < n && /[0-9a-fA-Fxobn.]/.test(src[i])) i++;
      // trailing exponent, e.g. 1e10, 1e-10, 1.5e+3
      if (src[i] === 'e' || src[i] === 'E') {
        i++;
        if (src[i] === '+' || src[i] === '-') i++;
        while (i < n && isDigit(src[i])) i++;
      }
      tokens.push({ type: 'number', start, end: i });
      continue;
    }

    // punctuation / operators — longest match wins
    let matched = null;
    for (const op of MULTI_CHAR_OPS) {
      if (src.startsWith(op, i)) { matched = op; break; }
    }
    const start = i;
    i += matched ? matched.length : 1;
    const text = src.slice(start, i);
    let type = 'op';
    if (text === '{') type = 'brace-open';
    else if (text === '}') type = 'brace-close';
    else if (text === '(' || text === '[') type = 'paren-open';
    else if (text === ')' || text === ']') type = 'paren-close';
    else if (text === ';') type = 'semi';
    else if (text === ',') type = 'comma';
    else if (text === '.') type = 'dot';
    else if (text === ':') type = 'colon';
    tokens.push({ type, start, end: i });
  }

  return tokens;
}

/**
 * Renders tokens into readable, indented source. Returns the output text
 * plus a sorted list of { origStart, origEnd, outStart } spans — one per
 * token that was copied verbatim — used to map an original offset forward
 * into the beautified output.
 */
function beautifyRenderTokens(tokens, src) {
  let indent = 0;
  let parenDepth = 0;
  const forHeaderDepths = new Set();
  let pendingFor = false;
  const spans = [];

  // Building \`out\` with repeated string concatenation (or, worse, slicing
  // its tail to "fix up" whitespace already written) is O(n) per token on a
  // string that grows to the size of the whole file — O(n^2) overall, which
  // hangs on a real multi-hundred-KB bundle. Instead we push pieces onto an
  // array and track the output length ourselves; a pending newline is only
  // materialized (at whatever indent is current *then*) right before the
  // next real token, so nothing already pushed ever needs to be revisited.
  const parts = [];
  let outLen = 0;
  let pendingNewline = false; // a line break is owed before the next token
  let lastCharWasSpace = true; // true at start: no leading space needed

  const IND = () => '  '.repeat(Math.max(0, indent));
  const push = (s) => { if (!s) return; parts.push(s); outLen += s.length; lastCharWasSpace = s[s.length - 1] === ' ' || s[s.length - 1] === '\\n'; };
  const requestNewline = () => { pendingNewline = true; };
  const flushPending = () => {
    if (pendingNewline) {
      push('\\n' + IND());
      pendingNewline = false;
    }
  };

  let prev = null;
  for (let ti = 0; ti < tokens.length; ti++) {
    const tok = tokens[ti];
    const text = src.slice(tok.start, tok.end);
    const prevText = prev ? src.slice(prev.start, prev.end) : '';

    if (tok.type === 'brace-close') {
      indent = Math.max(0, indent - 1);
      requestNewline();
      flushPending();
    } else if (prev) {
      // Decide spacing before this token based on the previous one. Any
      // branch that wants a line break just requests one — flushed below
      // (at whatever indent is current right now) instead of writing it
      // immediately, so a run of several such requests in a row collapses
      // into exactly one break instead of stacking blank lines.
      let needSpace = false;
      if (prev.type === 'comma') needSpace = true;
      else if (prev.type === 'word' && ['word', 'number', 'string', 'template', 'regex'].includes(tok.type)) needSpace = true;
      else if (tok.type === 'brace-open') needSpace = true;
      else if (tok.type === 'op' && SPACE_BOTH_SIDES_OPS.has(text)) needSpace = true;
      else if (prev.type === 'op' && SPACE_BOTH_SIDES_OPS.has(prevText)) needSpace = true;
      else if (prev.type === 'colon') needSpace = true;
      else if (prev.type === 'word' && CONTROL_KEYWORDS_SPACE_BEFORE_PAREN.has(prevText) && tok.type === 'paren-open') needSpace = true;
      else if (prev.type === 'linecomment') { requestNewline(); }
      else if (prev.type === 'brace-close') {
        if (['else', 'catch', 'finally'].includes(text)) needSpace = true;
        else if (![')', ']', ',', ';', '.'].includes(text)) requestNewline();
      }

      flushPending();
      if (needSpace && !lastCharWasSpace) push(' ');
    } else {
      flushPending();
    }

    spans.push({ origStart: tok.start, origEnd: tok.end, outStart: outLen });
    push(text);

    if (tok.type === 'brace-open') {
      indent++;
      requestNewline();
    } else if (tok.type === 'semi') {
      if (forHeaderDepths.has(parenDepth)) push(' ');
      else requestNewline();
    } else if (tok.type === 'linecomment') {
      requestNewline();
    }

    if (tok.type === 'word') {
      pendingFor = text === 'for';
    } else if (tok.type !== 'paren-open') {
      pendingFor = false;
    }

    if (tok.type === 'paren-open' && text === '(') {
      parenDepth++;
      if (pendingFor) { forHeaderDepths.add(parenDepth); pendingFor = false; }
    } else if (tok.type === 'paren-close' && text === ')') {
      forHeaderDepths.delete(parenDepth);
      parenDepth = Math.max(0, parenDepth - 1);
    }

    prev = tok;
  }

  const out = parts.join('');

  return { text: out, spans };
}

/**
 * Beautifies \`src\` and returns { text, mapOffset(origOffset) }.
 * mapOffset finds the verbatim token span containing (or nearest to)
 * origOffset and returns the corresponding offset in the beautified text.
 */
function beautifyJs(src) {
  const tokens = tokenize(src);
  const { text, spans } = beautifyRenderTokens(tokens, src);

  function mapOffset(origOffset) {
    if (!spans.length) return 0;
    // Binary search for the last span whose origStart <= origOffset.
    let lo = 0, hi = spans.length - 1, ans = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (spans[mid].origStart <= origOffset) { ans = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    const span = spans[ans];
    const within = Math.max(0, Math.min(origOffset - span.origStart, span.origEnd - span.origStart));
    return span.outStart + within;
  }

  return { text, mapOffset };
}
// --- end inlined beautifier ---------------------------------------------

/**
 * The one-click, no-hassle path from a finding to the exact code it's
 * about: fetches the full scanned file (server-cached snapshot from scan
 * time, or a fresh read/re-fetch), renders it with line numbers, and
 * scrolls straight to the flagged line with it highlighted — entirely
 * inside the dashboard, so it works the same for a local file or a remote
 * bundle, with no editor URI handler or browser text-fragment support
 * required.
 */
// Files above this size auto-open in raw mode instead of eagerly running the
// beautifier (which is O(n) but still a real chunk of synchronous main-thread
// work on a multi-MB bundle) — still one click away via the toggle.
const AUTO_BEAUTIFY_MAX_CHARS = 1500000;

let viewerRawContent = null;
let viewerFinding = null;
let viewerBeautified = null; // { text, mapOffset } | null (lazily computed)
let viewerBeautifyOn = false;
let viewerBeautifyFailed = false;

function computeOffset(content, line, col) {
  if (line == null) return null;
  const lines = content.split('\\n');
  let offset = 0;
  for (let i = 0; i < line - 1 && i < lines.length; i++) offset += lines[i].length + 1;
  return offset + (col || 0);
}

function offsetToLineCol(content, offset) {
  const before = content.slice(0, Math.max(0, offset));
  const lastNl = before.lastIndexOf('\\n');
  const nlCount = lastNl === -1 ? 0 : before.split('\\n').length - 1;
  return { line: nlCount + 1, col: before.length - (lastNl + 1) };
}

/** (Re)renders the viewer body from either the raw or beautified text,
 *  re-mapping the flagged line/column into whichever one is showing. */
function renderViewerContent() {
  const f = viewerFinding;
  const bodyEl = document.getElementById('viewerBody');
  const beautifyBtn = document.getElementById('viewerBeautifyBtn');
  const noteEl = document.getElementById('viewerSourceNote');
  if (!f || viewerRawContent == null) return;

  let content = viewerRawContent;
  let hitLine = f.line || 0;
  let hitCol = f.column;
  viewerBeautifyFailed = false;

  if (viewerBeautifyOn) {
    try {
      if (!viewerBeautified) viewerBeautified = beautifyJs(viewerRawContent);
      content = viewerBeautified.text;
      if (f.line != null) {
        const origOffset = computeOffset(viewerRawContent, f.line, f.column || 0);
        const outOffset = viewerBeautified.mapOffset(origOffset);
        const lc = offsetToLineCol(content, outOffset);
        hitLine = lc.line;
        hitCol = lc.col;
      }
    } catch (e) {
      // Beautifying is a best-effort heuristic over arbitrary (possibly
      // adversarial-looking, obfuscated) JS — never let it take the viewer
      // down. Fall back to the raw file, which always renders.
      viewerBeautifyFailed = true;
      content = viewerRawContent;
      hitLine = f.line || 0;
      hitCol = f.column;
    }
  }

  if (beautifyBtn) {
    beautifyBtn.textContent = viewerBeautifyOn ? 'Show raw' : 'Beautify';
    beautifyBtn.disabled = false;
  }
  if (noteEl && viewerBeautifyFailed) {
    noteEl.textContent = (noteEl.textContent || '').replace(/ — beautified$/, '') + ' — beautify failed on this file, showing raw';
  } else if (noteEl) {
    const base = (noteEl.dataset.base || noteEl.textContent || '');
    noteEl.dataset.base = base.replace(/ — beautified$/, '');
    noteEl.textContent = noteEl.dataset.base + (viewerBeautifyOn ? ' — beautified' : '');
  }

  const lines = content.split('\\n');
  // Best available highlight width at this exact column: the finding's own
  // literal value (recon/secrets), the dangerous-sink's exact match length
  // (postmessage), or a reasonable default so *something* is highlighted.
  // Beautifying only inserts/removes whitespace BETWEEN tokens, never inside
  // one, so a match that lands wholly inside a single token (a string value,
  // an identifier) still highlights the same text after reformatting; a
  // match that happened to span a token boundary may drift slightly.
  const matchLen = (f.value && f.value.length) || f.contextMatchLen || 40;

  const html = lines.map((lineText, i) => {
    const lineNo = i + 1;
    const isHit = lineNo === hitLine;
    let contentHtml;
    if (isHit && hitCol != null) {
      const before = lineText.slice(0, hitCol);
      const match = lineText.slice(hitCol, hitCol + matchLen);
      const after = lineText.slice(hitCol + matchLen);
      contentHtml = escapeHtmlJs(before) + '<mark>' + escapeHtmlJs(match) + '</mark>' + escapeHtmlJs(after);
    } else {
      contentHtml = escapeHtmlJs(lineText);
    }
    return '<div class="vline' + (isHit ? ' vline-hit' : '') + '" data-line="' + lineNo + '">' +
      '<span class="vline-no">' + lineNo + '</span>' +
      '<span class="vline-content">' + (contentHtml || ' ') + '</span>' +
      '</div>';
  }).join('');

  bodyEl.innerHTML = html || '<div class="viewer-error">(empty file)</div>';

  const hitEl = bodyEl.querySelector('.vline-hit mark') || bodyEl.querySelector('.vline-hit');
  if (hitEl) hitEl.scrollIntoView({ block: 'center', inline: 'center' });
}

/**
 * The one-click, no-hassle path from a finding to the exact code it's
 * about: fetches the full scanned file (server-cached snapshot from scan
 * time, or a fresh read/re-fetch), renders it with line numbers, and
 * scrolls straight to the flagged line with it highlighted — entirely
 * inside the dashboard, so it works the same for a local file or a remote
 * bundle, with no editor URI handler or browser text-fragment support
 * required. Minified input is reformatted (see the inlined beautifier
 * above) so the flagged line reads as actual code instead of one of a
 * handful of multi-thousand-character lines.
 */
async function openFileViewer(f) {
  const overlay = document.getElementById('viewerOverlay');
  const titleEl = document.getElementById('viewerTitle');
  const bodyEl = document.getElementById('viewerBody');
  const noteEl = document.getElementById('viewerSourceNote');
  const copyBtn = document.getElementById('viewerCopyBtn');
  const beautifyBtn = document.getElementById('viewerBeautifyBtn');

  viewerLastFocused = document.activeElement;
  viewerFinding = f;
  viewerRawContent = null;
  viewerBeautified = null;
  titleEl.textContent = f.file + (f.line ? ':' + f.line : '') + (f.column != null ? ':' + f.column : '');
  noteEl.textContent = 'Loading…';
  noteEl.dataset.base = '';
  copyBtn.style.display = 'none';
  if (beautifyBtn) beautifyBtn.style.display = 'none';
  bodyEl.innerHTML = '<div class="viewer-error">Loading file…</div>';
  overlay.classList.add('open');

  let data;
  try {
    const res = await fetch('/api/source?wksp=' + encodeURIComponent(CURRENT_WORKSPACE) + '&file=' + encodeURIComponent(f.file));
    data = await res.json();
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  } catch (e) {
    noteEl.textContent = '';
    bodyEl.innerHTML = '<div class="viewer-error">Could not load the file: ' + escapeHtmlJs(e.message) + '</div>';
    return;
  }

  const base = data.source === 'cache' ? 'snapshot from scan time' :
    data.source === 'live-refetch' ? 'freshly re-fetched (no cached snapshot for this run)' :
    data.source === 'live-read' ? 'freshly re-read from disk (no cached snapshot for this run)' : '';
  noteEl.dataset.base = base + (data.truncated ? ' — truncated to 3MB for display' : '');
  noteEl.textContent = noteEl.dataset.base;

  copyBtn.style.display = '';
  copyBtn.onclick = async () => {
    const ok = await copyText(viewerBeautifyOn && viewerBeautified ? viewerBeautified.text : data.content);
    copyBtn.textContent = ok ? 'Copied!' : 'Copy failed';
    setTimeout(() => { copyBtn.textContent = 'Copy full file'; }, 1500);
  };

  viewerRawContent = data.content;
  viewerBeautifyOn = data.content.length > 0 && data.content.length <= AUTO_BEAUTIFY_MAX_CHARS;

  if (beautifyBtn) {
    beautifyBtn.style.display = '';
    beautifyBtn.disabled = false;
    beautifyBtn.title = data.content.length > AUTO_BEAUTIFY_MAX_CHARS
      ? 'Large file (' + Math.round(data.content.length / 1024) + ' KB) — beautify on demand, may take a moment'
      : '';
  }

  renderViewerContent();
}

function closeFileViewer() {
  document.getElementById('viewerOverlay').classList.remove('open');
  document.getElementById('viewerBody').innerHTML = '';
  viewerRawContent = null;
  viewerFinding = null;
  viewerBeautified = null;
  if (viewerLastFocused && viewerLastFocused.focus) viewerLastFocused.focus();
}

document.getElementById('viewerBeautifyBtn').addEventListener('click', () => {
  const btn = document.getElementById('viewerBeautifyBtn');
  viewerBeautifyOn = !viewerBeautifyOn;
  // Beautifying a large file is real synchronous work — flip the label first
  // and defer a tick so the browser actually paints "Beautifying…" before
  // the main thread gets busy, instead of the click just looking stuck.
  if (viewerBeautifyOn && !viewerBeautified) {
    btn.disabled = true;
    btn.textContent = 'Beautifying…';
    setTimeout(renderViewerContent, 10);
  } else {
    renderViewerContent();
  }
});

document.getElementById('viewerCloseBtn').addEventListener('click', closeFileViewer);
document.getElementById('viewerOverlay').addEventListener('click', (e) => {
  if (e.target.id === 'viewerOverlay') closeFileViewer();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('viewerOverlay').classList.contains('open')) closeFileViewer();
});

function renderStats(rows) {
  const stats = { high:0, medium:0, low:0, info:0 };
  rows.forEach(f => stats[f.severity] = (stats[f.severity]||0) + 1);
  const total = rows.length || 1;
  const cards = ['high','medium','low','info'].map(k =>
    \`<div class="stat-card sev-\${k}"><div class="n">\${stats[k]}</div><div class="l">\${k}</div></div>\`
  ).join('') + \`<div class="stat-card sev-total"><div class="n">\${rows.length}</div><div class="l">total</div></div>\`;

  const bar = ['high','medium','low','info'].map(k =>
    stats[k] ? \`<div class="bar-seg \${k}" style="width:\${(stats[k]/total*100).toFixed(1)}%"></div>\` : ''
  ).join('');
  const legend = ['high','medium','low','info'].map(k =>
    \`<div class="li"><span class="sw \${k}"></span>\${k} (\${stats[k]})</div>\`
  ).join('');

  const newCount = rows.filter(f => f.isNew).length;
  const suppressedCount = rows.filter(f => f.triage && f.triage.status === 'false-positive').length;

  return \`<div class="stats-row">\${cards}</div>
    <div class="bar-wrap">
      <div class="bt">Severity distribution</div>
      <div class="bar-track">\${bar}</div>
      <div class="bar-legend">\${legend}</div>
      <div class="bar-legend" style="margin-top:6px">
        <div class="li"><span class="sw" style="background:#3fb950"></span>new since first seen (\${newCount})</div>
        <div class="li"><span class="sw" style="background:var(--muted)"></span>triaged false-positive (\${suppressedCount}\${suppressedCount ? ' — hidden, "Show suppressed" to view' : ''})</div>
      </div>
    </div>\`;
}

/** Recon Data gets its own chip row so recon-api-path / recon-port-url /
 *  recon-url etc. stay visibly separate instead of one undifferentiated list. */
function renderFieldChips(reconRows) {
  const counts = {};
  reconRows.forEach(f => { counts[f.field || f.type] = (counts[f.field || f.type] || 0) + 1; });
  const fields = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  if (!fields.length) return '';
  const allChip = \`<div class="chip \${reconFieldFilter === '' ? 'active' : ''}" data-field="">All fields <span class="n">\${reconRows.length}</span></div>\`;
  const chips = fields.map(f =>
    \`<div class="chip \${reconFieldFilter === f ? 'active' : ''}" data-field="\${escapeHtmlJs(f)}">\${escapeHtmlJs(RECON_FIELD_LABELS[f] || f)} <span class="n">\${counts[f]}</span></div>\`
  ).join('');
  return \`<div class="chip-row">\${allChip}\${chips}</div>\`;
}

/** Short, readable label for a scanned target: "host/basename.js" for a URL,
 *  just the basename for a local path (full path stays in the title attr). */
function shortAssetLabel(file) {
  if (!file) return '(unknown)';
  try {
    if (/^https?:\\/\\//i.test(file)) {
      const u = new URL(file);
      const base = u.pathname.split('/').filter(Boolean).pop() || '/';
      return u.host + '/' + base;
    }
  } catch (e) { /* not a valid URL — fall through to path handling */ }
  const parts = String(file).split(/[\\\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : file;
}

/** Every finding-listing section (not just Recon Data) gets an asset chip row
 *  whenever the current rows span more than one scanned target, so results
 *  from two different domains/files are never presented as one blended list —
 *  pick a chip to isolate just that asset's findings. */
function renderAssetChips(rows) {
  const counts = {};
  const order = [];
  rows.forEach(f => {
    const key = f.file || '(unknown)';
    if (!(key in counts)) { counts[key] = 0; order.push(key); }
    counts[key]++;
  });
  if (order.length < 2) return '';
  order.sort((a, b) => counts[b] - counts[a]);
  const allChip = \`<div class="chip asset-chip \${assetFilter === '' ? 'active' : ''}" data-asset="">All assets <span class="n">\${rows.length}</span></div>\`;
  const chips = order.map(key =>
    \`<div class="chip asset-chip \${assetFilter === key ? 'active' : ''}" data-asset="\${escapeHtmlJs(key)}" title="\${escapeHtmlJs(key)}">\${escapeHtmlJs(shortAssetLabel(key))} <span class="n">\${counts[key]}</span></div>\`
  ).join('');
  return \`<div class="chip-row asset-chip-row">\${allChip}\${chips}</div>\`;
}

/** Renders the actual <table> for one homogenous group of rows (no grouping logic). */
/** Small "Mark FP" / "Confirm" / "Clear" control row under a finding — only
 *  rendered when served (triage writes need the backend), reflects whatever
 *  triage decision (if any) is already on file for this exact value. */
function buildTriageRow(f) {
  if (!SERVED || f.__idx == null) return '';
  const idx = f.__idx;
  if (f.triage) {
    const noteHtml = f.triage.note ? '<span class="triage-note">— ' + escapeHtmlJs(f.triage.note) + '</span>' : '';
    return \`<div class="triage-row">
      <span class="triage-badge \${escapeHtmlJs(f.triage.status)}">\${escapeHtmlJs(f.triage.status)}</span>\${noteHtml}
      <button type="button" class="triage-btn" data-idx="\${idx}" data-status="clear">Clear</button>
    </div>\`;
  }
  return \`<div class="triage-row">
    <button type="button" class="triage-btn" data-idx="\${idx}" data-status="false-positive">Mark false positive</button>
    <button type="button" class="triage-btn" data-idx="\${idx}" data-status="confirmed">Confirm</button>
  </div>\`;
}

function renderPlainTable(rows) {
  return \`<table>
    <thead><tr><th>Severity</th><th>Type</th><th>File / Line:Col</th><th>Detail</th></tr></thead>
    <tbody>\${rows.map(f => \`
      <tr class="\${f.triage && f.triage.status === 'false-positive' ? 'suppressed-row' : ''}">
        <td><span class="badge \${f.severity}">\${f.severity}</span></td>
        <td>\${f.type}</td>
        <td>\${buildLocationCell(f)}</td>
        <td>
          \${f.isNew ? '<span class="new-badge">New</span>' : ''}
          \${f.field === 'api-path' ? '<span class="method-badge' + (f.method ? '' : ' none') + '">' + escapeHtmlJs(f.method || 'Not defined') + '</span>' : ''}
          \${f.value ? '<div class="val">' + escapeHtmlJs(f.value) + '</div>' : ''}
          \${!f.value && f.snippet ? '<div class="val">' + escapeHtmlJs(f.snippet) + '</div>' : ''}
          \${f.note ? '<div class="note">' + escapeHtmlJs(f.note) + '</div>' : ''}
          \${(f.seenInOtherFiles && f.seenInOtherFiles.length) ? '<div class="corr-note">Also found in ' + (f.seenInFileCount - 1) + ' other file(s): ' + f.seenInOtherFiles.slice(0, 5).map(escapeHtmlJs).join(', ') + (f.seenInOtherFiles.length > 5 ? ', ...' : '') + '</div>' : ''}
          \${(f.seenInOtherWorkspaces && f.seenInOtherWorkspaces.length) ? '<div class="corr-note cross-ws">Also found in ' + f.seenInWorkspaceCount + ' other workspace(s): ' + f.seenInOtherWorkspaces.map(w => escapeHtmlJs(w.workspace) + ' (' + w.files.length + ' file' + (w.files.length > 1 ? 's' : '') + ')').join(', ') + '</div>' : ''}
          \${(f.sources && f.sources.length) ? '<ul class="sources">' + f.sources.slice(0,15).map(s => '<li>' + escapeHtmlJs(s) + '</li>').join('') + (f.sources.length > 15 ? '<li>...and ' + (f.sources.length-15) + ' more</li>' : '') + '</ul>' : ''}
          \${buildContextBlock(f)}
          \${buildTriageRow(f)}
        </td>
      </tr>\`).join('')}
    </tbody>
  </table>\`;
}

/**
 * Splits findings into one table per scanned target (asset) whenever more
 * than one target is present, with a header naming that asset and how many
 * findings it has — this is what stops two domains' results from reading as
 * a single undifferentiated pile. Falls back to one plain table when the
 * current view already covers just a single asset.
 */
function renderTable(rows) {
  if (!rows.length) return '<div id="empty" style="display:block">No findings match the current filters.</div>';

  const byAsset = {};
  const order = [];
  rows.forEach(f => {
    const key = f.file || '(unknown)';
    if (!byAsset[key]) { byAsset[key] = []; order.push(key); }
    byAsset[key].push(f);
  });

  if (order.length < 2) return renderPlainTable(rows);

  // Keep groups in scan order (matches the Assets tab) rather than alphabetical.
  order.sort((a, b) => {
    const ia = TARGETS.indexOf(a), ib = TARGETS.indexOf(b);
    if (ia === -1 && ib === -1) return 0;
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });

  return order.map(key => \`
    <div class="asset-group">
      <div class="asset-group-header">
        <span class="agh-name" title="\${escapeHtmlJs(key)}">\${escapeHtmlJs(shortAssetLabel(key))} &mdash; \${escapeHtmlJs(key)}</span>
        <span class="agh-count">\${byAsset[key].length} finding(s)</span>
      </div>
      \${renderPlainTable(byAsset[key])}
    </div>\`
  ).join('');
}

function renderAddAssetForm() {
  if (!SERVED) {
    return \`<div class="add-asset">
      <div class="t">Add a JS file or URL</div>
      <div class="offline-note">This dashboard was opened as a static file, so it can't run new scans itself.
        Start it with <code>jsrecon --ui --serve</code> instead to add files/URLs here, or scan them from the
        command line with <code>jsrecon -u &lt;file-or-url&gt; -wksp ${escapeHtml(run.workspace || 'default')}</code>.</div>
    </div>\`;
  }
  const checkBoxes = ['postmessage','sourcemap','recon','secrets'].map(c =>
    \`<label><input type="checkbox" value="\${c}" \${DEFAULT_CHECKS.includes(c) ? 'checked' : ''}> \${c}</label>\`
  ).join('');
  return \`<div class="add-asset">
    <div class="t">Add JS file(s) or URL(s) to scan</div>
    <div class="d">One local path or http(s) URL per line. Runs the same analyzers as the CLI.</div>
    <textarea id="assetInput" placeholder="./downloaded/new-bundle.js&#10;https://target.example.com/main.js"></textarea>
    <div class="row" id="assetListFileRow">
      <label class="btn secondary" for="assetListFile" style="cursor:pointer;">Load .txt list file</label>
      <input type="file" id="assetListFile" accept=".txt,text/plain" style="display:none;">
      <span class="d" style="margin:0;">Same format as the box above — mixed local paths and http(s) URLs, one per line; lines get appended.</span>
    </div>
    <div class="row">
      <div class="checks">\${checkBoxes}</div>
    </div>
    <div class="row" id="assetWsRow">
      <label for="assetWorkspace" style="font-size:12px;color:var(--muted);">Save into workspace</label>
      <select id="assetWorkspace"><option value="\${escapeHtmlJs(CURRENT_WORKSPACE)}">\${escapeHtmlJs(CURRENT_WORKSPACE)} (current)</option><option value="__new__">+ Create new workspace...</option></select>
      <input type="text" id="assetWorkspaceNew" placeholder="new-workspace-name" style="display:none;">
    </div>
    <div class="row">
      <button class="btn" id="scanBtn">Scan &amp; add</button>
      <button class="btn secondary" id="clearBtn" type="button">Clear</button>
    </div>
    <div class="status" id="scanStatus"></div>
  </div>\`;
}

const WORKSPACE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function wireAddAssetForm() {
  if (!SERVED) return;
  const btn = document.getElementById('scanBtn');
  const clearBtn = document.getElementById('clearBtn');
  const textarea = document.getElementById('assetInput');
  const status = document.getElementById('scanStatus');
  const wsSelect = document.getElementById('assetWorkspace');
  const wsNewInput = document.getElementById('assetWorkspaceNew');
  if (!btn) return;

  // Offer every known workspace, not just the current one, so a scan can be
  // filed straight into an existing project without creating a duplicate.
  fetch('/api/workspaces').then(r => r.json()).then(body => {
    if (!body.workspaces || !wsSelect) return;
    const createOpt = wsSelect.querySelector('option[value="__new__"]');
    body.workspaces.filter(n => n !== CURRENT_WORKSPACE).sort().forEach(n => {
      const opt = document.createElement('option');
      opt.value = n;
      opt.textContent = n;
      wsSelect.insertBefore(opt, createOpt);
    });
  }).catch(() => {});

  wsSelect.addEventListener('change', () => {
    wsNewInput.style.display = wsSelect.value === '__new__' ? '' : 'none';
    if (wsSelect.value === '__new__') wsNewInput.focus();
  });

  clearBtn.addEventListener('click', () => { textarea.value = ''; status.textContent = ''; status.className = 'status'; });

  const listFileInput = document.getElementById('assetListFile');
  if (listFileInput) {
    listFileInput.addEventListener('change', () => {
      const file = listFileInput.files && listFileInput.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        // Same parsing rule as the CLI's -u/-f list files: one target per
        // line, blank lines and #-comments dropped, mixed local paths and
        // http(s) URLs are both fine.
        const lines = String(reader.result || '')
          .split(/\\r?\\n/)
          .map(s => s.trim())
          .filter(Boolean)
          .filter(s => !s.startsWith('#'));
        if (!lines.length) {
          status.textContent = 'That file had no usable lines (blank, or all comments).';
          status.className = 'status err';
          listFileInput.value = '';
          return;
        }
        const existing = textarea.value.split('\\n').map(s => s.trim()).filter(Boolean);
        const merged = existing.concat(lines.filter(l => !existing.includes(l)));
        textarea.value = merged.join('\\n');
        status.textContent = 'Loaded ' + lines.length + ' target(s) from ' + file.name + '.';
        status.className = 'status ok';
        listFileInput.value = ''; // allow re-selecting the same file later
      };
      reader.onerror = () => {
        status.textContent = 'Could not read ' + file.name + '.';
        status.className = 'status err';
      };
      reader.readAsText(file);
    });
  }

  btn.addEventListener('click', async () => {
    const targets = textarea.value.split('\\n').map(s => s.trim()).filter(Boolean);
    if (!targets.length) { status.textContent = 'Enter at least one file path or URL.'; status.className = 'status err'; return; }
    const checks = Array.from(document.querySelectorAll('.add-asset .checks input:checked')).map(el => el.value);

    let workspace = wsSelect.value;
    if (workspace === '__new__') {
      workspace = wsNewInput.value.trim();
      if (!WORKSPACE_NAME_RE.test(workspace)) {
        status.textContent = 'New workspace name may only contain letters, numbers, dot, dash, underscore.';
        status.className = 'status err';
        return;
      }
    }

    btn.disabled = true;
    status.textContent = 'Scanning ' + targets.length + ' target(s) into workspace "' + workspace + '"...';
    status.className = 'status';
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets, checks, workspace }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
      status.textContent = 'Scanned ' + body.scanned + ' target(s), ' + body.findingCount + ' finding(s)' + (body.errors ? ', ' + body.errors + ' error(s)' : '') + '. Switching to "' + body.workspace + '"...';
      status.className = 'status ok';
      await loadWorkspaceList();
      // Stay on the Assets tab so the newly scanned target is visible right
      // away, instead of bouncing the viewer back to Overview.
      await switchWorkspace(body.workspace, { keepSelection: true });
      textarea.value = '';
    } catch (e) {
      status.textContent = 'Scan failed: ' + e.message;
      status.className = 'status err';
    } finally {
      btn.disabled = false;
    }
  });
}

/** Pulls the latest run for the CURRENT workspace from the server, without a full page reload. */
async function refreshFromServer() {
  return switchWorkspace(CURRENT_WORKSPACE, { keepSelection: true });
}

/**
 * Switches the dashboard to another local workspace (or reloads the current
 * one) by fetching that workspace's merged 'all' run from the server and
 * re-rendering in place. This is what makes a scan kicked off from the
 * Assets tab actually reachable afterwards, instead of leaving the viewer
 * stuck on whatever workspace the server happened to start in.
 */
async function switchWorkspace(name, opts) {
  opts = opts || {};
  try {
    const res = await fetch('/api/run?wksp=' + encodeURIComponent(name) + '&run=all');
    const run = await res.json();
    DATA = tagIndices(run.findings || []);
    TARGETS = run.targets || [];
    CURRENT_WORKSPACE = name;
    const sel = document.getElementById('workspaceSelect');
    if (sel && sel.value !== name) sel.value = name;
    const wsRun = document.getElementById('wsRun');
    const wsTs = document.getElementById('wsTimestamp');
    if (wsRun) wsRun.textContent = 'run: ' + (run.runId || '-');
    if (wsTs) wsTs.textContent = run.timestamp || '';
    document.getElementById('targetCount').textContent = TARGETS.length + ' target(s) scanned';
    if (!opts.keepSelection) {
      currentSection = 'overview';
      reconFieldFilter = '';
      assetFilter = '';
      try { localStorage.setItem('jsrecon:lastSection', currentSection); } catch (e) {}
    }
    render();
  } catch (e) {
    location.reload();
  }
}

/** Populates the workspace dropdown from the server; no-op when offline. */
async function loadWorkspaceList() {
  if (!SERVED) return;
  try {
    const res = await fetch('/api/workspaces');
    const body = await res.json();
    const sel = document.getElementById('workspaceSelect');
    if (!sel || !body.workspaces) return;
    const names = body.workspaces.slice().sort();
    sel.innerHTML = names.map(n =>
      '<option value="' + escapeHtmlJs(n) + '"' + (n === CURRENT_WORKSPACE ? ' selected' : '') + '>' + escapeHtmlJs(n) + '</option>'
    ).join('');
    if (!names.includes(CURRENT_WORKSPACE)) {
      const opt = document.createElement('option');
      opt.value = CURRENT_WORKSPACE;
      opt.textContent = CURRENT_WORKSPACE;
      opt.selected = true;
      sel.prepend(opt);
    }
  } catch (e) { /* leave the single static option in place */ }
}

/**
 * One card per scanned asset with its own severity breakdown right there —
 * so which domain/file has what, structurally, is visible without even
 * opening a findings tab — plus a "View findings" jump and a "Remove"
 * button (served mode only) to drop a mis-added or stale asset entirely.
 */
function renderAssets() {
  const form = renderAddAssetForm();
  if (!TARGETS.length) return form + '<div id="empty" style="display:block">No targets recorded for this run.</div>';
  const list = TARGETS.map(t => {
    const rows = visibleForCounting(DATA.filter(f => f.file === t));
    const bySev = { high: 0, medium: 0, low: 0, info: 0 };
    rows.forEach(f => { bySev[f.severity] = (bySev[f.severity] || 0) + 1; });
    const badges = ['high', 'medium', 'low', 'info']
      .filter(k => bySev[k] > 0)
      .map(k => \`<span class="sev-badge \${k}">\${bySev[k]} \${k}</span>\`)
      .join('');
    return \`<div class="asset-card">
      <div class="asset-card-main">
        <span class="asset-card-name" title="\${escapeHtmlJs(t)}">\${escapeHtmlJs(t)}</span>
        <div class="asset-card-badges">\${badges || '<span class="sev-badge none">no findings</span>'}</div>
      </div>
      <div class="asset-card-actions">
        <span class="n">\${rows.length} finding(s)</span>
        <button type="button" class="btn secondary view-asset-btn" data-asset="\${escapeHtmlJs(t)}">View findings</button>
        \${SERVED ? '<button type="button" class="btn danger remove-asset-btn" data-asset="' + escapeHtmlJs(t) + '">Remove</button>' : ''}
      </div>
    </div>\`;
  }).join('');
  return form + '<div class="asset-list">' + list + '</div>';
}

function wireAssetCardActions() {
  document.querySelectorAll('.view-asset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      // Overview shows every type/severity, unlike Issues (medium/high only)
      // — the right landing spot for "everything this one asset produced".
      assetFilter = btn.dataset.asset;
      currentSection = 'overview';
      try { localStorage.setItem('jsrecon:lastSection', currentSection); } catch (e) {}
      render();
    });
  });

  document.querySelectorAll('.remove-asset-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const target = btn.dataset.asset;
      if (!confirm('Remove "' + target + '" and all of its findings from this workspace? This cannot be undone.')) return;
      btn.disabled = true;
      btn.textContent = 'Removing...';
      try {
        const res = await fetch('/api/delete-asset', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace: CURRENT_WORKSPACE, target }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
        await switchWorkspace(CURRENT_WORKSPACE, { keepSelection: true });
      } catch (e) {
        alert('Could not remove asset: ' + e.message);
        btn.disabled = false;
        btn.textContent = 'Remove';
      }
    });
  });
}

function render() {
  const section = SECTIONS.find(s => s.id === currentSection);
  document.getElementById('sectionTitle').textContent = section.label;
  document.getElementById('sectionDesc').textContent = section.desc;
  document.getElementById('statusDot').className = SERVED ? 'dot' : 'dot offline';
  document.getElementById('sidebarFooter').textContent = SERVED
    ? 'Live · served locally · you can add new files under Assets'
    : 'Local scan · no data leaves this machine';
  const delWsBtn = document.getElementById('deleteWorkspaceBtn');
  if (delWsBtn) {
    delWsBtn.disabled = !SERVED;
    delWsBtn.title = SERVED ? 'Delete this workspace' : 'Delete workspace (requires --serve)';
  }

  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('severityFilter').value;

  const hideOnAssets = section.id === 'assets' ? 'none' : '';
  document.getElementById('search').style.display = hideOnAssets;
  document.getElementById('severityFilter').style.display = hideOnAssets;
  document.getElementById('newOnlyFilter').closest('.toggle-label').style.display = hideOnAssets;
  document.getElementById('showSuppressedFilter').closest('.toggle-label').style.display = hideOnAssets;

  renderNav();

  if (section.id === 'assets') {
    document.getElementById('content').innerHTML = renderAssets();
    wireAddAssetForm();
    wireAssetCardActions();
    return;
  }

  const sectionRows = section.match ? DATA.filter(section.match) : DATA.slice();
  let rows = visibleForCounting(sectionRows);

  let html = '';
  // Stats always reflect this section's full row set (same as the existing
  // "ignores the severity dropdown" behavior) so the new/suppressed counts
  // stay meaningful even while the "Show suppressed" toggle is hiding them
  // from the table below.
  if (section.id === 'overview') html += renderStats(sectionRows);

  if (section.id === 'recon') {
    html += renderFieldChips(rows);
    if (reconFieldFilter) rows = rows.filter(f => (f.field || f.type) === reconFieldFilter);
  }

  if (sev) rows = rows.filter(f => f.severity === sev);
  if (q) {
    rows = rows.filter(f => {
      const hay = [f.value, f.snippet, f.note, f.file, f.type, ...(f.sources||[])].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  // Asset chips (every section, Overview included) so two domains/files
  // scanned in the same run never present as one blended list — pick a chip
  // to isolate one asset, or leave "All assets" selected to see every
  // asset's findings still split into their own labeled groups below. This
  // is also what "View findings" on an Assets-tab card jumps into.
  html += renderAssetChips(rows);
  if (assetFilter) rows = rows.filter(f => (f.file || '(unknown)') === assetFilter);

  rows.sort((a,b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));

  html += \`<div class="count-line">Showing \${rows.length} finding(s)\${section.id !== 'overview' ? '' : ' (all categories)'}</div>\`;
  html += renderTable(rows);
  document.getElementById('content').innerHTML = html;

  if (section.id === 'recon') {
    document.querySelectorAll('.chip:not(.asset-chip)').forEach(el => {
      el.addEventListener('click', () => { reconFieldFilter = el.dataset.field; render(); });
    });
  }
  document.querySelectorAll('.asset-chip').forEach(el => {
    el.addEventListener('click', () => { assetFilter = el.dataset.asset; render(); });
  });

  document.querySelectorAll('.triage-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.dataset.idx);
      const status = btn.dataset.status;
      const finding = DATA[idx];
      if (!finding || !finding.dedupeKey) return;
      const row = btn.closest('.triage-row');
      const prevHtml = row ? row.innerHTML : null;
      btn.disabled = true;
      try {
        const res = await fetch('/api/triage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace: CURRENT_WORKSPACE, dedupeKey: finding.dedupeKey, status }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
        if (body.triage) finding.triage = body.triage; else delete finding.triage;
        render();
      } catch (e) {
        alert('Could not update triage: ' + e.message);
        if (row && prevHtml != null) row.innerHTML = prevHtml;
        btn.disabled = false;
      }
    });
  });

  document.querySelectorAll('.copy-ctx-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.dataset.idx);
      const finding = DATA[idx];
      const status = document.querySelector('.copy-status[data-idx-status="' + idx + '"]');
      if (!finding || !finding.context) return;
      const ok = await copyText(finding.context);
      btn.textContent = ok ? 'Copied!' : 'Copy failed';
      if (status) status.textContent = ok ? 'Copied to clipboard' : 'Clipboard blocked — select the code above and copy manually';
      setTimeout(() => { btn.textContent = 'Copy code'; if (status) status.textContent = ''; }, 2000);
    });
  });

  document.querySelectorAll('.open-in-viewer-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.dataset.idx);
      const finding = DATA[idx];
      if (finding) openFileViewer(finding);
    });
  });
}

document.getElementById('search').addEventListener('input', render);
document.getElementById('severityFilter').addEventListener('change', render);
document.getElementById('newOnlyFilter').addEventListener('change', render);
document.getElementById('showSuppressedFilter').addEventListener('change', render);

const wsSelectEl = document.getElementById('workspaceSelect');
if (SERVED) {
  wsSelectEl.addEventListener('change', () => switchWorkspace(wsSelectEl.value));
  loadWorkspaceList();
} else {
  // Switching requires the backend — disable the control rather than let it
  // look interactive when opened as a static file.
  wsSelectEl.disabled = true;
  wsSelectEl.title = 'Workspace switching requires jsrecon --ui --serve';
}

const delWsBtnEl = document.getElementById('deleteWorkspaceBtn');
if (delWsBtnEl) {
  delWsBtnEl.addEventListener('click', async () => {
    const name = CURRENT_WORKSPACE;
    if (!confirm('Permanently delete the entire workspace "' + name + '"? This removes every run, finding, and cached source in it. This cannot be undone.')) return;
    delWsBtnEl.disabled = true;
    const prevTitle = delWsBtnEl.title;
    delWsBtnEl.title = 'Deleting...';
    try {
      const res = await fetch('/api/delete-workspace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace: name }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));

      const listRes = await fetch('/api/workspaces');
      const listBody = await listRes.json();
      const remaining = (listBody.workspaces || []).filter(n => n !== name).sort();

      if (remaining.length > 0) {
        await switchWorkspace(remaining[0]);
        await loadWorkspaceList();
      } else {
        // Nothing left at all — there's no run to fetch, so show an empty
        // state directly rather than pretending a workspace still exists.
        DATA = [];
        TARGETS = [];
        CURRENT_WORKSPACE = '';
        document.getElementById('wsRun').textContent = 'run: -';
        document.getElementById('wsTimestamp').textContent = '';
        document.getElementById('targetCount').textContent = '0 target(s) scanned';
        wsSelectEl.innerHTML = '<option value="">(no workspaces)</option>';
        currentSection = 'assets';
        document.getElementById('content').innerHTML =
          '<div id="empty" style="display:block">No workspaces left. Add a target under Assets, or scan one from the CLI, to create one.</div>';
        document.getElementById('sectionTitle').textContent = 'Assets';
        document.getElementById('sectionDesc').textContent = '';
        renderNav();
        wireAddAssetForm();
        delWsBtnEl.disabled = true;
        delWsBtnEl.title = 'No workspace to delete';
      }
    } catch (e) {
      alert('Could not delete workspace: ' + e.message);
      delWsBtnEl.disabled = false;
      delWsBtnEl.title = prevTitle;
    }
  });
}

render();
</script>
</body>
</html>`;
}

module.exports = { buildDashboardHtml };
