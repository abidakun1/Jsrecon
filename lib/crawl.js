'use strict';
/**
 * Minimal same-host crawler — the local equivalent of jsmon-cli's
 * `-d <domain> -depth N -keywords a,b -extensions js,json`.
 *
 * BFS from the seed URL, following <script src>, <link href> and plain
 * href="..." links up to `depth` hops, staying on the same registrable host,
 * and only queuing/reporting URLs whose path ends in one of `extensions`.
 * Regex-based link extraction (no DOM/headless browser) — good enough for
 * static recon, capped at maxPages so it can't run away on a large site.
 */

const LINK_RE = /(?:src|href)\s*=\s*["']([^"']+)["']/gi;

function sameHost(a, b) {
  try {
    return new URL(a).host === new URL(b).host;
  } catch {
    return false;
  }
}

function extOf(urlStr) {
  try {
    const p = new URL(urlStr).pathname;
    const m = p.match(/\.([a-zA-Z0-9]+)$/);
    return m ? m[1].toLowerCase() : '';
  } catch {
    return '';
  }
}

/**
 * @param seedUrl string — root URL to crawl
 * @param opts {depth, keywords[], extensions[], maxPages, fetchFn(url) => Promise<{ok,text}>}
 * @returns { pages: [{url, ext}], visited: number }
 */
async function crawl(seedUrl, opts) {
  const depth = opts.depth || 2;
  const keywords = opts.keywords || [];
  const extensions = (opts.extensions && opts.extensions.length) ? opts.extensions : ['js', 'mjs'];
  const maxPages = opts.maxPages || 200;
  const fetchFn = opts.fetchFn;
  const onLog = opts.onLog || (() => {});

  const seen = new Set([seedUrl]);
  const matched = [];
  let queue = [{ url: seedUrl, d: 0 }];
  let visited = 0;

  while (queue.length && visited < maxPages) {
    const batch = queue;
    queue = [];

    for (const { url, d } of batch) {
      if (visited >= maxPages) break;
      visited++;
      let text;
      try {
        const res = await fetchFn(url);
        if (!res.ok) { onLog(`skip ${url} (HTTP not ok)`); continue; }
        text = res.text;
      } catch (e) {
        onLog(`skip ${url} (${e.message})`);
        continue;
      }

      const ext = extOf(url);
      const keywordOk = keywords.length === 0 || keywords.some((k) => url.includes(k));
      if (extensions.includes(ext) && keywordOk) {
        matched.push({ url, ext });
      }

      if (d >= depth) continue;

      let m;
      LINK_RE.lastIndex = 0;
      while ((m = LINK_RE.exec(text)) !== null) {
        let abs;
        try {
          abs = new URL(m[1], url).toString().split('#')[0];
        } catch {
          continue;
        }
        if (seen.has(abs) || !sameHost(seedUrl, abs)) continue;
        seen.add(abs);
        queue.push({ url: abs, d: d + 1 });
      }
    }
  }

  return { pages: matched, visited };
}

module.exports = { crawl };
