// Source-level baseline checks for the transfer demo. These are not a WCAG
// certification; they enforce the binary UI constraints used by the project.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const htmlPath = join(here, '..', '..', 'demo', 'transfer.html');

test('transfer demo meets the baseline UI source constraints', async () => {
  const html = await readFile(htmlPath, 'utf8');

  assert.match(html, /100dvh/);
  assert.doesNotMatch(html, /\bh-screen\b/);
  assert.doesNotMatch(html, /\btracking-/);
  assert.doesNotMatch(html, /letter-spacing/);
  assert.doesNotMatch(html, /backdrop-filter/);
  assert.doesNotMatch(html, /blur\(/);
  assert.doesNotMatch(html, /will-change/);
  assert.doesNotMatch(html, /useEffect/);
  assert.match(html, /env\(safe-area-inset/);
  assert.match(html, /prefers-reduced-motion/);
  assert.match(html, /text-wrap:\s*balance/);
  assert.match(html, /text-wrap:\s*pretty/);
  assert.match(html, /font-variant-numeric:\s*tabular-nums/);
  assert.match(html, /:focus-visible/);
  assert.match(html, /min-block-size:\s*44px/);
  assert.match(html, /<label[^>]+for="relay-send"/);
  assert.match(html, /<label[^>]+for="relay-receive"/);
  assert.match(html, /<label[^>]+for="share-input"/);
  assert.match(html, /<label[^>]+for="files"/);
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /role="tablist"/);
  assert.match(html, /aria-selected=/);
  assert.match(html, /data-df-color-scale="detailed"/);
  assert.match(html, /data-df-density="compact"/);
  assert.match(html, /\.\.\/sdk\/dist\/index\.mjs/);
});
