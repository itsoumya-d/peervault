// Playwright smoke audit for the static transfer demo. Requires a global
// Playwright install with Chromium. Run from the repository root:
//   node demo/audit-browser.mjs
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile } from 'node:fs/promises';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const require = createRequire(import.meta.url);
const globalRoot = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
const { chromium } = require(join(globalRoot, 'playwright'));

const server = createServer(async (request, response) => {
  const urlPath = decodeURIComponent(request.url.split('?')[0]);
  const file = join(root, urlPath === '/' ? '/demo/transfer.html' : urlPath);
  try {
    const body = await readFile(file);
    const type = extname(file) === '.html'
      ? 'text/html; charset=utf-8'
      : file.endsWith('.mjs') || file.endsWith('.js')
        ? 'text/javascript; charset=utf-8'
        : 'application/octet-stream';
    response.writeHead(200, { 'content-type': type });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end('not found');
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const base = `http://127.0.0.1:${port}/demo/transfer.html`;
const artifacts = join(here, 'artifacts');
await mkdir(artifacts, { recursive: true });

const browser = await chromium.launch({ headless: true });
const results = [];
try {
  for (const viewport of [
    { width: 1440, height: 900, name: 'desktop' },
    { width: 390, height: 844, name: 'mobile' }
  ]) {
    const page = await browser.newPage({ viewport });
    const errors = [];
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('pageerror', (error) => errors.push(error.message));

    await page.goto(base, { waitUntil: 'networkidle' });
    assert.equal(await page.title(), 'PeerVault — encrypted P2P transfer');
    await page.click('#demo');
    await page.waitForFunction(
      () => document.querySelector('#send-status')?.textContent.includes('Simulation complete'),
      null,
      { timeout: 10000 }
    );

    const smallTargets = await page.evaluate(() =>
      [...document.querySelectorAll('button, input:not([type=file]):not([type=checkbox]), .file-drop')]
        .filter((element) => element.offsetParent !== null && element.getBoundingClientRect().height < 43.5)
        .map((element) => element.outerHTML.slice(0, 100))
    );
    assert.deepEqual(smallTargets, [], `undersized targets at ${viewport.name}`);

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1
    );
    assert.equal(overflow, false, `horizontal overflow at ${viewport.name}`);
    assert.deepEqual(errors, [], `browser errors at ${viewport.name}`);

    await page.screenshot({
      path: join(artifacts, `transfer-${viewport.name}.png`),
      fullPage: true
    });
    results.push({ viewport: `${viewport.width}x${viewport.height}`, ok: true });
    await page.close();
  }
} finally {
  await browser.close();
  server.close();
}
console.log(JSON.stringify({ ok: true, results }, null, 2));
