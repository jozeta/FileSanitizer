const express = require('express');
const { chromium } = require('playwright');
const dns = require('dns').promises;
const net = require('net');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Private/reserved IP blocks
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 127 || parts[0] === 10) return true;
    if (parts[0] === 169 && parts[1] === 254) return true; // Link-local / metadata
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] >= 224) return true; // Multicast / Reserved
  } else if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) {
      return true;
    }
  }
  return false;
}

let browserInstance = null;

async function getBrowser() {
  if (!browserInstance) {
    browserInstance = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu'
      ]
    });
  }
  return browserInstance;
}

app.post('/screenshot', async (req, res) => {
  let { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  url = url.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Malformed URL format' });
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'Invalid protocol' });
  }

  try {
    // SSRF DNS check
    const lookup = await dns.lookup(parsed.hostname, { all: true });
    for (const item of lookup) {
      if (isPrivateIp(item.address)) {
        return res.status(403).json({ error: 'Destination IP blocked (SSRF violation)' });
      }
    }
  } catch (dnsErr) {
    return res.status(400).json({ error: `DNS resolution failed: ${dnsErr.message}` });
  }

  let context = null;
  let page = null;

  try {
    const browser = await getBrowser();
    context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 FileSanitizer-Preview/1.0'
    });

    page = await context.newPage();

    // Prevent navigation to private networks on redirects
    page.on('response', async (response) => {
      try {
        const respUrl = new URL(response.url());
        const ips = await dns.lookup(respUrl.hostname, { all: true });
        for (const i of ips) {
          if (isPrivateIp(i.address)) {
            if (page) await page.close().catch(() => {});
          }
        }
      } catch (e) {}
    });

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForTimeout(600).catch(() => {});

    const buffer = await page.screenshot({ type: 'png', timeout: 6000 });
    res.setHeader('Content-Type', 'image/png');
    return res.send(buffer);
  } catch (err) {
    return res.status(500).json({ error: `Screenshot generation failed: ${err.message}` });
  } finally {
    if (page) await page.close().catch(() => {});
    if (context) await context.close().catch(() => {});
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'FileSanitizer Browser Sandbox' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sandboxed browser service listening on port ${PORT}`);
});
