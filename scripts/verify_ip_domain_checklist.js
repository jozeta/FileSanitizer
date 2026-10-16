const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: IP & Domain Security Analysis Checklist');
  console.log('================================================================\n');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 1050 },
    deviceScaleFactor: 2
  });

  const page = await context.newPage();

  console.log('[STEP 1] Navigating to Home...');
  await page.goto(FRONTEND_URL, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(1000);

  // Clear workspace if any existing items
  const clearBtn = page.locator('button[title="Clear entire workspace"]').first();
  if (await clearBtn.count() > 0) {
    console.log('Clearing existing workspace items...');
    await clearBtn.click();
    await page.waitForTimeout(1000);
  }

  console.log('[STEP 2] Submitting checklist_master_target.domain...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) {
    throw new Error('Could not find file input!');
  }

  await fileInput.setInputFiles('/tmp/checklist_master_target.domain');

  console.log('File submitted. Waiting for backend analysis to complete...');
  await page.waitForTimeout(5000);

  // Wait for any splashscreen to detach
  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      console.log('Waiting for splashscreen to disappear...');
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  await page.waitForTimeout(2000);

  // Click on "Domain / IP Intelligence" tab button to activate DomainAnalyticsCard
  console.log('Activating Domain / IP Intelligence tab in Analysis Dashboard...');
  const domainTabBtn = page.locator('button:has-text("Domain / IP Intelligence")').first();
  if (await domainTabBtn.count() > 0) {
    await domainTabBtn.waitFor({ state: 'visible', timeout: 20000 });
    await domainTabBtn.click();
    await page.waitForTimeout(1500);
  }

  console.log('Locating Executive Security Verdict Banner...');
  await page.waitForSelector('text=Executive Security Verdict', { timeout: 15000 });

  // --------------------------------------------------------------------------
  // SCREENSHOT 66: Executive Security Verdict Banner & Top Multi-Axis Gauges
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 66] Capturing Executive Verdict & Multi-Axis Risk Gauges...');
  const overviewTab = page.locator('button:has-text("Overview")').first();
  if (await overviewTab.count() > 0) {
    await overviewTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/66_ipdomain_executive_verdict_and_gauges.png`,
    fullPage: false
  });
  console.log('✓ Saved 66_ipdomain_executive_verdict_and_gauges.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 67: Indicator Normalisation & Unicode Homoglyph Impersonation
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 67] Capturing Indicator Normalisation & Homoglyph Analysis...');
  const normalisationTab = page.locator('button:has-text("Indicator Normalisation")').first();
  if (await normalisationTab.count() > 0) {
    await normalisationTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Indicator Validation'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/67_ipdomain_indicator_normalisation_and_homoglyphs.png`,
    fullPage: false
  });
  console.log('✓ Saved 67_ipdomain_indicator_normalisation_and_homoglyphs.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 68: Subdomain Takeover & Dangling CNAME Audit
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 68] Capturing Subdomain Takeover & Dangling CNAME Audit...');
  const takeoverTab = page.locator('button:has-text("Subdomain Takeover")').first();
  if (await takeoverTab.count() > 0) {
    await takeoverTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Subdomain Takeover'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/68_ipdomain_subdomain_takeover_audit.png`,
    fullPage: false
  });
  console.log('✓ Saved 68_ipdomain_subdomain_takeover_audit.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 69: Offline Tactical CLI Forensics Guide
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 69] Capturing Offline Forensic CLI Guide...');
  const cliTab = page.locator('button:has-text("Forensic CLI Guide")').first();
  if (await cliTab.count() > 0) {
    await cliTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Offline & Tactical CLI Forensics'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/69_ipdomain_offline_forensic_tools_guide.png`,
    fullPage: false
  });
  console.log('✓ Saved 69_ipdomain_offline_forensic_tools_guide.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 70: DNS Architecture, Fast-Flux & DNSSEC Audit
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 70] Capturing DNS Architecture & DNSSEC Cryptographic Audit...');
  const dnsTab = page.locator('button:has-text("DNS & DNSSEC")').first();
  if (await dnsTab.count() > 0) {
    await dnsTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('DNSSEC') || h.textContent.includes('DNS'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/70_ipdomain_dns_architecture_and_dnssec.png`,
    fullPage: false
  });
  console.log('✓ Saved 70_ipdomain_dns_architecture_and_dnssec.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 71: Email Spoofing, SPF Lookups Limit & DMARC Posture
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 71] Capturing Email Spoofing & SPF Lookup Limits Audit...');
  const emailSecTab = page.locator('button:has-text("Email & DMARC")').first();
  if (await emailSecTab.count() > 0) {
    await emailSecTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Spoofability') || h.textContent.includes('Email'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/71_ipdomain_email_spoofing_and_spf_limits.png`,
    fullPage: false
  });
  console.log('✓ Saved 71_ipdomain_email_spoofing_and_spf_limits.png');

  console.log('\n================================================================');
  console.log('  ALL 6 SCREENSHOTS (66 TO 71) CAPTURED SUCCESSFULLY!');
  console.log('================================================================\n');

  await browser.close();
}

run().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
