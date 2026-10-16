const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: Email Security Analysis (EML / MSG)');
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

  console.log('[STEP 2] Submitting checklist_master_email.eml...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) {
    throw new Error('Could not find file input!');
  }

  await fileInput.setInputFiles('/tmp/checklist_master_email.eml');

  console.log('File submitted. Waiting for backend analysis to complete...');
  await page.waitForTimeout(8000);

  // Wait for any splashscreen to detach
  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      console.log('Waiting for splashscreen to disappear...');
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  await page.waitForTimeout(2000);

  // Click on "Email Triage" tab button to activate EmailTriageCard
  console.log('Activating Email Triage tab in Analysis Dashboard...');
  const emailTriageBtn = page.locator('button:has-text("Email Triage")').first();
  await emailTriageBtn.waitFor({ state: 'visible', timeout: 20000 });
  await emailTriageBtn.click();
  await page.waitForTimeout(1500);

  console.log('Locating Email Security Dossier...');
  await page.waitForSelector('text=Executive Email Security Verdict', { timeout: 15000 });

  // --------------------------------------------------------------------------
  // SCREENSHOT 60: Executive Email Security Verdict & Auth Posture
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 60] Capturing Executive Verdict & Authentication Posture...');
  const authTab = page.locator('button:has-text("Auth & Lookalikes")').first();
  if (await authTab.count() > 0) {
    await authTab.click();
    await page.waitForTimeout(1000);
  }

  // Scroll to top
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/60_emailtriage_executive_verdict_and_auth.png`,
    fullPage: false
  });
  console.log('✓ Saved 60_emailtriage_executive_verdict_and_auth.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 61: Lookalike Domains & Display-Name Spoofing
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 61] Capturing Lookalike Typosquatting & Spoofing Engine...');
  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Display-Name Spoofing') || h.textContent.includes('Lookalike'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    } else {
      window.scrollBy(0, 600);
    }
  });
  await page.waitForTimeout(1000);

  await page.screenshot({
    path: `${OUTPUT_DIR}/61_emailtriage_lookalike_and_spoofing.png`,
    fullPage: false
  });
  console.log('✓ Saved 61_emailtriage_lookalike_and_spoofing.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 62: Hidden Text & URL Threat Forensics
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 62] Capturing Deceptive URLs & HTML Hidden Text...');
  const urlTab = page.locator('button:has-text("URLs & HTML Forensics")').first();
  if (await urlTab.count() > 0) {
    await urlTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('HTML Body'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'center' });
    } else {
      window.scrollTo(0, 450);
    }
  });
  await page.waitForTimeout(1000);

  await page.screenshot({
    path: `${OUTPUT_DIR}/62_emailtriage_hidden_text_and_url_threats.png`,
    fullPage: false
  });
  console.log('✓ Saved 62_emailtriage_hidden_text_and_url_threats.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 63: Attachment Forensics & File Signature Mismatch
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 63] Capturing Attachment Forensics...');
  const attTab = page.locator('button:has-text("Attachment Forensics")').first();
  if (await attTab.count() > 0) {
    await attTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Attachment Forensics Table'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    } else {
      window.scrollTo(0, 300);
    }
  });
  await page.waitForTimeout(1000);

  await page.screenshot({
    path: `${OUTPUT_DIR}/63_emailtriage_attachment_forensics.png`,
    fullPage: false
  });
  console.log('✓ Saved 63_emailtriage_attachment_forensics.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 64: BEC & Financial Fraud Model
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 64] Capturing BEC & Financial Fraud Model...');
  const becTab = page.locator('button:has-text("BEC & Financial Fraud")').first();
  if (await becTab.count() > 0) {
    await becTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h3, h4'));
    const target = headings.find(h => h.textContent.includes('Financial Fraud') || h.textContent.includes('BEC'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -80);
    } else {
      window.scrollTo(0, 300);
    }
  });
  await page.waitForTimeout(1000);

  await page.screenshot({
    path: `${OUTPUT_DIR}/64_emailtriage_bec_and_financial_fraud.png`,
    fullPage: false
  });
  console.log('✓ Saved 64_emailtriage_bec_and_financial_fraud.png');

  // --------------------------------------------------------------------------
  // SCREENSHOT 65: Offline Forensic Tools CLI Guide
  // --------------------------------------------------------------------------
  console.log('\n[SCREENSHOT 65] Capturing Offline Forensic Tools CLI Guide...');
  const cliTab = page.locator('button:has-text("Offline Tools CLI")').first();
  if (await cliTab.count() > 0) {
    await cliTab.click();
    await page.waitForTimeout(1000);
  }

  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h4'));
    const target = headings.find(h => h.textContent.includes('Offline Forensic Tools'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -60);
    } else {
      window.scrollTo(0, 300);
    }
  });
  await page.waitForTimeout(1000);

  await page.screenshot({
    path: `${OUTPUT_DIR}/65_emailtriage_offline_tools_guide.png`,
    fullPage: false
  });
  console.log('✓ Saved 65_emailtriage_offline_tools_guide.png');

  console.log('\n================================================================');
  console.log('  ALL EMAIL CHECKLIST SCREENSHOTS CAPTURED SUCCESSFULLY!');
  console.log('================================================================\n');

  await browser.close();
}

run().catch((err) => {
  console.error('Fatal error during execution:', err);
  process.exit(1);
});
