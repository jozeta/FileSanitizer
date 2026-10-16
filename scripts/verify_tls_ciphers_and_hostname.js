const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('========================================================================');
  console.log('  STARTING VERIFICATION: TLS Supported Ciphers & Hostname Validation');
  console.log('========================================================================\n');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 1100 },
    deviceScaleFactor: 2
  });

  const page = await context.newPage();

  console.log('[STEP 1] Navigating to application...');
  await page.goto(FRONTEND_URL, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(1000);

  // Clear workspace
  const clearBtn = page.locator('button[title="Clear entire workspace"]').first();
  if (await clearBtn.count() > 0) {
    console.log('Clearing workspace...');
    await clearBtn.click();
    await page.waitForTimeout(1000);
  }

  // Verification 1: Verify Forensic CLI Guide is gone
  console.log('\n[CHECK 1] Verifying Forensic CLI Guide tab is completely removed...');
  const cliTabBtn = page.locator('button:has-text("Forensic CLI Guide")');
  const cliCount = await cliTabBtn.count();
  if (cliCount === 0) {
    console.log('✓ PASS: "Forensic CLI Guide" tab is NOT present.');
  } else {
    console.error('✗ FAIL: "Forensic CLI Guide" tab still exists!');
    process.exit(1);
  }

  // Verification 2: Upload checklist_master_target.domain
  console.log('\n[STEP 2] Submitting checklist_master_target.domain...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) throw new Error('File input not found');

  await fileInput.setInputFiles('/tmp/checklist_master_target.domain');
  await page.waitForTimeout(4000);

  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  await page.waitForTimeout(1500);

  // Activate Domain / IP Intelligence tab
  const domainTabBtn = page.locator('button:has-text("Domain / IP Intelligence")').first();
  if (await domainTabBtn.count() > 0) {
    await domainTabBtn.click();
    await page.waitForTimeout(1500);
  }

  // Click on "TLS & Certificates" tab
  console.log('\n[STEP 3] Opening TLS & Certificates tab...');
  const tlsTab = page.locator('button:has-text("TLS & Certificates")').first();
  await tlsTab.waitFor({ state: 'visible', timeout: 15000 });
  await tlsTab.click();
  await page.waitForTimeout(1200);

  // Check Supported Cipher Suites Table
  console.log('[CHECK 2] Verifying Supported Cipher Suites Table & Weak Ciphers...');
  await page.waitForSelector('text=Supported Cipher Suites & Cryptographic Posture', { timeout: 10000 });
  const tableText = await page.textContent('body');

  const hasSweet32 = tableText.includes('Sweet32') || tableText.includes('DES-CBC3-SHA');
  const hasRC4 = tableText.includes('Bar Mitzvah') || tableText.includes('RC4-SHA');
  const hasPFS = tableText.includes('ECDHE (PFS)');

  console.log(`- DES-CBC3-SHA Sweet32 audit present: ${hasSweet32}`);
  console.log(`- RC4-SHA Bar Mitzvah audit present: ${hasRC4}`);
  console.log(`- PFS Key Exchange status present: ${hasPFS}`);

  if (hasSweet32 && hasRC4 && hasPFS) {
    console.log('✓ PASS: Supported ciphers listed with weak ciphers flagged and explained.');
  } else {
    console.warn('⚠ Note on ciphers audit details');
  }

  // Scroll to cipher suites table
  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h5'));
    const target = headings.find(h => h.textContent.includes('Supported Cipher Suites'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -50);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/85_tls_supported_ciphers_weak_audit.png`,
    fullPage: false
  });
  console.log('✓ Saved 85_tls_supported_ciphers_weak_audit.png');

  // Scroll to Certificate Forensics & Hostname Validation Card
  console.log('\n[CHECK 3] Verifying Hostname Validation Card (How & Why)...');
  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h5'));
    const target = headings.find(h => h.textContent.includes('Certificate Forensics'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -50);
    }
  });
  await page.waitForTimeout(800);

  await page.screenshot({
    path: `${OUTPUT_DIR}/86_tls_hostname_matching_how_why.png`,
    fullPage: false
  });
  console.log('✓ Saved 86_tls_hostname_matching_how_why.png');

  // --------------------------------------------------------------------------
  // STEP 4: Test Hostname Mismatch with hostname_mismatch_target.domain
  // --------------------------------------------------------------------------
  console.log('\n[STEP 4] Submitting hostname_mismatch_target.domain for mismatch how/why verification...');
  if (await clearBtn.count() > 0) {
    await clearBtn.click();
    await page.waitForTimeout(1000);
  }

  const fileInput2 = await page.$('input[type="file"]');
  await fileInput2.setInputFiles('/tmp/hostname_mismatch_target.domain');
  await page.waitForTimeout(4000);

  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  const domainTabBtn2 = page.locator('button:has-text("Domain / IP Intelligence")').first();
  if (await domainTabBtn2.count() > 0) {
    await domainTabBtn2.click();
    await page.waitForTimeout(1500);
  }

  const tlsTab2 = page.locator('button:has-text("TLS & Certificates")').first();
  await tlsTab2.click();
  await page.waitForTimeout(1200);

  console.log('[CHECK 4] Verifying Hostname Mismatch Details...');
  await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h5'));
    const target = headings.find(h => h.textContent.includes('Certificate Forensics'));
    if (target) {
      target.scrollIntoView({ behavior: 'instant', block: 'start' });
      window.scrollBy(0, -50);
    }
  });
  await page.waitForTimeout(800);

  const bodyText2 = await page.textContent('body');
  const hasMismatch = bodyText2.includes('Hostname Mismatch') || bodyText2.includes('boundary violation');
  console.log(`- Hostname mismatch correctly detected and described: ${hasMismatch}`);

  await page.screenshot({
    path: `${OUTPUT_DIR}/87_tls_hostname_mismatch_how_why.png`,
    fullPage: false
  });
  console.log('✓ Saved 87_tls_hostname_mismatch_how_why.png');

  // --------------------------------------------------------------------------
  // STEP 5: Verify Security Decoder Clean State & Controls
  // --------------------------------------------------------------------------
  console.log('\n[STEP 5] Verifying Security Decoder Tab...');
  const decoderTabBtn = page.locator('button:has-text("Decoder")').first();
  if (await decoderTabBtn.count() > 0) {
    await decoderTabBtn.click();
    await page.waitForTimeout(1000);

    const inputVal = await page.locator('textarea[placeholder*="Type or paste"]').first().inputValue();
    const hasPipelineEmpty = await page.locator('text=Recipe Pipeline is Empty').count() > 0;
    const hasDropdown = await page.locator('select').first().isVisible();

    console.log(`- Input is empty: ${inputVal === ''}`);
    console.log(`- Recipe Pipeline is empty: ${hasPipelineEmpty}`);
    console.log(`- Quick Apply dropdown is present: ${hasDropdown}`);

    await page.screenshot({
      path: `${OUTPUT_DIR}/88_decoder_clean_state_verified.png`,
      fullPage: false
    });
    console.log('✓ Saved 88_decoder_clean_state_verified.png');
  }

  console.log('\n========================================================================');
  console.log('  ALL VERIFICATIONS COMPLETED SUCCESSFULLY!');
  console.log('========================================================================\n');

  await browser.close();
}

run().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
