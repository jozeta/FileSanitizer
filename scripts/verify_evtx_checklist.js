const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: Windows Event Logs (EVTX) Security Forensics');
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

  console.log('[STEP 2] Submitting Security_Comprehensive.evtx...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) {
    throw new Error('Could not find file input!');
  }

  await fileInput.setInputFiles('/tmp/Security_Comprehensive.evtx');

  console.log('File submitted. Waiting 10 seconds for backend analysis to settle...');
  await page.waitForTimeout(10000);

  // Wait for any splashscreen to detach
  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      console.log('Waiting for splashscreen to disappear...');
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  await page.waitForTimeout(3000);

  // Click on the EVTX job row if not already selected
  const evtxJobItem = page.locator('text=Security_Comprehensive.evtx').first();
  if (await evtxJobItem.count() > 0) {
    console.log('Selecting Security_Comprehensive.evtx from job list...');
    await evtxJobItem.click();
    await page.waitForTimeout(2000);
  }

  // Click on Windows Event Log Forensics tab in main navigation if visible
  const evtxNavBtn = page.locator('button:has-text("Windows Event Log Forensics")').first();
  if (await evtxNavBtn.count() > 0) {
    console.log('Clicking Windows Event Log Forensics main navigation tab...');
    await evtxNavBtn.click();
    await page.waitForTimeout(2000);
  }

  console.log('\n[STEP 3] Capturing Screenshot 54: Executive EVTX Verdict & Sigma IDS Alerts...');
  const sigmaTabBtn = page.locator('button:has-text("Sigma IDS Alerts")').first();
  if (await sigmaTabBtn.count() > 0) {
    await sigmaTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/54_evtxtriage_executive_verdict_and_sigma.png`,
    fullPage: false
  });
  console.log('Saved 54_evtxtriage_executive_verdict_and_sigma.png');

  console.log('\n[STEP 4] Capturing Screenshot 55: Capture Integrity & Log Coverage Audit...');
  const integrityTabBtn = page.locator('button:has-text("Capture Integrity & Coverage")').first();
  if (await integrityTabBtn.count() > 0) {
    await integrityTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/55_evtxtriage_capture_integrity_and_coverage.png`,
    fullPage: false
  });
  console.log('Saved 55_evtxtriage_capture_integrity_and_coverage.png');

  console.log('\n[STEP 5] Capturing Screenshot 56: Auth, Logon Types, NTSTATUS & Kerberoasting Forensics...');
  const authTabBtn = page.locator('button:has-text("Auth & Kerberos Forensics")').first();
  if (await authTabBtn.count() > 0) {
    await authTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/56_evtxtriage_auth_and_kerberos_forensics.png`,
    fullPage: false
  });
  console.log('Saved 56_evtxtriage_auth_and_kerberos_forensics.png');

  console.log('\n[STEP 6] Capturing Screenshot 57: Account & Privilege Management (Admins, SIDs, SeDebugPrivilege)...');
  const accountTabBtn = page.locator('button:has-text("Account & Privilege Management")').first();
  if (await accountTabBtn.count() > 0) {
    await accountTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/57_evtxtriage_account_and_privilege_management.png`,
    fullPage: false
  });
  console.log('Saved 57_evtxtriage_account_and_privilege_management.png');

  console.log('\n[STEP 7] Capturing Screenshot 58: Lateral Movement Chains & Anti-Forensics Log Tampering...');
  const lateralTabBtn = page.locator('button:has-text("Lateral Movement Chains")').first();
  if (await lateralTabBtn.count() > 0) {
    await lateralTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/58_evtxtriage_lateral_movement_and_tampering.png`,
    fullPage: false
  });
  console.log('Saved 58_evtxtriage_lateral_movement_and_tampering.png');

  console.log('\n[STEP 8] Capturing Screenshot 59: Offline Forensic Tools Guide (wevtutil, EvtxECmd, Chainsaw, Hayabusa)...');
  const toolsTabBtn = page.locator('button:has-text("Offline Tools Guide")').first();
  if (await toolsTabBtn.count() > 0) {
    await toolsTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/59_evtxtriage_offline_tools_guide.png`,
    fullPage: false
  });
  console.log('Saved 59_evtxtriage_offline_tools_guide.png');

  await browser.close();
  console.log('\n================================================================');
  console.log('  VERIFICATION COMPLETE: All EVTX screenshots generated successfully!');
  console.log('================================================================');
}

run().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
