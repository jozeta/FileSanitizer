const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: Comprehensive PE & DLL Security Analysis');
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

  console.log('[STEP 2] Submitting demo_advanced_implant.exe and version.dll...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) {
    throw new Error('Could not find file input!');
  }

  await fileInput.setInputFiles([
    '/tmp/test_samples/demo_advanced_implant.exe',
    '/tmp/test_samples/version.dll'
  ]);

  console.log('Files submitted. Waiting 12 seconds for backend analysis to settle...');
  await page.waitForTimeout(12000);

  // Wait for any splash to detach
  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      console.log('Waiting for splashscreen to disappear...');
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  // -------------------------------------------------------------
  // TEST 1: Inspect demo_advanced_implant.exe
  // -------------------------------------------------------------
  console.log('\n[TEST 1] Inspecting demo_advanced_implant.exe...');
  const exeTab = page.locator('div[title="demo_advanced_implant.exe"]').first();
  if (await exeTab.count() > 0) {
    await exeTab.click();
    await page.waitForTimeout(1500);
  }

  // Click on "PE / Binary Analysis" tab
  console.log('Clicking "PE / Binary Analysis" tab on demo_advanced_implant.exe...');
  const peMainTab = page.locator('button:has-text("PE / Binary Analysis")').first();
  await peMainTab.waitFor({ state: 'visible', timeout: 15000 });
  await peMainTab.click();
  await page.waitForTimeout(1500);

  // 1. Executive Verdict & Malware Capabilities (ATT&CK) Tab
  console.log('[STEP 3] Capturing Executive Verdict & Malware Capabilities...');
  const capsTab = page.locator('button:has-text("Malware Capabilities")').first();
  if (await capsTab.count() > 0) {
    await capsTab.click();
    await page.waitForTimeout(1000);
  }
  await page.screenshot({ path: `${OUTPUT_DIR}/44_petriage_executive_verdict_and_capabilities.png` });
  console.log('Captured 44_petriage_executive_verdict_and_capabilities.png');

  // 2. PE Exploit Mitigations & Vulnerabilities Tab
  console.log('[STEP 4] Capturing Vulnerabilities & CRT...');
  const vulnsTab = page.locator('button:has-text("Vulnerabilities & CRT")').first();
  if (await vulnsTab.count() > 0) {
    await vulnsTab.click();
    await page.waitForTimeout(1000);
  }
  await page.screenshot({ path: `${OUTPUT_DIR}/45_petriage_vulnerabilities_and_crt.png` });
  console.log('Captured 45_petriage_vulnerabilities_and_crt.png');

  // 3. MZ & PE Headers & Trailing Overlay Forensics Tab
  console.log('[STEP 5] Capturing MZ & PE Headers and Trailing Overlay Forensics...');
  const headersTab = page.locator('button:has-text("MZ & PE Headers")').first();
  if (await headersTab.count() > 0) {
    await headersTab.click();
    await page.waitForTimeout(1000);
    // Scroll down to trailing overlay card
    const overlayCard = page.locator('text=Trailing Overlay Forensics').first();
    if (await overlayCard.count() > 0) {
      await overlayCard.scrollIntoViewIfNeeded();
      await page.waitForTimeout(600);
    } else {
      await page.evaluate(() => window.scrollBy(0, 900));
      await page.waitForTimeout(600);
    }
  }
  await page.screenshot({ path: `${OUTPUT_DIR}/46_petriage_trailing_overlay_forensics.png` });
  console.log('Captured 46_petriage_trailing_overlay_forensics.png');

  // -------------------------------------------------------------
  // TEST 2: Inspect version.dll (Proxy Sideloading, TLS & .NET)
  // -------------------------------------------------------------
  console.log('\n[TEST 2] Inspecting version.dll...');
  // Scroll back to top so workspace tab bar is in view
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(500);

  const dllWorkspaceTab = page.locator('div[title="version.dll"]').first();
  await dllWorkspaceTab.waitFor({ state: 'visible', timeout: 10000 });
  await dllWorkspaceTab.click();
  console.log('Clicked version.dll workspace tab.');
  await page.waitForTimeout(2000);

  // Ensure PE / Binary Analysis tab is selected
  const peMainTabDll = page.locator('button:has-text("PE / Binary Analysis")').first();
  if (await peMainTabDll.count() > 0) {
    await peMainTabDll.click();
    await page.waitForTimeout(1500);
  }

  // 4. DLL Forensics & Sideloading Tab
  console.log('[STEP 6] Capturing DLL Forensics, Forwarded Proxy Exports & TLS Callbacks...');
  const dllTab = page.locator('button:has-text("DLL & Sideloading")').first();
  await dllTab.waitFor({ state: 'visible', timeout: 10000 });
  await dllTab.click();
  await page.waitForTimeout(1000);
  await page.screenshot({ path: `${OUTPUT_DIR}/47_petriage_dll_proxy_and_tls_callbacks.png` });
  console.log('Captured 47_petriage_dll_proxy_and_tls_callbacks.png');

  // 5. .NET CLR Assembly Forensics Tab
  console.log('[STEP 7] Capturing .NET CLR Assembly Forensics...');
  const dotnetTab = page.locator('button:has-text(".NET CLR Assembly")').first();
  await dotnetTab.waitFor({ state: 'visible', timeout: 10000 });
  await dotnetTab.click();
  await page.waitForTimeout(1000);
  await page.screenshot({ path: `${OUTPUT_DIR}/48_petriage_dotnet_clr_assembly.png` });
  console.log('Captured 48_petriage_dotnet_clr_assembly.png');

  await browser.close();
  console.log('\n================================================================');
  console.log('  VERIFICATION COMPLETE: All 5 PE Forensic screenshots captured!');
  console.log('================================================================\n');
}

run().catch((err) => {
  console.error('Verification failed:', err);
  process.exit(1);
});
