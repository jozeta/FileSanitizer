const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: Comprehensive PCAP / PCAPNG Security Forensics');
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

  console.log('[STEP 2] Submitting demo_network_attack.pcap...');
  const fileInput = await page.$('input[type="file"]');
  if (!fileInput) {
    throw new Error('Could not find file input!');
  }

  await fileInput.setInputFiles('/tmp/test_samples/demo_network_attack.pcap');

  console.log('File submitted. Waiting 12 seconds for backend analysis to settle...');
  await page.waitForTimeout(12000);

  // Wait for any splashscreen to detach
  try {
    const splash = page.locator('text=Analyzing File Security...').first();
    if (await splash.count() > 0 && await splash.isVisible()) {
      console.log('Waiting for splashscreen to disappear...');
      await page.waitForSelector('text=Analyzing File Security...', { state: 'hidden', timeout: 30000 });
    }
  } catch (e) {}

  await page.waitForTimeout(3000);

  // Click on the PCAP job row if not already selected
  const pcapJobItem = page.locator('text=demo_network_attack.pcap').first();
  if (await pcapJobItem.count() > 0) {
    console.log('Selecting demo_network_attack.pcap from job list...');
    await pcapJobItem.click();
    await page.waitForTimeout(2000);
  }

  // Click on PCAP Network Forensics tab in main navigation
  const pcapNavBtn = page.locator('button:has-text("PCAP Network Forensics")').first();
  if (await pcapNavBtn.count() > 0) {
    console.log('Clicking PCAP Network Forensics main navigation tab...');
    await pcapNavBtn.click();
    await page.waitForTimeout(2000);
  }

  console.log('\n[STEP 3] Capturing Screenshot 49: Executive PCAP Verdict & Suricata IDS Alerts...');
  // Find Suricata IDS Alerts tab button
  const suricataTabBtn = page.locator('button:has-text("Suricata IDS")').first();
  if (await suricataTabBtn.count() > 0) {
    await suricataTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/49_pcaptriage_executive_verdict_and_suricata.png`,
    fullPage: false
  });
  console.log('Saved 49_pcaptriage_executive_verdict_and_suricata.png');

  console.log('\n[STEP 4] Capturing Screenshot 50: Zeek Structured Forensic Session Logs...');
  const zeekTabBtn = page.locator('button:has-text("Zeek Logs")').first();
  if (await zeekTabBtn.count() > 0) {
    await zeekTabBtn.click();
    await page.waitForTimeout(1000);

    // Click dns.log subtab to show multiple logs
    const dnsSubtab = page.locator('button:has-text("dns.log")').first();
    if (await dnsSubtab.count() > 0) {
      await dnsSubtab.click();
      await page.waitForTimeout(800);
    }
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/50_pcaptriage_zeek_structured_logs.png`,
    fullPage: false
  });
  console.log('Saved 50_pcaptriage_zeek_structured_logs.png');

  console.log('\n[STEP 5] Capturing Screenshot 51: Capture Integrity, Frame Sizing & Evidence Provenance...');
  const integrityTabBtn = page.locator('button:has-text("Capture Integrity & Provenance")').first();
  if (await integrityTabBtn.count() > 0) {
    await integrityTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/51_pcaptriage_capture_integrity_and_provenance.png`,
    fullPage: false
  });
  console.log('Saved 51_pcaptriage_capture_integrity_and_provenance.png');

  console.log('\n[STEP 6] Capturing Screenshot 52: Reconnaissance & East-West Lateral Movement...');
  const lateralTabBtn = page.locator('button:has-text("Recon & Lateral")').first();
  if (await lateralTabBtn.count() > 0) {
    await lateralTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/52_pcaptriage_recon_and_lateral_movement.png`,
    fullPage: false
  });
  console.log('Saved 52_pcaptriage_recon_and_lateral_movement.png');

  console.log('\n[STEP 7] Capturing Screenshot 53: Protocol Anomalies & Industrial OT (SCADA)...');
  const protocolTabBtn = page.locator('button:has-text("Protocol Anomalies & OT")').first();
  if (await protocolTabBtn.count() > 0) {
    await protocolTabBtn.click();
    await page.waitForTimeout(1000);
  }

  await page.screenshot({
    path: `${OUTPUT_DIR}/53_pcaptriage_protocol_anomalies_and_ot.png`,
    fullPage: false
  });
  console.log('Saved 53_pcaptriage_protocol_anomalies_and_ot.png');

  await browser.close();
  console.log('\n================================================================');
  console.log('  VERIFICATION COMPLETE: All PCAP screenshots generated successfully!');
  console.log('================================================================');
}

run().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
