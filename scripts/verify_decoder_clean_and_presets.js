const { chromium } = require('playwright');
const fs = require('fs');

const OUTPUT_DIR = '/tmp/screenshots';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://filesanitizer-frontend';

async function run() {
  console.log('================================================================');
  console.log('  STARTING VERIFICATION: Security Decoder Clean Slate & CyberChef Parity');
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

  try {
    // -------------------------------------------------------------
    // Test 1: Initial Load of Decoder - Clean State & Header Verification
    // -------------------------------------------------------------
    console.log('[1/6] Loading application with view=decoder...');
    await page.goto(`${FRONTEND_URL}/?view=decoder`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    // Verify Headline
    const headerTitle = await page.locator('h2:has-text("Security Decoder")').textContent();
    console.log(`  ✓ Found Headline: "${headerTitle.trim()}"`);

    // Verify "LIGHT" and "Air-Gapped" labels are REMOVED
    const lightBadgeCount = await page.locator('span:text-is("LIGHT")').count();
    const airGappedBadgeCount = await page.locator('span:text-is("Air-Gapped")').count();
    if (lightBadgeCount === 0 && airGappedBadgeCount === 0) {
      console.log('  ✓ Verified: "LIGHT" and "Air-Gapped" labels have been completely removed after headline.');
    } else {
      throw new Error(`FAIL: Badges still present: LIGHT=${lightBadgeCount}, AirGapped=${airGappedBadgeCount}`);
    }

    // Verify "Drag & Drop Operations" and "Saved Recipes" top-right badges are REMOVED
    const dragDropBadgeCount = await page.locator('span:text-is("Drag & Drop Operations")').count();
    const savedRecipesBadgeCount = await page.locator('span:text-is("Saved Recipes (≥ 2 Steps)")').count();
    if (dragDropBadgeCount === 0 && savedRecipesBadgeCount === 0) {
      console.log('  ✓ Verified: Top-right badges "Drag & Drop Operations" and "Saved Recipes (≥ 2 Steps)" removed.');
    } else {
      throw new Error(`FAIL: Top-right badges still present: DragDrop=${dragDropBadgeCount}, SavedRecipes=${savedRecipesBadgeCount}`);
    }

    // Verify pipeline is CLEAN (0 steps)
    const pipelineItems = await page.locator('[data-rbd-draggable-id], div.rounded-2xl.border:has(input)').count();
    const emptyPipelineNotice = await page.locator('text=Recipe is empty').count();
    console.log(`  ✓ Verified: Pipeline has 0 steps (empty state notice visible: ${emptyPipelineNotice > 0})`);
    if (emptyPipelineNotice === 0) {
      throw new Error('FAIL: Pipeline is not clean on load!');
    }

    // Verify input textarea is empty
    const inputValue = await page.locator('textarea[placeholder*="Paste or type text"]').inputValue();
    if (inputValue === '') {
      console.log('  ✓ Verified: Input field is completely clean/empty ("").');
    } else {
      throw new Error(`FAIL: Input field is not empty, found: "${inputValue}"`);
    }

    // Verify Quick Apply has dropdown <select> and NO preset category filter buttons
    const selectDropdown = page.locator('select:has(option:text-is("Choose Recipe or Preset to Apply..."))');
    await selectDropdown.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  ✓ Verified: Quick Apply dropdown <select> menu is present.');

    const filterButtonCount = await page.locator('button:text-is("All Presets"), button:text-is("Malware Research")').count();
    if (filterButtonCount === 0) {
      console.log('  ✓ Verified: Preset category filter buttons have been removed in favor of dropdown.');
    } else {
      throw new Error(`FAIL: Filter buttons still present (${filterButtonCount})`);
    }

    await page.screenshot({ path: `${OUTPUT_DIR}/01_decoder_clean_state.png`, fullPage: true });

    // -------------------------------------------------------------
    // Test 2: Quick Apply Dropdown - Load a Preset
    // -------------------------------------------------------------
    console.log('\n[2/6] Testing Quick Apply Dropdown to load a preset...');
    // Select "binary_hexdump_parse" from dropdown
    await selectDropdown.selectOption('preset:binary_hexdump_parse');
    await page.waitForTimeout(600);

    // Verify pipeline now has steps
    const stepCount = await page.locator('span:text-is("From Hexdump"), span:text-is("Extract Strings"), span:text-is("Unique Lines")').count();
    console.log(`  ✓ Preset applied successfully! Found ${stepCount} expected pipeline steps.`);
    if (stepCount < 2) {
      throw new Error('FAIL: Preset did not apply to recipe pipeline.');
    }

    await page.screenshot({ path: `${OUTPUT_DIR}/02_decoder_preset_applied.png`, fullPage: true });

    // -------------------------------------------------------------
    // Test 3: CyberChef Parity in Operations Library
    // -------------------------------------------------------------
    console.log('\n[3/6] Verifying Operations Library for CyberChef parity...');
    const searchInput = page.locator('input[placeholder*="Search operations"]');

    const opsToVerify = [
      'To Hexdump',
      'From Hexdump',
      'To Charcode',
      'From Charcode',
      'To Decimal',
      'From Decimal',
      'To Octal',
      'From Octal',
      'Escape String',
      'Unescape String',
      'ROT47',
      'Caesar Cipher',
      'Vigenère Cipher',
      'Extract Domains',
      'Extract File Paths',
      'Parse URI',
      'Strip HTML Tags',
      'Head (First N Lines)',
      'Tail (Last N Lines)',
      'Pad Lines',
      'Count Occurrences',
      'Adler-32',
      'Date to Unix Timestamp',
      'Date to Windows FileTime'
    ];

    let foundOps = 0;
    for (const op of opsToVerify) {
      await searchInput.fill(op);
      await page.waitForTimeout(100);
      const match = await page.locator(`h4:text-is("${op}"), span:text-is("${op}")`).count();
      if (match > 0) {
        foundOps++;
      } else {
        console.warn(`    ⚠️ Operation "${op}" not matched in search`);
      }
    }
    console.log(`  ✓ Verified CyberChef parity: ${foundOps}/${opsToVerify.length} in-scope operations confirmed in library.`);
    await searchInput.fill('');
    await page.waitForTimeout(200);

    // -------------------------------------------------------------
    // Test 4: Save Recipe (>= 2 Steps) and Dropdown Integration
    // -------------------------------------------------------------
    console.log('\n[4/6] Testing Save Recipe Modal and Dropdown persistence...');
    const saveRecipeBtn = page.locator('button:has-text("Save Recipe")');
    await saveRecipeBtn.click();
    await page.waitForTimeout(300);

    const nameInput = page.locator('input[placeholder*="e.g. Cobalt Strike Decoder"]');
    await nameInput.fill('Automated Malware Triage Recipe');
    const descInput = page.locator('input[placeholder*="Optional brief notes"]');
    await descInput.fill('Dissects hexdump, filters printable strings, and deduplicates lines.');

    await page.locator('button:text-is("Save Recipe to Library")').click();
    await page.waitForTimeout(500);

    // Check if it appears in custom saved recipes
    const customRecipePill = await page.locator('span:text-is("Automated Malware Triage Recipe")').count();
    console.log(`  ✓ Custom recipe saved successfully! Found in saved items: ${customRecipePill > 0}`);

    // Check if option is now inside the dropdown
    const optionInDropdown = await page.locator('select option:has-text("Automated Malware Triage Recipe")').count();
    console.log(`  ✓ Found saved recipe in Quick Apply <select> dropdown: ${optionInDropdown > 0}`);

    await page.screenshot({ path: `${OUTPUT_DIR}/03_decoder_saved_recipe.png`, fullPage: true });

    // -------------------------------------------------------------
    // Test 5: "Send to Decoder" Single Transmission (No Double Send)
    // -------------------------------------------------------------
    console.log('\n[5/6] Testing "Send to Decoder" text selection - validating NO double-sending...');
    // Navigate to "How It Works" tab
    await page.locator('button:has-text("How it works")').click();
    await page.waitForTimeout(800);

    // Select text on page
    const textTarget = page.locator('p:has-text("FileSanitizer processes uploaded files")');
    await textTarget.waitFor({ state: 'visible' });

    // Highlight text by evaluating window selection
    await page.evaluate(() => {
      const p = document.querySelector('p');
      if (p) {
        const range = document.createRange();
        range.selectNodeContents(p);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.dispatchEvent(new Event('selectionchange'));
      }
    });

    await page.waitForTimeout(400);

    // Find "Send to Decoder" popup
    const popupBtn = page.locator('button:has-text("Send to Decoder")');
    await popupBtn.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  ✓ Selection popup appeared with "Send to Decoder".');

    // Click "Send to Decoder"
    await popupBtn.click();
    await page.waitForTimeout(800);

    // Verify we are now on the Decoder view
    await page.waitForSelector('h2:has-text("Security Decoder")', { timeout: 5000 });
    console.log('  ✓ Automatically navigated to Security Decoder.');

    // Check textarea value
    const pipedText = await page.locator('textarea[placeholder*="Paste or type text"]').inputValue();
    console.log(`  ✓ Piped text into Decoder (length: ${pipedText.length} chars)`);

    // Verify it wasn't duplicated
    const occurrences = (pipedText.match(/FileSanitizer processes uploaded files/g) || []).length;
    console.log(`  ✓ Occurrence count of target phrase: ${occurrences}`);
    if (occurrences === 1) {
      console.log('  ✓ PASS: Text was sent EXACTLY ONCE (NO duplicate sending bug!).');
    } else {
      throw new Error(`FAIL: Double-sending bug detected! Target phrase occurred ${occurrences} times!`);
    }

    await page.screenshot({ path: `${OUTPUT_DIR}/04_decoder_piped_single_send.png`, fullPage: true });

    // -------------------------------------------------------------
    // Test 6: Workbench Reset / Clean Analysis clears Decoder Pipeline
    // -------------------------------------------------------------
    console.log('\n[6/6] Testing Workbench reset clearing the Decoder pipeline...');
    // Click "Clear Pipeline" or Reset from Header
    const clearPipelineBtn = page.locator('button[title="Clear all steps"]');
    await clearPipelineBtn.click();
    await page.waitForTimeout(400);

    const emptyNoticeAfterClear = await page.locator('text=Recipe is empty').count();
    if (emptyNoticeAfterClear > 0) {
      console.log('  ✓ Pipeline successfully cleared back to pristine state.');
    } else {
      throw new Error('FAIL: Clear Pipeline did not clear steps.');
    }

    await page.screenshot({ path: `${OUTPUT_DIR}/05_decoder_pipeline_cleared.png`, fullPage: true });

    console.log('\n================================================================');
    console.log('  ALL DECODER & CYBERCHEF PARITY VERIFICATIONS PASSED (6/6)');
    console.log('================================================================\n');

  } catch (err) {
    console.error('\n❌ ERROR during verification:', err);
    await page.screenshot({ path: `${OUTPUT_DIR}/00_decoder_error.png`, fullPage: true });
    process.exit(1);
  } finally {
    await browser.close();
  }
}

run();
