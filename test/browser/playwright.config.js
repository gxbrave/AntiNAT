// Playwright config for AntiNAT P17 browser tests (frozen at
// playwright@1.62.1, see docs/ui-design-direction.md §9 and README.md).
// The suite runs against a locally started controller (never a real WAN), set
// up by scripts/test-browser.sh. Each spec logs in / seeds what it needs over
// the frozen HTTP API or via the store-backed seeder.
const { defineConfig, devices } = require('playwright/test');

module.exports = defineConfig({
  testDir: __dirname,
  outputDir: __dirname + '/test-results',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.ANTINAT_BROWSER_REPORTER || [['list']],
  globalSetup: require.resolve('./global-setup.js'),
  use: {
    baseURL: process.env.ANTINAT_BASE_URL || 'http://127.0.0.1:3111',
    storageState: process.env.ANTINAT_AUTH_STATE || undefined,
    trace: 'off',
    screenshot: 'off',
  },
  projects: [
    { name: 'chromium-desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } } },
  ],
});