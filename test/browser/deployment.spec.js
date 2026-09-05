// @ts-check
// P17 Stories 4-5: node creation/deployment profile and safe command builder.
const { test, expect } = require('playwright/test');

const ADMIN = {
  username: process.env.ANTINAT_TEST_USER || 'admin',
  password: process.env.ANTINAT_TEST_PASSWORD || ''
};
// The deployment surface contains a one-time credential. Do not retain
// Playwright traces/screenshots for this suite if a test fails.
test.use({ trace: 'off', screenshot: 'off', video: 'off' });

async function login(page) {
  await page.goto('/admin');
  if (await page.locator('[data-login-form]').isVisible()) {
    await page.fill('[data-login-user]', ADMIN.username);
    await page.fill('[data-login-pass]', ADMIN.password);
    await page.click('[data-login-submit]');
  }
  await expect(page.locator('[data-tabs]')).toBeVisible();
}

async function nodes(page) {
  await page.locator('[data-tab="nodes"]').click();
  await expect(page.locator('[data-nodes-table]')).toBeVisible();
}

test.describe('node deployment flow', () => {
  test('create failure stays recoverable in the create dialog', async ({ page }) => {
    await login(page);
    await nodes(page);
    await page.route('**/api/v1/nodes', (route) => {
      if (route.request().method() === 'POST') return route.abort();
      return route.continue();
    });
    await page.locator('[data-node-create]').click();
    await page.fill('[data-new-node-name]', 'browser-create-failure');
    await page.locator('[data-node-create-submit]').click();
    await expect(page.locator('[data-node-create-error]')).toBeVisible();
    await expect(page.locator('[data-node-create-submit]')).toBeEnabled();
    await expect(page.locator('[data-dialog]')).toBeVisible();
    await page.unroute('**/api/v1/nodes');
  });

  test('double-submitting node creation produces one POST', async ({ page }) => {
    await login(page);
    await nodes(page);
    let creates = 0;
    await page.route('**/api/v1/nodes', async (route) => {
      if (route.request().method() === 'POST') creates += 1;
      await route.continue();
    });
    await page.locator('[data-node-create]').click();
    await page.fill('[data-new-node-name]', 'browser-double-create');
    await page.locator('[data-node-create-submit]').evaluate((button) => { button.click(); button.click(); });
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible({ timeout: 5000 });
    expect(creates).toBe(1);
    await page.locator('[data-deployment-close]').click();
    await page.unroute('**/api/v1/nodes');
  });

  test('creates a node once and enters a secret-free deployment dialog', async ({ page }) => {
    await login(page);
    await nodes(page);
    await page.locator('[data-node-create]').click();
    await expect(page.locator('[data-dialog]')).toBeVisible();
    const name = 'browser-node-' + Math.random().toString(36).slice(2, 9);
    await page.fill('[data-new-node-name]', name);
    const submit = page.locator('[data-node-create-submit]');
    await submit.click();

    await expect(page.locator('[data-deployment-dialog]')).toBeVisible({ timeout: 5000 });
    const token = await page.locator('[data-deployment-token]').textContent();
    expect(token).toBeTruthy();
    expect(await page.locator('[data-deployment-command]').count()).toBe(0);
    await page.locator('[data-deployment-continue]').click();
    const command = await page.locator('[data-deployment-command]').textContent();
    expect(command).toContain('--controller-endpoint');
    expect(command).not.toContain(token);
    expect(command).not.toContain('--token');
    expect(command).toContain('bash -o pipefail -c');
    expect(await page.locator('[data-deployment-token]').count()).toBe(0);
  });

  test('renders platform-specific commands and removes installer-only Docker options', async ({ page }) => {
    await login(page);
    await nodes(page);
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible();
    await page.locator('[data-deployment-continue]').click();

    const platform = page.locator('[data-deploy-field="platform"]');
    await platform.selectOption('docker');
    await expect(page.locator('[data-deployment-command]')).toContainText('docker run');
    const dockerCommand = await page.locator('[data-deployment-command]').textContent();
    expect(dockerCommand).toContain('--network host');
    expect(dockerCommand).toContain('--restart=always');
    expect(dockerCommand).not.toContain('--install-dir');
    expect(dockerCommand).not.toContain('--service-name');
    expect(dockerCommand).not.toContain('--github-proxy');
    expect(dockerCommand).not.toContain('--token');
    expect(dockerCommand).toContain('--interactive');
    expect(dockerCommand).toContain('--tty');
    expect(dockerCommand).not.toContain('--rm');
    expect(dockerCommand).toMatch(/--env 'ANTINAT_ENDPOINT=/);
    expect(dockerCommand).toContain("--env 'ANTINAT_NODE=node-online'");
    expect(dockerCommand).toMatch(/--env 'ANTINAT_PIN=[0-9a-f]{64}'/);
    expect(dockerCommand).toContain("--volume '/secure/antinat/enrollment.token:/run/secrets/antinat_enrollment_token:ro'");
    expect(dockerCommand).not.toContain('--controller-endpoint');
    expect(dockerCommand.trim()).toMatch(/ghcr\.io\/gxbrave\/antinat-agent:latest$/);

    await platform.selectOption('windows');
    await expect(page.locator('[data-deployment-command]')).toContainText(/powershell/i);
    await expect(page.locator('[data-deployment-command]')).toContainText(/ExecutionPolicy Bypass/);

    await platform.selectOption('linux');
    await expect(page.locator('[data-deployment-command]')).toContainText(/curl/);
    await expect(page.locator('[data-deployment-command]')).toContainText(/sudo env/);
  });

  test('saves a structured profile, reloads it, and keeps invalid values out of persistence', async ({ page }) => {
    await login(page);
    await nodes(page);
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible();
    await page.locator('[data-deployment-continue]').click();

    await page.fill('[data-deploy-field="controller_endpoint"]', 'https://ctl.example.test:3111/base/');
    await page.check('[data-deploy-enable="github_proxy"]');
    await page.fill('[data-deploy-field="github_proxy"]', 'ghfast.top/');
    await page.selectOption('[data-deploy-field="detection_scheduler"]', 'parallel');
    await page.click('[data-deployment-save]');
    await expect(page.locator('[data-deployment-save-status]')).toContainText(/已保存|Saved/);

    await page.locator('[data-deployment-close]').click();
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await page.locator('[data-deployment-continue]').click();
    await expect(page.locator('[data-deploy-field="controller_endpoint"]')).toHaveValue('https://ctl.example.test:3111/base');
    await expect(page.locator('[data-deploy-field="github_proxy"]')).toHaveValue('https://ghfast.top');
    await expect(page.locator('[data-deploy-field="detection_scheduler"]')).toHaveValue('parallel');
  });

  test('double-saving a profile produces one PUT', async ({ page }) => {
    await login(page);
    await nodes(page);
    let saves = 0;
    await page.route('**/api/v1/nodes/node-online/deployment-profile', async (route) => {
      if (route.request().method() === 'PUT') saves += 1;
      await route.continue();
    });
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible();
    await page.locator('[data-deployment-continue]').click();
    await page.locator('[data-deployment-save]').evaluate((button) => { button.click(); button.click(); });
    await expect(page.locator('[data-deployment-save-status]')).toContainText(/已保存|Saved/);
    expect(saves).toBe(1);
    await page.unroute('**/api/v1/nodes/node-online/deployment-profile');
  });

  test('clipboard failure leaves a manually selectable command', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => Promise.reject(new Error('clipboard unavailable')) } });
    });
    await login(page);
    await nodes(page);
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible();
    await page.locator('[data-deployment-continue]').click();
    await page.click('[data-deployment-copy]');
    await expect(page.locator('[data-deployment-copy-notice]')).toContainText(/手动|manually|select/i);
    await expect(page.locator('[data-deployment-command]')).toBeVisible();
  });

  test('frontend PowerShell builder does not expose raw shell syntax', async ({ page }) => {
    await login(page);
    const command = await page.evaluate(() => window.antinat.deployment.buildInstallCommand({
      platform: 'windows',
      controller_endpoint: 'https://ctl.example.test',
      bind_interface: 'eth0"; $(Remove-Item C:\\); & Write-Output pwned',
      detection_scheduler: 'sequential',
      log_level: 'info',
      auto_update: 'disabled'
    }, { node_id: 'node-browser', controller_pin: 'abababababababababababababababababababababababababababababababab' }));
    expect(command).toContain('-EncodedCommand');
    expect(command).not.toContain('Remove-Item');
  });

  test('allows saving when detection is unavailable and shows a recoverable error', async ({ page }) => {
    await login(page);
    await nodes(page);
    await page.route('**/api/v1/nodes/node-online/traversal-detection', (route) => route.abort());
    await page.locator('[data-node="node-online"] [data-action="deploy"]').click();
    await expect(page.locator('[data-deployment-dialog]')).toBeVisible();
    await page.locator('[data-deployment-continue]').click();
    await page.click('[data-deployment-detect]');
    await expect(page.locator('[data-detection-state="error"]')).toBeVisible();
    await expect(page.locator('[data-deployment-save]')).toBeEnabled();
    await page.unroute('**/api/v1/nodes/node-online/traversal-detection');
  });
});
