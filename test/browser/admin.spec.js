// @ts-check
// Admin shell RED tests (P17 Story 3): four tabs with keyboard navigation,
// durable status labels (never color-only), loading/error/empty states, SSE
// connect + reconnect, long bilingual strings, and a mobile layout without
// horizontal overflow.
const { test, expect } = require('playwright/test');

const ADMIN = { username: 'admin', password: 's3cret-pass-123' };

async function login(page) {
  await page.goto('/admin');
  if (await page.locator('[data-login-form]').isVisible()) {
    await page.fill('[data-login-user]', ADMIN.username);
    await page.fill('[data-login-pass]', ADMIN.password);
    await page.click('[data-login-submit]');
    await expect(page.locator('[data-tabs]')).toBeVisible();
  }
}

test.describe('admin shell', () => {
  test('four tabs render and arrow keys switch tabs', async ({ page }) => {
    await login(page);
    const tabs = page.locator('[data-tabs] [role="tab"]');
    await expect(tabs).toHaveCount(4);
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'true');
    await tabs.nth(0).focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#tab-forwards')).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'true');
  });

  test('forwards tab shows durable text statuses and the evidence chain', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="forwards"]').click();
    const verified = page.locator('[data-fwd="fwd-verified"]');
    await expect(verified).toBeVisible();
    await expect(verified).toHaveAttribute('data-status', 'verified');
    await expect(verified.locator('.status-label')).toContainText(/已验证|Verified/);
    await expect(verified).toHaveAttribute('data-clickable', 'true');

    const unverified = page.locator('[data-fwd="fwd-unverified"]');
    await expect(unverified).toHaveAttribute('data-status', 'unverified');

    // Evidence chain with real orthogonal axes (not decorative).
    await verified.getByRole('button', { name: /详情|Detail/ }).click();
    const rail = verified.locator('[data-evidence-rail]');
    await expect(rail).toBeVisible();
    await expect(rail.locator('[data-ring]')).toHaveCount(6);
    await expect(rail.locator('[data-ring="control_state"]')).toHaveAttribute('data-value', 'ONLINE');
    await expect(rail.locator('[data-ring="wan_reachability_state"]')).toHaveAttribute('data-value', 'OPEN_FROM_VANTAGE');
  });

  test('nodes tab distinguishes offline/online durably in text + shape', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="nodes"]').click();
    const offline = page.locator('[data-node="node-offline"]');
    await expect(offline).toBeVisible();
    await expect(offline.locator('.status-label')).toContainText(/离线|Offline/);
    const online = page.locator('[data-node="node-online"]');
    await expect(online.locator('.status-label')).toContainText(/在线|Online/);
  });

  test('loading, error, and retry states are explicit', async ({ page }) => {
    await login(page);
    let blocked = true;
    await page.route('**/api/v1/forwards*', (route) => {
      if (blocked) route.abort();
      else route.continue();
    });
    await page.locator('[data-tab="forwards"]').click();
    await expect(page.locator('[data-pane-state="error"]')).toBeVisible();
    blocked = false;
    await page.locator('[data-pane-state="error"] button').click();
    await expect(page.locator('[data-pane-state="error"]')).toHaveCount(0);
    await expect(page.locator('[data-fwd="fwd-verified"]')).toBeVisible();
    await page.unroute('**/api/v1/forwards*');
  });

  test('a group with no forwards renders the empty state', async ({ page }) => {
    await login(page);
    await page.route('**/api/v1/forwards*', (route) =>
      route.fulfill({ json: { items: [], page: 1, page_size: 200, total: 0 } })
    );
    await page.locator('[data-tab="forwards"]').click();
    await expect(page.locator('[data-pane-state="empty"]')).toBeVisible();
    await page.unroute('**/api/v1/forwards*');
  });

  test('SSE connects, reconnects after a dropped stream, and surfaces a new admin event', async ({ page }) => {
    await login(page);
    let attempts = 0;
    await page.route('**/api/v1/events', (route) => {
      attempts += 1;
      if (attempts === 1) route.abort();
      else route.continue();
    });
    // Reload so the EventSource is created after the route is installed.
    await page.reload();
    const dot = page.locator('[data-sse]');
    await expect(dot).toHaveAttribute('data-sse-state', 'connected');

    // A node create through the frozen API writes a durable admin event.
    const key = 'k-' + Math.random().toString(36).slice(2, 12);
    const resp = await page.request.post('/api/v1/nodes', {
      data: { name: 'sse-node' },
      headers: { 'Idempotency-Key': key }
    });
    expect(resp.ok()).toBeTruthy();

    const log = page.locator('[data-sse-log]');
    await page.locator('[data-sse-panel] summary').click();
    await expect(log.locator('li').first()).toBeVisible({ timeout: 5000 });
    await page.unroute('**/api/v1/events');
  });

  test('global settings tab loads the form from a real settings record', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="global"]').click();
    await expect(page.locator('[data-field-group="language"]')).toBeVisible();
    await expect(page.locator('[data-field="language"]')).toHaveValue('zh');
    await expect(page.locator('[data-field="controller_endpoint"]')).toHaveValue('https://ctl.example.com:3111');
    await expect(page.locator('[data-field="private_site"]')).not.toBeChecked();
  });

  test('long bilingual strings do not overflow the page', async ({ page }) => {
    await login(page);
    // Create a forward with a very long single-value name through the API.
    const longName = '这是一个非常非常长的中文转发名称，用来验证长文案在卡片与表格中不会造成任何横向溢出 The quick brown fox jumps over the lazy dog 验证长文案'.repeat(2);
    const key = 'k-' + Math.random().toString(36).slice(2, 12);
    const fwdResp = await page.request.post('/api/v1/forwards', {
      data: { node_id: 'node-online', name: longName, protocol: 'tcp', target: '192.0.2.50:8080', strategy: 'auto' },
      headers: { 'Idempotency-Key': key }
    });
    expect(fwdResp.ok()).toBeTruthy();
    await page.locator('[data-tab="forwards"]').click();
    const longCard = page.locator('.fwd-title h4').filter({ hasText: longName.slice(0, 12) }).first();
    await expect(longCard).toContainText(longName.slice(0, 12));
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });

  test('mobile admin stays inside the viewport with scrollable tables', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 720 });
    await login(page);
    await page.locator('[data-tab="nodes"]').click();
    const wrap = page.locator('.data-table-wrap');
    await expect(wrap.locator('[data-node="node-offline"]')).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
});