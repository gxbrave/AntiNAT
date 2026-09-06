// @ts-check
// Public home RED tests (P17 Story 2). The fixture (test/browser/seed) creates
// four cards: verified (web.example.com), unverified, stale, offline, on a
// public site (private_site=false). Every durable status must be asserted in
// text/shape, never color-only.
const { test, expect } = require('playwright/test');

test.describe('public home', () => {
  test('renders the four durable states with text, shape and risk', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h1')).toBeVisible();

    const cards = page.locator('[data-card]');
    await expect(cards).toHaveCount(4);

    const statuses = await cards.evaluateAll((els) =>
      els.map((el) => el.getAttribute('data-status'))
    );
    expect(statuses.sort()).toEqual(['offline', 'stale', 'unverified', 'verified']);

    // Verified card labels its state in text (never color-only).
    const verified = page.locator('[data-card][data-status="verified"]');
    await expect(verified.locator('[data-status-label]')).toContainText(/已?验证|Verified/);

    // Unverified card continuously shows a risk note.
    const unverified = page.locator('[data-card][data-status="unverified"]');
    await expect(unverified.locator('[data-risk-note]')).toHaveText(/\S+/);

    // Offline card is grayed (status-bad) and shows red indicator shape.
    const offline = page.locator('[data-card][data-status="offline"]');
    await expect(offline).toHaveClass(/status-bad/);
    await expect(offline.locator('.status-shape')).toHaveClass(/shape-bad/);
    await expect(offline.locator('[data-status-label]')).toContainText(/离线|Offline/);

    // Stale card shows its text label and warn shape.
    const stale = page.locator('[data-card][data-status="stale"]');
    await expect(stale).toHaveClass(/status-warn/);
    await expect(stale.locator('[data-status-label]')).toContainText(/过期|Stale/);
  });

  test('verified card is the only default-clickable link and points at the published URL', async ({ page }) => {
    await page.goto('/');
    const openLinks = page.locator('a[data-open]');
    await expect(openLinks).toHaveCount(1);
    await expect(openLinks).toHaveAttribute('href', 'https://web.example.com');
    const clickable = await page.locator('[data-card][data-clickable="true"]').count();
    expect(clickable).toBe(1);
  });

  test('unverified card opens only after an explicit risk confirmation', async ({ page }) => {
    await page.goto('/');
    const unverified = page.locator('[data-card][data-status="unverified"]');
    await expect(unverified.locator('a[data-open]')).toHaveCount(0);
    const riskBtn = unverified.locator('[data-open-any]');
    await expect(riskBtn).toBeVisible();
    await riskBtn.click();
    const revealed = unverified.locator('a[data-open]');
    await expect(revealed).toHaveCount(1);
    await expect(revealed).toHaveAttribute('href', 'https://files.example.com');
  });

  test('offline card keeps the last address and copies it only after a risk confirm', async ({ page }) => {
    await page.goto('/');
    const offline = page.locator('[data-card][data-status="offline"]');
    await expect(offline.locator('[data-last-address]')).toHaveText('nas.example.com');

    let confirmed = false;
    page.once('dialog', (dialog) => {
      confirmed = dialog.message().length > 0;
      dialog.accept();
    });
    await offline.locator('[data-copy-address]').click();
    expect(confirmed).toBe(true);
    await expect(offline.locator('[data-copy-address]')).toHaveText(/已复制|Copied/);
  });

  test('category navigation filters cards and "all" restores them', async ({ page }) => {
    await page.goto('/');
    await page.locator('[data-cat]').getByText('工作 Work').click();
    const visible = await page.locator('[data-card]:visible').count();
    expect(visible).toBe(2);
    await page.locator('[data-cat]').getByText('全部').click();
    await expect(page.locator('[data-card]')).toHaveCount(4);
  });

  test('mobile category strip becomes a horizontally scrolling rail', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    const strip = page.locator('[data-cat-nav]');
    const style = await strip.evaluate((el) => getComputedStyle(el));
    expect(style.flexDirection).toBe('row');
    expect(style.overflowX).toBe('auto');
    await expect(page.locator('[data-card]')).toHaveCount(4);
  });
});