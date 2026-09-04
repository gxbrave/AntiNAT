// @ts-check
// P17 Story 7: accessibility floor, responsive proof, and review screenshots.
const { test, expect } = require('playwright/test');

const ADMIN = {
  username: process.env.ANTINAT_TEST_USER || 'admin',
  password: process.env.ANTINAT_TEST_PASSWORD || ''
};

async function login(page) {
  await page.goto('/admin');
  if (await page.locator('[data-login-form]').isVisible()) {
    await page.fill('[data-login-user]', ADMIN.username);
    await page.fill('[data-login-pass]', ADMIN.password);
    await page.click('[data-login-submit]');
  }
  await expect(page.locator('[data-tabs]')).toBeVisible();
}

async function assertAccessibleControls(page) {
  const unnamed = await page.locator('button, input, select, textarea, a').evaluateAll((nodes) => nodes
    .filter((node) => {
      if (node.hasAttribute('hidden') || node.getAttribute('aria-hidden') === 'true') return false;
      if (node instanceof HTMLInputElement && node.type === 'hidden') return false;
      const name = node.getAttribute('aria-label') || node.getAttribute('title') || node.textContent ||
        (node.id && document.querySelector(`label[for="${CSS.escape(node.id)}"]`)?.textContent) || '';
      return !name.trim();
    })
    .map((node) => node.outerHTML.slice(0, 180)));
  expect(unnamed, 'every visible control needs an accessible name').toEqual([]);
}

test.describe('accessibility and review evidence', () => {
  test('keyboard focus, labels, reduced motion, and desktop screenshot', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await login(page);
    await assertAccessibleControls(page);
    await page.keyboard.press('Tab');
    const outline = await page.evaluate(() => {
      const active = document.activeElement;
      return active ? getComputedStyle(active).outlineStyle : 'none';
    });
    expect(outline).not.toBe('none');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--ac-duration').trim())).toBe('0ms');
    await page.screenshot({ path: 'evidence/p17-admin-desktop.png', fullPage: true });
  });

  test('mobile admin has no horizontal overflow and keeps controls usable', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);
    await page.locator('[data-tab="nodes"]').click();
    await assertAccessibleControls(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({ path: 'evidence/p17-admin-mobile.png', fullPage: true });
  });

  test('verified publication requires every evidence axis to be ready', async ({ page }) => {
    await login(page);
    const status = await page.evaluate(() => {
      const fwd = {
        states: {
          control_state: 'ONLINE',
          listener_state: 'STARTING',
          mapping_state: 'PUBLIC_CANDIDATE',
          keepalive_state: 'HEALTHY',
          wan_reachability_state: 'OPEN_FROM_VANTAGE',
          return_path_state: 'VERIFIED',
          target_health_state: 'PASS',
          publication_state: 'PUBLISHED_VERIFIED',
          data_plane_state: 'READY'
        }
      };
      return {
        aggregate: window.antinat.deriveForwardStatus(fwd),
        clickable: window.antinat.isClickable(fwd)
      };
    });
    expect(status.aggregate).not.toBe('verified');
    expect(status.clickable).toBeFalsy();
  });
});
