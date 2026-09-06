// @ts-check
// P17 Story 7: accessibility floor, responsive proof, and review screenshots.
const { test, expect } = require('playwright/test');

const ADMIN = {
  username: process.env.ANTINAT_TEST_USER || 'admin',
  password: process.env.ANTINAT_TEST_PASSWORD || ''
};
const SCREENSHOT_DIR = process.env.ANTINAT_BROWSER_EVIDENCE_DIR || 'evidence';

function screenshotPath(name) {
  return `${SCREENSHOT_DIR}/${name}`;
}

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
    await page.screenshot({ path: screenshotPath('p17-admin-desktop.png'), fullPage: true });
  });

  test('mobile admin has no horizontal overflow and keeps controls usable', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);
    await page.locator('[data-tab="nodes"]').click();
    await assertAccessibleControls(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    const touchTargets = await page.locator('button:visible, [role="tab"]:visible, .cat:visible').evaluateAll((nodes) => nodes
      .map((node) => {
        const rect = node.getBoundingClientRect();
        return { label: node.textContent?.trim() || node.getAttribute('aria-label') || node.tagName, width: rect.width, height: rect.height };
      })
      .filter((item) => item.width < 44 || item.height < 44));
    expect(touchTargets, 'visible mobile controls must be at least 44x44').toEqual([]);
    await page.screenshot({ path: screenshotPath('p17-admin-mobile.png'), fullPage: true });
  });

  test('captures public and admin language evidence without retaining a token', async ({ page }) => {
    async function setLanguage(language) {
      const get = await page.evaluate(async () => {
        const response = await fetch('/api/v1/settings', { credentials: 'same-origin' });
        return { ok: response.ok, body: await response.json() };
      });
      expect(get.ok).toBeTruthy();
      const body = get.body;
      const etag = body.etag;
      delete body.etag;
      body.language = language;
      const put = await page.evaluate(async ({ body, etag }) => {
        const response = await fetch('/api/v1/settings', {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'If-Match': etag },
          body: JSON.stringify(body)
        });
        return response.ok;
      }, { body, etag });
      expect(put).toBeTruthy();
    }

    await login(page);
    await page.setViewportSize({ width: 1280, height: 800 });
    await setLanguage('zh');
    await page.goto('/');
    await expect(page.locator('[data-cards]')).toBeVisible();
    await page.screenshot({ path: screenshotPath('p17-home-zh.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: screenshotPath('p17-home-mobile.png'), fullPage: true });

    await setLanguage('en');
    await page.goto('/');
    await expect(page.locator('[data-cards]')).toBeVisible();
    await page.screenshot({ path: screenshotPath('p17-home-en.png'), fullPage: true });
    await page.goto('/admin');
    await expect(page.locator('[data-tabs]')).toBeVisible();
    await page.screenshot({ path: screenshotPath('p17-admin-en.png'), fullPage: true });
    await setLanguage('zh');
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
