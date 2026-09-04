// @ts-check
// Private-site home RED tests (P17 Story 2). The test-browser.sh driver seeds
// private_site=true before this suite: an unauthenticated / must redirect to
// /admin (the login form), and after sign-in / renders the public directory.
const { test, expect } = require('playwright/test');

const ADMIN_USER = process.env.ANTINAT_TEST_USER || 'admin';
const ADMIN_PASSWORD = process.env.ANTINAT_TEST_PASSWORD || '';
const WRONG_PASSWORD = (ADMIN_PASSWORD || 'test') + '-wrong';

test.describe('private home', () => {
  test('unauthenticated / redirects to the sign-in page', async ({ page }) => {
    await page.goto('/');
    await page.waitForURL(/\/admin$/);
    await expect(page.locator('[data-login-form]')).toBeVisible();
  });

  test('sign-in succeeds and then / renders the public directory', async ({ page }) => {
    await page.goto('/admin');
    await page.fill('[data-login-user]', ADMIN_USER);
    await page.fill('[data-login-pass]', ADMIN_PASSWORD);
    await page.click('[data-login-submit]');
    // After login the shell reloads; expect the tab bar to appear.
    await expect(page.locator('[data-tabs]')).toBeVisible();
    // A signed-in session may now view home.
    await page.goto('/');
    await expect(page.locator('[data-cards]')).toBeVisible();
    await expect(page.locator('[data-card]')).toHaveCount(4);
  });

  test('wrong credentials stay on the sign-in form and show an error', async ({ page }) => {
    await page.goto('/admin');
    await page.fill('[data-login-user]', ADMIN_USER);
    await page.fill('[data-login-pass]', WRONG_PASSWORD);
    await page.click('[data-login-submit]');
    await expect(page.locator('[data-login-form]')).toBeVisible();
    await expect(page.locator('[data-login-error]')).not.toBeHidden();
  });
});