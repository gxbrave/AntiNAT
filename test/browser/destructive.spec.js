// @ts-check
// P17 Story 6: consequence-exact destructive dialogs and focus behavior.
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

test.describe('destructive dialogs', () => {
  test('forward delete states immediate listener/connection consequences and returns focus on cancel', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="forwards"]').click();
    const deleteButton = page.locator('[data-fwd="fwd-verified"] [data-action="delete"]');
    await deleteButton.click();
    const dialog = page.locator('[data-dialog]');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(/立即关闭|immediately closes/);
    await expect(dialog).toContainText(/删除转发|Delete forward/);
    const dialogButtons = dialog.getByRole('button');
    await page.keyboard.press('Shift+Tab');
    await expect(dialogButtons.last()).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(dialogButtons.first()).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(deleteButton).toBeFocused();
  });

  test('normal and force node deletion have distinct consequences and offline warning', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="nodes"]').click();
    const offlineDelete = page.locator('[data-node="node-offline"] [data-action="delete"]');
    await offlineDelete.click();
    const dialog = page.locator('[data-dialog]');
    await expect(dialog).toContainText(/离线|offline/i);
    await expect(dialog.locator('[data-delete-mode="normal"]')).toContainText(/删除节点|Delete node/);
    await expect(dialog.locator('[data-delete-mode="force"]')).toContainText(/强制删除|Force delete/);
    await page.keyboard.press('Escape');

    const onlineDelete = page.locator('[data-node="node-online"] [data-action="delete"]');
    await onlineDelete.click();
    const bodyText = await dialog.textContent();
    expect(bodyText).toMatch(/remote cleanup is not confirmed|remote_cleanup_confirmed=false|远端残留需手动清理/);
    await expect(page.locator('[data-delete-mode="force"]')).toContainText(/强制删除|Force delete/);
    await page.keyboard.press('Escape');
  });

  test('a precondition failure keeps the dialog open with a recoverable error', async ({ page }) => {
    await login(page);
    await page.locator('[data-tab="forwards"]').click();
    await page.route('**/api/v1/forwards/fwd-verified', (route) =>
      route.fulfill({ status: 412, contentType: 'application/json', body: JSON.stringify({ code: 'PRECONDITION_FAILED', message: 'ETag mismatch', request_id: 'test' }) })
    );
    await page.locator('[data-fwd="fwd-verified"] [data-action="delete"]').click();
    await page.locator('[data-dialog-confirm]').click();
    await expect(page.locator('[data-dialog-error]')).toContainText(/ETag mismatch/);
    await expect(page.locator('[data-dialog]')).toBeVisible();
    await page.unroute('**/api/v1/forwards/fwd-verified');
    await page.keyboard.press('Escape');
  });
});
