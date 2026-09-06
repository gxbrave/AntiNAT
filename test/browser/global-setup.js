// Playwright global setup for authenticated suites. It deliberately creates
// one session per npx invocation so the product's login rate limiter remains
// enabled and the test suite does not spend its budget on repeated setup.
const { request } = require('playwright');

module.exports = async function globalSetup() {
  const statePath = process.env.ANTINAT_AUTH_STATE;
  if (!statePath) return;

  const api = await request.newContext({
    baseURL: process.env.ANTINAT_BASE_URL || 'http://127.0.0.1:3111',
  });
  try {
    const response = await api.post('/api/v1/auth/login', {
      data: {
        username: process.env.ANTINAT_TEST_USER || 'admin',
        password: process.env.ANTINAT_TEST_PASSWORD || ''
      },
    });
    if (!response.ok()) {
      throw new Error(`browser auth setup failed: HTTP ${response.status()}`);
    }
    await api.storageState({ path: statePath });
  } finally {
    await api.dispose();
  }
};
