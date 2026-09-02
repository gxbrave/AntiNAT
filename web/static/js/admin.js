/* Admin shell controller (P17 Story 3). Vanilla JS, no framework.
   Story 2: login form submission. Story 3 adds the four-tab shell, loading of
   panes over the frozen API, durable status labels, SSE reconnect, and
   destructive dialogs (Story 6). */
(function () {
  'use strict';

  var t = function (key) {
    if (window.I18N && Object.prototype.hasOwnProperty.call(window.I18N, key)) return window.I18N[key];
    return key;
  };

  function byData(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  /* --- Login form --- */
  function initLogin() {
    var form = document.querySelector('[data-login-form]');
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var user = form.querySelector('[data-login-user]').value.trim();
      var pass = form.querySelector('[data-login-pass]').value;
      var error = form.querySelector('[data-login-error]');
      var submit = form.querySelector('[data-login-submit]');
      if (!user || !pass) {
        error.textContent = t('admin.login.error') + ' ' + t('admin.login.username');
        setHidden(error, false);
        return;
      }
      submit.disabled = true;
      fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
        credentials: 'same-origin'
      }).then(function (resp) {
        if (resp.ok) {
          window.location.reload();
          return;
        }
        return resp.json().then(function (body) {
          error.textContent = body && body.message ? body.message : t('admin.login.error');
          setHidden(error, false);
        });
      }).catch(function () {
        error.textContent = t('admin.login.error');
        setHidden(error, false);
      }).finally(function () {
        submit.disabled = false;
      });
    });
  }

  function setHidden(el, hidden) {
    if (hidden) el.setAttribute('hidden', '');
    else el.removeAttribute('hidden');
  }

  /* --- Story 3 minimum: tab switching + logout --- */
  function initTabs() {
    var tabsEl = document.querySelector('[data-tabs]');
    if (!tabsEl) return;
    var tabs = byData('[role="tab"]', tabsEl);
    var panes = byData('[data-pane]');

    function activate(tabName) {
      tabs.forEach(function (tab) {
        var active = tab.getAttribute('data-tab') === tabName;
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
        tab.tabIndex = active ? 0 : -1;
      });
      panes.forEach(function (pane) {
        var active = pane.getAttribute('data-pane') === tabName;
        pane.classList.toggle('is-active', active);
        setHidden(pane, !active);
      });
    }

    tabs.forEach(function (tab, idx) {
      tab.addEventListener('click', function () { activate(tab.getAttribute('data-tab')); });
      tab.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        var next = e.key === 'ArrowRight' ? (idx + 1) % tabs.length : (idx - 1 + tabs.length) % tabs.length;
        tabs[next].focus();
        activate(tabs[next].getAttribute('data-tab'));
      });
    });

    var logout = document.querySelector('[data-logout]');
    if (logout) {
      logout.addEventListener('click', function () {
        fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' }).finally(function () {
          window.location.href = '/admin';
        });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    initLogin();
    initTabs();
  });
})();