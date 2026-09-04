/* Admin shell controller (P17 Story 3 + Story 6): tab switching with lazy
   panes, SSE connect/reconnect status, a small dialog system, and a toast.
   Vanilla JS, no framework. */
(function () {
  'use strict';

  var U = window.antinat;
  var t = U.t, h = U.h, byData = U.byData, setHidden = U.setHidden, api = U.api;

  /* --- Toast (non-disruptive feedback; motion <<150ms, never only channel) --- */
  function initToast() {
    var host = document.createElement('div');
    host.className = 'toast-host';
    host.setAttribute('aria-live', 'polite');
    document.body.appendChild(host);
    window.antinat.toast = function (msg) {
      var el = h('div', { class: 'toast', role: 'status' }, msg);
      host.appendChild(el);
      setTimeout(function () {
        el.classList.add('is-leaving');
        setTimeout(function () { el.remove(); }, 160);
      }, 2200);
    };
  }

  /* --- Dialog system: focus trap + focus return --- */
  function initDialogs() {
    var root = h('div', { class: 'dialog-root', 'data-dialog-root': '' });
    root.hidden = true;
    document.body.appendChild(root);
    var lastFocus = null;
    var dialogEl = null;

    function open(opts) {
      lastFocus = document.activeElement;
      root.hidden = false;
      root.textContent = '';
      var body = h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'dlg-title', 'data-dialog': '' });
      var title = h('h2', { id: 'dlg-title', class: 'dialog-title', text: opts.title || '' });
      var closeX = h('button', { class: 'btn btn-quiet btn-small dlg-close', type: 'button', 'aria-label': t('admin.close'), text: '×' });
      closeX.addEventListener('click', close);
      var actions = h('div', { class: 'dialog-actions' });
      (opts.actions || []).forEach(function (a) { actions.appendChild(a); });
      body.appendChild(h('div', { class: 'dialog-head' }, [title, closeX]));
      body.appendChild(h('div', { class: 'dialog-body' }, opts.body || ''));
      body.appendChild(actions);
      root.appendChild(body);
      dialogEl = body;
      var first = body.querySelector('input, select, textarea, button');
      if (first) first.focus();
      document.addEventListener('keydown', trapKey, true);
    }

    function trapKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key !== 'Tab') return;
      var focusable = byData('input, select, textarea, button, [tabindex]:not([tabindex="-1"])', dialogEl || root);
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (!dialogEl || !dialogEl.contains(document.activeElement)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
        return;
      }
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    function close() {
      document.removeEventListener('keydown', trapKey, true);
      root.hidden = true;
      root.textContent = '';
      dialogEl = null;
      if (lastFocus && lastFocus.focus) lastFocus.focus();
      lastFocus = null;
    }

    function showActionError(el, resp, fallback) {
      el.textContent = (resp && resp.data && resp.data.message) ? String(resp.data.message) : fallback;
      setHidden(el, false);
    }

    function confirmForwardDelete(fwd) {
      var error = h('p', { class: 'form-error', 'data-dialog-error': '' });
      setHidden(error, true);
      var confirm = h('button', { class: 'btn btn-danger', type: 'button', 'data-dialog-confirm': '' }, t('dlg.confirm'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('dlg.cancel'));
      var body = h('div', { class: 'confirm-body' }, [
        h('p', { text: t('dlg.forwardDelete.body') }),
        h('p', { class: 'dialog-target', text: fwd && fwd.name ? String(fwd.name) : '' }),
        error
      ]);
      confirm.addEventListener('click', async function () {
        if (confirm.disabled) return;
        confirm.disabled = true;
        try {
          var response = await api('/api/v1/forwards/' + encodeURIComponent(fwd.id), {
            method: 'DELETE', headers: { 'If-Match': fwd.etag || '' }
          });
          if (!response.ok) {
            showActionError(error, response, t('admin.saveError'));
            return;
          }
          close();
          if (window.antinat.toast) window.antinat.toast(t('dlg.forwardDelete.queued'));
          window.location.reload();
        } catch (e) {
          error.textContent = e.message || t('admin.saveError');
          setHidden(error, false);
        } finally {
          confirm.disabled = false;
        }
      });
      cancel.addEventListener('click', close);
      open({ title: t('dlg.forwardDelete.title'), body: body, actions: [confirm, cancel] });
    }

    function confirmNodeDelete(node) {
      var error = h('p', { class: 'form-error', 'data-dialog-error': '' });
      setHidden(error, true);
      var normal = h('button', { class: 'btn btn-danger', type: 'button', 'data-delete-mode': 'normal' }, t('dlg.normalDelete'));
      var force = h('button', { class: 'btn btn-danger', type: 'button', 'data-delete-mode': 'force' }, t('dlg.forceDeleteAction'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('dlg.cancel'));
      var body = h('div', { class: 'confirm-body' }, [
        h('p', { text: t('dlg.nodeDelete.body') }),
        h('p', { class: 'dialog-target', text: node && node.name ? String(node.name) : '' }),
        h('p', { class: 'dialog-consequence', 'data-delete-consequence': 'force', text: t('dlg.forceDelete.body') }),
        node && node.control_state === 'OFFLINE' ? h('p', { class: 'dialog-consequence dialog-warning', 'data-delete-consequence': 'offline', text: t('dlg.offlinePending.note') }) : null,
        error
      ]);
      function deleteNode(mode, button) {
        return async function () {
          if (button.disabled) return;
          normal.disabled = true;
          force.disabled = true;
          try {
            var response = await api('/api/v1/nodes/' + encodeURIComponent(node.id) + '/delete', {
              method: 'POST', body: { mode: mode }
            });
            if (!response.ok) {
              showActionError(error, response, t('admin.saveError'));
              return;
            }
            close();
            if (window.antinat.toast) window.antinat.toast(mode === 'force' ? t('dlg.forceDelete.queued') : t('dlg.nodeDelete.queued'));
            window.location.reload();
          } catch (e) {
            error.textContent = e.message || t('admin.saveError');
            setHidden(error, false);
          } finally {
            normal.disabled = false;
            force.disabled = false;
          }
        };
      }
      normal.addEventListener('click', deleteNode('normal', normal));
      force.addEventListener('click', deleteNode('force', force));
      cancel.addEventListener('click', close);
      open({ title: t('dlg.nodeDelete.title'), body: body, actions: [normal, force, cancel] });
    }

    function editNode(node) {
      var input = h('input', { type: 'text', value: node.name || '', 'data-edit-node-name': '', 'aria-label': t('admin.name') });
      var error = h('p', { class: 'form-error', 'data-dialog-error': '' });
      setHidden(error, true);
      var save = h('button', { class: 'btn btn-primary', type: 'button' }, t('admin.save'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('admin.cancel'));
      var body = h('div', { class: 'field' }, [h('label', { text: t('admin.name') }), input, error]);
      save.addEventListener('click', async function () {
        var name = input.value.trim();
        if (!name) {
          error.textContent = t('admin.name') + ' ' + t('node.create.error');
          setHidden(error, false);
          return;
        }
        save.disabled = true;
        try {
          var response = await api('/api/v1/nodes/' + encodeURIComponent(node.id), {
            method: 'PATCH', body: { name: name }, headers: { 'If-Match': node.etag || '' }
          });
          if (!response.ok) {
            showActionError(error, response, t('admin.saveError'));
            return;
          }
          close();
          window.location.reload();
        } catch (e) {
          error.textContent = e.message || t('admin.saveError');
          setHidden(error, false);
        } finally {
          save.disabled = false;
        }
      });
      cancel.addEventListener('click', close);
      open({ title: t('admin.edit'), body: body, actions: [save, cancel] });
    }

    function editNavigation(row) {
      var isItem = !!row.category_id;
      var collection = isItem ? 'items' : 'categories';
      var name = h('input', { type: 'text', value: row.name || '', 'data-navigation-edit-name': '', 'aria-label': t('admin.name') });
      var description = h('input', { type: 'text', value: row.description || '', 'data-navigation-edit-description': '', 'aria-label': t('admin.description') });
      var error = h('p', { class: 'form-error', 'data-dialog-error': '' });
      setHidden(error, true);
      var fields = [h('div', { class: 'field' }, [h('label', { text: t('admin.name') }), name])];
      if (isItem) fields.push(h('div', { class: 'field' }, [h('label', { text: t('admin.description') }), description]));
      fields.push(error);
      var save = h('button', { class: 'btn btn-primary', type: 'button', 'data-navigation-edit-save': '' }, t('admin.save'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('admin.cancel'));
      save.addEventListener('click', async function () {
        if (!name.value.trim()) {
          error.textContent = t('admin.name') + ' ' + t('node.create.error');
          setHidden(error, false);
          return;
        }
        save.disabled = true;
        var payload = { name: name.value.trim() };
        if (isItem) payload.description = description.value;
        try {
          var response = await api('/api/v1/navigation/' + collection + '/' + encodeURIComponent(row.id), {
            method: 'PATCH', headers: { 'If-Match': row.etag || '' }, body: payload
          });
          if (!response.ok) {
            showActionError(error, response, t('admin.saveError'));
            return;
          }
          close();
          window.location.reload();
        } catch (e) {
          error.textContent = e.message || t('admin.saveError');
          setHidden(error, false);
        } finally {
          save.disabled = false;
        }
      });
      cancel.addEventListener('click', close);
      open({ title: t('admin.edit'), body: h('div', { class: 'navigation-edit-body' }, fields), actions: [save, cancel] });
    }

    function confirmNavigationDelete(row) {
      var isItem = !!row.category_id;
      var collection = isItem ? 'items' : 'categories';
      var error = h('p', { class: 'form-error', 'data-dialog-error': '' });
      setHidden(error, true);
      var confirm = h('button', { class: 'btn btn-danger', type: 'button', 'data-navigation-delete': '' }, t('dlg.confirm'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('dlg.cancel'));
      var body = h('div', { class: 'confirm-body' }, [
        h('p', { text: t('dlg.navigationDelete.body') }),
        h('p', { class: 'dialog-target', text: row.name || '' }),
        error
      ]);
      confirm.addEventListener('click', async function () {
        confirm.disabled = true;
        try {
          var response = await api('/api/v1/navigation/' + collection + '/' + encodeURIComponent(row.id), {
            method: 'DELETE', headers: { 'If-Match': row.etag || '' }
          });
          if (!response.ok) {
            showActionError(error, response, t('admin.saveError'));
            return;
          }
          close();
          window.location.reload();
        } catch (e) {
          error.textContent = e.message || t('admin.saveError');
          setHidden(error, false);
        } finally {
          confirm.disabled = false;
        }
      });
      cancel.addEventListener('click', close);
      open({ title: t('dlg.navigationDelete.title'), body: body, actions: [confirm, cancel] });
    }

    window.antinat.dialogs = {
      open: open,
      close: close,
      confirmForwardDelete: confirmForwardDelete,
      confirmNodeDelete: confirmNodeDelete,
      confirmNavigationDelete: confirmNavigationDelete,
      editNavigation: editNavigation,
      editNode: editNode
    };
  }

  /* --- Tab switching with lazy panes --- */
  function initTabs() {
    var tabsEl = document.querySelector('[data-tabs]');
    if (!tabsEl) return;
    var tabs = byData('[role="tab"]', tabsEl);
    var panes = byData('[data-pane]');
    var loaded = {};

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
        if (active && !loaded[tabName]) {
          loaded[tabName] = true;
          var fn = window.antinat.panes[tabName];
          if (fn) fn(pane);
        }
      });
    }

    var refreshTimer = null;
    window.antinat.refreshActivePane = function () {
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = setTimeout(function () {
        refreshTimer = null;
        var activePane = panes.find(function (pane) { return !pane.hidden; });
        if (!activePane) return;
        var activeName = activePane.getAttribute('data-pane');
        var refresh = window.antinat.panes[activeName];
        if (refresh) refresh(activePane);
      }, 100);
    };

    tabs.forEach(function (tab, idx) {
      tab.addEventListener('click', function () { activate(tab.getAttribute('data-tab')); });
      tab.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        var next = e.key === 'ArrowRight' ? (idx + 1) % tabs.length : (idx - 1 + tabs.length) % tabs.length;
        activate(tabs[next].getAttribute('data-tab'));
        tabs[next].focus();
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

    activate('home');
  }

  /* --- SSE: durable stream + status dot, EventSource auto-reconnect --- */
  function initSSE() {
    var dot = document.querySelector('[data-sse]');
    var log = document.querySelector('[data-sse-log]');
    if (!dot) return;
    var connected = false;

    function setState(state) {
      connected = state === 'connected';
      dot.setAttribute('data-sse-state', connected ? 'connected' : 'disconnected');
      dot.setAttribute('title', connected ? 'SSE connected' : 'SSE reconnecting');
      if (typeof window.antinat.events.emit === 'function') {
        window.antinat.events.emit('state', state);
      }
    }

    var es = new EventSource('/api/v1/events');
    function appendEvent(e) {
      if (log) {
        var li = document.createElement('li');
        var payload = String(e.data || '').replace(/[\\r\\n]+/g, ' ').slice(0, 240);
        li.textContent = (e.type && e.type !== 'message' ? e.type + ' ' : '') + payload;
        log.appendChild(li);
        while (log.childElementCount > 12) log.removeChild(log.firstChild);
      }
      setState('connected');
      if (typeof window.antinat.events.emit === 'function') window.antinat.events.emit('message', e);
      if (typeof window.antinat.refreshActivePane === 'function') window.antinat.refreshActivePane();
    }
    es.onopen = function () { setState('connected'); };
    es.onmessage = appendEvent;
    // EventSource dispatches frames with an `event:` field only to a listener
    // for that exact type; onmessage alone would silently drop durable admin
    // events. Keep this allowlist in sync with the server's admin event names.
    [
      'NODE_CREATED', 'NODE_UPDATED', 'NODE_DELETED',
      'IDEMPOTENCY_KEY_EXPIRED',
      'ENROLLMENT_BOUND', 'ENROLLMENT_REJECTED', 'ENROLLMENT_REPLAYED', 'ENROLLMENT_REBIND_REJECTED',
      'CONTROL_SESSION_ACTIVE', 'CONTROL_SESSION_CLOSED', 'CONTROL_HANDSHAKE_REJECTED',
      'CONTROL_FRAME_REJECTED', 'CONTROL_STATE_FAILED', 'CONTROL_STATUS_STALE',
      'CONTROL_RESULT_CORRELATION_ERROR', 'CONTROL_RESULT_INBOX_STATE_ERROR',
      'PROBE_RECEIPT_REJECTED', 'PROBE_SINK_ERROR', 'PROBE_STATE_ERROR',
      'PROBE_INBOX_STATE_ERROR', 'PROBE_ARM_CORRELATION_ERROR',
      'PROBE_RECEIPT_INBOX_ERROR', 'PROBE_RECEIPT_STATE_ERROR',
      'PROBE_RECEIPT_REJECTION_STATE_ERROR', 'PROBE_ARMED_STATE_ERROR',
      'HOOK_DELIVERY_RETRY', 'HOOK_DELIVERY_DROPPED', 'HOOK_DELIVERY_DLQED',
      'HOOK_DELIVERY_COALESCED', 'HOOK_DELIVERY_DROPPED_DUE_TO_DECOMMISSION',
      'HOOK_DECOMMISSION_MARKED'
    ].forEach(function (eventType) { es.addEventListener(eventType, appendEvent); });
    es.onerror = function () { setState('disconnected'); };
    window.antinat.sse = { close: function () { es.close(); }, isConnected: function () { return connected; } };
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

  document.addEventListener('DOMContentLoaded', function () {
    initToast();
    initDialogs();
    initLogin();
    initTabs();
    initSSE();
  });
})();