/* Shared admin runtime (P17 Story 3): i18n t(), a tiny DOM builder, the API
   fetch helper, and durable-state metadata. Vanilla JS, no framework. */
(function () {
  'use strict';

  window.antinat = window.antinat || {};

  function t(key) {
    if (window.I18N && Object.prototype.hasOwnProperty.call(window.I18N, key)) return window.I18N[key];
    return key;
  }

  /* h('div', {class:'x', onclick: fn}, [child...]) -> DOM node.
     Children: node, string (text), or array. User strings are always
     textContent (auto-escaped). */
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'html') el.innerHTML = v; // trusted structure only
        else if (k.indexOf('on') === 0 && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === 'data' && typeof v === 'object') setData(el, v);
        else if (k === 'hidden') { if (v) el.setAttribute('hidden', ''); }
        else el.setAttribute(k, typeof v === 'string' || typeof v === 'number' ? String(v) : v);
      }
    }
    if (children !== undefined && children !== null) addChildren(el, children);
    return el;
  }

  function setData(el, map) {
    for (var k in map) {
      if (Object.prototype.hasOwnProperty.call(map, k)) el.setAttribute('data-' + k, map[k]);
    }
  }

  function addChildren(el, children) {
    var list = Array.isArray(children) ? children : [children];
    list.forEach(function (c) {
      if (c === null || c === undefined) return;
      if (typeof c === 'string' || typeof c === 'number') el.appendChild(document.createTextNode(String(c)));
      else el.appendChild(c);
    });
  }

  function byData(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function setHidden(el, hidden) {
    if (!el) return;
    if (hidden) el.setAttribute('hidden', '');
    else el.removeAttribute('hidden');
  }

  /* API helper: fetch JSON with the session cookie. Returns
     {ok, status, data, etag}. On network error throws {status:0}. */
  async function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
    if (opts.headers) Object.assign(init.headers, opts.headers);
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(path, init);
    var text = await resp.text();
    var data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (e) { data = text; }
    }
    return { ok: resp.ok, status: resp.status, data: data, etag: resp.headers.get('ETag') };
  }

  /* Durable-state metadata: every state carries a CSS shape + a text lookup
     key, so no status is ever color-only. */
  var VOID = { key: 'state.unknown', shape: 'neutral' };
  var STATE_META = {
    verified: { key: 'home.verified', shape: 'ok' },
    unverified: { key: 'home.unverified', shape: 'warn' },
    stale: { key: 'home.stale', shape: 'warn' },
    offline: { key: 'state.offline', shape: 'bad' },
    failed: { key: 'state.failed', shape: 'bad' },
    delete_pending_offline: { key: 'home.deletePendingOffline', shape: 'bad' },
    unknown: VOID,
    ONLINE: { key: 'state.online', shape: 'ok' },
    OFFLINE: { key: 'state.offline', shape: 'bad' }
  };

  function stateMeta(name) {
    return STATE_META[name] || VOID;
  }

  /* statusLine renders <span class="status-line status-<shape>" data-status=..>
     with a shape glyph + translated label + optional detail. */
  function statusLine(status, detail) {
    var meta = stateMeta(status);
    return h('span', { class: 'status-line status-' + meta.shape, 'data-status': status },
      [h('span', { class: 'status-shape shape-' + meta.shape, 'aria-hidden': 'true' }),
       h('span', { class: 'status-label' }, t(meta.key)),
       detail ? h('span', { class: 'status-detail' }, detail) : null]);
  }

  /* evidenceChain renders the six-ring evidence rail from real states. */
  function evidenceChain(states) {
    var rail = h('ol', { class: 'evidence-rail', 'data-evidence-rail': '' });
    if (!states) return rail;
    var steps = [
      ['admin.detail.control', 'control_state'],
      ['admin.detail.listener', 'listener_state'],
      ['admin.detail.gatewayMapping', 'mapping_state'],
      ['admin.detail.stunKeepalive', 'keepalive_state'],
      ['admin.detail.wanVantage', 'wan_reachability_state'],
      ['admin.detail.target', 'target_health_state']
    ];
    steps.forEach(function (step) {
      var axisValue = states[step[1]];
      var tone = axisTone(step[1], axisValue);
      rail.appendChild(h('li', { class: 'rail-ring ring-' + tone, 'data-ring': step[1], 'data-value': axisValue || '' },
        [h('span', { class: 'ring-axis' }, t(step[0])),
         h('span', { class: 'ring-value' }, [h('span', { class: 'status-shape shape-' + tone, 'aria-hidden': 'true' }), axisValue || t('state.unknown')])]));
    });
    return rail;
  }

  function axisTone(axis, value) {
    if (!value) return 'neutral';
    var badVals = { listener_state: ['ERROR', 'STOPPED'], mapping_state: ['LOST', 'ERROR'], keepalive_state: ['LOST'], wan_reachability_state: ['REJECTED', 'TIMEOUT'], return_path_state: ['FAILED'], target_health_state: ['FAIL', 'UNSUPPORTED'], data_plane_state: ['ERROR'], control_state: ['OFFLINE'] };
    var warnVals = { listener_state: ['STARTING'], mapping_state: ['ACQUIRING', 'FIRST_HOP_MAPPED'], keepalive_state: ['DEGRADED'], wan_reachability_state: ['PROBING', 'NO_INDEPENDENT_VANTAGE', 'PROBE_INFRA_UNAVAILABLE', 'UNKNOWN'], target_health_state: ['SKIPPED'], data_plane_state: ['DEGRADED'], publication_state: ['PUBLISHED_UNVERIFIED', 'STALE'] };
    var okVals = { control_state: ['ONLINE'], listener_state: ['READY'], mapping_state: ['PUBLIC_CANDIDATE', 'NOT_REQUIRED'], keepalive_state: ['HEALTHY', 'NOT_REQUIRED'], wan_reachability_state: ['OPEN_FROM_VANTAGE'], return_path_state: ['VERIFIED', 'NOT_TESTED', 'UNKNOWN'], target_health_state: ['PASS'], data_plane_state: ['READY'], publication_state: ['PUBLISHED_VERIFIED', 'NONE'] };
    if (badVals[axis] && badVals[axis].indexOf(value) !== -1) return 'bad';
    if (warnVals[axis] && warnVals[axis].indexOf(value) !== -1) return 'warn';
    if (okVals[axis] && okVals[axis].indexOf(value) !== -1) return 'ok';
    return 'neutral';
  }

  /* deriveForwardStatus mirrors the home page logic against an API forwardView.
     Returns the durable aggregate name. */
  function deriveForwardStatus(fwd) {
    var states = fwd && fwd.states;
    if (!states) return 'unknown';
    if (states.control_state === 'OFFLINE') return 'offline';
    if (brokenAxis(states)) return 'failed';
    switch (states.publication_state) {
      case 'PUBLISHED_VERIFIED': return verifiedAxes(states) ? 'verified' : 'unverified';
      case 'PUBLISHED_UNVERIFIED': return 'unverified';
      case 'STALE': return 'stale';
      default: return states.wan_reachability_state ? 'unverified' : 'unknown';
    }
  }

  function brokenAxis(states) {
    return states.listener_state === 'ERROR' ||
      states.mapping_state === 'LOST' || states.mapping_state === 'ERROR' ||
      states.keepalive_state === 'LOST' ||
      states.wan_reachability_state === 'REJECTED' || states.wan_reachability_state === 'TIMEOUT' ||
      states.return_path_state === 'FAILED' ||
      states.target_health_state === 'FAIL' ||
      states.data_plane_state === 'ERROR';
  }

  function verifiedAxes(states) {
    return states.control_state === 'ONLINE' &&
      states.listener_state === 'READY' &&
      (states.mapping_state === 'PUBLIC_CANDIDATE' || states.mapping_state === 'NOT_REQUIRED') &&
      (states.keepalive_state === 'HEALTHY' || states.keepalive_state === 'NOT_REQUIRED') &&
      states.wan_reachability_state === 'OPEN_FROM_VANTAGE' &&
      states.return_path_state === 'VERIFIED' &&
      states.target_health_state === 'PASS' &&
      states.data_plane_state === 'READY';
  }

  function publishedURL(fwd) {
    var scheme = fwd.publish_scheme || 'http';
    var host = (fwd.published_host || '').trim();
    if (!host) return '';
    return scheme + '://' + host;
  }

  function isClickable(fwd) {
    return deriveForwardStatus(fwd) === 'verified';
  }

  function eventListeners() {
    var fns = [];
    function on(fn) { fns.push(fn); }
    function emit() {
      var args = arguments;
      fns.forEach(function (fn) { try { fn.apply(null, args); } catch (e) { /* per-listener guard */ } });
    }
    return { on: on, emit: emit };
  }

  window.antinat = {
    t: t,
    h: h,
    byData: byData,
    setHidden: setHidden,
    api: api,
    statusLine: statusLine,
    stateMeta: stateMeta,
    evidenceChain: evidenceChain,
    deriveForwardStatus: deriveForwardStatus,
    publishedURL: publishedURL,
    isClickable: isClickable,
    events: eventListeners()
  };
})();