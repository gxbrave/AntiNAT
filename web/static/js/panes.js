/* Four admin panes (P17 Story 3): Home Settings, Forwards, Nodes, Global
   Settings. Pure vanilla JS over the frozen API. Every status renders as
   shape + text (never color-only); loading/error/empty states are explicit;
   long bilingual strings are textContent (escaped). */
(function () {
  'use strict';

  var U = window.antinat;
  var t = U.t, h = U.h, api = U.api, byData = U.byData, setHidden = U.setHidden;
  var statusLine = U.statusLine, deriveForwardStatus = U.deriveForwardStatus, publishedURL = U.publishedURL, isClickable = U.isClickable;

  function errorMessage(resp, fallback) {
    if (resp && resp.data && typeof resp.data === 'object' && resp.data.message) return String(resp.data.message);
    return fallback;
  }

  function requestError(resp, fallback) {
    var err = new Error(errorMessage(resp, fallback));
    err.status = resp && resp.status ? resp.status : 0;
    return err;
  }

  function dialogs() { return window.antinat.dialogs; }

  function renderWithState(el, fn) {
    el.textContent = '';
    el.appendChild(h('div', { class: 'pane-empty', 'data-pane-state': 'loading' }, t('admin.loading')));
    return Promise.resolve()
      .then(fn)
      .then(function (nodes) {
        el.textContent = '';
        if (!nodes || !nodes.length) {
          el.appendChild(h('div', { class: 'pane-empty', 'data-pane-state': 'empty' }, t('admin.empty')));
          return;
        }
        nodes.forEach(function (n) { if (n) el.appendChild(n); });
      })
      .catch(function (e) {
        el.textContent = '';
        el.appendChild(h('div', { class: 'pane-error', 'data-pane-state': 'error' },
          [h('p', { text: t('admin.error') + (e && e.status ? ' (' + e.status + ')' : '') }),
           h('button', { class: 'btn btn-primary', type: 'button', onclick: function () { renderWithState(el, fn); } }, t('admin.retry'))]));
      });
  }

  function valueOf(el) { return el && el.value !== undefined ? el.value : ''; }

  /* ============ Home Settings ============ */
  function homeSettingsPane(el) {
    renderWithState(el, async function () {
      var catsResp = await api('/api/v1/navigation/categories');
      var itemsResp = await api('/api/v1/navigation/items');
      var fwdResp = await api('/api/v1/forwards?page=1&page_size=200');
      if (!catsResp.ok) throw requestError(catsResp, t('admin.error'));
      if (!itemsResp.ok) throw requestError(itemsResp, t('admin.error'));
      if (!fwdResp.ok) throw requestError(fwdResp, t('admin.error'));
      var cats = catsResp.data || [];
      var items = itemsResp.data || [];
      var forwards = (fwdResp.data && fwdResp.data.items) || [];

      var byCat = {};
      cats.forEach(function (c) { byCat[c.id] = []; });
      items.forEach(function (it) { (byCat[it.category_id] = byCat[it.category_id] || []).push(it); });

      var root = h('div', { class: 'home-settings' });
      root.appendChild(h('div', { class: 'panel-title' }, t('admin.tab.home')));

      /* Add category */
      var newCatName = h('input', { type: 'text', 'data-new-cat': '', placeholder: t('admin.name'), 'aria-label': t('admin.name') });
      var addCat = h('button', { class: 'btn btn-primary btn-small', type: 'button' }, t('admin.create'));
      addCat.addEventListener('click', async function () {
        var name = valueOf(newCatName).trim();
        if (!name) return;
        var nextCategoryOrder = cats.reduce(function (max, category) { return Math.max(max, Number(category.order_index) || 0); }, -1) + 1;
        // Idempotency-Key is required for creates.
        var resp = await api('/api/v1/navigation/categories', {
          method: 'POST',
          body: { name: name, order_index: nextCategoryOrder },
          headers: { 'Idempotency-Key': 'nav-cat-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10) }
        });
        if (resp.ok) reload();
      });
      root.appendChild(h('div', { class: 'inline-form' }, [newCatName, addCat]));

      /* Add item */
      var newItemName = h('input', { type: 'text', 'data-new-item': '', placeholder: t('admin.name'), 'aria-label': t('admin.name') });
      var newItemDesc = h('input', { type: 'text', 'data-new-desc': '', placeholder: t('admin.description'), 'aria-label': t('admin.description') });
      var catSel = h('select', { 'data-new-cat-sel': '', 'aria-label': t('admin.category') });
      cats.forEach(function (c) { catSel.appendChild(h('option', { value: c.id }, c.name)); });
      var fwdSel = h('select', { 'data-new-fwd-sel': '', 'aria-label': t('admin.forward') });
      forwards.forEach(function (f) { fwdSel.appendChild(h('option', { value: f.id }, f.name + ' [' + f.id + ']')); });
      var addItem = h('button', { class: 'btn btn-primary btn-small', type: 'button' }, t('admin.create'));
      addItem.addEventListener('click', async function () {
        var name = valueOf(newItemName).trim();
        if (!name) return;
        var categoryItems = byCat[catSel.value] || [];
        var nextItemOrder = categoryItems.reduce(function (max, item) { return Math.max(max, Number(item.order_index) || 0); }, -1) + 1;
        var resp = await api('/api/v1/navigation/items', {
          method: 'POST',
          body: { name: name, description: valueOf(newItemDesc).trim(), category_id: catSel.value, forward_id: fwdSel.value, order_index: nextItemOrder },
          headers: { 'Idempotency-Key': 'nav-item-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10) }
        });
        if (resp.ok) reload();
      });
      root.appendChild(h('div', { class: 'inline-form' }, [newItemName, newItemDesc, catSel, fwdSel, addItem]));

      /* Category list with per-category items + reorder + delete */
      cats.forEach(function (c, ci) {
        var itemRows = (byCat[c.id] || []).map(function (it, ii) {
          var up = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-icon': '^', 'data-nav-action': 'item-up', title: t('admin.moveUp'), 'aria-label': t('admin.moveUp') });
          var down = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-icon': 'v', 'data-nav-action': 'item-down', title: t('admin.moveDown'), 'aria-label': t('admin.moveDown') });
          var edit = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-icon': '…', 'data-nav-action': 'item-edit', title: t('admin.edit'), 'aria-label': t('admin.edit') });
          var del = h('button', { class: 'btn btn-quiet btn-small btn-danger-text', type: 'button', 'data-icon': '×', 'data-nav-action': 'item-delete', title: t('admin.delete'), 'aria-label': t('admin.delete') });
          bindItemOrder(up, it, -1, byCat[c.id] || []);
          bindItemOrder(down, it, 1, byCat[c.id] || []);
          bindItemEdit(edit, it);
          bindItemDelete(del, it);
          return h('li', { class: 'nav-item', 'data-nav-item': it.id },
            [h('span', { class: 'nav-item-name', text: it.name }),
             h('span', { class: 'nav-item-actions' }, [up, down, edit, del])]);
        });
        var box = h('section', { class: 'admin-panel', 'data-cat': c.id, draggable: 'true' },
          [h('div', { class: 'panel-title' }, [h('span', { text: c.name }),
             h('span', { class: 'panel-actions' }, [
               categoryAction(c, 'up', ci > 0),
               categoryAction(c, 'down', ci + 1 < cats.length),
               categoryAction(c, 'edit', true),
               categoryAction(c, 'delete', true)
             ])]),
           h('ol', { class: 'nav-items', 'data-sortable-category': c.id }, itemRows)]);
        box.addEventListener('dragstart', function (event) {
          if (event.target !== box) return;
          event.dataTransfer.setData('text/plain', c.id);
          event.dataTransfer.effectAllowed = 'move';
        });
        box.addEventListener('dragover', function (event) { event.preventDefault(); });
        box.addEventListener('drop', function (event) {
          event.preventDefault();
          var movedID = event.dataTransfer.getData('text/plain');
          var moved = cats.find(function (candidate) { return candidate.id === movedID; });
          if (!moved || moved.id === c.id) return;
          var current = cats.slice();
          var from = current.findIndex(function (candidate) { return candidate.id === movedID; });
          var to = current.findIndex(function (candidate) { return candidate.id === c.id; });
          current.splice(from, 1); current.splice(to, 0, moved);
          persistOrder('/api/v1/navigation/categories/', current, 'category');
        });
        root.appendChild(box);
      });

      /* Live preview: the same durable cards the public home renders. */
      var preview = h('section', { class: 'admin-panel', 'data-preview': '' },
        [h('div', { class: 'panel-title' }, t('admin.previewTitle'))]);
      items.forEach(function (it) {
        var fwd = forwards.find(function (f) { return f.id === it.forward_id; });
        var card = h('article', { class: 'card status-' + statusShape(fwd), 'data-preview-card': '' });
        card.appendChild(h('h4', { text: it.name }));
        if (it.description) card.appendChild(h('p', { class: 'card-desc', text: it.description }));
        if (fwd) card.appendChild(statusLine(deriveForwardStatus(fwd)));
        preview.appendChild(card);
      });
      root.appendChild(preview);

      return [root];
    });

    function statusShape(fwd) {
      if (!fwd) return 'neutral';
      var meta = U.stateMeta(deriveForwardStatus(fwd));
      return meta.shape;
    }

    function reload() { window.location.reload(); }

    function categoryAction(category, action, enabled) {
      var labels = { up: t('admin.moveUp'), down: t('admin.moveDown'), edit: t('admin.edit'), delete: t('admin.delete') };
      var button = h('button', {
        class: 'btn btn-quiet btn-small' + (action === 'delete' ? ' btn-danger-text' : ''),
        type: 'button', 'data-icon': action === 'delete' ? '×' : (action === 'edit' ? '…' : (action === 'up' ? '^' : 'v')),
        'data-nav-action': 'category-' + action, title: labels[action], 'aria-label': labels[action]
      });
      if (!enabled) button.disabled = true;
      button.addEventListener('click', function () {
        if (action === 'delete') {
          if (window.antinat.dialogs) window.antinat.dialogs.confirmNavigationDelete(category);
          return;
        }
        if (action === 'edit') {
          if (window.antinat.dialogs) window.antinat.dialogs.editNavigation(category);
          return;
        }
        moveNavigationCategory(category, catsForMove(), action === 'up' ? -1 : 1);
      });
      return button;
    }

    function catsForMove() {
      return Array.prototype.slice.call(root.querySelectorAll('[data-cat]')).map(function (box) {
        var original = cats.find(function (category) { return category.id === box.getAttribute('data-cat'); }) || {};
        return Object.assign({}, original, { id: box.getAttribute('data-cat'), order_index: Array.prototype.indexOf.call(root.querySelectorAll('[data-cat]'), box) });
      });
    }

    async function moveNavigationCategory(category, current, delta) {
      var index = current.findIndex(function (c) { return c.id === category.id; });
      var target = index + delta;
      if (index < 0 || target < 0 || target >= current.length) return;
      var ordered = current.slice();
      var tmp = ordered[index]; ordered[index] = ordered[target]; ordered[target] = tmp;
      await persistOrder('/api/v1/navigation/categories/', ordered, 'category');
    }

    async function persistOrder(prefix, ordered, kind) {
      // The P15 API protects each row with If-Match and enforces unique order
      // indexes. Move every row to a disjoint temporary range first, then to
      // its final position; this avoids a transient duplicate-order conflict.
      var tempBase = 1000000 + Date.now() % 100000;
      for (var i = 0; i < ordered.length; i++) {
        var row = ordered[i];
        var id = row.id;
        var etag = row.etag || '"rev-1"';
        var first = await api(prefix + id, { method: 'PATCH', headers: { 'If-Match': etag }, body: { order_index: tempBase + i } });
        if (!first.ok) { if (window.antinat.toast) window.antinat.toast(errorMessage(first, t('admin.saveError'))); return; }
        ordered[i] = Object.assign({}, row, { etag: first.data && first.data.etag, order_index: i });
      }
      for (var j = 0; j < ordered.length; j++) {
        var finalRow = ordered[j];
        var second = await api(prefix + finalRow.id, { method: 'PATCH', headers: { 'If-Match': finalRow.etag || '' }, body: { order_index: j } });
        if (!second.ok) { if (window.antinat.toast) window.antinat.toast(errorMessage(second, t('admin.saveError'))); return; }
      }
      reload();
    }

    function bindItemOrder(button, item, delta, itemsForCategory) {
      button.disabled = (delta < 0 && itemsForCategory[0] === item) || (delta > 0 && itemsForCategory[itemsForCategory.length - 1] === item);
      button.addEventListener('click', function () {
        var index = itemsForCategory.findIndex(function (candidate) { return candidate.id === item.id; });
        var target = index + delta;
        if (index < 0 || target < 0 || target >= itemsForCategory.length) return;
        var ordered = itemsForCategory.slice();
        var tmp = ordered[index]; ordered[index] = ordered[target]; ordered[target] = tmp;
        persistOrder('/api/v1/navigation/items/', ordered, 'item');
      });
    }

    function bindItemDelete(button, item) {
      button.addEventListener('click', function () {
        if (window.antinat.dialogs) window.antinat.dialogs.confirmNavigationDelete(item);
      });
    }

    function bindItemEdit(button, item) {
      button.addEventListener('click', function () {
        if (window.antinat.dialogs) window.antinat.dialogs.editNavigation(item);
      });
    }
  }

  /* ============ Forwards ============ */
  function forwardsPane(el) {
    renderWithState(el, async function () {
      var fwdResp = await api('/api/v1/forwards?page=1&page_size=200');
      var nodeResp = await api('/api/v1/nodes?page=1&page_size=200');
      if (!fwdResp.ok) throw requestError(fwdResp, t('admin.error'));
      if (!nodeResp.ok) throw requestError(nodeResp, t('admin.error'));
      var forwards = (fwdResp.data && fwdResp.data.items) || [];
      var nodes = (nodeResp.data && nodeResp.data.items) || [];

      var byNode = {};
      forwards.forEach(function (f) { (byNode[f.node_id] = byNode[f.node_id] || []).push(f); });

      var groups = [];
      nodes.forEach(function (n) {
        if (byNode[n.id]) groups.push([n, byNode[n.id]]);
      });
      Object.keys(byNode).forEach(function (nid) {
        if (!nodes.find(function (n) { return n.id === nid; })) groups.push([{ id: nid, name: nid, control_state: 'UNKNOWN' }, byNode[nid]]);
      });

      var create = h('button', { class: 'btn btn-primary', type: 'button', 'data-forward-create': '' }, t('forward.create'));
      create.addEventListener('click', function () { openForwardCreateDialog(nodes); });
      var out = [h('div', { class: 'pane-toolbar' }, [
        h('div', { class: 'pane-heading' }, [h('h2', { text: t('admin.tab.forwards') }), h('p', { class: 'field-hint', text: t('forward.listHint') })]),
        create
      ])];
      if (!groups.length) return out.concat([h('div', { class: 'pane-empty', 'data-pane-state': 'empty' }, t('forward.empty'))]);
      groups.forEach(function (g) {
        var node = g[0];
        var list = h('ul', { class: 'fwd-list', 'data-fwd-group': node.id });
        g[1].forEach(function (fwd) { list.appendChild(forwardCard(fwd)); });
        out.push(h('section', { class: 'fwd-group', 'data-fwd-node': node.id },
          [h('div', { class: 'group-head' }, [h('h3', { text: node.name }),
             statusLine(node.control_state || 'unknown')]),
           list]));
      });
      return out;
    });
  }

  function forwardCard(fwd) {
    var status = deriveForwardStatus(fwd);
    var url = publishedURL(fwd);
    var card = h('article', { class: 'fwd-card', 'data-fwd': fwd.id, 'data-status': status, 'data-clickable': isClickable(fwd) ? 'true' : 'false' });

    card.appendChild(h('div', { class: 'fwd-top' },
      [h('div', { class: 'fwd-title' }, [h('h4', { text: fwd.name }), h('code', { text: fwd.id })]),
       statusLine(status)]));

    var meta = h('div', { class: 'fwd-meta' });
    row(meta, t('admin.protocol'), fwd.protocol);
    row(meta, t('admin.detail.target'), fwd.target || '—');
    row(meta, t('admin.strategy'), fwd.strategy || '—');
    row(meta, t('admin.publishedUrl'), url || '—');
    if (fwd.requested_local_port) row(meta, t('admin.localPort'), String(fwd.requested_local_port));
    if (fwd.requested_public_port) row(meta, t('admin.publicPort'), String(fwd.requested_public_port));
    if (fwd.rate_limit_bps) row(meta, t('admin.rateLimit'), String(fwd.rate_limit_bps) + ' bps');
    row(meta, t('admin.detailedStats'), fwd.detailed_stats ? t('admin.yes') : t('admin.no'));
    card.appendChild(meta);

    var detailBtn = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-action': 'detail', 'aria-expanded': 'false' }, t('admin.detail'));
    var editBtn = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-action': 'edit' }, t('admin.edit'));
    var delBtn = h('button', { class: 'btn btn-quiet btn-small btn-danger-text', type: 'button', 'data-action': 'delete' }, t('admin.delete'));
    var actions = h('div', { class: 'actions' }, [detailBtn, editBtn, delBtn]);
    card.appendChild(actions);

    editBtn.addEventListener('click', function () { editForwardDialog(fwd).then(function () { forwardsPane(card.parentElement && card.parentElement.closest('[data-pane="forwards"]')); }); });
    delBtn.addEventListener('click', function () {
      if (window.antinat.dialogs) window.antinat.dialogs.confirmForwardDelete(fwd);
    });
    detailBtn.addEventListener('click', function () {
      toggleDetail(card, fwd);
      detailBtn.setAttribute('aria-expanded', card.querySelector('[data-fwd-detail]') ? 'true' : 'false');
    });
    return card;

    function row(el, label, value) {
      el.appendChild(h('div', { class: 'meta-row' }, [h('span', { class: 'meta-label' }, label), h('span', { class: 'meta-value' }, String(value))]));
    }
  }

  function toggleDetail(card, fwd) {
    var existing = card.querySelector('[data-fwd-detail]');
    if (existing) { existing.remove(); return; }
    var states = fwd.states || null;
    var detail = h('div', { class: 'fwd-detail', 'data-fwd-detail': '' });
    if (!states) {
      detail.appendChild(h('p', { class: 'pane-empty' }, t('admin.empty')));
    } else {
      detail.appendChild(h('div', { class: 'evidence-summary' }, [h('span', { 'aria-hidden': 'true' }), t('admin.detail.derived')]));
      detail.appendChild(U.evidenceChain(states, fwd));
      detail.appendChild(h('div', { class: 'advanced', 'data-advanced': '' },
        [h('details', null, [h('summary', { text: t('admin.detail.advanced') }),
          h('div', { class: 'advanced-body' }, advancedRows(states))])]));
    }
    card.appendChild(detail);
  }

  function advancedRows(states) {
    var rows = [
      ['publication_state', states.publication_state],
      ['return_path_state', states.return_path_state],
      ['data_plane_state', states.data_plane_state]
    ];
    return rows.map(function (r) {
      return h('div', { class: 'meta-row' }, [h('span', { class: 'meta-label' }, r[0]), h('span', { class: 'meta-value mono' }, r[1] || '—')]);
    });
  }

  function editForwardDialog(fwd) {
    return new Promise(function (resolve) {
      var name = h('input', { type: 'text', value: fwd.name, 'data-edit-name': '', 'aria-label': t('admin.name') });
      var target = h('input', { type: 'text', value: fwd.target || '', 'data-edit-target': '', 'aria-label': t('admin.detail.target') });
      var save = h('button', { class: 'btn btn-primary', type: 'button' }, t('admin.save'));
      var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('admin.cancel'));
      var bodyError = h('p', { class: 'form-error', 'data-edit-forward-error': '' });
      setHidden(bodyError, true);
      var body = h('div', { class: 'field' }, [h('label', { text: t('admin.name') }), name,
        h('label', { text: t('admin.detail.target') }), target, bodyError]);
      save.addEventListener('click', async function () {
        if (save.disabled) return;
        var payload = {};
        if (name.value.trim() && name.value.trim() !== fwd.name) payload.name = name.value.trim();
        if (target.value.trim() && target.value.trim() !== (fwd.target || '')) payload.target = target.value.trim();
        if (Object.keys(payload).length) {
          save.disabled = true;
          try {
            var response = await api('/api/v1/forwards/' + encodeURIComponent(fwd.id), { method: 'PATCH', body: payload, headers: { 'If-Match': fwd.etag } });
            if (!response.ok) {
              bodyError.textContent = errorMessage(response, t('admin.saveError'));
              setHidden(bodyError, false);
              return;
            }
          } catch (e) {
            bodyError.textContent = e.message || t('admin.saveError');
            setHidden(bodyError, false);
            return;
          } finally {
            save.disabled = false;
          }
        }
        window.antinat.dialogs.close();
        resolve();
      });
      cancel.addEventListener('click', function () { window.antinat.dialogs.close(); resolve(); });
      window.antinat.dialogs.open({ title: t('admin.edit'), body: body, actions: [save, cancel] });
    });
  }

  function openForwardCreateDialog(nodes) {
    if (!nodes || !nodes.length) {
      if (window.antinat.toast) window.antinat.toast(t('forward.noNodes'));
      return;
    }
    var node = h('select', { 'data-forward-field': 'node_id' });
    nodes.forEach(function (n) { node.appendChild(h('option', { value: n.id }, n.name + ' [' + n.id + ']')); });
    var name = h('input', { type: 'text', 'data-forward-field': 'name', autocomplete: 'off' });
    var protocol = h('select', { 'data-forward-field': 'protocol' });
    protocol.appendChild(h('option', { value: 'tcp' }, t('home.protocolTcp')));
    protocol.appendChild(h('option', { value: 'udp' }, t('home.protocolUdp')));
    var target = h('input', { type: 'text', 'data-forward-field': 'target', placeholder: '192.0.2.10:8080', spellcheck: 'false' });
    var strategy = h('select', { 'data-forward-field': 'strategy' });
    [['auto', 'auto'], ['direct-v4', 'direct-v4'], ['manual-static-v4', 'manual-static-v4'], ['explicit-gateway', 'explicit-gateway'], ['stun-only', 'stun-only']].forEach(function (item) {
      strategy.appendChild(h('option', { value: item[0] }, item[1]));
    });
    var scheme = h('select', { 'data-forward-field': 'publish_scheme' });
    scheme.appendChild(h('option', { value: '' }, t('forward.noPublishedURL')));
    scheme.appendChild(h('option', { value: 'http' }, 'http'));
    scheme.appendChild(h('option', { value: 'https' }, 'https'));
    var publishedHost = h('input', { type: 'text', 'data-forward-field': 'published_host', placeholder: 'service.example.com' });
    var form = h('div', { class: 'settings-form' });
    add('forward.node', node); add('admin.name', name); add('admin.protocol', protocol);
    add('admin.detail.target', target); add('admin.strategy', strategy); add('forward.publishScheme', scheme); add('forward.publishedHost', publishedHost);
    var error = h('p', { class: 'form-error', 'data-forward-create-error': '' });
    setHidden(error, true);
    var save = h('button', { class: 'btn btn-primary', type: 'button', 'data-forward-create-submit': '' }, t('forward.create'));
    var cancel = h('button', { class: 'btn btn-quiet', type: 'button' }, t('admin.cancel'));
    save.addEventListener('click', async function () {
      if (save.disabled) return;
      if (!name.value.trim() || !target.value.trim()) {
        error.textContent = t('forward.required');
        setHidden(error, false);
        return;
      }
      save.disabled = true;
      try {
        var response = await api('/api/v1/forwards', {
          method: 'POST',
          body: {
            node_id: node.value, name: name.value.trim(), protocol: protocol.value,
            target: target.value.trim(), strategy: strategy.value,
            publish_scheme: scheme.value, published_host: publishedHost.value.trim()
          },
          headers: { 'Idempotency-Key': 'forward-create-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10) }
        });
        if (!response.ok) {
          error.textContent = errorMessage(response, t('forward.createError'));
          setHidden(error, false);
          return;
        }
        dialogs().close();
        window.location.reload();
      } catch (e) {
        error.textContent = e.message || t('forward.createError');
        setHidden(error, false);
      } finally {
        save.disabled = false;
      }
    });
    cancel.addEventListener('click', function () { dialogs().close(); });
    dialogs().open({ title: t('forward.create'), body: h('div', { class: 'forward-create-body' }, [form, error]), actions: [save, cancel] });

    function add(key, control) {
      if (!control.id) control.id = 'forward-' + key.replace(/[^a-z0-9_-]/gi, '-');
      var label = h('label', { text: t(key) });
      label.setAttribute('for', control.id);
      var field = h('div', { class: 'field' }, [label, control]);
      form.appendChild(field);
    }
  }

  /* ============ Nodes ============ */
  function nodesPane(el) {
    renderWithState(el, async function () {
      var nodeResp = await api('/api/v1/nodes?page=1&page_size=200');
      if (!nodeResp.ok) throw requestError(nodeResp, t('admin.error'));
      var nodes = (nodeResp.data && nodeResp.data.items) || [];

      var create = h('button', { class: 'btn btn-primary', type: 'button', 'data-node-create': '' }, t('node.create'));
      create.addEventListener('click', function () {
        if (window.antinat.deployment) window.antinat.deployment.openCreate();
      });
      var toolbar = h('div', { class: 'pane-toolbar' }, [
        h('div', { class: 'pane-heading' }, [h('h2', { text: t('admin.tab.nodes') }), h('p', { class: 'field-hint', text: t('node.listHint') })]),
        create
      ]);
      if (!nodes.length) return [toolbar, h('div', { class: 'pane-empty', 'data-node-empty': '' }, t('node.empty'))];

      var tbl = h('table', { class: 'data-table', 'data-nodes-table': '' });
      tbl.appendChild(h('caption', { text: t('admin.tab.nodes') }));
      tbl.appendChild(h('thead', null, h('tr', null,
        [h('th', { scope: 'col', text: t('admin.name') }), h('th', { scope: 'col', text: t('admin.status') }), h('th', { scope: 'col', text: t('admin.createdAt') }), h('th', { scope: 'col', text: t('admin.actions') })])));
      var tbody = h('tbody');
      nodes.forEach(function (n) { tbody.appendChild(nodeRow(n)); });
      tbl.appendChild(tbody);
      return [toolbar, h('div', { class: 'data-table-wrap' }, tbl)];
    });
  }

  function nodeRow(n) {
    var tr = h('tr', { 'data-node': n.id, 'data-status': n.control_state || 'unknown' });
    tr.appendChild(h('td', { class: 'node-name' }, n.name));
    tr.appendChild(h('td', null, statusLine(n.control_state || 'unknown')));
    tr.appendChild(h('td', { class: 'mono' }, n.created_at || ''));
    var deploy = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-action': 'deploy' }, t('node.deploy'));
    var reprobe = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-action': 'reprobe' }, t('node.reprobe'));
    var edit = h('button', { class: 'btn btn-quiet btn-small', type: 'button', 'data-action': 'edit' }, t('admin.edit'));
    var del = h('button', { class: 'btn btn-quiet btn-small btn-danger-text', type: 'button', 'data-action': 'delete' }, t('admin.delete'));
    var acts = h('td', { class: 'node-actions' }, [deploy, reprobe, edit, del]);
    tr.appendChild(acts);

    deploy.addEventListener('click', function () { if (window.antinat.deployment) window.antinat.deployment.open(n); });
    reprobe.addEventListener('click', async function () {
      reprobe.disabled = true;
      try {
        var resp = await api('/api/v1/nodes/' + encodeURIComponent(n.id) + '/traversal-detection', { method: 'POST' });
        if (resp.ok && window.antinat.toast) window.antinat.toast(resp.data && resp.data.operation_id ? t('node.detectStarted') + ' ' + resp.data.operation_id : t('node.detectStarted'));
        else if (window.antinat.toast) window.antinat.toast(errorMessage(resp, t('node.detectError')));
      } catch (e) {
        if (window.antinat.toast) window.antinat.toast(e.message || t('node.detectError'));
      } finally {
        reprobe.disabled = false;
      }
    });
    edit.addEventListener('click', function () { if (window.antinat.dialogs) window.antinat.dialogs.editNode(n); });
    del.addEventListener('click', function () { if (window.antinat.dialogs) window.antinat.dialogs.confirmNodeDelete(n); });
    return tr;
  }

  /* ============ Global Settings ============ */
  function globalSettingsPane(el) {
    renderWithState(el, async function () {
      var resp = await api('/api/v1/settings');
      if (!resp.ok) throw requestError(resp, t('admin.error'));
      var s = resp.data || {};
      var etag = resp.etag || (s.etag || '');

      var lang = h('select', { 'data-field': 'language', 'data-field-el': '' });
      lang.appendChild(h('option', { value: 'zh' }, t('admin.language.zh')));
      lang.appendChild(h('option', { value: 'en' }, t('admin.language.en')));
      lang.value = s.language || 'zh';

      var controllerEndpoint = h('input', { type: 'text', value: s.controller_endpoint || '', 'data-field': 'controller_endpoint', 'data-field-el': '', spellcheck: 'false' });
      var privateSite = h('input', { type: 'checkbox', 'data-field': 'private_site', checked: s.private_site ? 'checked' : null });
      var scheduler = h('input', { type: 'text', value: s.detection_scheduler || '', 'data-field': 'detection_scheduler', 'data-field-el': '' });
      var providerPin = h('input', { type: 'text', value: s.probe_provider_pin || '', 'data-field': 'probe_provider_pin', 'data-field-el': '' });
      var vantage = h('input', { type: 'text', value: s.probe_vantage || '', 'data-field': 'probe_vantage', 'data-field-el': '' });
      var retention = h('input', { type: 'number', min: '0', value: s.retention_days || 0, 'data-field': 'retention_days', 'data-field-el': '' });
      var updatePolicy = h('input', { type: 'text', value: s.update_policy || '', 'data-field': 'update_policy', 'data-field-el': '' });

      var form = h('div', { class: 'settings-form' });
      field(form, t('admin.language'), lang, 'language');
      field(form, t('admin.settings.controllerEndpoint'), controllerEndpoint, 'controller_endpoint');
      field(form, t('admin.settings.privateSite'), privateSite, 'private_site');
      field(form, t('admin.settings.scheduler'), scheduler, 'detection_scheduler');
      field(form, t('admin.settings.providerPin'), providerPin, 'probe_provider_pin');
      field(form, t('admin.settings.vantage'), vantage, 'probe_vantage');
      field(form, t('admin.settings.retention'), retention, 'retention_days');
      field(form, t('admin.settings.updatePolicy'), updatePolicy, 'update_policy');

      var statusEl = h('p', { class: 'form-error', 'data-settings-status': '' });
      var save = h('button', { class: 'btn btn-primary', type: 'button' }, t('admin.save'));
      save.addEventListener('click', async function () {
        if (save.disabled) return;
        var payload = {};
        byData('[data-field-el]', form).forEach(function (ctrl) {
          var name = ctrl.getAttribute('data-field');
          if (ctrl.type === 'checkbox') payload[name] = ctrl.checked;
          else if (name === 'retention_days') payload[name] = parseInt(ctrl.value, 10) || 0;
          else payload[name] = ctrl.value;
        });
        save.disabled = true;
        setHidden(statusEl, true);
        try {
          var out = await api('/api/v1/settings', { method: 'PUT', body: payload, headers: { 'If-Match': etag } });
          if (out.ok) {
            var previousLanguage = s.language || 'zh';
            etag = out.etag || (out.data && out.data.etag) || etag;
            s = Object.assign({}, s, payload, { etag: etag });
            statusEl.textContent = t('admin.saved');
            setHidden(statusEl, false);
            if (payload.language && payload.language !== previousLanguage) {
              setTimeout(function () { window.location.reload(); }, 350);
            }
          } else if (out.status === 412) {
            var fresh = await api('/api/v1/settings');
            if (fresh.ok && fresh.data) {
              etag = fresh.etag || fresh.data.etag || etag;
              statusEl.textContent = t('admin.saveConflict');
            } else {
              statusEl.textContent = t('admin.saveError') + ' (412)';
            }
            setHidden(statusEl, false);
          } else {
            statusEl.textContent = t('admin.saveError') + (out.status ? ' (' + out.status + ')' : '');
            setHidden(statusEl, false);
          }
        } catch (e) {
          statusEl.textContent = e.message || t('admin.saveError');
          setHidden(statusEl, false);
        } finally {
          save.disabled = false;
        }
      });

      var root = h('div', { class: 'global-settings' });
      root.appendChild(form);
      root.appendChild(h('div', { class: 'settings-actions' }, [save, statusEl]));
      return [root];
    });

    function field(root, labelText, ctrl, name) {
      var wrap = h('div', { class: 'field', 'data-field-group': name });
      if (!ctrl.id) ctrl.id = 'settings-' + name.replace(/[^a-z0-9_-]/gi, '-');
      var label = h('label');
      label.setAttribute('for', ctrl.id);
      label.textContent = labelText;
      if (ctrl.tagName === 'INPUT' && ctrl.type === 'checkbox') {
        var check = h('span', { class: 'check-wrap' }, ctrl);
        label.appendChild(check);
        wrap.appendChild(label);
      } else {
        wrap.appendChild(label);
        wrap.appendChild(ctrl);
      }
      root.appendChild(wrap);
    }
  }

  window.antinat.panes = {
    home: homeSettingsPane,
    homeSettings: homeSettingsPane,
    forwards: forwardsPane,
    nodes: nodesPane,
    global: globalSettingsPane,
    globalSettings: globalSettingsPane,
    renderWithState: renderWithState
  };
})();