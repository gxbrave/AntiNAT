/* Home page behavior (P17 Story 2): category filtering, risk confirmation for
   unverified/stale/offline actions, and copy-last-address with explicit risk
   confirmation. Vanilla JS, no framework. */
(function () {
  'use strict';

  var t = function (key) {
    if (window.I18N && Object.prototype.hasOwnProperty.call(window.I18N, key)) return window.I18N[key];
    return key;
  };

  function byData(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function setHidden(el, hidden) {
    if (hidden) el.setAttribute('hidden', '');
    else el.removeAttribute('hidden');
  }

  /* Category filter (works both as the desktop left rail and mobile strip). */
  function initCategories() {
    var nav = document.querySelector('[data-cat-nav]');
    var cards = byData('[data-card]');
    if (!nav || !cards.length) return;

    function apply(catID) {
      var showAll = catID === 'all';
      cards.forEach(function (card) {
        var vis = showAll || card.getAttribute('data-category') === catID;
        setHidden(card, !vis);
      });
    }

    byData('.cat', nav).forEach(function (btn) {
      btn.addEventListener('click', function () {
        byData('.cat', nav).forEach(function (b) { b.classList.remove('is-active'); b.setAttribute('aria-pressed', 'false'); });
        btn.classList.add('is-active');
        btn.setAttribute('aria-pressed', 'true');
        apply(btn.getAttribute('data-cat'));
      });
    });
  }

  /* Risk confirmation: clicking the quiet "risk" button reveals the real open
     action in place. The unverified risk wording stays visible either way. */
  function initRiskActions() {
    byData('[data-open-any]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var href = btn.getAttribute('data-open-any');
        if (!href) return;
        var link = document.createElement('a');
        link.className = 'btn btn-primary';
        link.href = href;
        link.rel = 'noopener';
        link.target = '_blank';
        link.setAttribute('data-open', '');
        link.textContent = t('home.openAnyway');
        btn.replaceWith(link);
      });
    });
  }

  /* Copy last address: requires an explicit confirm (risk). Uses the async
     clipboard API with a manual-selection fallback. */
  function initCopyAddress() {
    byData('[data-copy-address]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (!window.confirm(t('home.copyConfirm'))) return;
        var value = btn.getAttribute('data-value') || '';
        function done() {
          btn.textContent = t('home.addressCopied');
          setTimeout(function () { btn.textContent = t('home.copyLastAddress'); }, 1600);
        }
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(value).then(done, function () { fallback(btn, value, done); });
        } else {
          fallback(btn, value, done);
        }
      });
    });
  }

  function fallback(btn, value, done) {
    try {
      var ta = document.createElement('textarea');
      ta.value = value;
      ta.setAttribute('readonly', '');
      ta.style.position = 'absolute';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      done();
    } catch (e) {
      var note = document.createElement('span');
      note.className = 'risk-note';
      note.textContent = t('home.copyConfirm');
      btn.parentNode.insertBefore(note, btn.nextSibling);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    initCategories();
    initRiskActions();
    initCopyAddress();
  });
})();