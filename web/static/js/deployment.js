/* P17 Stories 4-5: node creation, deployment profile and safe command UI.
   The token is intentionally kept only in this closure and a one-time text
   surface. It is never part of the profile, command builder, URL, or storage. */
(function () {
  'use strict';

  var U = window.antinat;
  var t = U.t, h = U.h, api = U.api, setHidden = U.setHidden;
  var dialogs = function () { return window.antinat.dialogs; };

  var PLATFORM_LINUX = 'linux';
  var PLATFORM_WINDOWS = 'windows';
  var PLATFORM_DOCKER = 'docker';
  var defaultProfile = {
    platform: PLATFORM_LINUX,
    controller_endpoint: '',
    bind_interface: '',
    detection_scheduler: 'sequential',
    github_proxy: '',
    install_dir: '/opt/antinat',
    service_name: 'antinat-agent.service',
    log_level: 'info',
    auto_update: 'disabled'
  };

  function randomKey(prefix) {
    var suffix = Math.random().toString(36).slice(2, 12);
    return prefix + '-' + Date.now().toString(36) + '-' + suffix;
  }

  function errorMessage(resp, fallback) {
    if (resp && resp.data && typeof resp.data === 'object' && resp.data.message) return String(resp.data.message);
    return fallback;
  }

  function normalizeOptionalServiceURL(raw) {
    raw = String(raw || '').trim();
    if (!raw) return '';
    if (/[\u0000-\u001f\u007f\s]/.test(raw)) throw new Error(t('node.deploy.invalidUrl'));
    if (!raw.includes('://')) raw = 'https://' + raw;
    var parsed;
    try { parsed = new URL(raw); } catch (e) { throw new Error(t('node.deploy.invalidUrl')); }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error(t('node.deploy.invalidUrl'));
    if (!parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error(t('node.deploy.invalidUrl'));
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    return parsed.toString().replace(/\/$/, '');
  }

  function quoteShellArg(value) {
    return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
  }

  function quoteShellArgs(args) {
    return (args || []).map(quoteShellArg).join(' ');
  }

  function quotePowerShellArg(value) {
    return "'" + String(value).replace(/'/g, "''") + "'";
  }

  function encodePowerShellCommand(command) {
    // PowerShell -EncodedCommand consumes UTF-16LE. Encoding the complete
    // script removes the outer cmd.exe/PowerShell quote ambiguity for values
    // containing double quotes, $, backticks, or call operators.
    var bytes = '';
    for (var i = 0; i < command.length; i++) {
      var unit = command.charCodeAt(i);
      bytes += String.fromCharCode(unit & 0xff, (unit >> 8) & 0xff);
    }
    return btoa(bytes);
  }

  function validateText(name, value) {
    if (String(value || '').length > 1024 || /[\u0000-\u001f\u007f]/.test(String(value || ''))) {
      throw new Error(t('node.deploy.invalidProfile') + ': ' + name);
    }
  }

  function cloneProfile(profile) {
    var out = Object.assign({}, defaultProfile, profile || {});
    return out;
  }

  function validateProfile(profile) {
    profile = cloneProfile(profile);
    if ([PLATFORM_LINUX, PLATFORM_WINDOWS, PLATFORM_DOCKER].indexOf(profile.platform) < 0) {
      throw new Error(t('node.deploy.invalidProfile') + ': platform');
    }
    profile.controller_endpoint = normalizeOptionalServiceURL(profile.controller_endpoint);
    if (!profile.controller_endpoint) throw new Error(t('node.deploy.endpointRequired'));
    ['bind_interface', 'github_proxy', 'install_dir', 'service_name', 'detection_scheduler', 'log_level', 'auto_update'].forEach(function (key) {
      validateText(key, profile[key]);
    });
    if (profile.detection_scheduler !== 'sequential' && profile.detection_scheduler !== 'parallel') {
      throw new Error(t('node.deploy.invalidProfile') + ': detection_scheduler');
    }
    if (['debug', 'info', 'warn', 'error'].indexOf(profile.log_level) < 0) {
      throw new Error(t('node.deploy.invalidProfile') + ': log_level');
    }
    if (['disabled', 'manual', 'stable', 'enabled'].indexOf(profile.auto_update) < 0) {
      throw new Error(t('node.deploy.invalidProfile') + ': auto_update');
    }
    if (profile.github_proxy) profile.github_proxy = normalizeOptionalServiceURL(profile.github_proxy);
    return profile;
  }

  function buildAgentArguments(profile) {
    profile = validateProfile(profile);
    var args = ['--platform', profile.platform, '--controller-endpoint', profile.controller_endpoint];
    if (profile.bind_interface) args.push('--bind-interface', profile.bind_interface);
    args.push('--detection-scheduler', profile.detection_scheduler);
    args.push('--log-level', profile.log_level);
    args.push('--auto-update', profile.auto_update);
    if (profile.platform !== PLATFORM_DOCKER) {
      if (profile.github_proxy) args.push('--github-proxy', profile.github_proxy);
      if (profile.install_dir) args.push('--install-dir', profile.install_dir);
      if (profile.service_name) args.push('--service-name', profile.service_name);
    }
    return args;
  }

  function installerURL(profile) {
    var url = profile.platform === PLATFORM_WINDOWS
      ? 'https://github.com/gxbrave/AntiNAT/releases/latest/download/install.ps1'
      : 'https://github.com/gxbrave/AntiNAT/releases/latest/download/install.sh';
    if (profile.github_proxy && profile.platform !== PLATFORM_DOCKER) {
      url = profile.github_proxy.replace(/\/+$/, '') + '/' + url;
    }
    return url;
  }

  function buildInstallCommand(profile) {
    profile = validateProfile(profile);
    var args = buildAgentArguments(profile);
    if (profile.platform === PLATFORM_DOCKER) {
      var dockerArgs = [];
      for (var i = 0; i < args.length; i++) {
        if (args[i] === '--platform' && i + 1 < args.length) {
          dockerArgs.push('--platform ' + args[++i]);
        } else {
          dockerArgs.push(quoteShellArg(args[i]));
        }
      }
      return 'docker run --network host --restart=always --volume /var/lib/antinat:/var/lib/antinat ghcr.io/gxbrave/antinat-agent:latest ' + dockerArgs.join(' ');
    }
    if (profile.platform === PLATFORM_WINDOWS) {
      var psArgs = ['install'].concat(args.map(quotePowerShellArg));
      var body = '$script = (Invoke-WebRequest -UseBasicParsing -Uri ' + quotePowerShellArg(installerURL(profile)) + ').Content; & ([scriptblock]::Create($script)) ' + psArgs.join(' ');
      return 'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + encodePowerShellCommand(body);
    }
    return 'curl --fail --silent --show-error --location ' + quoteShellArg(installerURL(profile)) + ' | sudo bash -s -- install ' + quoteShellArgs(args);
  }

  function formControl(labelKey, key, type, value) {
    var input = h(type === 'select' ? 'select' : 'input', {
      type: type === 'select' ? null : (type || 'text'),
      class: 'deploy-control',
      'data-deploy-field': key,
      value: type === 'checkbox' ? null : value
    });
    if (type === 'select') {
      return input;
    }
    return input;
  }

  function addField(root, labelText, control, key, hint) {
    var field = h('div', { class: 'field deploy-field', 'data-deploy-field-group': key });
    var label = h('label', { text: labelText });
    if (!control.id) control.id = 'deploy-' + key.replace(/[^a-z0-9_-]/gi, '-');
    label.setAttribute('for', control.id);
    field.appendChild(label);
    field.appendChild(control);
    if (hint) field.appendChild(h('small', { class: 'field-hint', text: hint }));
    root.appendChild(field);
    return field;
  }

  function createNodeDialog() {
    var name = h('input', { type: 'text', 'data-new-node-name': '', autocomplete: 'off', 'aria-label': t('admin.name') });
    var error = h('p', { class: 'form-error', 'data-node-create-error': '' });
    setHidden(error, true);
    var submit = h('button', { class: 'btn btn-primary', type: 'button', 'data-node-create-submit': '' }, t('node.create'));
    var cancel = h('button', { class: 'btn btn-quiet', type: 'button', 'data-node-create-cancel': '' }, t('admin.cancel'));
    var body = h('div', { class: 'node-create-body' }, [
      h('p', { class: 'dialog-copy', text: t('node.create.name') }),
      addCreateField(name), error
    ]);
    function addCreateField(input) {
      var field = h('div', { class: 'field' });
      field.appendChild(h('label', { text: t('admin.name') }));
      field.appendChild(input);
      return field;
    }
    submit.addEventListener('click', async function () {
      if (submit.disabled) return;
      setHidden(error, true);
      submit.disabled = true;
      submit.classList.add('is-loading');
      submit.textContent = t('node.deploy.createSubmitting');
      try {
        var resp = await api('/api/v1/nodes', {
          method: 'POST',
          body: { name: name.value.trim() },
          headers: { 'Idempotency-Key': randomKey('node-create') }
        });
        if (!resp.ok || !resp.data || !resp.data.id) {
          error.textContent = errorMessage(resp, t('node.create.error'));
          setHidden(error, false);
          return;
        }
        dialogs().close();
        await open(resp.data);
      } catch (e) {
        error.textContent = e && e.message ? e.message : t('node.create.error');
        setHidden(error, false);
      } finally {
        submit.disabled = false;
        submit.classList.remove('is-loading');
        submit.textContent = t('node.create');
      }
    });
    cancel.addEventListener('click', function () { dialogs().close(); });
    dialogs().open({ title: t('node.create'), body: body, actions: [submit, cancel] });
  }

  function open(node) {
    var nodeID = node && (node.id || node.ID);
    if (!nodeID) return Promise.resolve();
    return api('/api/v1/nodes/' + encodeURIComponent(nodeID) + '/deployment-profile')
      .then(function (profileResp) {
        if (!profileResp.ok || !profileResp.data) throw new Error(errorMessage(profileResp, t('node.deploy.profileError')));
        var profile = cloneProfile(profileResp.data.profile);
        var etag = profileResp.data.etag || '"rev-0"';
        return api('/api/v1/nodes/' + encodeURIComponent(nodeID) + '/enrollment-token', { method: 'POST' })
          .then(function (tokenResp) {
            if (!tokenResp.ok || !tokenResp.data || !tokenResp.data.token) throw new Error(errorMessage(tokenResp, t('node.deploy.tokenError')));
            renderTokenStep(node, String(tokenResp.data.token), profile, etag);
          });
      }).catch(function (err) {
      var message = err && err.message ? err.message : t('node.deploy.profileError');
      if (dialogs()) {
        var body = h('div', { class: 'pane-error', 'data-deployment-error': '' }, h('p', { text: message }));
        var close = h('button', { class: 'btn btn-quiet', type: 'button', 'data-deployment-close': '' }, t('admin.close'));
        close.addEventListener('click', function () { dialogs().close(); });
        dialogs().open({ title: t('node.deploy.title'), body: body, actions: [close] });
      }
    });
  }

  function renderTokenStep(node, oneTimeToken, sourceProfile, sourceETag) {
    var wrap = h('div', { class: 'deployment-dialog-content deployment-token-surface', 'data-deployment-dialog': '', 'data-deployment-token-dialog': '' });
    wrap.appendChild(h('p', { class: 'dialog-copy', text: node.name || node.id || '' }));
    wrap.appendChild(h('section', { class: 'token-panel', 'data-deployment-token-panel': '' }, [
      h('h3', { text: t('node.deploy.token') }),
      h('p', { class: 'field-hint', 'data-deployment-token-notice': '', text: t('node.deploy.tokenNotice') }),
      h('code', { class: 'secret-value', 'data-deployment-token': '', text: oneTimeToken })
    ]));
    wrap.appendChild(h('p', { class: 'field-hint', text: t('node.deploy.tokenStepHint') }));
    var next = h('button', { class: 'btn btn-primary', type: 'button', 'data-deployment-continue': '' }, t('node.deploy.continue'));
    var close = h('button', { class: 'btn btn-quiet', type: 'button', 'data-deployment-close': '' }, t('admin.close'));
    next.addEventListener('click', function () {
      // The token panel is removed before the command surface is constructed.
      oneTimeToken = null;
      renderCommandStep(node, sourceProfile, sourceETag);
    });
    close.addEventListener('click', function () { dialogs().close(); });
    dialogs().open({ title: t('node.deploy.title'), body: wrap, actions: [next, close] });
  }

  function renderCommandStep(node, sourceProfile, sourceETag) {
    var nodeID = node && (node.id || node.ID);
    var state = { profile: cloneProfile(sourceProfile), etag: sourceETag, detection: 'not_tested' };
    var wrap = h('div', { class: 'deployment-dialog-content deployment-command-surface', 'data-deployment-dialog': '', 'data-deployment-command-dialog': '' });
    var nodeLabel = node.name || node.id || '';
    wrap.appendChild(h('p', { class: 'dialog-copy', text: nodeLabel }));

    var form = h('div', { class: 'deploy-form' });
    var platform = h('select', { 'data-deploy-field': 'platform' });
    [['linux', 'node.deploy.platform.linux'], ['windows', 'node.deploy.platform.windows'], ['docker', 'node.deploy.platform.docker']].forEach(function (option) {
      platform.appendChild(h('option', { value: option[0] }, t(option[1])));
    });
    platform.value = state.profile.platform;
    addField(form, t('node.deploy.field.platform'), platform, 'platform');

    var endpoint = h('input', { type: 'url', 'data-deploy-field': 'controller_endpoint', value: state.profile.controller_endpoint, spellcheck: 'false', autocomplete: 'url' });
    addField(form, t('node.deploy.field.controllerEndpoint'), endpoint, 'controller_endpoint', t('node.deploy.endpointHint'));
    var bind = h('input', { type: 'text', 'data-deploy-field': 'bind_interface', value: state.profile.bind_interface, autocomplete: 'off' });
    addField(form, t('node.deploy.field.bindInterface'), bind, 'bind_interface');
    var scheduler = h('select', { 'data-deploy-field': 'detection_scheduler' });
    scheduler.appendChild(h('option', { value: 'sequential' }, t('node.deploy.schedulerSequential')));
    scheduler.appendChild(h('option', { value: 'parallel' }, t('node.deploy.schedulerParallel')));
    scheduler.value = state.profile.detection_scheduler;
    addField(form, t('node.deploy.field.scheduler'), scheduler, 'detection_scheduler');

    var proxyEnable = h('input', { type: 'checkbox', 'data-deploy-enable': 'github_proxy' });
    var proxy = h('input', { type: 'url', 'data-deploy-field': 'github_proxy', value: state.profile.github_proxy, placeholder: 'https://ghfast.top/' });
    var proxyField = addToggleField(form, proxyEnable, t('node.deploy.field.githubProxy'), proxy, 'github_proxy');
    proxyEnable.checked = !!state.profile.github_proxy;

    var installDirEnable = h('input', { type: 'checkbox', 'data-deploy-enable': 'install_dir' });
    var installDir = h('input', { type: 'text', 'data-deploy-field': 'install_dir', value: state.profile.install_dir });
    var installDirField = addToggleField(form, installDirEnable, t('node.deploy.field.installDir'), installDir, 'install_dir');
    installDirEnable.checked = !!state.profile.install_dir;

    var serviceEnable = h('input', { type: 'checkbox', 'data-deploy-enable': 'service_name' });
    var serviceName = h('input', { type: 'text', 'data-deploy-field': 'service_name', value: state.profile.service_name });
    var serviceField = addToggleField(form, serviceEnable, t('node.deploy.field.serviceName'), serviceName, 'service_name');
    serviceEnable.checked = !!state.profile.service_name;

    var logLevel = h('select', { 'data-deploy-field': 'log_level' });
    ['debug', 'info', 'warn', 'error'].forEach(function (level) { logLevel.appendChild(h('option', { value: level }, level)); });
    logLevel.value = state.profile.log_level;
    addField(form, t('node.deploy.field.logLevel'), logLevel, 'log_level');
    var autoUpdate = h('select', { 'data-deploy-field': 'auto_update' });
    [['disabled', 'admin.no'], ['manual', 'node.deploy.autoUpdateManual'], ['stable', 'node.deploy.autoUpdateStable'], ['enabled', 'admin.yes']].forEach(function (option) {
      autoUpdate.appendChild(h('option', { value: option[0] }, t(option[1])));
    });
    autoUpdate.value = state.profile.auto_update;
    addField(form, t('node.deploy.field.updatePolicy'), autoUpdate, 'auto_update');
    wrap.appendChild(form);

    var detection = h('p', { class: 'deployment-status', 'data-detection-state': 'not_tested', text: t('node.deploy.notTested') });
    var detectionHint = h('p', { class: 'field-hint', 'data-detection-limit': '', text: t('node.deploy.detectionLimit') });
    var formError = h('p', { class: 'form-error', 'data-deployment-form-error': '' });
    setHidden(formError, true);
    var saveStatus = h('p', { class: 'form-success', 'data-deployment-save-status': '' });
    setHidden(saveStatus, true);

    var commandPanel = h('section', { class: 'command-panel' }, [
      h('h3', { text: t('node.deploy.step.command') }),
      h('pre', { class: 'cmd deployment-command', tabindex: '0', 'data-deployment-command': '' }),
      h('p', { class: 'field-hint', 'data-deployment-copy-notice': '', text: t('node.deploy.fdNotice') })
    ]);
    wrap.appendChild(commandPanel);
    wrap.appendChild(detection);
    wrap.appendChild(detectionHint);
    wrap.appendChild(formError);
    wrap.appendChild(saveStatus);

    var detect = h('button', { class: 'btn btn-quiet', type: 'button', 'data-deployment-detect': '' }, t('node.deploy.step.detect'));
    var save = h('button', { class: 'btn btn-primary', type: 'button', 'data-deployment-save': '' }, t('node.deploy.save'));
    var copy = h('button', { class: 'btn btn-quiet', type: 'button', 'data-deployment-copy': '' }, t('node.deploy.copy'));
    var close = h('button', { class: 'btn btn-quiet', type: 'button', 'data-deployment-close': '' }, t('admin.close'));
    var actions = [detect, save, copy, close];
    detect.addEventListener('click', runDetection);
    save.addEventListener('click', saveProfile);
    copy.addEventListener('click', copyCommand);
    close.addEventListener('click', function () { dialogs().close(); });
    [platform, endpoint, bind, scheduler, proxyEnable, proxy, installDirEnable, installDir, serviceEnable, serviceName, logLevel, autoUpdate].forEach(function (control) {
      control.addEventListener('input', updateCommand);
      control.addEventListener('change', updateCommand);
    });
    proxyEnable.addEventListener('change', function () { if (!proxyEnable.checked) proxy.value = ''; updateCommand(); });
    installDirEnable.addEventListener('change', function () { if (!installDirEnable.checked) installDir.value = ''; updateCommand(); });
    serviceEnable.addEventListener('change', function () { if (!serviceEnable.checked) serviceName.value = ''; updateCommand(); });

    dialogs().open({ title: t('node.deploy.title'), body: wrap, actions: actions });
    updateCommand();
    updatePlatformFields();

    function addToggleField(root, toggle, labelText, control, key) {
      var field = h('div', { class: 'field deploy-field deploy-optional-field', 'data-deploy-field-group': key });
      var label = h('label', { class: 'toggle-label' }, [toggle, h('span', { text: labelText })]);
      control.setAttribute('aria-label', labelText);
      field.appendChild(label);
      field.appendChild(control);
      root.appendChild(field);
      return field;
    }

    function profileFromForm() {
      var p = {
        platform: platform.value,
        controller_endpoint: endpoint.value,
        bind_interface: bind.value,
        detection_scheduler: scheduler.value,
        github_proxy: proxyEnable.checked ? proxy.value : '',
        install_dir: installDirEnable.checked ? installDir.value : '',
        service_name: serviceEnable.checked ? serviceName.value : '',
        log_level: logLevel.value,
        auto_update: autoUpdate.value
      };
      return validateProfile(p);
    }

    function updateCommand() {
      updatePlatformFields();
      var command = '';
      try {
        command = buildInstallCommand(profileFromForm());
        setHidden(formError, true);
      } catch (e) {
        command = t('node.deploy.commandUnavailable');
        formError.textContent = e && e.message ? e.message : t('node.deploy.invalidProfile');
        setHidden(formError, false);
      }
      commandPanel.querySelector('[data-deployment-command]').textContent = command;
    }

    function updatePlatformFields() {
      var docker = platform.value === PLATFORM_DOCKER;
      [proxyField, installDirField, serviceField].forEach(function (field) {
        setHidden(field, docker);
      });
      if (docker) {
        proxyEnable.checked = false;
        proxy.value = '';
        installDirEnable.checked = false;
        installDir.value = '';
        serviceEnable.checked = false;
        serviceName.value = '';
      }
    }

    async function saveProfile() {
      if (save.disabled) return;
      var profile;
      try { profile = profileFromForm(); } catch (e) {
        formError.textContent = e.message;
        setHidden(formError, false);
        return;
      }
      save.disabled = true;
      setHidden(formError, true);
      setHidden(saveStatus, true);
      try {
        var response = await api('/api/v1/nodes/' + encodeURIComponent(nodeID) + '/deployment-profile', {
          method: 'PUT',
          headers: { 'If-Match': state.etag },
          body: { profile: profile }
        });
        if (!response.ok) {
          formError.textContent = errorMessage(response, t('admin.saveError'));
          setHidden(formError, false);
          return;
        }
        state.profile = cloneProfile(response.data.profile);
        state.etag = response.data.etag || state.etag;
        saveStatus.textContent = t('node.deploy.saved');
        setHidden(saveStatus, false);
        updateCommand();
      } catch (e) {
        formError.textContent = e.message || t('admin.saveError');
        setHidden(formError, false);
      } finally {
        save.disabled = false;
      }
    }

    async function runDetection() {
      detection.setAttribute('data-detection-state', 'pending');
      detection.textContent = t('node.deploy.pending');
      detect.disabled = true;
      try {
        var response = await api('/api/v1/nodes/' + encodeURIComponent(nodeID) + '/traversal-detection', { method: 'POST' });
        if (!response.ok) {
          detection.setAttribute('data-detection-state', 'error');
          detection.textContent = errorMessage(response, t('node.deploy.detectionError'));
          return;
        }
        state.detection = 'pending';
        detection.setAttribute('data-detection-state', 'pending');
        detection.textContent = t('node.deploy.pending') + (response.data && response.data.operation_id ? ' · ' + response.data.operation_id : '');
        detectionHint.textContent = t('node.deploy.detectionLimit');
      } catch (e) {
        detection.setAttribute('data-detection-state', 'error');
        detection.textContent = e.message || t('node.deploy.detectionError');
      } finally {
        detect.disabled = false;
      }
    }

    async function copyCommand() {
      var command = commandPanel.querySelector('[data-deployment-command]').textContent;
      if (!command || command === t('node.deploy.commandUnavailable')) return;
      try {
        if (!navigator.clipboard || !window.isSecureContext) throw new Error('clipboard unavailable');
        await navigator.clipboard.writeText(command);
        commandPanel.querySelector('[data-deployment-copy-notice]').textContent = t('node.deploy.copied');
      } catch (e) {
        var selection = window.getSelection();
        var range = document.createRange();
        range.selectNodeContents(commandPanel.querySelector('[data-deployment-command]'));
        selection.removeAllRanges();
        selection.addRange(range);
        commandPanel.querySelector('[data-deployment-copy-notice]').textContent = t('node.deploy.copyFailNotice');
      }
    }
  }

  U.deployment = {
    open: open,
    openCreate: createNodeDialog,
    normalizeOptionalServiceURL: normalizeOptionalServiceURL,
    quoteShellArg: quoteShellArg,
    quoteShellArgs: quoteShellArgs,
    quotePowerShellArg: quotePowerShellArg,
    buildAgentArguments: buildAgentArguments,
    buildInstallCommand: buildInstallCommand,
    validateProfile: validateProfile
  };
})();
