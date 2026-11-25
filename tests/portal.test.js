const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT_DIR = path.resolve(__dirname, '..');
const BACKEND_DIR = path.join(ROOT_DIR, 'backend');
const CODE_JS_PATH = path.join(BACKEND_DIR, 'Code.js');
const PORTAL_HTML_PATH = path.join(BACKEND_DIR, 'Portal.html');
const ADMIN_HTML_PATH = path.join(BACKEND_DIR, 'Admin.html');
const APPSSCRIPT_JSON_PATH = path.join(BACKEND_DIR, 'appsscript.json');
const CLASP_JSON_PATH = path.join(ROOT_DIR, '.clasp.json');
const CLASPIGNORE_PATH = path.join(ROOT_DIR, '.claspignore');
const LINKS_JS_PATH = path.join(ROOT_DIR, 'links.js');

const WEBAPP_EXEC_URL = 'https://script.google.com/macros/s/AKfycbzKRSk7evTLpYUmktyE94Cs54w-F9NtJzo00HmeBSwgxG-C-gPxSNVflz1dX7sbuVg4/exec';

function buildSigningPayload(authTimestamp, ev) {
  return [
    String(ev.schemaVersion || '2.0'),
    String(ev.eventId || ''),
    String(authTimestamp || ''),
    String(ev.unidade || ''),
    String(ev.ambiente || ''),
    String(ev.tipoEvento || ''),
    String(ev.versao || ''),
    String(ev.commit || ''),
    String(ev.deploymentId || ''),
    String(ev.deploymentVersion || ''),
    String(ev.url || ''),
    String(ev.publicadoEm || ''),
    String(ev.estadoHomologacao || '')
  ].join('\n');
}

function signEvent(ev, secret, authTimestamp) {
  const ts = authTimestamp || new Date().toISOString();
  const sig = crypto
    .createHmac('sha256', secret)
    .update(buildSigningPayload(ts, ev), 'utf8')
    .digest('hex');
  return {
    action: 'publish_event',
    event: ev,
    auth: {
      timestamp: ts,
      eventId: ev.eventId,
      signature: sig
    }
  };
}

function createGasContext(options = {}) {
  const store = Object.assign({}, options.initialProperties || {});
  const cacheStore = Object.create(null);
  const userStore = Object.create(null);
  let activeEmail = options.userEmail !== undefined ? options.userEmail : '';
  const serviceUrl = options.serviceUrl !== undefined ? options.serviceUrl : WEBAPP_EXEC_URL;
  let lockCalls = 0;
  let unlockCalls = 0;
  let mockFetchHandler = options.fetchHandler || null;
  let mockFetchAllHandler = options.fetchAllHandler || null;
  const triggers = (options.initialTriggers || []).map((t, idx) => ({
    id: t.id || `trig-${idx + 1}`,
    handler: t.handler || 'runScheduledMonitoringCheck',
    intervalMinutes: t.intervalMinutes || 15
  }));
  let triggerSeq = triggers.length + 1;

  function toSignedByteArray(buf) {
    return Array.from(buf, (b) => (b > 127 ? b - 256 : b));
  }

  function makeResponseObj(res) {
    const code = res.status !== undefined ? res.status : 200;
    const headers = res.headers || {};
    const body = res.body !== undefined ? String(res.body) : '';
    return {
      getResponseCode() { return code; },
      getHeaders() { return headers; },
      getContentText() { return body; }
    };
  }

  const context = {
    console,
    Date: options.date || Date,
    JSON,
    Math,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Error,
    RegExp,
    isNaN,
    parseInt,
    encodeURIComponent,
    unescape,
    PropertiesService: {
      getUserProperties() {
        return {
          getProperty(key) { return userStore[key] || null; },
          setProperty(key, value) { userStore[key] = String(value); }
        };
      },
      getScriptProperties() {
        return {
          getProperty(key) {
            return Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null;
          },
          setProperty(key, val) {
            store[key] = String(val);
          },
          deleteProperty(key) {
            delete store[key];
          }
        };
      }
    },
    CacheService: {
      getScriptCache() {
        return {
          get(key) {
            return Object.prototype.hasOwnProperty.call(cacheStore, key) ? cacheStore[key] : null;
          },
          put(key, val) {
            cacheStore[key] = String(val);
          },
          remove(key) {
            delete cacheStore[key];
          }
        };
      }
    },
    LockService: {
      getScriptLock() {
        return {
          waitLock() { lockCalls++; },
          releaseLock() { unlockCalls++; }
        };
      }
    },
    UrlFetchApp: {
      fetch(url, params) {
        if (mockFetchHandler) {
          const out = mockFetchHandler(url, params);
          if (out instanceof Error) throw out;
          return makeResponseObj(out);
        }
        return makeResponseObj({ status: 200, body: '<html><title>SISFAR</title></html>' });
      },
      fetchAll(reqs) {
        if (mockFetchAllHandler) {
          const arr = mockFetchAllHandler(reqs);
          return arr.map((item) => {
            if (item instanceof Error) throw item;
            return makeResponseObj(item);
          });
        }
        return reqs.map((r) => context.UrlFetchApp.fetch(r.url, r));
      }
    },
    Utilities: {
      DigestAlgorithm: { SHA_256: 'SHA_256' },
      Charset: { UTF_8: 'UTF_8' },
      getUuid() {
        return crypto.randomUUID();
      },
      formatDate(date, tz, fmt) {
        if (fmt === 'yyyy-MM-dd') {
          return new Intl.DateTimeFormat('en-CA', {
            timeZone: tz || 'America/Sao_Paulo',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit'
          }).format(date);
        }
        return date.toISOString();
      },
      computeDigest(alg, input) {
        assert.equal(alg, 'SHA_256');
        return toSignedByteArray(crypto.createHash('sha256').update(String(input), 'utf8').digest());
      },
      computeHmacSha256Signature(msg, key) {
        return toSignedByteArray(crypto.createHmac('sha256', String(key)).update(String(msg), 'utf8').digest());
      }
    },
    Session: {
      getEffectiveUser() {
        throw new Error('Session.getEffectiveUser requires authorization in web runtime');
      },
      getActiveUser() {
        return {
          getEmail() {
            return activeEmail;
          }
        };
      }
    },
    ScriptApp: {
      getService() {
        return {
          getUrl() {
            return serviceUrl;
          }
        };
      },
      getProjectTriggers() {
        return triggers.map((t) => ({
          getHandlerFunction() { return t.handler; },
          getUniqueId() { return t.id; },
          _raw: t
        }));
      },
      deleteTrigger(trigObj) {
        const uid = trigObj && trigObj.getUniqueId ? trigObj.getUniqueId() : null;
        const idx = triggers.findIndex((t) => t.id === uid);
        if (idx !== -1) triggers.splice(idx, 1);
      },
      newTrigger(handlerName) {
        let mins = 15;
        return {
          timeBased() {
            return {
              everyMinutes(m) { mins = m; return this; },
              everyHours(h) { mins = h * 60; return this; },
              create() {
                const created = { id: `trig-${triggerSeq++}`, handler: handlerName, intervalMinutes: mins };
                triggers.push(created);
                return {
                  getHandlerFunction() { return created.handler; },
                  getUniqueId() { return created.id; }
                };
              }
            };
          }
        };
      }
    },
    HtmlService: {
      XFrameOptionsMode: { ALLOWALL: 'ALLOWALL' },
      createHtmlOutputFromFile(name) {
        const filePath = path.join(BACKEND_DIR, `${name}.html`);
        const content = fs.readFileSync(filePath, 'utf8');
        return {
          _type: 'HtmlOutput',
          getContent() {
            return content;
          }
        };
      },
      createHtmlOutput(html) {
        let title = '';
        let xframe = '';
        return {
          _type: 'HtmlOutput',
          setTitle(t) {
            title = t;
            return this;
          },
          setXFrameOptionsMode(m) {
            xframe = m;
            return this;
          },
          getContent() {
            return html;
          },
          getTitle() {
            return title;
          },
          getXFrameOptionsMode() {
            return xframe;
          }
        };
      }
    },
    ContentService: {
      MimeType: { JSON: 'application/json' },
      createTextOutput(text) {
        let mime = '';
        return {
          _type: 'TextOutput',
          setMimeType(m) {
            mime = m;
            return this;
          },
          getContent() {
            return text;
          },
          getMimeType() {
            return mime;
          }
        };
      }
    }
  };

  vm.createContext(context);
  const code = fs.readFileSync(CODE_JS_PATH, 'utf8');
  vm.runInContext(code, context, { filename: CODE_JS_PATH });

  return {
    ctx: context,
    store,
    cacheStore,
    triggers,
    runScheduled() {
      if (!triggers.some((trigger) => trigger.handler === 'runScheduledMonitoringCheck_')) {
        context.syncMonitoringTriggerInternal_();
      }
      const trigger = triggers.find((item) => item.handler === 'runScheduledMonitoringCheck_');
      return context.runScheduledMonitoringCheck_({ triggerUid: trigger.id });
    },
    getLockStats() { return { lockCalls, unlockCalls }; },
    setFetchHandler(fn) { mockFetchHandler = fn; },
    setFetchAllHandler(fn) { mockFetchAllHandler = fn; },
    setUserEmail(email) {
      activeEmail = email;
    }
  };
}

function createDomHarness(html) {
  const elements = {};

  function makeEl(id, initialTag) {
    const attrs = {};
    const classes = new Set();
    const listeners = {};
    const el = {
      id,
      tagName: initialTag || 'DIV',
      href: '#',
      target: '',
      rel: '',
      value: '',
      textContent: '',
      innerHTML: '',
      className: '',
      children: [],
      classList: {
        add(c) {
          classes.add(c);
          el.className = Array.from(classes).join(' ');
        },
        remove(c) {
          classes.delete(c);
          el.className = Array.from(classes).join(' ');
        },
        toggle(c, force) {
          if (force === true) classes.add(c);
          else if (force === false) classes.delete(c);
          else if (classes.has(c)) classes.delete(c);
          else classes.add(c);
          el.className = Array.from(classes).join(' ');
        },
        contains(c) {
          return classes.has(c);
        }
      },
      setAttribute(name, value) {
        attrs[name] = String(value);
        if (name === 'href') el.href = String(value);
      },
      getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null;
      },
      removeAttribute(name) {
        delete attrs[name];
        if (name === 'target') el.target = '';
        if (name === 'rel') el.rel = '';
      },
      appendChild(child) {
        const idx = el.children.indexOf(child);
        if (idx !== -1) el.children.splice(idx, 1);
        el.children.push(child);
        return child;
      },
      addEventListener(type, fn) {
        listeners[type] = listeners[type] || [];
        listeners[type].push(fn);
      },
      dispatch(type) {
        (listeners[type] || []).forEach((fn) => fn.call(el));
      }
    };
    return el;
  }

  elements.unitsGrid = makeEl('unitsGrid', 'DIV');
  for (const unit of ['CPPA', 'PEPOA', 'MADRE']) {
    const card = makeEl(`unit-card-${unit}`, 'ARTICLE');
    elements[card.id] = card;
    elements.unitsGrid.appendChild(card);
  }

  const ids = [
    'cppa-oficial',
    'pepoa-oficial',
    'madre-oficial',
    'cppa-audit',
    'pepoa-audit',
    'madre-audit'
  ];
  for (const suffix of ids) {
    const slot = makeEl(`card-${suffix}`, 'DIV');
    const unit = suffix.split('-')[0].toUpperCase();
    elements[slot.id] = slot;
    elements[`unit-card-${unit}`].appendChild(slot);
    elements[`link-${suffix}`] = makeEl(`link-${suffix}`, 'A');
    elements[`name-${suffix}`] = makeEl(`name-${suffix}`, 'P');
    elements[`badge-${suffix}`] = makeEl(`badge-${suffix}`, 'SPAN');
    elements[`label-${suffix}`] = makeEl(`label-${suffix}`, 'SPAN');
    elements[`ver-${suffix}`] = makeEl(`ver-${suffix}`, 'SPAN');
    elements[`dep-${suffix}`] = makeEl(`dep-${suffix}`, 'SPAN');
    elements[`date-${suffix}`] = makeEl(`date-${suffix}`, 'SPAN');
    elements[`state-${suffix}`] = makeEl(`state-${suffix}`, 'SPAN');
  }

  for (const extraId of [
    'kpiActiveEnvs', 'kpiReleaseCount', 'kpiReleaseSub', 'kpiAnnCount', 'kpiAnnSub',
    'kpiLastRelease', 'kpiLastReleaseSub', 'navCountReleases', 'navCountAnnouncements',
    'currentDatePtBr', 'centralTitleBadge', 'centralSubtitle', 'obsBanner', 'obsBannerText',
    'stageMatrixGrid', 'releasesHistoryContainer', 'releasesFilterSummary',
    'announcementsContainer', 'annSummaryNote', 'btnThemeToggle', 'themeLabel',
    'filterRelUnit', 'filterRelEnv', 'filterRelVersion', 'btnClearReleaseFilters',
    'filterAnnUnit', 'filterAnnCat', 'btnClearAnnFilters'
  ]) {
    elements[extraId] = makeEl(extraId, 'DIV');
  }
  elements.filterRelUnit.value = 'TODAS';
  elements.filterRelEnv.value = 'TODOS';
  elements.filterAnnUnit.value = 'TODAS';
  elements.filterAnnCat.value = 'TODAS';

  const scriptMatches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(scriptMatches.length >= 1, 'Portal HTML deve conter bloco <script>');
  const inlineScript = scriptMatches[scriptMatches.length - 1][1];

  const docEl = makeEl('html', 'HTML');
  const lsMap = {};

  return {
    elements,
    docEl,
    lsMap,
    run(rpcMock) {
      const domCtx = {
        console,
        Object,
        Array,
        Date,
        Math,
        String,
        Number,
        Boolean,
        Error,
        RegExp,
        isNaN,
        parseInt,
        encodeURIComponent,
        setTimeout,
        clearTimeout,
        localStorage: {
          getItem(k) { return Object.prototype.hasOwnProperty.call(lsMap, k) ? lsMap[k] : null; },
          setItem(k, v) { lsMap[k] = String(v); }
        },
        document: {
          readyState: 'complete',
          documentElement: docEl,
          createElement(tag) { return makeEl('dyn-' + Math.random(), tag); },
          getElementById(id) {
            return elements[id] || null;
          },
          querySelectorAll() {
            return [];
          }
        },
        google: rpcMock
          ? { script: { run: rpcMock } }
          : undefined
      };
      domCtx.window = domCtx;
      vm.createContext(domCtx);
      vm.runInContext(inlineScript, domCtx);
    }
  };
}

test('Arquivos CLASP e manifesto Apps Script são válidos e exclusivos do portal', () => {
  const clasp = JSON.parse(fs.readFileSync(CLASP_JSON_PATH, 'utf8'));
  assert.equal(clasp.rootDir, 'backend');
  assert.equal(clasp.scriptId, '1DIa-2xjZOrDZp4WTanMb1jYwu3p8VIE9krlrw8qTw1scq1uLwDfzxyGv');

  const manifest = JSON.parse(fs.readFileSync(APPSSCRIPT_JSON_PATH, 'utf8'));
  assert.equal(manifest.runtimeVersion, 'V8');
  assert.equal(manifest.timeZone, 'America/Sao_Paulo');
  assert.equal(manifest.webapp.executeAs, 'USER_DEPLOYING');
  assert.equal(manifest.webapp.access, 'ANYONE_ANONYMOUS');

  assert.ok(fs.existsSync(CLASPIGNORE_PATH), '.claspignore deve existir');
  assert.ok(fs.existsSync(PORTAL_HTML_PATH), 'backend/Portal.html deve existir');
  assert.ok(fs.existsSync(ADMIN_HTML_PATH), 'backend/Admin.html deve existir');
});

test('Funções internas de escrita são estritamente privadas (sufixo _)', () => {
  const code = fs.readFileSync(CODE_JS_PATH, 'utf8');
  assert.equal(/function\s+saveConfigInternal\s*\(/.test(code), false, 'saveConfigInternal não pode ser pública');
  assert.equal(/function\s+saveConfigInternal_\s*\(/.test(code), true, 'saveConfigInternal_ deve ser privada');
  assert.equal(/function\s+recordReleaseEventInternal_\s*\(/.test(code), true);
  assert.equal(/function\s+saveAnnouncementInternal_\s*\(/.test(code), true);
});

test('doGet(?view=portal) e doGet() renderizam portal 2.0 Clinical Clean sem dependências externas', () => {
  const { ctx } = createGasContext();
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);

  for (const eventArg of [{ parameter: { view: 'portal' } }, {}, undefined]) {
    const out = ctx.doGet(eventArg);
    assert.equal(out._type, 'HtmlOutput');
    assert.equal(out.getXFrameOptionsMode(), 'ALLOWALL');
    const html = out.getContent();

    assert.ok(html.includes('<base target="_top">'));
    assert.ok(html.includes('#F4F7F9'));
    assert.ok(html.includes('#0F766E'));
    assert.ok(html.includes('#0369A1'));
    assert.ok(html.includes('#0B1220'));
    assert.ok(html.includes('#131E2D'));
    assert.ok(html.includes('Central de trabalho'));
    assert.ok(html.includes('Atualizações'));
    assert.ok(html.includes('Comunicados'));
    assert.ok(html.includes('Administração'));
    assert.ok(html.includes('prefers-reduced-motion'));
    assert.ok(html.includes(`${WEBAPP_EXEC_URL}?view=admin`));
    assert.equal(html.includes('lukaslaurino.github.io'), false);
    assert.equal(html.includes('src="links.js"'), false);
    assert.equal(html.includes('href="favicon.svg"'), false);
    assert.equal(/\bOnline\b/i.test(html), false, 'Portal nunca deve afirmar Online por existir URL');

    for (const [key, env] of Object.entries(SISFAR_CONFIG.ambientes)) {
      assert.ok(html.includes(env.url), `Portal deve incluir URL atual de ${key}`);
    }
  }
});

test('doGet(?action=get) e doGet(?action=bootstrap) mantêm contratos públicos de leitura', () => {
  const { ctx } = createGasContext();
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);

  const outGet = ctx.doGet({ parameter: { action: 'get' } });
  assert.equal(outGet._type, 'TextOutput');
  assert.equal(outGet.getMimeType(), 'application/json');
  const parsedGet = JSON.parse(outGet.getContent());
  assert.equal(parsedGet.success, true);
  assert.deepEqual(Object.keys(parsedGet.data), Object.keys(SISFAR_CONFIG.ambientes));

  const outBoot = ctx.doGet({ parameter: { action: 'bootstrap' } });
  const parsedBoot = JSON.parse(outBoot.getContent());
  assert.equal(parsedBoot.success, true);
  assert.equal(parsedBoot.schemaVersion, '2.0');
  assert.deepEqual(parsedBoot.releaseHistory, []);
  assert.deepEqual(parsedBoot.announcements, []);
  assert.equal(parsedBoot.releaseState.environments.cppaOficial, null);
});

test('Persistência dinâmica via CONFIG_LINKS reflete nos 3 cards de unidade, ordem e ativo', () => {
  const { ctx, store } = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  const updated = JSON.parse(JSON.stringify(ctx.getConfig()));
  updated.cppaOficial.url = 'https://script.google.com/macros/s/AKfycb_UPDATED_CPPA/exec';
  updated.cppaOficial.nome = 'CPPA — Unidade Atualizada</script>';
  updated.madreAudit.ativo = false;
  updated.pepoaOficial.ordem = 1;
  updated.cppaOficial.ordem = 2;
  updated.madreOficial.ordem = 3;

  const saveRes = ctx.apiSaveAdminConfig(updated);
  assert.equal(saveRes.success, true);
  assert.ok(store.CONFIG_LINKS);

  const portalHtml = ctx.doGet({ parameter: { view: 'portal' } }).getContent();
  assert.equal(portalHtml.includes('</script>","tipo"'), false);

  const harness = createDomHarness(portalHtml);
  harness.run();

  assert.equal(harness.elements['link-cppa-oficial'].href, 'https://script.google.com/macros/s/AKfycb_UPDATED_CPPA/exec');
  assert.equal(harness.elements['name-cppa-oficial'].textContent, 'CPPA — Unidade Atualizada</script>');
  assert.equal(harness.elements['link-madre-audit'].classList.contains('disabled'), true);
  assert.equal(harness.elements['link-madre-audit'].getAttribute('aria-disabled'), 'true');
  assert.equal(harness.elements['label-madre-audit'].textContent, 'Indisponível no momento');
  assert.equal(harness.elements['badge-madre-audit'].textContent, 'Manutenção');
  assert.equal(harness.elements.kpiActiveEnvs.textContent, '5 / 6 ativos');

  const orderedUnits = harness.elements.unitsGrid.children.map((c) => c.id);
  assert.deepEqual(orderedUnits, ['unit-card-PEPOA', 'unit-card-CPPA', 'unit-card-MADRE']);

  const resetRes = ctx.apiResetAdminConfig();
  assert.equal(resetRes.success, true);
  assert.equal(
    ctx.getConfig().cppaOficial.url,
    'https://script.google.com/macros/s/AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww/exec'
  );
});

test('Cliente do portal aceita atualização via apiGetPublicBootstrap() e apiGetPublicConfig()', () => {
  const { ctx } = createGasContext();
  const portalHtml = ctx.doGet({ parameter: { view: 'portal' } }).getContent();
  const harness = createDomHarness(portalHtml);

  const liveData = JSON.parse(JSON.stringify(ctx.getConfig()));
  liveData.pepoaAudit.url = 'https://script.google.com/macros/s/AKfycb_LIVE_RPC/exec';

  const rpcMock = {
    withSuccessHandler(fn) {
      return {
        withFailureHandler() {
          return {
            apiGetPublicBootstrap() {
              fn({
                success: true,
                data: liveData,
                releaseState: {
                  environments: {
                    pepoaAudit: {
                      unidade: 'PEPOA',
                      ambiente: 'AUDIT',
                      versao: '4.38.9',
                      commit: '2c6169b',
                      deploymentVersion: '118',
                      publicadoEm: '2026-11-25T01:37:02.718Z',
                      estadoHomologacao: 'EM_HOMOLOGACAO',
                      tipoEvento: 'publish'
                    }
                  }
                },
                releaseHistory: [{
                  eventId: 'evt-pepoa-audit-1',
                  unidade: 'PEPOA',
                  ambiente: 'AUDIT',
                  versao: '4.38.9',
                  commit: '2c6169b',
                  deploymentId: 'AKfycbyx3tZUUB__KsFaZJSobePjt7ImZRNHF_bQK8U0pQDY-_LSdTppcrsqAFtLgpVSl3Mr',
                  deploymentVersion: '118',
                  publicadoEm: '2026-11-25T01:37:02.718Z',
                  estadoHomologacao: 'EM_HOMOLOGACAO',
                  tipoEvento: 'publish',
                  notas: 'Release clínica 4.38.9'
                }],
                announcements: []
              });
            }
          };
        }
      };
    }
  };

  harness.run(rpcMock);
  assert.equal(harness.elements['link-pepoa-audit'].href, 'https://script.google.com/macros/s/AKfycb_LIVE_RPC/exec');
  assert.equal(harness.elements['ver-pepoa-audit'].textContent, 'v4.38.9');
  assert.equal(harness.elements['state-pepoa-audit'].textContent, 'EM_HOMOLOGACAO');
  assert.equal(harness.elements.kpiReleaseCount.textContent, '1');
});

test('Ingestão HMAC-SHA256: CPPA oficial, PEPOA audit, duplicata, inválido, sem auth, atrasado, rollback e segmentação', () => {
  const SECRET = 'segredo-super-forte-hmac-2026-teste';
  const { ctx, store } = createGasContext({
    userEmail: '',
    initialProperties: { PORTAL_WEBHOOK_SECRET: SECRET }
  });

  // 1. Sem segredo configurado -> bloqueia fail-closed
  const noSecretCtx = createGasContext({ userEmail: '' });
  const evBase = {
    eventId: 'evt-cppa-oficial-4389-264',
    schemaVersion: '2.0',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    versao: '4.38.9',
    commit: '2c6169b',
    deploymentId: 'AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww',
    deploymentVersion: '264',
    url: 'https://script.google.com/macros/s/AKfycb_FROM_EVENT/exec',
    publicadoEm: '2026-11-25T01:39:00.722Z',
    notas: 'Release clínica 4.38.9 CPPA OFICIAL',
    estadoHomologacao: 'PENDENTE',
    tipoEvento: 'publish'
  };
  const noSecretRes = JSON.parse(noSecretCtx.ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evBase, SECRET)) }
  }).getContent());
  assert.equal(noSecretRes.success, false);
  assert.equal(noSecretRes.code, 'SECRET_NOT_CONFIGURED');

  // 2. Assinatura inválida -> bloqueia 403
  const badSigBody = signEvent(evBase, 'segredo-errado-invalido-123456');
  const badSigRes = JSON.parse(ctx.doPost({ postData: { contents: JSON.stringify(badSigBody) } }).getContent());
  assert.equal(badSigRes.success, false);
  assert.equal(badSigRes.code, 'INVALID_SIGNATURE');

  // 3. Timestamp expirado (fora da janela replay) -> bloqueia 401
  const oldAuthTs = new Date(Date.now() - 20 * 60 * 1000).toISOString();
  const expiredRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evBase, SECRET, oldAuthTs)) }
  }).getContent());
  assert.equal(expiredRes.success, false);
  assert.equal(expiredRes.code, 'TIMESTAMP_EXPIRED');

  // 4. CPPA OFICIAL válido -> aplica estado e preserva CONFIG_LINKS original
  const originalCppaUrl = ctx.getConfig().cppaOficial.url;
  const okCppa = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evBase, SECRET)) }
  }).getContent());
  assert.equal(okCppa.success, true);
  assert.equal(okCppa.duplicate, false);
  assert.equal(okCppa.stale, false);
  assert.equal(okCppa.appliedToCurrentState, true);
  assert.equal(ctx.getConfig().cppaOficial.url, originalCppaUrl, 'Evento não deve sobrescrever CONFIG_LINKS');

  // 5. Duplicata (mesmo eventId) -> idempotente sem duplicar histórico
  const dupRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evBase, SECRET)) }
  }).getContent());
  assert.equal(dupRes.success, true);
  assert.equal(dupRes.duplicate, true);
  assert.equal(ctx.getReleaseHistory_().length, 1);

  // 6. PEPOA AUDIT válido -> estado independente
  const evPepoaAudit = {
    eventId: 'evt-pepoa-audit-4389-118',
    schemaVersion: '2.0',
    unidade: 'PEPOA',
    ambiente: 'AUDIT',
    versao: '4.38.9',
    commit: '2c6169b',
    deploymentId: 'AKfycbyx3tZUUB__KsFaZJSobePjt7ImZRNHF_bQK8U0pQDY-_LSdTppcrsqAFtLgpVSl3Mr',
    deploymentVersion: '118',
    url: ctx.getConfig().pepoaAudit.url,
    publicadoEm: '2026-11-25T01:37:02.718Z',
    notas: 'Validação AUDIT PEPOA',
    estadoHomologacao: 'EM_HOMOLOGACAO',
    tipoEvento: 'publish'
  };
  const okPepoa = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evPepoaAudit, SECRET)) }
  }).getContent());
  assert.equal(okPepoa.success, true);
  assert.equal(ctx.getReleaseStateCurrent_().environments.pepoaAudit.versao, '4.38.9');

  // 7. Evento atrasado (timestamp mais antigo que CPPA OFICIAL atual) -> não substitui estado novo
  const evAtrasado = {
    eventId: 'evt-cppa-oficial-4388-262-atrasado',
    schemaVersion: '2.0',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    versao: '4.38.8',
    commit: '6e92576',
    deploymentId: 'AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww',
    deploymentVersion: '262',
    url: 'https://script.google.com/macros/s/AKfycb_ANTIGO/exec',
    publicadoEm: '2026-11-24T12:00:00.000Z',
    notas: 'Evento antigo atrasado',
    estadoHomologacao: 'HOMOLOGADO',
    tipoEvento: 'publish'
  };
  const delayedRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evAtrasado, SECRET)) }
  }).getContent());
  assert.equal(delayedRes.success, true);
  assert.equal(delayedRes.stale, true);
  assert.equal(delayedRes.appliedToCurrentState, false);
  assert.equal(ctx.getReleaseStateCurrent_().environments.cppaOficial.versao, '4.38.9');
  assert.equal(ctx.getConfig().cppaOficial.url, originalCppaUrl);

  // 8. Rollback próprio (timestamp novo, tipoEvento: rollback) -> atualiza estado para versão revertida
  const evRollback = {
    eventId: 'evt-cppa-oficial-rollback-4388-263',
    schemaVersion: '2.0',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    versao: '4.38.8',
    commit: '6e92576',
    deploymentId: 'AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww',
    deploymentVersion: '265',
    url: originalCppaUrl,
    publicadoEm: '2026-11-25T02:15:00.000Z',
    notas: 'Rollback preventivo após checagem',
    estadoHomologacao: 'REVERTIDO',
    tipoEvento: 'rollback'
  };
  const rbRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify(signEvent(evRollback, SECRET)) }
  }).getContent());
  assert.equal(rbRes.success, true);
  assert.equal(rbRes.stale, false);
  assert.equal(rbRes.appliedToCurrentState, true);
  assert.equal(ctx.getReleaseStateCurrent_().environments.cppaOficial.tipoEvento, 'rollback');
  assert.equal(ctx.getReleaseStateCurrent_().environments.cppaOficial.versao, '4.38.8');
  assert.equal(ctx.getReleaseStateCurrent_().environments.cppaOficial.estadoHomologacao, 'REVERTIDO');

  // 9. Segmentação e limite PropertiesService (25 eventos não ultrapassam 7800 bytes por chave)
  for (let i = 0; i < 25; i++) {
    const evLoop = {
      eventId: `evt-loop-madre-audit-${i}`,
      schemaVersion: '2.0',
      unidade: 'MADRE',
      ambiente: 'AUDIT',
      versao: `4.39.${i}`,
      commit: `abc00${i}`,
      deploymentId: 'AKfycbydhH8Vle_nakjHAlKU0_a2fBr6e0c5roker9IHxXAve48UqUhPG7VfWIvI0fNTyaWj',
      deploymentVersion: String(200 + i),
      url: ctx.getConfig().madreAudit.url,
      publicadoEm: new Date(Date.UTC(2026, 10, 25, 3, i, 0)).toISOString(),
      notas: `Nota sintética de segmentação ${i}`,
      estadoHomologacao: 'PENDENTE',
      tipoEvento: 'publish'
    };
    const r = JSON.parse(ctx.doPost({ postData: { contents: JSON.stringify(signEvent(evLoop, SECRET)) } }).getContent());
    assert.equal(r.success, true);
  }
  const stats = ctx.getReleaseStorageStats_();
  assert.ok(stats.segmentsCount <= 6, 'Segmentos devem respeitar o limite máximo');
  for (const seg of stats.segments) {
    assert.ok(seg.bytes <= 7800, `Segmento ${seg.key} excedeu limite seguro: ${seg.bytes}`);
  }
  assert.ok(store.SISFAR_RELEASE_HIST_META_V2);
});

test('Comunicados administráveis respeitam unidade, prioridade, ativo e validade', () => {
  const { ctx } = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });

  const activeRes = ctx.apiSaveAdminAnnouncement({
    titulo: 'Manutenção programada PEPOA',
    descricao: 'Janela técnica às 23h.',
    categoria: 'Manutenção',
    prioridade: 'Alta',
    unidade: 'PEPOA',
    validade: '2099-12-31',
    ativo: true
  });
  assert.equal(activeRes.success, true);

  ctx.apiSaveAdminAnnouncement({
    titulo: 'Comunicado expirado',
    descricao: 'Não deve aparecer no portal público.',
    categoria: 'Informativo',
    prioridade: 'Baixa',
    unidade: 'TODAS',
    validade: '2020-01-01',
    ativo: true
  });

  ctx.apiSaveAdminAnnouncement({
    titulo: 'Comunicado inativo',
    descricao: 'Desativado.',
    categoria: 'Operacional',
    prioridade: 'Normal',
    unidade: 'CPPA',
    ativo: false
  });

  const boot = ctx.apiGetPublicBootstrap();
  assert.equal(boot.announcements.length, 1);
  assert.equal(boot.announcements[0].titulo, 'Manutenção programada PEPOA');

  const delRes = ctx.apiDeleteAdminAnnouncement(activeRes.item.id);
  assert.equal(delRes.success, true);
  assert.equal(ctx.apiGetPublicBootstrap().announcements.length, 0);
});

test('Autenticação administrativa: Google allowlist + fallback configurado sem abrir escrita anônima', () => {
  // 1. Sem e-mail Google e sem ADMIN_AUTH_HASH -> 403 Acesso Restrito
  const anon = createGasContext({ userEmail: '' });
  const deniedHtml = anon.ctx.doGet({ parameter: { view: 'admin' } }).getContent();
  assert.ok(deniedHtml.includes('403 — Acesso Restrito'));
  assert.ok(deniedHtml.includes(`${WEBAPP_EXEC_URL}?view=portal`));
  assert.equal(deniedHtml.includes('lukaslaurino.github.io'), false);

  // 2. Com Google e-mail autorizado -> abre workspace diretamente
  const admin = createGasContext({ userEmail: 'lukaslaurinocppa@gmail.com' });
  const adminHtml = admin.ctx.doGet({ parameter: { admin: '1' } }).getContent();
  assert.ok(adminHtml.includes('<base target="_top">'));
  assert.ok(adminHtml.includes('lukaslaurinocppa@gmail.com'));
  assert.ok(adminHtml.includes('Ambientes'));
  assert.ok(adminHtml.includes('Releases'));
  assert.ok(adminHtml.includes('Comunicados'));
  assert.ok(adminHtml.includes('Configurações'));

  // 3. Execução pública (email vazio) com ADMIN_AUTH_HASH configurada -> exige login válido
  const pubFallback = createGasContext({ userEmail: '' });
  pubFallback.ctx.configurarChaveAdminPortal_('ChaveAdminForte#2026');
  const gateHtml = pubFallback.ctx.doGet({ parameter: { view: 'admin' } }).getContent();
  assert.ok(gateHtml.includes('Autenticação Administrativa'));
  assert.ok(gateHtml.includes('"requirePasscodeLogin":true'));

  // Sem token ainda bloqueia RPCs
  assert.throws(() => pubFallback.ctx.apiGetAdminBootstrap(), /Acesso negado/);
  assert.throws(() => pubFallback.ctx.apiAdminAuthenticate('intruso@example.com', 'ChaveAdminForte#2026'), /allowlist/);
  assert.throws(() => pubFallback.ctx.apiAdminAuthenticate('lukaslaurino@gmail.com', 'errada'), /Credencial/);

  // Com credencial válida emite token e libera RPCs
  const authRes = pubFallback.ctx.apiAdminAuthenticate('lukaslaurino@gmail.com', 'ChaveAdminForte#2026');
  assert.equal(authRes.success, true);
  assert.ok(authRes.authToken);

  const bootRes = pubFallback.ctx.apiGetAdminBootstrap(authRes.authToken);
  assert.equal(bootRes.success, true);
  assert.equal(bootRes.user, 'lukaslaurino@gmail.com');

  const settingsRes = pubFallback.ctx.apiSaveAdminSettings({
    tituloCentral: 'Central SISFAR Operacional',
    janelaReplaySegundos: 180
  }, authRes.authToken);
  assert.equal(settingsRes.success, true);
  assert.equal(settingsRes.settings.tituloCentral, 'Central SISFAR Operacional');
});

test('Segurança fail-closed bloqueia mutações anônimas/não autorizadas e payloads inválidos', () => {
  const { ctx, store } = createGasContext({ userEmail: 'intruso@example.com' });

  const postRes = JSON.parse(
    ctx.doPost({ postData: { contents: JSON.stringify(ctx.getConfig()) } }).getContent()
  );
  assert.equal(postRes.success, false);
  assert.match(postRes.error, /403/);
  assert.equal(store.CONFIG_LINKS, undefined);

  assert.throws(() => ctx.apiHealthCheck(), /Acesso negado/);
  assert.throws(() => ctx.apiGetAdminConfig(), /Acesso negado/);
  assert.throws(() => ctx.apiGetAdminBootstrap(), /Acesso negado/);
  assert.throws(() => ctx.apiSaveAdminConfig(ctx.getConfig()), /Acesso negado/);
  assert.throws(() => ctx.apiResetAdminConfig(), /Acesso negado/);
  assert.throws(() => ctx.apiRecordAdminReleaseEvent({}), /Acesso negado/);
  assert.throws(() => ctx.apiUpdateAdminHomologation('cppaOficial', 'HOMOLOGADO'), /Acesso negado/);
  assert.throws(() => ctx.apiSaveAdminAnnouncement({ titulo: 'x', descricao: 'y' }), /Acesso negado/);
  assert.throws(() => ctx.apiDeleteAdminAnnouncement('id-1'), /Acesso negado/);
  assert.throws(() => ctx.apiSaveAdminSettings({}), /Acesso negado/);

  const admin = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  const badUrl = JSON.parse(JSON.stringify(admin.ctx.getConfig()));
  badUrl.cppaOficial.url = 'http://inseguro.example.com';
  assert.throws(() => admin.ctx.apiSaveAdminConfig(badUrl), /https:\/\//);

  const missingEnv = JSON.parse(JSON.stringify(admin.ctx.getConfig()));
  delete missingEnv.madreAudit;
  assert.throws(() => admin.ctx.apiSaveAdminConfig(missingEnv), /esperado exatamente 6/);
});

test('doPost ações admin_* exigem autenticação (Google allowlist ou authToken), configuram credenciais sem expor segredos e preservam CONFIG_LINKS', () => {
  const { ctx, store, setUserEmail } = createGasContext({ userEmail: '' });

  // 1. Sem autenticação: bloqueia leitura e escrita admin_*
  for (const action of ['admin_health', 'admin_bootstrap', 'admin_save_settings', 'admin_save_config']) {
    const res = JSON.parse(ctx.doPost({
      postData: { contents: JSON.stringify({ action, payload: {} }) }
    }).getContent());
    assert.equal(res.success, false);
    assert.match(res.error, /Acesso negado/);
  }

  // 2. Via sessão Google autorizada: configura segredo HMAC e credencial admin sem retornar segredos
  setUserEmail('lukaslaurinocppa@gmail.com');
  const webhookSec = crypto.randomBytes(32).toString('hex');
  const adminPass = crypto.randomBytes(32).toString('base64url');
  const saveSecRes = JSON.parse(ctx.doPost({
    postData: {
      contents: JSON.stringify({
        action: 'admin_save_settings',
        payload: { newWebhookSecret: webhookSec, newAdminPasscode: adminPass }
      })
    }
  }).getContent());
  assert.equal(saveSecRes.success, true);
  assert.equal(saveSecRes.webhookSecretConfigured, true);
  assert.equal(saveSecRes.adminPasscodeConfigured, true);
  assert.equal(JSON.stringify(saveSecRes).includes(webhookSec), false);
  assert.equal(JSON.stringify(saveSecRes).includes(adminPass), false);
  assert.equal(store.PORTAL_WEBHOOK_SECRET, webhookSec);
  assert.ok(store.ADMIN_AUTH_HASH);
  assert.ok(store.ADMIN_AUTH_SALT);

  // 3. Sem sessão Google: autentica via admin_authenticate e executa leitura/escrita controlada
  setUserEmail('');
  const badAuth = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify({ action: 'admin_authenticate', email: 'lukaslaurinocppa@gmail.com', passcode: 'incorreta' }) }
  }).getContent());
  assert.equal(badAuth.success, false);

  const okAuth = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify({ action: 'admin_authenticate', email: 'lukaslaurinocppa@gmail.com', passcode: adminPass }) }
  }).getContent());
  assert.equal(okAuth.success, true);
  assert.ok(okAuth.authToken);

  const bootRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify({ action: 'admin_bootstrap', authToken: okAuth.authToken }) }
  }).getContent());
  assert.equal(bootRes.success, true);
  assert.equal(bootRes.authMethod, 'admin_key_session');
  assert.equal(bootRes.securityStatus.webhookSecretConfigured, true);
  assert.equal(bootRes.securityStatus.adminPasscodeConfigured, true);

  const cfgRes = JSON.parse(ctx.doPost({
    postData: { contents: JSON.stringify({ action: 'admin_save_config', payload: bootRes.config, authToken: okAuth.authToken }) }
  }).getContent());
  assert.equal(cfgRes.success, true);
  assert.deepEqual(ctx.getConfig(), bootRes.config);
});

test('Motor de monitoramento 2.1: classificação HTTP 200, login 200, redirect Google, 403, 404, 500, falha rede, lento e desativado', () => {
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);
  const fetchedUrls = [];
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    fetchHandler(url, params) {
      fetchedUrls.push({ url, followRedirects: params.followRedirects, muteHttpExceptions: params.muteHttpExceptions });
      if (url === SISFAR_CONFIG.ambientes.cppaOficial.url) {
        return { status: 200, body: '<!doctype html><html><title>SISFAR</title><body>App Paciente_TOKEN_NAO_PERSISTIR</body></html>' };
      }
      if (url === SISFAR_CONFIG.ambientes.pepoaOficial.url) {
        return { status: 200, body: '<html><title>Sign in - Google Accounts</title><form id="gaia_loginform"></form></html>' };
      }
      if (url === SISFAR_CONFIG.ambientes.madreOficial.url) {
        return { status: 302, headers: { Location: 'https://accounts.google.com/v3/signin?continue=https://script.google.com/secret_ticket=123' } };
      }
      if (url === SISFAR_CONFIG.ambientes.cppaAudit.url) {
        return { status: 403, body: 'Forbidden' };
      }
      if (url === SISFAR_CONFIG.ambientes.pepoaAudit.url) {
        return { status: 404, body: 'Not Found' };
      }
      return { status: 500, body: 'Internal Server Error' };
    }
  });

  // Desativar madreAudit administrativamente e configurar slowThreshold baixo para testar lentidão
  const cfg = JSON.parse(JSON.stringify(gas.ctx.getConfig()));
  cfg.madreAudit.ativo = false;
  gas.ctx.apiSaveAdminConfig(cfg);
  const originalCppaUrl = cfg.cppaOficial.url;

  const res = gas.runScheduled();
  assert.equal(res.success, true);
  assert.equal(res.checkedCount, 5); // madreAudit desativado não é sondado!
  assert.equal(fetchedUrls.some((f) => f.url === cfg.madreAudit.url), false);
  for (const f of fetchedUrls) {
    assert.equal(f.followRedirects, false, 'Sondas não devem seguir redirects');
    assert.equal(f.muteHttpExceptions, true);
  }

  const boot = gas.ctx.apiGetPublicBootstrap();
  const envs = boot.monitoring.environments;
  assert.equal(envs.cppaOficial.effectiveStatus, 'ACESSIVEL');
  assert.equal(envs.pepoaOficial.effectiveStatus, 'AUTENTICACAO_NECESSARIA');
  assert.equal(envs.madreOficial.effectiveStatus, 'AUTENTICACAO_NECESSARIA');
  assert.equal(envs.cppaAudit.effectiveStatus, 'NAO_VERIFICAVEL'); // acesso proibido
  assert.equal(envs.pepoaAudit.effectiveStatus, 'FALHA_VERIFICACAO'); // 1ª falha
  assert.equal(envs.madreAudit.effectiveStatus, 'DESATIVADO');
  assert.equal(boot.monitoring.summary.accessible, 1);
  assert.equal(boot.monitoring.summary.nonVerifiable, 4); // 2 auth + 1 proibido + 1 desativado (nunca contados como sucesso!)
  assert.equal(boot.monitoring.incidents.length, 0); // ainda na 1ª falha

  // Não persistir conteúdo integral/tokens/cookies
  const dumped = JSON.stringify(gas.store);
  assert.equal(dumped.includes('Paciente_TOKEN_NAO_PERSISTIR'), false);
  assert.equal(dumped.includes('secret_ticket=123'), false);
  assert.equal(gas.ctx.getConfig().cppaOficial.url, originalCppaUrl);

  // Testar 500 e erro de rede + lentidão com fetchAll fallback
  gas.ctx.apiSaveMonitoringSettings({ slowThresholdMs: 500, useFetchAll: true });
  gas.setFetchAllHandler(() => { throw new Error('Batch network error'); });
  gas.setFetchHandler((url) => {
    if (url === cfg.cppaOficial.url) {
      const t0 = Date.now();
      while (Date.now() - t0 < 515) {} // simula resposta lenta >= 500ms
      return { status: 200, body: '<html><title>OK</title></html>' };
    }
    if (url === cfg.cppaAudit.url) {
      throw new Error('Request failed for https://script.google.com/macros/s/test?token=abc: Timed out');
    }
    if (url === cfg.pepoaAudit.url) {
      return { status: 500, body: 'Server error' };
    }
    return { status: 302, headers: { Location: 'https://accounts.google.com/ServiceLogin' } };
  });

  const res2 = gas.runScheduled();
  assert.equal(res2.mode, 'isolated_fetch'); // fallback automático quando fetchAll falha
  const envs2 = gas.ctx.apiGetPublicBootstrap().monitoring.environments;
  assert.equal(envs2.cppaOficial.effectiveStatus, 'RESPOSTA_LENTA');
  assert.equal(envs2.cppaAudit.effectiveStatus, 'FALHA_VERIFICACAO');
  assert.equal(envs2.pepoaAudit.effectiveStatus, 'INDISPONIVEL');
  assert.equal(envs2.cppaAudit.lastErrorSanitized.includes('token=abc'), false);
});

test('Incidentes consecutivos, estados administrativos e regra de recuperação configurável', () => {
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);
  let cppaOk = false;
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    fetchHandler(url) {
      if (url === SISFAR_CONFIG.ambientes.cppaOficial.url) {
        return cppaOk ? { status: 200, body: '<html>OK</html>' } : { status: 500, body: 'Down' };
      }
      return { status: 200, body: '<html>OK</html>' };
    }
  });

  // 1ª falha -> FALHA_VERIFICACAO, sem incidente
  gas.runScheduled();
  let mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'FALHA_VERIFICACAO');
  assert.equal(mon.incidents.length, 0);

  // 2ª falha consecutiva -> INDISPONIVEL, abre incidente INVESTIGACAO
  gas.runScheduled();
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'INDISPONIVEL');
  assert.equal(mon.incidents.length, 1);
  const incId = mon.incidents[0].id;
  assert.equal(mon.incidents[0].estado, 'INVESTIGACAO');
  assert.equal(mon.incidents[0].falhasConsecutivas, 2);

  // Admin confirma incidente e adiciona observação
  const upd = gas.ctx.apiUpdateMonitoringIncident({
    id: incId,
    estado: 'CONFIRMADO',
    observacao: 'Falha confirmada no container CPPA'
  });
  assert.equal(upd.item.estado, 'CONFIRMADO');
  assert.equal(upd.item.observacao, 'Falha confirmada no container CPPA');

  // Regra de recuperação padrão = 2 sucessos consecutivos: 1º sucesso ainda mantém INDISPONIVEL (recoveringCount = 1)
  cppaOk = true;
  gas.runScheduled();
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'INDISPONIVEL');
  assert.equal(mon.environments.cppaOficial.recoveringCount, 1);
  assert.equal(mon.incidents[0].estado, 'CONFIRMADO');

  // 2º sucesso consecutivo -> recupera para ACESSIVEL e resolve incidente
  gas.runScheduled();
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'ACESSIVEL');
  assert.equal(mon.incidents[0].estado, 'RESOLVIDO');
  assert.ok(mon.incidents[0].encerramento);

  // Novo incidente encerrado administrativamente
  cppaOk = false;
  gas.runScheduled();
  gas.runScheduled();
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  const inc2 = mon.incidents.find((i) => i.estado === 'INVESTIGACAO');
  assert.ok(inc2);
  const closedAdm = gas.ctx.apiUpdateMonitoringIncident({
    id: inc2.id,
    estado: 'ENCERRADO_ADMIN',
    observacao: 'Encerrado manualmente após validação'
  });
  assert.equal(closedAdm.item.estado, 'ENCERRADO_ADMIN');
});

test('Manutenções CRUD (America/Sao_Paulo) preservam evidências reais e retornam ao encerrar; expiração marca DADOS_DESATUALIZADOS', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.runScheduled();

  const startLocal = new Date(Date.now() - 3600000 - 3 * 3600000).toISOString().slice(0, 16); // -1h em BRT (-03:00)
  const endLocal = new Date(Date.now() + 3600000 - 3 * 3600000).toISOString().slice(0, 16);   // +1h em BRT (-03:00)

  const mntRes = gas.ctx.apiSaveMonitoringMaintenance({
    titulo: 'Atualização programada CPPA',
    descricao: 'Troca de versão do container',
    aviso: 'Em manutenção preventiva',
    alvo: 'CPPA',
    estado: 'EM_ANDAMENTO',
    inicio: startLocal,
    fim: endLocal
  });
  assert.equal(mntRes.success, true);

  let mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'MANUTENCAO');
  assert.equal(mon.environments.cppaAudit.effectiveStatus, 'MANUTENCAO');
  assert.equal(mon.environments.pepoaOficial.effectiveStatus, 'ACESSIVEL');
  assert.equal(mon.environments.cppaOficial.rawClassification, 'ACESSIVEL', 'Evidência real deve ser preservada');

  // Encerrar manutenção -> retorna imediatamente às evidências reais
  const endRes = gas.ctx.apiUpdateMonitoringMaintenanceStatus(mntRes.item.id, 'ENCERRADA');
  assert.equal(endRes.success, true);
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'ACESSIVEL');

  // Expiração (DADOS_DESATUALIZADOS) quando última amostra é mais antiga que staleMinutes
  const stObj = JSON.parse(gas.store.MONITOR_STATE);
  stObj.environments.cppaOficial.lastCheckedAt = new Date(Date.now() - 120 * 60000).toISOString();
  gas.store.MONITOR_STATE = JSON.stringify(stObj);
  mon = gas.ctx.apiGetPublicBootstrap().monitoring;
  assert.equal(mon.environments.cppaOficial.effectiveStatus, 'DADOS_DESATUALIZADOS');
});

test('Retenção, limites PropertiesService (<7800 B), agregação diária, lock de concorrência e deduplicação de triggers', () => {
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    initialTriggers: [
      { id: 'dup-1', handler: 'runScheduledMonitoringCheck', intervalMinutes: 15 },
      { id: 'dup-2', handler: 'runScheduledMonitoringCheck', intervalMinutes: 15 },
      { id: 'other-1', handler: 'otherTriggerHandler', intervalMinutes: 60 }
    ]
  });

  // Sincronizar remove duplicatas e mantém exatamente 1 trigger de monitoramento, preservando triggers alheios
  const sync1 = gas.ctx.apiSyncMonitoringTrigger();
  assert.equal(sync1.success, true);
  assert.equal(sync1.installedCount, 1);
  assert.equal(gas.triggers.filter((t) => t.handler === 'runScheduledMonitoringCheck_').length, 1);
  assert.equal(gas.triggers.filter((t) => t.handler === 'otherTriggerHandler').length, 1);

  // Salvar mesma frequência é idempotente (não duplica)
  gas.ctx.apiSaveMonitoringSettings({ intervalMinutes: 15 });
  assert.equal(gas.triggers.filter((t) => t.handler === 'runScheduledMonitoringCheck_').length, 1);

  // Pausar monitoramento remove trigger de monitoramento
  gas.ctx.apiSaveMonitoringSettings({ enabled: false });
  assert.equal(gas.triggers.filter((t) => t.handler === 'runScheduledMonitoringCheck_').length, 0);
  gas.ctx.apiSaveMonitoringSettings({ enabled: true });
  assert.equal(gas.triggers.filter((t) => t.handler === 'runScheduledMonitoringCheck_').length, 1);

  // Executar 35 ciclos para testar segmentação, retenção e agregação diária dentro de <=7800 bytes por propriedade
  for (let i = 0; i < 35; i++) {
    gas.runScheduled();
  }
  const bootAdmin = gas.ctx.apiGetAdminBootstrap();
  const storage = bootAdmin.monitoring.storageStats;
  assert.ok(storage.segmentsCount <= 6);
  for (const b of storage.breakdown) {
    assert.ok(b.bytes <= 7800, `Propriedade ${b.key} excedeu 7800 bytes: ${b.bytes}`);
  }
  const dayKeys = Object.keys(bootAdmin.monitoring.daily);
  assert.equal(dayKeys.length, 1);
  assert.equal(bootAdmin.monitoring.daily[dayKeys[0]].cppaOficial.count, 35);

  const lockStats = gas.getLockStats();
  assert.ok(lockStats.lockCalls > 0 && lockStats.lockCalls === lockStats.unlockCalls, 'WaitLock e ReleaseLock devem ser simétricos');
});

test('Autorização fail-closed no monitoramento, doPost admin_monitoring_*, preservação CONFIG_LINKS e renderização resiliente a falhas', () => {
  const { ctx, setUserEmail } = createGasContext({
    userEmail: '',
    fetchHandler() {
      return { status: 500, body: 'Total outage' };
    }
  });

  // Todas mutações de monitoramento bloqueadas sem autenticação
  assert.throws(() => ctx.apiSaveMonitoringSettings({ enabled: false }), /Acesso negado/);
  assert.throws(() => ctx.apiUpdateMonitoringIncident({ id: 'inc-1', estado: 'RESOLVIDO' }), /Acesso negado/);
  assert.throws(() => ctx.apiSaveMonitoringMaintenance({ titulo: 'x', inicio: '2026-11-25T10:00', fim: '2026-11-25T12:00' }), /Acesso negado/);
  assert.throws(() => ctx.apiUpdateMonitoringMaintenanceStatus('mnt-1', 'ENCERRADA'), /Acesso negado/);
  assert.throws(() => ctx.apiRunManualMonitoringCheck(), /Acesso negado/);
  assert.throws(() => ctx.apiSyncMonitoringTrigger(), /Acesso negado/);

  for (const action of [
    'admin_monitoring_save_settings',
    'admin_monitoring_update_incident',
    'admin_monitoring_save_maintenance',
    'admin_monitoring_maintenance_status',
    'admin_monitoring_run_now',
    'admin_monitoring_sync_trigger'
  ]) {
    const res = JSON.parse(ctx.doPost({ postData: { contents: JSON.stringify({ action, payload: {} }) } }).getContent());
    assert.equal(res.success, false);
    assert.match(res.error, /Acesso negado/);
  }

  // Mesmo com todos 6 endpoints retornando 500 e 2 falhas consecutivas -> portal e status renderizam normalmente
  setUserEmail('lukaslaurino@gmail.com');
  const originalCfg = JSON.stringify(ctx.getConfig());
  ctx.apiRunManualMonitoringCheck();
  ctx.apiRunManualMonitoringCheck();
  assert.equal(JSON.stringify(ctx.getConfig()), originalCfg, 'Monitoramento nunca deve alterar CONFIG_LINKS');

  setUserEmail('');
  const portalOut = ctx.doGet({ parameter: { view: 'portal' } });
  const portalHtml = portalOut.getContent();
  assert.ok(portalHtml.includes('view-status'));
  assert.ok(portalHtml.includes('data-view="status"'));
  assert.equal(/\bOnline\b/i.test(portalHtml), false);

  const statusJson = JSON.parse(ctx.doGet({ parameter: { action: 'status' } }).getContent());
  assert.equal(statusJson.success, true);
  assert.equal(statusJson.monitoring.summary.unavailable, 6);
  assert.equal(statusJson.monitoring.summary.activeIncidents, 6);

  // Admin HTML inclui aba Monitoramento
  setUserEmail('lukaslaurinocppa@gmail.com');
  const adminHtml = ctx.doGet({ parameter: { view: 'admin' } }).getContent();
  assert.ok(adminHtml.includes('data-tab="monitoramento"'));
  assert.ok(adminHtml.includes('tab-monitoramento'));
  assert.equal(adminHtml.includes('PORTAL_WEBHOOK_SECRET'), false);
});

test('Cliente Portal 2.1: painel Status, amostra insuficiente, disponibilidade observada e lacunas explícitas', () => {
  const { ctx, runScheduled } = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  const portalHtml = ctx.doGet({ parameter: { view: 'portal' } }).getContent();
  const harness = createDomHarness(portalHtml);

  for (const suffix of ['cppa-oficial', 'pepoa-oficial', 'madre-oficial', 'cppa-audit', 'pepoa-audit', 'madre-audit']) {
    harness.elements[`mon-status-${suffix}`] = { className: '', innerHTML: '', textContent: '' };
    harness.elements[`mon-check-${suffix}`] = { className: '', innerHTML: '', textContent: '' };
  }
  for (const extra of [
    'navCountStatus', 'activeIncidentsBanner', 'activeIncidentsBannerText',
    'statusKpiMonitored', 'statusKpiMonitoredSub', 'statusKpiAccessible',
    'statusKpiAttention', 'statusKpiAttentionSub', 'statusKpiIncidents',
    'statusKpiNonVerifiable', 'statusKpiNonVerifiableSub', 'statusKpiLastRun', 'statusKpiLastRunSub',
    'statusEnvTableContainer', 'statusFilterSummary', 'statusAvailabilityContainer',
    'statusTimelineContainer', 'statusSvgChartContainer', 'statusIncidentsContainer', 'statusMaintenancesContainer',
    'filterStatusUnit', 'filterStatusEnv', 'filterStatusPeriod'
  ]) {
    harness.elements[extra] = {
      id: extra, value: extra === 'filterStatusPeriod' ? '24h' : (extra === 'filterStatusUnit' ? 'TODAS' : 'TODOS'),
      textContent: '', innerHTML: '', className: '',
      classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
      addEventListener() {}
    };
  }

  // Simular 2 amostras apenas para cppaOficial (abaixo do mínimo 4 -> Amostra insuficiente) e 4 para pepoaAudit
  const now = Date.now();
  runScheduled();
  runScheduled();

  const boot = ctx.apiGetPublicBootstrap();
  // Injetar 2 amostras extras em memória no mock de bootstrap apenas para validar o cálculo >= 4 vs < 4 no cliente
  boot.monitoring.samples.push(
    { t: new Date(now - 600000).toISOString(), e: 'pepoaAudit', s: 'ACESSIVEL', r: 'ACESSIVEL', d: 210, c: 200, k: 'HTTP_200_OK', m: 0 },
    { t: new Date(now - 1200000).toISOString(), e: 'pepoaAudit', s: 'ACESSIVEL', r: 'ACESSIVEL', d: 240, c: 200, k: 'HTTP_200_OK', m: 0 }
  );

  harness.run({
    withSuccessHandler(fn) {
      return {
        withFailureHandler() {
          return {
            apiGetPublicBootstrap() { fn(boot); }
          };
        }
      };
    }
  });

  assert.ok(harness.elements['mon-status-cppa-oficial'].innerHTML.includes('Acessível (HTTP)'));
  assert.ok(harness.elements.statusAvailabilityContainer.innerHTML.includes('Amostra insuficiente (2/4 verificáveis)'));
  assert.ok(harness.elements.statusAvailabilityContainer.innerHTML.includes('100% HTTP acessível'));
  assert.ok(harness.elements.statusTimelineContainer.innerHTML.includes('lacunas'));
  assert.ok(harness.elements.statusSvgChartContainer.innerHTML.includes('<svg'));
});

test('UrlFetchApp.fetchAll lote bem-sucedido e contrato público ?action=status sem vazamento administrativo', () => {
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);
  let fetchAllCalls = 0;
  let singleFetchCalls = 0;
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    fetchHandler() {
      singleFetchCalls++;
      return { status: 200, body: '<html>OK</html>' };
    },
    fetchAllHandler(reqs) {
      fetchAllCalls++;
      return reqs.map((r) => {
        assert.equal(r.followRedirects, false);
        assert.equal(r.muteHttpExceptions, true);
        if (r.url === SISFAR_CONFIG.ambientes.cppaOficial.url) {
          return { status: 200, body: '<html>OK</html>' };
        }
        return { status: 302, headers: { Location: 'https://accounts.google.com/ServiceLogin?continue=' + encodeURIComponent(r.url) } };
      });
    }
  });

  gas.ctx.apiSaveMonitoringSettings({ useFetchAll: true });
  const res = gas.runScheduled();
  assert.equal(res.success, true);
  assert.equal(res.mode, 'fetchAll');
  assert.equal(fetchAllCalls, 1);
  assert.equal(singleFetchCalls, 0);

  // Consulta pública ?action=status com sessão anônima
  gas.setUserEmail('');
  const statusRes = JSON.parse(gas.ctx.doGet({ parameter: { action: 'status' } }).getContent());
  assert.equal(statusRes.success, true);
  assert.equal(statusRes.schemaVersion, '2.1');
  assert.equal(statusRes.monitoring.summary.accessible, 1);
  assert.equal(statusRes.monitoring.summary.authRequired, 5);
  assert.equal(statusRes.monitoring.summary.nonVerifiable, 5);
  assert.equal(statusRes.monitoring.triggerDiagnostics, undefined, 'Endpoint público não deve expor diagnóstico de triggers');
  assert.equal(statusRes.monitoring.storageStats, undefined, 'Endpoint público não deve expor detalhes internos de armazenamento');
  assert.equal(statusRes.monitoring.quotaEstimate.checksPerDayNominal, 576);
});

test('Cliente Admin 2.1: renderização de diagnóstico, cotas, incidentes, manutenções e gate fail-closed', () => {
  const gas = createGasContext({
    userEmail: 'lukaslaurinocppa@gmail.com',
    fetchHandler(url) {
      if (url.includes('AKfycbwNoAHomZzaIT25QL7U7Tod9XA')) {
        return { status: 500, body: 'Outage' };
      }
      return { status: 302, headers: { Location: 'https://accounts.google.com/ServiceLogin' } };
    }
  });

  gas.runScheduled();
  gas.runScheduled();
  gas.ctx.apiSyncMonitoringTrigger();
  gas.ctx.apiSaveMonitoringMaintenance({
    titulo: 'Janela preventiva teste',
    alvo: 'PEPOA',
    estado: 'EM_ANDAMENTO',
    inicio: '2026-11-25T08:00',
    fim: '2026-11-25T18:00'
  });

  const adminBoot = gas.ctx.apiGetAdminBootstrap();
  const adminHtml = gas.ctx.doGet({ parameter: { view: 'admin' } }).getContent();
  const harness = createDomHarness(adminHtml);

  for (const id of [
    'loginGate', 'adminWorkspace', 'adminEmailLabel', 'statusSummary', 'lastUpdate',
    'groupOficial', 'groupAudit', 'adminReleaseStateGrid', 'adminReleaseHistoryWrap',
    'storageStatsLine', 'adminAnnListWrap', 'secStatusBadges',
    'cfgTitle', 'cfgSubtitle', 'cfgObs', 'cfgMaxSegs', 'cfgReplaySec', 'cfgAdminEmails',
    'monDiagnosticsBox', 'monEnabled', 'monInterval', 'monSlowMs', 'monFailThresh',
    'monRecoveryThresh', 'monStaleMin', 'monHistDays', 'monDailyDays', 'monIncDays',
    'monFetchMode', 'monEnvTogglesWrap', 'monIncidentsWrap', 'monMaintListWrap',
    'btnThemeToggle', 'btnHealthCheck', 'btnReload', 'btnSave', 'btnReset',
    'btnRecordRelease', 'btnResetAnnForm', 'btnSaveAnn', 'btnSaveSettings',
    'btnAdminLogin', 'btnMonRunNow', 'btnMonSyncTrigger', 'btnSaveMonSettings',
    'btnResetMaintForm', 'btnSaveMaint'
  ]) {
    harness.elements[id] = {
      id,
      value: '',
      textContent: '',
      innerHTML: '',
      className: '',
      style: {},
      classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
      querySelectorAll() { return []; },
      appendChild() {},
      addEventListener() {}
    };
  }

  harness.run({
    withSuccessHandler(fn) {
      return {
        withFailureHandler() {
          return {
            apiGetAdminBootstrap() { fn(adminBoot); }
          };
        }
      };
    }
  });

  assert.equal(harness.elements.loginGate.style.display, 'none');
  assert.equal(harness.elements.adminWorkspace.style.display, 'block');
  assert.ok(harness.elements.monDiagnosticsBox.innerHTML.includes('1 trigger ativo (OK)'));
  assert.ok(harness.elements.monDiagnosticsBox.innerHTML.includes('576'));
  assert.ok(harness.elements.monDiagnosticsBox.innerHTML.includes('20000'));
  assert.ok(harness.elements.monEnvTogglesWrap.innerHTML.includes('INDISPONIVEL'));
  assert.ok(harness.elements.monEnvTogglesWrap.innerHTML.includes('AUTENTICACAO_NECESSARIA'));
  assert.ok(harness.elements.monIncidentsWrap.innerHTML.includes('INVESTIGACAO'));
  assert.ok(harness.elements.monMaintListWrap.innerHTML.includes('Janela preventiva teste'));
});

test('A coleta anônima fica bloqueada antes de sondar ou persistir', () => {
  let fetches = 0;
  const { ctx, store, setUserEmail } = createGasContext({
    fetchHandler() { fetches++; return { status: 200 }; }
  });
  assert.equal(typeof ctx.runScheduledMonitoringCheck, 'undefined');
  assert.equal(ctx.runScheduledMonitoringCheck_({ triggerUid: 'forged' }).skipped, true);
  assert.throws(() => ctx.apiRunManualMonitoringCheck(), /Acesso negado/);
  assert.equal(fetches, 0);
  assert.equal(store.MONITOR_STATE, undefined);
  setUserEmail('lukaslaurino@gmail.com');
  assert.equal(ctx.apiRunManualMonitoringCheck().checkedCount, 6);
  assert.equal(fetches, 6);
  assert.equal(Object.keys(JSON.parse(store.MONITOR_STATE).environments).length, 6);
});

test('A sonda roda fora do lock e ignora um ciclo simultâneo antes da rede', () => {
  let fetches = 0;
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    fetchHandler() {
      fetches++;
      const { lockCalls, unlockCalls } = gas.getLockStats();
      assert.equal(lockCalls, unlockCalls);
      if (fetches === 1) assert.equal(gas.ctx.apiRunManualMonitoringCheck().skipped, true);
      return { status: 200 };
    }
  });
  const result = gas.ctx.apiRunManualMonitoringCheck();
  assert.equal(result.checkedCount, 6);
  assert.equal(fetches, 6);
  assert.equal(result.monitoring.samples.length, 6);
});

test('Um ciclo atrasado perde a concessão e não sobrescreve o sucessor', () => {
  const originalTime = Date.now();
  let time = originalTime;
  let successorStarted = false;
  let successorRunning = false;
  class Clock extends Date {
    constructor(value = time) { super(value); }
    static now() { return time; }
  }
  const gas = createGasContext({
    date: Clock,
    userEmail: 'lukaslaurino@gmail.com',
    fetchHandler() {
      if (!successorStarted) {
        successorStarted = true;
        time += 8 * 60000;
        successorRunning = true;
        assert.equal(gas.ctx.apiRunManualMonitoringCheck().checkedCount, 6);
        successorRunning = false;
      }
      return { status: successorRunning ? 200 : 503 };
    }
  });
  const result = gas.ctx.apiRunManualMonitoringCheck();
  assert.equal(result.skipped, true);
  assert.equal(result.monitoring.environments.cppaOficial.httpStatus, 200);
  assert.equal(result.monitoring.samples.length, 6);
  assert.equal(result.monitoring.samples[0].t, new Date(originalTime + 8 * 60000).toISOString());
});

test('A sincronização migra gatilhos antigos e mantém o ID do único gatilho válido', () => {
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    initialTriggers: [
      { id: 'old', handler: 'runScheduledMonitoringCheck' },
      { id: 'other', handler: 'other' }
    ]
  });
  const first = gas.ctx.apiSyncMonitoringTrigger();
  const second = gas.ctx.apiSyncMonitoringTrigger();
  assert.equal(first.success, true);
  assert.equal(second.action, 'kept_existing');
  const trigger = gas.triggers.find((item) => item.handler === 'runScheduledMonitoringCheck_');
  assert.deepEqual(gas.triggers.map((item) => item.id), ['other', trigger.id]);
  assert.equal(trigger.intervalMinutes, 15);
  assert.equal(gas.ctx.runScheduledMonitoringCheck_({ triggerUid: 'old' }).skipped, true);
  assert.equal(gas.ctx.runScheduledMonitoringCheck_({ triggerUid: trigger.id }).checkedCount, 6);
});

test('Redirect técnico e 403 sem login são inconclusivos, sem latência individual de lote', () => {
  const gas = createGasContext({
    userEmail: 'lukaslaurino@gmail.com',
    fetchAllHandler(requests) {
      return requests.map((_, i) => i % 2 === 0
        ? { status: 302, headers: { Location: 'https://script.googleusercontent.com/macros/echo' } }
        : { status: 403 });
    }
  });
  gas.ctx.apiSaveMonitoringSettings({ useFetchAll: true });
  gas.ctx.apiRunManualMonitoringCheck();
  const { monitoring } = gas.ctx.apiRunManualMonitoringCheck();
  assert.equal(monitoring.summary.nonVerifiable, 6);
  assert.equal(monitoring.summary.accessible, 0);
  assert.equal(monitoring.summary.unavailable, 0);
  assert.equal(monitoring.incidents.length, 0);
  assert.ok(monitoring.samples.every((sample) => sample.d === null));
  assert.ok(Object.values(monitoring.environments).every((env) => env.durationMs === null));
});

test('A coleta preserva CONFIG_LINKS, histórico de releases e homologação', () => {
  const { ctx, store } = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  ctx.apiSaveAdminConfig(ctx.getConfig());
  ctx.apiRecordAdminReleaseEvent({
    schemaVersion: '2.0',
    eventId: 'evt-monitor-no-release-mutation',
    deploymentId: ctx.getConfig().pepoaAudit.url.split('/')[5],
    unidade: 'PEPOA',
    ambiente: 'AUDIT',
    tipoEvento: 'publish',
    versao: '4.38.9',
    commit: '2c6169b',
    deploymentVersion: '118',
    url: ctx.getConfig().pepoaAudit.url,
    publicadoEm: new Date().toISOString(),
    estadoHomologacao: 'EM_HOMOLOGACAO'
  });
  const before = ctx.apiGetPublicBootstrap();
  const releaseKeys = Object.keys(store).filter((key) => key.startsWith('SISFAR_RELEASE'));
  const protectedKeys = ['CONFIG_LINKS', ...releaseKeys];
  const original = protectedKeys.map((key) => store[key]);
  assert.equal(ctx.apiRunManualMonitoringCheck().checkedCount, 6);
  const after = ctx.apiGetPublicBootstrap();
  assert.deepEqual(protectedKeys.map((key) => store[key]), original);
  assert.deepEqual(after.releaseHistory, before.releaseHistory);
  assert.equal(after.releaseState.environments.pepoaAudit.estadoHomologacao, 'EM_HOMOLOGACAO');
});

test('A leitura legado omite duração sem origem e corrige redirecionamento agregado', () => {
  const t = new Date().toISOString();
  const day = t.slice(0, 10);
  const key = 'MONITOR_HISTORY_SEG_0';
  const category = 'HTTP_3XX_REDIRECT_SLOW';
  const gas = createGasContext({
    initialProperties: {
      MONITOR_STATE: JSON.stringify({ lastRunMode: 'fetchAll (clock-trigger)', environments: {
        cppaOficial: { lastCheckedAt: t, durationMs: 9000, rawClassification: 'RESPOSTA_LENTA',
          category, lastSummarySanitized: 'HTTP 302 — Redirecionamento técnico · 9000 ms' }
      }}),
      MONITOR_HISTORY: JSON.stringify({ segments: [key], daily: {
        [day]: { cppaOficial: { count: 4, ok: 3, slow: 1, fail: 0, auth: 0, sumMs: 36000 } }
      }}),
      [key]: JSON.stringify([{ e: 'cppaOficial', t, s: 'RESPOSTA_LENTA', r: 'RESPOSTA_LENTA', d: 9000, k: category }])
    }
  });
  const { monitoring } = gas.ctx.apiGetPublicBootstrap();
  const env = monitoring.environments.cppaOficial;
  assert.equal(env.effectiveStatus, 'NAO_VERIFICAVEL');
  assert.equal(env.durationMs, null);
  assert.doesNotMatch(env.statusReason, /9000/);
  assert.equal(monitoring.samples[0].d, null);
  assert.equal(monitoring.daily[day].cppaOficial.ok, 0);
  assert.equal(monitoring.daily[day].cppaOficial.unknown, 4);
  assert.match(gas.store[key], /9000/);
});

/* ==================== TESTES 2.2 — CENTRAL DE SUPORTE, OCORRÊNCIAS E SUGESTÕES ==================== */

test('Suporte 2.2: acesso verificado (credencial/convite/sessão Google), bloqueio anônimo e regra APAC exclusiva PEPOA', () => {
  const gas = createGasContext({ userEmail: '' });

  // Sem credencial configurada e sem e-mail Google -> fail-closed
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Login',
    titulo: 'Erro sem credencial',
    descricao: 'Tentativa anônima irrestrita deve falhar imediatamente.',
    solicitanteNome: 'Operador Teste',
    confirmacaoSemDadosClinicos: true
  }), /403 Não Autorizado/);

  // Admin configura credencial de suporte distinta do admin e HMAC
  gas.setUserEmail('lukaslaurino@gmail.com');
  gas.ctx.apiSaveAdminSettings({
    newAdminPasscode: 'AdminPass123456',
    newWebhookSecret: 'WebhookSecret1234567890'
  });

  // Tentativa de definir credencial igual ao admin ou HMAC deve ser bloqueada
  assert.throws(() => gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'AdminPass123456' }), /distinta da chave administrativa/);
  assert.throws(() => gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'WebhookSecret1234567890' }), /distinta do segredo HMAC/);

  const supCfgRes = gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'SuporteSisfar2026' });
  assert.equal(supCfgRes.success, true);
  assert.equal(supCfgRes.supportCredentialConfigured, true);

  // Credencial de suporte não pode autenticar como admin
  assert.throws(() => gas.ctx.apiAdminAuthenticate('lukaslaurino@gmail.com', 'SuporteSisfar2026'), /Credencial administrativa inválida/);

  // Registrar uma release na PEPOA AUDIT para verificar confirmação backend
  gas.ctx.apiRecordAdminReleaseEvent({
    schemaVersion: '2.0',
    eventId: 'evt-sup-rel-1',
    unidade: 'PEPOA',
    ambiente: 'AUDIT',
    tipoEvento: 'publish',
    versao: '4.39.2',
    commit: 'abc1234',
    deploymentVersion: '210',
    deploymentId: 'AKfycb_PEPOA_AUDIT_DEP',
    url: gas.ctx.getConfig().pepoaAudit.url,
    publicadoEm: new Date().toISOString(),
    estadoHomologacao: 'EM_HOMOLOGACAO'
  });

  // Gerar convite restrito à PEPOA com limite de 1 uso
  const invRes = gas.ctx.apiCreateAdminSupportInvite({
    rotulo: 'Equipe PEPOA',
    unidade: 'PEPOA',
    diasValidade: 7,
    maxUsos: 1
  });
  assert.equal(invRes.success, true);
  assert.ok(invRes.inviteCode.startsWith('SUP-INV-'));

  // Usuário público sem Google email
  gas.setUserEmail('');

  // Admin passcode / HMAC secret não funcionam no suporte
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Login',
    titulo: 'Tentativa com admin key',
    descricao: 'Chave admin não deve abrir chamado público.',
    solicitanteNome: 'Tester',
    supportCode: 'AdminPass123456',
    confirmacaoSemDadosClinicos: true
  }), /403 Não Autorizado/);

  // APAC bloqueado para CPPA e MADRE
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'APAC',
    titulo: 'Erro APAC na CPPA',
    descricao: 'Módulo APAC não pertence à unidade CPPA.',
    solicitanteNome: 'Farmacêutico CPPA',
    supportCode: 'SuporteSisfar2026',
    confirmacaoSemDadosClinicos: true
  }), /APAC é pertinente exclusivamente à unidade PEPOA/);

  // Convite restrito à PEPOA rejeitado na CPPA
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    categoria: 'Solicitação de suporte',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Dashboard',
    titulo: 'Convite em unidade errada',
    descricao: 'Convite da PEPOA não pode ser usado na CPPA.',
    solicitanteNome: 'Operador CPPA',
    supportCode: invRes.inviteCode,
    confirmacaoSemDadosClinicos: true
  }), /Convite restrito à unidade PEPOA/);

  // Convite válido na PEPOA + módulo APAC funciona e confirma release backend (ignorando versão forjada do cliente)
  const created = gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'PEPOA',
    ambiente: 'AUDIT',
    modulo: 'APAC',
    titulo: 'Divergência no filtro de relatório APAC',
    descricao: 'Ao filtrar por período de 30 dias no módulo APAC, a contagem total exibe valor antigo.',
    observado: 'Total exibido permanece do filtro anterior',
    esperado: 'Total deve atualizar conforme período selecionado',
    impactoInformado: 'Moderado',
    versaoContexto: { versao: '9.9.9-FORJADA' },
    solicitanteNome: 'Farmacêutica PEPOA',
    supportCode: invRes.inviteCode,
    confirmacaoSemDadosClinicos: true
  });
  assert.equal(created.success, true);
  assert.match(created.protocolo, /^SUP-\d{8}-[A-Z0-9]{6}$/);
  assert.ok(created.trackingToken.startsWith('stk_'));
  assert.equal(created.ticket.versaoContexto.versao, '4.39.2');
  assert.equal(created.ticket.versaoContexto.deploymentVersion, '210');
  assert.equal(created.ticket.versaoContexto.confirmadaPorRelease, true);

  // Token em texto claro nunca deve ser persistido no store
  const allStoreText = JSON.stringify(gas.store);
  assert.equal(allStoreText.includes(created.trackingToken), false);

  // Bootstrap público nunca inclui lista de chamados
  const boot = JSON.parse(gas.ctx.doGet({ parameter: { action: 'bootstrap' } }).getContent());
  assert.equal(boot.tickets, undefined);
  assert.ok(boot.supportConfig);
  assert.equal(boot.supportConfig.apacUnit, 'PEPOA');

  // 2ª tentativa com o mesmo convite (maxUsos=1) deve falhar
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    categoria: 'Outros',
    unidade: 'PEPOA',
    ambiente: 'AUDIT',
    modulo: 'APAC',
    titulo: 'Segundo uso de convite esgotado',
    descricao: 'Convite com limite de 1 uso deve bloquear a segunda chamada.',
    solicitanteNome: 'Farmacêutica PEPOA',
    supportCode: invRes.inviteCode,
    confirmacaoSemDadosClinicos: true
  }), /Limite de usos do convite/);
});

test('Suporte 2.2: validação de payload inválido, privacidade clínica, anexos, limites e sanitização XSS', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'CredSuporte01' });
  gas.setUserEmail('');

  const base = {
    categoria: 'Erro de sistema',
    unidade: 'MADRE',
    ambiente: 'OFICIAL',
    modulo: 'Dispensação',
    titulo: 'Falha válida de teste',
    descricao: 'Descrição válida suficiente para validação inicial do formulário.',
    solicitanteNome: 'Equipe MADRE',
    supportCode: 'CredSuporte01',
    confirmacaoSemDadosClinicos: true
  };

  // Sem confirmação explícita de ausência de dados clínicos
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, confirmacaoSemDadosClinicos: false }), /Confirme explicitamente/);

  // Com anexos ou base64
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, anexos: ['a.png'] }), /Anexos e arquivos não são permitidos/);
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, descricao: 'Print: data:image/png;base64,AAAA123456' }), /base64/);

  // Com CPF formatado ou identificador INFOPEN/prontuário
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, descricao: 'Paciente CPF 123.456.789-00 com erro' }), /CPF/);
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, descricao: 'Verificar prontuário: 99887766 urgente' }), /identificadores individuais/);

  // Honeypot preenchido
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, website: 'http://spam.example' }), /anti-spam/);

  // Categoria, módulo, título curto e descrição gigante
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, categoria: 'Inexistente' }), /Categoria inválida/);
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, modulo: 'Invalido' }), /Módulo inválido/);
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, titulo: 'Oi' }), /Título deve ter/);
  assert.throws(() => gas.ctx.apiCreateSupportTicket({ ...base, descricao: 'x'.repeat(13000) }), /excede o tamanho máximo/);

  // Sanitização XSS mantendo texto legível
  const xssRes = gas.ctx.apiCreateSupportTicket({
    ...base,
    titulo: 'Erro <script>alert(1)</script>tempo < 3s',
    descricao: 'Ao clicar <img src=x onerror=alert(2)> ocorre javascript:alert(3) na tela.',
    observado: '<svg onload=alert(4)>Falha visual</svg> e valor < 10'
  });
  assert.equal(xssRes.success, true);
  assert.equal(xssRes.ticket.titulo.includes('<script>'), false);
  assert.equal(xssRes.ticket.descricao.includes('onerror='), false);
  assert.equal(xssRes.ticket.descricao.includes('javascript:'), false);
  assert.equal(xssRes.ticket.observado.includes('<svg'), false);
  assert.ok(xssRes.ticket.observado.includes('< 10'));
});

test('Suporte 2.2: idempotência por clientRequestId e rate limiting de criação e consulta', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'CredRate2026' });
  gas.setUserEmail('');

  const payload = {
    categoria: 'Lentidão',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Consultas',
    titulo: 'Lentidão na consulta de estoque',
    descricao: 'Consulta demora acima de 10 segundos no início do turno.',
    solicitanteNome: 'Operador CPPA',
    supportCode: 'CredRate2026',
    confirmacaoSemDadosClinicos: true,
    clientRequestId: 'req-idemp-123456'
  };

  const first = gas.ctx.apiCreateSupportTicket(payload);
  const second = gas.ctx.apiCreateSupportTicket(payload);
  assert.equal(first.duplicate, false);
  assert.equal(second.duplicate, true);
  assert.equal(second.protocolo, first.protocolo);

  // Rate limit: até 5 criações por 10 min por credencial+unidade; a 6ª deve bloquear (429)
  for (let i = 2; i <= 5; i++) {
    const r = gas.ctx.apiCreateSupportTicket({
      ...payload,
      titulo: `Chamado sequencial ${i}`,
      clientRequestId: `req-rate-${i}-abcdef`
    });
    assert.equal(r.success, true);
  }
  assert.throws(() => gas.ctx.apiCreateSupportTicket({
    ...payload,
    titulo: 'Chamado 6 excedendo limite',
    clientRequestId: 'req-rate-6-abcdef'
  }), /429 Limite de frequência/);

  // Rate limit de consultas falhas no mesmo protocolo (máx 10 tentativas)
  for (let a = 1; a <= 10; a++) {
    assert.throws(() => gas.ctx.apiLookupSupportTicket(first.protocolo, 'stk_token_invalido_1234567890'), /Chamado não encontrado ou token/);
  }
  assert.throws(() => gas.ctx.apiLookupSupportTicket(first.protocolo, 'stk_token_invalido_1234567890'), /429 Muitas tentativas inválidas/);
});

test('Suporte 2.2: consulta individual, privacidade de notas internas, ciclo de estados e não-encerramento por release', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'CredPriv2026' });
  gas.setUserEmail('');

  const t1 = gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'PEPOA',
    ambiente: 'OFICIAL',
    modulo: 'Prescrições',
    titulo: 'Erro ao salvar ajuste de horário',
    descricao: 'Tela exibe mensagem inesperada ao confirmar ajuste.',
    esperado: 'Ajuste deve ser salvo sem erro.',
    solicitanteNome: 'Farmacêutico A',
    supportCode: 'CredPriv2026',
    confirmacaoSemDadosClinicos: true
  });

  const t2 = gas.ctx.apiCreateSupportTicket({
    categoria: 'Sugestão de melhoria',
    unidade: 'MADRE',
    ambiente: 'AUDIT',
    modulo: 'Relatórios',
    titulo: 'Filtro por turno em relatório',
    descricao: 'Permitir filtrar relatório de dispensação por turno diurno/noturno.',
    solicitanteNome: 'Farmacêutica B',
    supportCode: 'CredPriv2026',
    confirmacaoSemDadosClinicos: true
  });

  // Escrita admin não autorizada (anônimo) bloqueada via RPC e via doPost
  assert.throws(() => gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, estado: 'ENCERRADO' }), /Acesso negado/);
  assert.throws(() => gas.ctx.apiExportAdminSupportTickets([t1.ticketId], 'markdown'), /Acesso negado/);
  const unauthPost = JSON.parse(gas.ctx.doPost({
    postData: { contents: JSON.stringify({ action: 'admin_support_update', payload: { id: t1.ticketId, estado: 'ENCERRADO' } }) }
  }).getContent());
  assert.equal(unauthPost.success, false);
  assert.match(unauthPost.error, /Acesso negado/);

  // Token de t2 não consulta t1
  assert.throws(() => gas.ctx.apiLookupSupportTicket(t1.protocolo, t2.trackingToken), /Chamado não encontrado ou token/);

  // Admin executa ciclo de vida, nota interna, resposta pública e vínculos
  gas.setUserEmail('lukaslaurinocppa@gmail.com');
  gas.ctx.apiUpdateAdminSupportTicket({
    id: t1.ticketId,
    estado: 'AGUARDANDO_INFORMACOES',
    prioridade: 'crítica',
    respostaPublica: 'Por favor informe se ocorre em apenas um computador.',
    notaInterna: 'SEGREDO_INTERNO: Suspeita de lock na planilha auxiliar X.',
    linksRelacionados: {
      commit: 'f610074',
      releaseVersao: '4.39.0',
      duplicadoDe: t2.protocolo
    }
  });

  // Auto-vínculo como duplicata deve ser rejeitado
  assert.throws(() => gas.ctx.apiUpdateAdminSupportTicket({
    id: t1.ticketId,
    linksRelacionados: { duplicadoDe: t1.protocolo }
  }), /duplicata de si mesmo/);

  // Publicação de nova release NÃO deve encerrar chamados automaticamente
  gas.ctx.apiRecordAdminReleaseEvent({
    schemaVersion: '2.0',
    eventId: 'evt-no-autoclose-1',
    unidade: 'PEPOA',
    ambiente: 'OFICIAL',
    tipoEvento: 'publish',
    versao: '4.40.0',
    commit: 'deadbeef',
    deploymentVersion: '220',
    deploymentId: 'AKfycb_PEPOA_OFICIAL_220',
    url: gas.ctx.getConfig().pepoaOficial.url,
    publicadoEm: new Date().toISOString(),
    estadoHomologacao: 'HOMOLOGADO'
  });

  // Consulta pública via token individual
  gas.setUserEmail('');
  const lookup1 = gas.ctx.apiLookupSupportTicket(t1.protocolo, t1.trackingToken);
  assert.equal(lookup1.success, true);
  assert.equal(lookup1.ticket.estado, 'AGUARDANDO_INFORMACOES');
  assert.equal(lookup1.ticket.prioridade, 'crítica');
  assert.equal(lookup1.ticket.notasInternas, undefined, 'Notas internas nunca podem vazar na consulta pública');
  assert.equal(lookup1.ticket.trackingTokenHash, undefined);
  assert.equal(JSON.stringify(lookup1).includes('SEGREDO_INTERNO'), false);
  assert.equal(lookup1.ticket.respostasPublicas.length, 1);
  assert.ok(lookup1.ticket.historicoPublico.every((h) => h.tipo !== 'nota_interna'));

  // Solicitante responde complemento público -> volta para EM_ANALISE
  const replyRes = gas.ctx.apiAddPublicSupportReply(t1.protocolo, t1.trackingToken, 'Ocorre em todos os terminais.');
  assert.equal(replyRes.ticket.estado, 'EM_ANALISE');

  // Admin avança para EM_DESENVOLVIMENTO -> EM_HOMOLOGACAO -> RESOLVIDO -> ENCERRADO e depois REABRE
  gas.setUserEmail('lukaslaurino@gmail.com');
  gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, estado: 'EM_DESENVOLVIMENTO' });
  gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, estado: 'EM_HOMOLOGACAO' });
  const resResolved = gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, estado: 'RESOLVIDO' });
  assert.ok(resResolved.ticket.resolvidoEm);
  const resClosed = gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, estado: 'ENCERRADO' });
  assert.ok(resClosed.ticket.encerradoEm);

  // Não aceita complemento público após ENCERRADO
  gas.setUserEmail('');
  assert.throws(() => gas.ctx.apiAddPublicSupportReply(t1.protocolo, t1.trackingToken, 'Nova msg'), /já está encerrado/);

  // Reabrir limpa resolvidoEm/encerradoEm e preserva histórico
  gas.setUserEmail('lukaslaurino@gmail.com');
  const reopened = gas.ctx.apiUpdateAdminSupportTicket({ id: t1.ticketId, reabrir: true, justificativa: 'Recorrência observada' });
  assert.equal(reopened.ticket.estado, 'EM_ANALISE');
  assert.equal(reopened.ticket.encerradoEm, null);
  assert.equal(reopened.ticket.resolvidoEm, null);
  assert.ok(reopened.ticket.historico.some((h) => h.tipo === 'reaberto'));
});

test('Suporte 2.2: exportação administrativa consolidada Markdown e JSON sem inventar campos ausentes', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'CredExp2026' });

  gas.ctx.apiRecordAdminReleaseEvent({
    schemaVersion: '2.0',
    eventId: 'evt-exp-1',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    tipoEvento: 'publish',
    versao: '4.41.0',
    commit: '1122334',
    deploymentVersion: '301',
    deploymentId: 'AKfycb_CPPA_DEP_301',
    url: gas.ctx.getConfig().cppaOficial.url,
    publicadoEm: new Date().toISOString(),
    estadoHomologacao: 'HOMOLOGADO'
  });

  gas.setUserEmail('');
  const complete = gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Dispensação',
    titulo: 'Erro completo com contexto',
    descricao: 'Botão confirmar não grava lote na dispensação.',
    observado: 'Botão permanece desabilitado após clicar.',
    esperado: 'Dispensação deve concluir e exibir recibo.',
    passosReproduzir: '1. Selecionar item 2. Clicar Confirmar.',
    impactoInformado: 'Alto',
    solicitanteNome: 'Farmácia CPPA',
    supportCode: 'CredExp2026',
    confirmacaoSemDadosClinicos: true
  });

  // Chamado mínimo na MADRE sem release, sem observado, sem esperado, sem impacto
  const minimal = gas.ctx.apiCreateSupportTicket({
    categoria: 'Dificuldade de utilização',
    unidade: 'MADRE',
    ambiente: 'AUDIT',
    modulo: 'Dashboard',
    titulo: 'Dúvida mínima sem campos opcionais',
    descricao: 'Como visualizar o total mensal no painel principal?',
    solicitanteNome: 'Operadora MADRE',
    supportCode: 'CredExp2026',
    confirmacaoSemDadosClinicos: true
  });

  gas.setUserEmail('lukaslaurino@gmail.com');
  const mdRes = gas.ctx.apiExportAdminSupportTickets([complete.ticketId, minimal.ticketId], 'markdown');
  assert.equal(mdRes.success, true);
  assert.equal(mdRes.count, 2);
  assert.ok(mdRes.content.includes(complete.protocolo));
  assert.ok(mdRes.content.includes('v4.41.0 (@301'));
  assert.ok(mdRes.content.includes('### Comportamento Observado'));
  assert.ok(mdRes.content.includes('### Critérios de Aceite (Derivados do Esperado Informado)'));
  assert.ok(mdRes.content.includes(minimal.protocolo));
  assert.ok(mdRes.content.includes('Sem release confirmada no portal para este ambiente'));
  // Verifica que o bloco do chamado mínimo NÃO inventou critérios de aceite nem impacto
  const minimalSection = mdRes.content.split(`## ${minimal.protocolo}`)[1];
  assert.equal(minimalSection.includes('Critérios de Aceite'), false);
  assert.equal(minimalSection.includes('Impacto Informado'), false);
  assert.equal(minimalSection.includes('Comportamento Observado'), false);

  const jsonRes = gas.ctx.apiExportAdminSupportTickets([complete.ticketId, minimal.ticketId], 'json');
  assert.equal(jsonRes.success, true);
  const parsedJson = JSON.parse(jsonRes.content);
  assert.equal(parsedJson.count, 2);
  assert.equal(parsedJson.tickets[0].trackingTokenHash, undefined);
});

test('Suporte 2.2: segmentação PropertiesService (<7800 B), LockService, retenção/arquivamento e preservação de monitoramento/CONFIG_LINKS', () => {
  let nowTime = Date.now();
  class Clock extends Date {
    constructor(value = nowTime) { super(value); }
    static now() { return nowTime; }
  }
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com', date: Clock });
  gas.ctx.apiSaveAdminConfig(gas.ctx.getConfig());
  gas.ctx.apiSyncMonitoringTrigger();
  gas.runScheduled();

  const monStateBefore = gas.store.MONITOR_STATE;
  const cfgLinksBefore = gas.store.CONFIG_LINKS;
  const triggersBefore = gas.triggers.map((t) => `${t.id}:${t.handler}`);

  gas.ctx.apiSaveAdminSupportSettings({
    newSupportCredential: 'CredRet2026',
    maxActiveSegments: 4,
    maxArchiveSegments: 3
  });

  // Criar 10 chamados (avançando janela de rate limit) para forçar múltiplos segmentos e verificar limite <= 7800 bytes
  const createdIds = [];
  for (let i = 0; i < 10; i++) {
    if (i > 0 && i % 4 === 0) nowTime += 11 * 60000;
    const res = gas.ctx.apiCreateSupportTicket({
      categoria: i % 2 === 0 ? 'Erro de sistema' : 'Sugestão de melhoria',
      unidade: i % 3 === 0 ? 'PEPOA' : 'CPPA',
      ambiente: i % 2 === 0 ? 'OFICIAL' : 'AUDIT',
      modulo: 'Relatórios',
      titulo: `Chamado segmentado ${i} com texto descritivo realista`,
      descricao: `Descrição sintética do chamado ${i} para validar segmentação e retenção no Apps Script. ` + 'Detalhes '.repeat(30),
      solicitanteNome: `Operador ${i}`,
      supportCode: 'CredRet2026',
      confirmacaoSemDadosClinicos: true
    });
    createdIds.push(res.ticketId);
  }

  // Encerrar 6 chamados e executar retenção (overrideCloseDays: 0 para arquivar encerrados)
  for (let j = 0; j < 6; j++) {
    gas.ctx.apiUpdateAdminSupportTicket({ id: createdIds[j], estado: 'ENCERRADO' });
  }
  const retRes = gas.ctx.apiRunAdminSupportRetention({ overrideCloseDays: 0 });
  assert.equal(retRes.success, true);
  assert.equal(retRes.newlyArchived, 6);
  assert.equal(retRes.activeCount, 4);
  assert.equal(retRes.archivedCount, 6);

  const bootAdmin = gas.ctx.apiGetAdminBootstrap();
  assert.equal(bootAdmin.support.kpis.abertos, 4);
  assert.equal(bootAdmin.support.kpis.arquivados, 6);

  // Verificar teto real < 7800 bytes em TODAS propriedades SUPPORT_*
  for (const [k, v] of Object.entries(gas.store)) {
    if (k.startsWith('SUPPORT_')) {
      const bytes = Buffer.byteLength(String(v), 'utf8');
      assert.ok(bytes <= 7800, `Propriedade ${k} excedeu 7800 B: ${bytes}`);
    }
  }

  const lockStats = gas.getLockStats();
  assert.ok(lockStats.lockCalls > 0 && lockStats.lockCalls === lockStats.unlockCalls);

  // Preservação integral de monitoramento, trigger e CONFIG_LINKS
  assert.equal(gas.store.MONITOR_STATE, monStateBefore);
  assert.equal(gas.store.CONFIG_LINKS, cfgLinksBefore);
  assert.deepEqual(gas.triggers.map((t) => `${t.id}:${t.handler}`), triggersBefore);
});

test('Suporte 2.2: clientes Portal.html (?view=suporte) e Admin.html (aba Suporte) hidratam corretamente', () => {
  const gas = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  gas.ctx.apiSaveAdminSupportSettings({ newSupportCredential: 'CredUi2026' });
  gas.ctx.apiCreateSupportTicket({
    categoria: 'Erro de sistema',
    unidade: 'CPPA',
    ambiente: 'OFICIAL',
    modulo: 'Login',
    titulo: 'Teste UI Admin Suporte',
    descricao: 'Chamado sintético para validar KPIs na interface administrativa.',
    solicitanteNome: 'Operador UI',
    supportCode: 'CredUi2026',
    confirmacaoSemDadosClinicos: true
  });

  const portalHtml = gas.ctx.doGet({ parameter: { view: 'suporte' } }).getContent();
  assert.ok(portalHtml.includes('view-suporte'));
  assert.ok(portalHtml.includes('data-view="suporte"'));
  assert.ok(portalHtml.includes('Não informe nome de paciente, CPF, INFOPEN'));
  assert.equal(/\bOnline\b/i.test(portalHtml), false);

  const pHarness = createDomHarness(portalHtml);
  pHarness.run();

  const adminBoot = gas.ctx.apiGetAdminBootstrap();
  const adminHtml = gas.ctx.doGet({ parameter: { view: 'admin' } }).getContent();
  assert.ok(adminHtml.includes('data-tab="suporte"'));
  assert.ok(adminHtml.includes('tab-suporte'));

  const aHarness = createDomHarness(adminHtml);
  for (const id of [
    'loginGate', 'adminWorkspace', 'adminEmailLabel', 'statusSummary', 'lastUpdate',
    'groupOficial', 'groupAudit', 'adminReleaseStateGrid', 'adminReleaseHistoryWrap',
    'storageStatsLine', 'adminAnnListWrap', 'secStatusBadges',
    'cfgTitle', 'cfgSubtitle', 'cfgObs', 'cfgMaxSegs', 'cfgReplaySec', 'cfgAdminEmails',
    'monDiagnosticsBox', 'monEnabled', 'monInterval', 'monSlowMs', 'monFailThresh',
    'monRecoveryThresh', 'monStaleMin', 'monHistDays', 'monDailyDays', 'monIncDays',
    'monFetchMode', 'monEnvTogglesWrap', 'monIncidentsWrap', 'monMaintListWrap',
    'supKpiOpen', 'supKpiAnalysis', 'supKpiCritical', 'supKpiDev', 'supKpiResolved',
    'supKpiSuggestions', 'supStorageSummary', 'adminSupTicketsWrap', 'supFilterCountNote',
    'supSelectedCount', 'adminSupInvitesWrap', 'supCfgEnabled', 'supCfgAllowGoogle',
    'supCfgRetClosed', 'supCfgRetArchive', 'supCfgMaxSegs', 'supCfgMaxArchSegs',
    'supCredStatusBadge', 'btnThemeToggle', 'btnHealthCheck', 'btnReload', 'btnSave',
    'btnReset', 'btnRecordRelease', 'btnResetAnnForm', 'btnSaveAnn', 'btnSaveSettings',
    'btnAdminLogin', 'btnMonRunNow', 'btnMonSyncTrigger', 'btnSaveMonSettings',
    'btnResetMaintForm', 'btnSaveMaint'
  ]) {
    aHarness.elements[id] = {
      id, value: '', textContent: '', innerHTML: '', className: '', style: {},
      classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
      querySelectorAll() { return []; }, appendChild() {}, addEventListener() {}
    };
  }
  aHarness.run({
    withSuccessHandler(fn) {
      return { withFailureHandler() { return { apiGetAdminBootstrap() { fn(adminBoot); } }; } };
    }
  });
  assert.equal(aHarness.elements.supKpiOpen.textContent, '1');
  assert.ok(aHarness.elements.adminSupTicketsWrap.innerHTML.includes('Teste UI Admin Suporte'));
});
