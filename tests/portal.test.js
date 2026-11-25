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
  let activeEmail = options.userEmail !== undefined ? options.userEmail : '';
  const serviceUrl = options.serviceUrl !== undefined ? options.serviceUrl : WEBAPP_EXEC_URL;

  function toSignedByteArray(buf) {
    return Array.from(buf, (b) => (b > 127 ? b - 256 : b));
  }

  const context = {
    console,
    Date,
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
          waitLock() {},
          releaseLock() {}
        };
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
        localStorage: {
          getItem(k) { return Object.prototype.hasOwnProperty.call(lsMap, k) ? lsMap[k] : null; },
          setItem(k, v) { lsMap[k] = String(v); }
        },
        document: {
          documentElement: docEl,
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
