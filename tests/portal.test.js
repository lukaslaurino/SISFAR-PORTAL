const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT_DIR = path.resolve(__dirname, '..');
const CODE_JS_PATH = path.join(ROOT_DIR, 'backend', 'Code.js');
const APPSSCRIPT_JSON_PATH = path.join(ROOT_DIR, 'backend', 'appsscript.json');
const CLASP_JSON_PATH = path.join(ROOT_DIR, '.clasp.json');
const CLASPIGNORE_PATH = path.join(ROOT_DIR, '.claspignore');
const LINKS_JS_PATH = path.join(ROOT_DIR, 'links.js');

const WEBAPP_EXEC_URL = 'https://script.google.com/macros/s/AKfycb_PORTAL_TEST_DEPLOY/exec';

function createGasContext(options = {}) {
  const store = Object.assign({}, options.initialProperties || {});
  let activeEmail = options.userEmail !== undefined ? options.userEmail : '';
  const serviceUrl = options.serviceUrl !== undefined ? options.serviceUrl : WEBAPP_EXEC_URL;

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
    isNaN,
    PropertiesService: {
      getScriptProperties() {
        return {
          getProperty(key) {
            return Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null;
          },
          setProperty(key, val) {
            store[key] = String(val);
          }
        };
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
    setUserEmail(email) {
      activeEmail = email;
    }
  };
}

function createDomHarness(html) {
  const elements = {};
  const grids = {
    gridOficial: { id: 'gridOficial', children: [] },
    gridAudit: { id: 'gridAudit', children: [] }
  };

  function makeEl(id, initialTag) {
    const attrs = {};
    const classes = new Set();
    const el = {
      id,
      tagName: initialTag || 'DIV',
      href: '#',
      target: '',
      rel: '',
      textContent: '',
      className: '',
      classList: {
        add(c) {
          classes.add(c);
          el.className = Array.from(classes).join(' ');
        },
        remove(c) {
          classes.delete(c);
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
        if (!el.children) el.children = [];
        const idx = el.children.indexOf(child);
        if (idx !== -1) el.children.splice(idx, 1);
        el.children.push(child);
        return child;
      }
    };
    return el;
  }

  for (const [gridId, gridObj] of Object.entries(grids)) {
    elements[gridId] = Object.assign(makeEl(gridId, 'DIV'), gridObj);
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
    const card = makeEl(`card-${suffix}`, 'DIV');
    elements[card.id] = card;
    const gridKey = suffix.endsWith('oficial') ? 'gridOficial' : 'gridAudit';
    elements[gridKey].appendChild(card);
    elements[`link-${suffix}`] = makeEl(`link-${suffix}`, 'A');
    elements[`name-${suffix}`] = makeEl(`name-${suffix}`, 'P');
    elements[`badge-${suffix}`] = makeEl(`badge-${suffix}`, 'SPAN');
    elements[`label-${suffix}`] = makeEl(`label-${suffix}`, 'SPAN');
  }

  const scriptMatches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(scriptMatches.length >= 1, 'Portal HTML deve conter bloco <script>');
  const inlineScript = scriptMatches[scriptMatches.length - 1][1];

  return {
    elements,
    inlineScript,
    run(rpcMock) {
      const domCtx = {
        console,
        Object,
        document: {
          getElementById(id) {
            return elements[id] || null;
          }
        },
        google: rpcMock
          ? {
              script: {
                run: rpcMock
              }
            }
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
  assert.ok(Object.prototype.hasOwnProperty.call(clasp, 'scriptId'));

  const manifest = JSON.parse(fs.readFileSync(APPSSCRIPT_JSON_PATH, 'utf8'));
  assert.equal(manifest.runtimeVersion, 'V8');
  assert.equal(manifest.timeZone, 'America/Sao_Paulo');
  assert.equal(manifest.webapp.executeAs, 'USER_DEPLOYING');
  assert.equal(manifest.webapp.access, 'ANYONE_ANONYMOUS');

  assert.ok(fs.existsSync(CLASPIGNORE_PATH), '.claspignore deve existir');
});

test('doGet(?view=portal) e doGet() renderizam portal via HtmlService sem dependência do GitHub', () => {
  const { ctx } = createGasContext();
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);

  for (const eventArg of [{ parameter: { view: 'portal' } }, {}, undefined]) {
    const out = ctx.doGet(eventArg);
    assert.equal(out._type, 'HtmlOutput');
    assert.equal(out.getXFrameOptionsMode(), 'ALLOWALL');
    const html = out.getContent();

    assert.ok(html.includes('<base target="_top">'));
    assert.ok(html.includes('SISFAR'));
    assert.ok(html.includes('Operação Oficial'));
    assert.ok(html.includes('Ambientes de Homologação / AUDIT'));
    assert.ok(html.includes(`${WEBAPP_EXEC_URL}?view=admin`));
    assert.equal(html.includes('lukaslaurino.github.io'), false, 'Não deve depender do GitHub');
    assert.equal(html.includes('src="links.js"'), false, 'Não deve depender de links.js externo');
    assert.equal(html.includes('href="favicon.svg"'), false, 'Não deve usar caminho relativo favicon.svg');

    for (const [key, env] of Object.entries(SISFAR_CONFIG.ambientes)) {
      assert.ok(html.includes(env.url), `Portal deve incluir URL atual de ${key}`);
    }
  }
});

test('doGet(?action=get) mantém leitura JSON pública com os 6 ambientes atuais', () => {
  const { ctx } = createGasContext();
  const { SISFAR_CONFIG } = require(LINKS_JS_PATH);

  const out = ctx.doGet({ parameter: { action: 'get' } });
  assert.equal(out._type, 'TextOutput');
  assert.equal(out.getMimeType(), 'application/json');

  const parsed = JSON.parse(out.getContent());
  assert.equal(parsed.success, true);
  assert.deepEqual(Object.keys(parsed.data), Object.keys(SISFAR_CONFIG.ambientes));
  for (const key of Object.keys(SISFAR_CONFIG.ambientes)) {
    assert.equal(parsed.data[key].url, SISFAR_CONFIG.ambientes[key].url);
  }
});

test('doGet(?view=admin / ?admin=1) aplica allowlist e aponta retorno para ?view=portal sem GitHub', () => {
  const anon = createGasContext({ userEmail: '' });
  const deniedOut = anon.ctx.doGet({ parameter: { view: 'admin' } });
  const deniedHtml = deniedOut.getContent();
  assert.ok(deniedHtml.includes('403 — Acesso Restrito'));
  assert.ok(deniedHtml.includes(`${WEBAPP_EXEC_URL}?view=portal`));
  assert.equal(deniedHtml.includes('lukaslaurino.github.io'), false);

  const admin = createGasContext({ userEmail: 'lukaslaurinocppa@gmail.com' });
  const adminOut = admin.ctx.doGet({ parameter: { admin: '1' } });
  const adminHtml = adminOut.getContent();
  assert.ok(adminHtml.includes('<base target="_top">'));
  assert.ok(adminHtml.includes('lukaslaurinocppa@gmail.com'));
  assert.ok(adminHtml.includes(`${WEBAPP_EXEC_URL}?view=portal`));
  assert.equal(adminHtml.includes('lukaslaurino.github.io'), false);
});

test('Persistência dinâmica via CONFIG_LINKS reflete no portal HtmlService e suporta reset', () => {
  const { ctx, store } = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  const updated = JSON.parse(JSON.stringify(ctx.getConfig()));
  updated.cppaOficial.url = 'https://script.google.com/macros/s/AKfycb_UPDATED_CPPA/exec';
  updated.cppaOficial.nome = 'CPPA — Unidade Atualizada</script>';
  updated.madreAudit.ativo = false;
  updated.pepoaOficial.ordem = 1;
  updated.cppaOficial.ordem = 2;

  const saveRes = ctx.apiSaveAdminConfig(updated);
  assert.equal(saveRes.success, true);
  assert.ok(store.CONFIG_LINKS, 'CONFIG_LINKS deve ser persistido em ScriptProperties');

  const portalHtml = ctx.doGet({ parameter: { view: 'portal' } }).getContent();
  assert.equal(portalHtml.includes('</script>","tipo"'), false, 'Deve escapar </script> no JSON embutido');
  assert.ok(portalHtml.includes('https://script.google.com/macros/s/AKfycb_UPDATED_CPPA/exec'));

  const harness = createDomHarness(portalHtml);
  harness.run();

  assert.equal(
    harness.elements['link-cppa-oficial'].href,
    'https://script.google.com/macros/s/AKfycb_UPDATED_CPPA/exec'
  );
  assert.equal(harness.elements['name-cppa-oficial'].textContent, 'CPPA — Unidade Atualizada</script>');
  assert.equal(harness.elements['link-madre-audit'].classList.contains('disabled'), true);
  assert.equal(harness.elements['link-madre-audit'].getAttribute('aria-disabled'), 'true');
  assert.equal(harness.elements['label-madre-audit'].textContent, 'Indisponível no momento');
  assert.equal(harness.elements['badge-madre-audit'].textContent, 'Manutenção');

  const orderedOficialIds = harness.elements.gridOficial.children.map((c) => c.id);
  assert.deepEqual(orderedOficialIds, ['card-pepoa-oficial', 'card-cppa-oficial', 'card-madre-oficial']);

  const resetRes = ctx.apiResetAdminConfig();
  assert.equal(resetRes.success, true);
  assert.equal(
    ctx.getConfig().cppaOficial.url,
    'https://script.google.com/macros/s/AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww/exec'
  );
});

test('Cliente do portal também aceita atualização via google.script.run.apiGetPublicConfig()', () => {
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
            apiGetPublicConfig() {
              fn({ success: true, data: liveData });
            }
          };
        }
      };
    }
  };

  harness.run(rpcMock);
  assert.equal(
    harness.elements['link-pepoa-audit'].href,
    'https://script.google.com/macros/s/AKfycb_LIVE_RPC/exec'
  );
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
  assert.throws(() => ctx.apiSaveAdminConfig(ctx.getConfig()), /Acesso negado/);
  assert.throws(() => ctx.apiResetAdminConfig(), /Acesso negado/);

  const admin = createGasContext({ userEmail: 'lukaslaurino@gmail.com' });
  const badUrl = JSON.parse(JSON.stringify(admin.ctx.getConfig()));
  badUrl.cppaOficial.url = 'http://inseguro.example.com';
  assert.throws(() => admin.ctx.apiSaveAdminConfig(badUrl), /https:\/\//);

  const missingEnv = JSON.parse(JSON.stringify(admin.ctx.getConfig()));
  delete missingEnv.madreAudit;
  assert.throws(() => admin.ctx.apiSaveAdminConfig(missingEnv), /esperado exatamente 6/);
});
