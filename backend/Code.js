/**
 * SISFAR — Backend Seguro de Configuração de Links do Portal (Google Apps Script)
 *
 * Arquitetura de Segurança:
 * 1. Leitura Pública (GET): Acesso anônimo permitido exclusivamente para leitura dos links pelo portal público (Zero mutações).
 * 2. Operações Administrativas (POST / Server Functions): Estritamente restritas à autenticação via Conta Google (Session.getActiveUser().getEmail()) em allowlist explícita.
 * 3. Validação Fail-Closed: Validação estrita de schema dos 6 IDs canônicos, URLs HTTPS, tipos e integridade.
 */

const DEFAULT_CONFIG = {
  cppaOficial: {
    id: "cppaOficial",
    nome: "CPPA — Cadeia Pública de Porto Alegre",
    tipo: "oficial",
    url: "https://script.google.com/macros/s/AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww/exec",
    ativo: true,
    ordem: 1
  },
  pepoaOficial: {
    id: "pepoaOficial",
    nome: "PEPOA — Penitenciária Estadual de Porto Alegre",
    tipo: "oficial",
    url: "https://script.google.com/macros/s/AKfycbyJC0gBSbzIBY_PCyPr4g4r_FcH2nF52qUE8q7Sv0pyu6pE70AnpQTY09Q77sSaZzhRlw/exec",
    ativo: true,
    ordem: 2
  },
  madreOficial: {
    id: "madreOficial",
    nome: "MADRE — Presídio Estadual Feminino Madre Pelletier",
    tipo: "oficial",
    url: "https://script.google.com/macros/s/AKfycbxtJ5mN2etzdWEsP1Q6krDJ4PNttERTEX3Nm8s1GP28CpVoxj6lEeEjWgZ_ssu6_ADb/exec",
    ativo: true,
    ordem: 3
  },
  cppaAudit: {
    id: "cppaAudit",
    nome: "CPPA — Cadeia Pública de Porto Alegre",
    tipo: "audit",
    url: "https://script.google.com/macros/s/AKfycbzrXoszhMpcjcigdqRRIJC6mZT-vSlqkICo9cDjeCa6Q80YhxmKSzNpTeOhC5ujrmwkvA/exec",
    ativo: true,
    ordem: 4
  },
  pepoaAudit: {
    id: "pepoaAudit",
    nome: "PEPOA — Penitenciária Estadual de Porto Alegre",
    tipo: "audit",
    url: "https://script.google.com/macros/s/AKfycbyx3tZUUB__KsFaZJSobePjt7ImZRNHF_bQK8U0pQDY-_LSdTppcrsqAFtLgpVSl3Mr/exec",
    ativo: true,
    ordem: 5
  },
  madreAudit: {
    id: "madreAudit",
    nome: "MADRE — Presídio Estadual Feminino Madre Pelletier",
    tipo: "audit",
    url: "https://script.google.com/macros/s/AKfycbydhH8Vle_nakjHAlKU0_a2fBr6e0c5roker9IHxXAve48UqUhPG7VfWIvI0fNTyaWj/exec",
    ativo: true,
    ordem: 6
  }
};

const CANONICAL_IDS = ["cppaOficial", "pepoaOficial", "madreOficial", "cppaAudit", "pepoaAudit", "madreAudit"];

function getAdminAllowlist() {
  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty("ADMIN_EMAILS");
  if (raw) {
    return raw.split(",").map(function(e) { return e.trim().toLowerCase(); }).filter(Boolean);
  }
  return ["lukaslaurino@gmail.com", "lukaslaurinocppa@gmail.com"];
}

function isAuthorizedUser(email) {
  if (!email || typeof email !== "string") return false;
  const allowlist = getAdminAllowlist();
  return allowlist.includes(email.toLowerCase());
}

function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Payload inválido: formato de objeto esperado.");
  }

  const keys = Object.keys(payload);
  if (keys.length !== CANONICAL_IDS.length) {
    throw new Error("Payload inválido: esperado exatamente " + CANONICAL_IDS.length + " ambientes, recebido " + keys.length + ".");
  }

  for (let i = 0; i < CANONICAL_IDS.length; i++) {
    const id = CANONICAL_IDS[i];
    if (!payload[id]) {
      throw new Error("Ambiente obrigatório ausente: " + id);
    }
    const item = payload[id];
    if (item.id !== id) {
      throw new Error("ID inconsistente no ambiente " + id);
    }
    if (typeof item.nome !== "string" || item.nome.trim().length === 0) {
      throw new Error("Nome inválido para o ambiente " + id);
    }
    if (typeof item.url !== "string" || item.url.indexOf("https://") !== 0) {
      throw new Error("URL inválida para o ambiente " + id + ": deve iniciar com https://");
    }
    if (typeof item.ativo !== "boolean") {
      throw new Error("Campo ativo deve ser booleano para o ambiente " + id);
    }
    if (typeof item.ordem !== "number" || isNaN(item.ordem) || item.ordem < 1) {
      throw new Error("Ordem inválida para o ambiente " + id);
    }
    const expectedTipo = id.toLowerCase().indexOf("oficial") !== -1 ? "oficial" : "audit";
    if (item.tipo !== expectedTipo) {
      throw new Error("Tipo inválido para o ambiente " + id + ": esperado " + expectedTipo);
    }
  }

  return true;
}

function getConfig() {
  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty("CONFIG_LINKS");
  if (!raw) return DEFAULT_CONFIG;
  try {
    const parsed = JSON.parse(raw);
    validatePayload(parsed);
    return parsed;
  } catch (e) {
    return DEFAULT_CONFIG;
  }
}

function saveConfigInternal(data, author) {
  validatePayload(data);
  const props = PropertiesService.getScriptProperties();
  const timestamp = new Date().toISOString();
  props.setProperty("CONFIG_LINKS", JSON.stringify(data));
  props.setProperty("CONFIG_UPDATED_AT", timestamp);
  props.setProperty("CONFIG_UPDATED_BY", author || "admin_autorizado");
  return {
    success: true,
    message: "Configuração persistida com sucesso!",
    updatedAt: timestamp,
    updatedBy: author || "admin_autorizado"
  };
}

/**
 * Ponto de entrada GET
 * 1. Sem parâmetros ou ?action=get: Retorna JSON de leitura pública (somente leitura).
 * 2. ?admin=1 ou ?view=admin: Renderiza a interface administrativa com verificação de autenticação Google.
 */
function doGet(e) {
  const params = (e && e.parameter) || {};
  
  if (params.admin === "1" || params.view === "admin") {
    return renderAdminHtml();
  }

  // Consulta pública de leitura de links (Zero mutações permitidas via GET)
  const responseData = {
    success: true,
    data: getConfig(),
    updatedAt: PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT") || new Date().toISOString()
  };

  return ContentService.createTextOutput(JSON.stringify(responseData))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Ponto de entrada POST (Rejeição Fail-Closed de chamadas anônimas / não autorizadas)
 */
function doPost(e) {
  const userEmail = Session.getActiveUser().getEmail();

  if (!isAuthorizedUser(userEmail)) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: "403 Não Autorizado: Operações de escrita exigem autenticação de administrador autorizada via Conta Google em allowlist."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  try {
    let payload = null;
    if (e && e.postData && e.postData.contents) {
      payload = JSON.parse(e.postData.contents);
    } else if (e && e.parameter && e.parameter.data) {
      payload = JSON.parse(e.parameter.data);
    }

    const result = saveConfigInternal(payload, userEmail);
    return ContentService.createTextOutput(JSON.stringify(result))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: "Erro ao processar alteração: " + err.message
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function apiGetAdminConfig() {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }
  return {
    success: true,
    user: userEmail,
    data: getConfig(),
    updatedAt: PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT") || new Date().toISOString()
  };
}

function apiSaveAdminConfig(payload) {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }
  return saveConfigInternal(payload, userEmail);
}

function apiResetAdminConfig() {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }
  return saveConfigInternal(DEFAULT_CONFIG, userEmail + " (reset)");
}

function renderAdminHtml() {
  const userEmail = Session.getActiveUser().getEmail();
  const isAuth = isAuthorizedUser(userEmail);

  if (!isAuth) {
    return HtmlService.createHtmlOutput(
      "<!DOCTYPE html><html><head><meta charset=\\"UTF-8\\"><title>SISFAR — Acesso Negado</title><style>" +
      "body{font-family:-apple-system,sans-serif;background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}" +
      ".card{background:#1e293b;padding:2rem;border-radius:12px;border:1px solid #334155;text-align:center;max-width:450px;}" +
      "h2{color:#f87171;margin-top:0;}p{color:#94a3b8;font-size:0.9rem;line-height:1.5;}" +
      ".email{font-family:monospace;background:#0f172a;padding:0.3rem 0.6rem;border-radius:6px;color:#fbbf24;}" +
      "a{display:inline-block;margin-top:1.5rem;color:#38bdf8;text-decoration:none;font-size:0.875rem;}" +
      "</style></head><body><div class=\\"card\\">" +
      "<h2>403 — Acesso Restrito</h2>" +
      "<p>A Central Administrativa do SISFAR é restrita a administradores autorizados.</p>" +
      "<p>Conta conectada: <span class=\\"email\\">" + (userEmail || "Nenhuma conta Google detectada") + "</span></p>" +
      "<p>Solicite permissão ao administrador central do sistema.</p>" +
      "<a href=\\"https://lukaslaurino.github.io/SISFAR-PORTAL/\\">← Voltar ao Portal Público</a>" +
      "</div></body></html>"
    ).setTitle("SISFAR — Acesso Negado");
  }

  const htmlContent = \`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SISFAR — Central Administrativa</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0f172a; --bg-surface: #1e293b; --bg-card: #1e293b; --border-subtle: #334155;
      --text-primary: #f8fafc; --text-secondary: #94a3b8; --text-muted: #64748b;
      --oficial-accent: #10b981; --oficial-badge-bg: rgba(16, 185, 129, 0.15); --oficial-badge-text: #34d399; --oficial-btn: #059669;
      --audit-accent: #f59e0b; --audit-badge-bg: rgba(245, 158, 11, 0.15); --audit-badge-text: #fbbf24; --audit-btn: #d97706;
      --radius-md: 10px; --radius-lg: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Inter", sans-serif; background: var(--bg-main); color: var(--text-primary); min-height: 100vh; padding: 2rem 1.5rem 6rem; }
    .container { max-width: 1100px; margin: 0 auto; }
    .top-nav { display: flex; justify-content: space-between; align-items: center; padding-bottom: 1.5rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border-subtle); }
    .brand-group { display: flex; align-items: center; gap: 1rem; }
    .brand-mark { width: 42px; height: 42px; border-radius: var(--radius-md); background: linear-gradient(135deg, #0284c7, #0369a1); display: flex; align-items: center; justify-content: center; color: #fff; }
    h1 { font-size: 1.4rem; font-weight: 700; }
    .subtitle { font-size: 0.875rem; color: var(--text-secondary); }
    .status-box { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1rem 1.25rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
    .section-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    .grid-forms { display: flex; flex-direction: column; gap: 1.25rem; margin-bottom: 2rem; }
    .config-card { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 1.25rem 1.5rem; }
    .config-card.oficial { border-left: 4px solid var(--oficial-accent); }
    .config-card.audit { border-left: 4px solid var(--audit-accent); }
    .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; font-weight: 700; }
    .form-row { display: grid; grid-template-columns: 2fr 3fr 1fr 1fr; gap: 1rem; align-items: flex-end; }
    .form-group { display: flex; flex-direction: column; gap: 0.35rem; }
    label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); }
    input, select { background: #0f172a; border: 1px solid var(--border-subtle); color: #fff; padding: 0.65rem 0.85rem; border-radius: var(--radius-md); font-size: 0.875rem; width: 100%; outline: none; }
    .btn-test { background: #334155; color: #fff; padding: 0.65rem 0.85rem; border-radius: var(--radius-md); text-decoration: none; font-size: 0.8rem; font-weight: 600; }
    .action-bar { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(8px); border-top: 1px solid var(--border-subtle); padding: 1rem 1.5rem; display: flex; justify-content: center; }
    .action-inner { max-width: 1100px; width: 100%; display: flex; justify-content: space-between; align-items: center; }
    .btn-primary { background: var(--oficial-btn); color: #fff; border: none; padding: 0.75rem 1.5rem; border-radius: var(--radius-md); font-weight: 600; cursor: pointer; }
    .btn-secondary { background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 0.6rem 1rem; border-radius: var(--radius-md); text-decoration: none; font-size: 0.875rem; cursor: pointer; }
    #toast { position: fixed; bottom: 5rem; right: 2rem; padding: 1rem 1.5rem; border-radius: var(--radius-md); font-size: 0.875rem; display: none; }
    #toast.success { background: #065f46; color: #a7f3d0; border: 1px solid #059669; }
    #toast.error { background: #991b1b; color: #fecaca; border: 1px solid #dc2626; }
    @media (max-width: 850px) { .form-row { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="top-nav">
      <div class="brand-group">
        <div class="brand-mark">✓</div>
        <div>
          <h1>Central Administrativa de Links (Segura)</h1>
          <p class="subtitle">SISFAR — Usuário autenticado: \` + userEmail + \`</p>
        </div>
      </div>
      <a href="https://lukaslaurino.github.io/SISFAR-PORTAL/" class="btn-secondary">← Voltar ao Portal</a>
    </div>

    <div class="status-box">
      <div><strong>Status:</strong> Conectado com permissão de Administrador (\` + userEmail + \`)</div>
      <div id="lastUpdate">Sincronizando...</div>
    </div>

    <section>
      <div class="section-title">Ambientes Oficiais de Operação</div>
      <div class="grid-forms" id="groupOficial"></div>
    </section>

    <section>
      <div class="section-title">Ambientes de Homologação / AUDIT</div>
      <div class="grid-forms" id="groupAudit"></div>
    </section>
  </div>

  <div class="action-bar">
    <div class="action-inner">
      <div style="display:flex;gap:0.75rem;">
        <button type="button" id="btnReset" class="btn-secondary">Restaurar Padrões</button>
        <button type="button" id="btnReload" class="btn-secondary">Recarregar</button>
      </div>
      <button type="button" id="btnSave" class="btn-primary">Salvar Todas as Alterações</button>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    var currentConfig = null;
    function showToast(msg, type) {
      var t = document.getElementById("toast");
      t.textContent = msg; t.className = type; t.style.display = "block";
      setTimeout(function() { t.style.display = "none"; }, 4000);
    }
    function render(ambientes) {
      var go = document.getElementById("groupOficial");
      var ga = document.getElementById("groupAudit");
      go.innerHTML = ""; ga.innerHTML = "";
      Object.keys(ambientes).sort(function(a,b){return (ambientes[a].ordem||0)-(ambientes[b].ordem||0);}).forEach(function(key){
        var item = ambientes[key];
        var isOf = item.tipo === "oficial";
        var card = document.createElement("div");
        card.className = "config-card " + (isOf ? "oficial" : "audit");
        card.innerHTML = "<div class=\\"card-top\\"><span>" + item.id + "</span><a href=\\"" + item.url + "\\" target=\\"_blank\\" class=\\"btn-test\\">Testar Link ↗</a></div>" +
          "<div class=\\"form-row\\">" +
            "<div class=\\"form-group\\"><label>Nome</label><input type=\\"text\\" id=\\"name_" + key + "\\" value=\\"" + (item.nome||"") + "\\"></div>" +
            "<div class=\\"form-group\\"><label>URL</label><input type=\\"url\\" id=\\"url_" + key + "\\" value=\\"" + (item.url||"") + "\\"></div>" +
            "<div class=\\"form-group\\"><label>Status</label><select id=\\"status_" + key + "\\"><option value=\\"true\\"" + (item.ativo!==false?" selected":"") + ">Ativo</option><option value=\\"false\\"" + (item.ativo===false?" selected":"") + ">Inativo</option></select></div>" +
            "<div class=\\"form-group\\"><label>Ordem</label><input type=\\"number\\" id=\\"order_" + key + "\\" value=\\"" + (item.ordem||1) + "\\"></div>" +
          "</div>";
        if (isOf) go.appendChild(card); else ga.appendChild(card);
      });
    }
    function loadData() {
      google.script.run
        .withSuccessHandler(function(res) {
          currentConfig = res.data;
          render(currentConfig);
          document.getElementById("lastUpdate").textContent = "Última atualização: " + new Date(res.updatedAt).toLocaleString("pt-BR");
        })
        .withFailureHandler(function(err) { showToast(err.message, "error"); })
        .apiGetAdminConfig();
    }
    document.getElementById("btnSave").addEventListener("click", function() {
      var payload = {};
      for (var key in currentConfig) {
        payload[key] = {
          id: key,
          nome: document.getElementById("name_" + key).value.trim(),
          tipo: currentConfig[key].tipo,
          url: document.getElementById("url_" + key).value.trim(),
          ativo: document.getElementById("status_" + key).value === "true",
          ordem: parseInt(document.getElementById("order_" + key).value, 10)
        };
      }
      google.script.run
        .withSuccessHandler(function(res) {
          showToast(res.message, "success");
          currentConfig = payload;
          loadData();
        })
        .withFailureHandler(function(err) { showToast(err.message, "error"); })
        .apiSaveAdminConfig(payload);
    });
    document.getElementById("btnReset").addEventListener("click", function() {
      if (!confirm("Restaurar todos os links para os padrões originais?")) return;
      google.script.run
        .withSuccessHandler(function(res) { showToast(res.message, "success"); loadData(); })
        .withFailureHandler(function(err) { showToast(err.message, "error"); })
        .apiResetAdminConfig();
    });
    document.getElementById("btnReload").addEventListener("click", loadData);
    loadData();
  </script>
</body>
</html>\`;

  return HtmlService.createHtmlOutput(htmlContent)
    .setTitle("SISFAR — Central Administrativa")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
