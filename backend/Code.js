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
  try {
    const props = PropertiesService.getScriptProperties();
    const raw = props.getProperty("CONFIG_LINKS");
    if (!raw) return DEFAULT_CONFIG;
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
  let updatedAt = new Date().toISOString();
  try {
    const ts = PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT");
    if (ts) updatedAt = ts;
  } catch (err) {}

  const responseData = {
    success: true,
    data: getConfig(),
    updatedAt: updatedAt
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

/**
 * Diagnóstico RPC Administrativo (Health Check)
 */
function apiHealthCheck() {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }
  return {
    success: true,
    user: userEmail,
    timestamp: new Date().toISOString()
  };
}

/**
 * Leitura de Configuração via RPC Google Apps Script
 */
function apiGetAdminConfig() {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }

  let updatedAt = new Date().toISOString();
  try {
    const ts = PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT");
    if (ts) updatedAt = ts;
  } catch (e) {}

  return {
    success: true,
    user: userEmail,
    data: getConfig(),
    updatedAt: updatedAt
  };
}

/**
 * Gravação de Configuração via RPC Google Apps Script
 */
function apiSaveAdminConfig(payload) {
  const userEmail = Session.getActiveUser().getEmail();
  if (!isAuthorizedUser(userEmail)) {
    throw new Error("Acesso negado: Usuário " + (userEmail || "não autenticado") + " não possui permissão de administrador.");
  }
  return saveConfigInternal(payload, userEmail);
}

/**
 * Restauração de Configuração Padrão via RPC Google Apps Script
 */
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
      "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><base target=\"_top\"><title>SISFAR — Acesso Negado</title><style>" +
      "body{font-family:-apple-system,sans-serif;background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;padding:1.5rem;box-sizing:border-box;}" +
      ".card{background:#1e293b;padding:2.5rem 2rem;border-radius:14px;border:1px solid #334155;text-align:center;max-width:480px;box-shadow:0 10px 25px rgba(0,0,0,0.5);}" +
      "h2{color:#f87171;margin-top:0;font-size:1.4rem;}p{color:#94a3b8;font-size:0.9rem;line-height:1.6;margin:1rem 0;}" +
      ".email{font-family:monospace;background:#0f172a;padding:0.35rem 0.65rem;border-radius:6px;color:#fbbf24;display:inline-block;margin:0.5rem 0;border:1px solid #334155;}" +
      "a{display:inline-block;margin-top:1.5rem;color:#38bdf8;text-decoration:none;font-size:0.875rem;font-weight:600;}" +
      "a:hover{text-decoration:underline;}" +
      "</style></head><body><div class=\"card\">" +
      "<h2>403 — Acesso Restrito</h2>" +
      "<p>A Central Administrativa do SISFAR é restrita a administradores autorizados.</p>" +
      "<p>Conta conectada:<br><span class=\"email\">" + (userEmail || "Nenhuma conta Google detectada") + "</span></p>" +
      "<p>Solicite permissão ao administrador central do sistema caso necessite de acesso.</p>" +
      "<a href=\"https://lukaslaurino.github.io/SISFAR-PORTAL/\">← Voltar ao Portal Público</a>" +
      "</div></body></html>"
    ).setTitle("SISFAR — Acesso Negado");
  }

  const safeEmail = userEmail.replace(/"/g, "&quot;");

  const htmlContent = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <base target="_top">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SISFAR — Central Administrativa</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0f172a; --bg-surface: #1e293b; --bg-card: #1e293b; --border-subtle: #334155;
      --text-primary: #f8fafc; --text-secondary: #94a3b8; --text-muted: #64748b;
      --oficial-accent: #10b981; --oficial-badge-bg: rgba(16, 185, 129, 0.15); --oficial-badge-text: #34d399; --oficial-btn: #059669; --oficial-btn-hover: #10b981;
      --audit-accent: #f59e0b; --audit-badge-bg: rgba(245, 158, 11, 0.15); --audit-badge-text: #fbbf24; --audit-btn: #d97706; --audit-btn-hover: #f59e0b;
      --danger: #ef4444; --danger-hover: #dc2626;
      --radius-md: 10px; --radius-lg: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg-main); color: var(--text-primary); min-height: 100vh; padding: 2rem 1.5rem 6.5rem; }
    .container { max-width: 1100px; margin: 0 auto; }
    .top-nav { display: flex; justify-content: space-between; align-items: center; padding-bottom: 1.5rem; margin-bottom: 1.75rem; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 1rem; }
    .brand-group { display: flex; align-items: center; gap: 1rem; }
    .brand-mark { width: 44px; height: 44px; border-radius: var(--radius-md); background: linear-gradient(135deg, #0284c7, #0369a1); display: flex; align-items: center; justify-content: center; color: #fff; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3); }
    .brand-mark svg { width: 24px; height: 24px; }
    h1 { font-size: 1.35rem; font-weight: 700; }
    .subtitle { font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.2rem; }
    .subtitle strong { color: #38bdf8; }
    .status-box { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1rem 1.25rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem; font-size: 0.875rem; }
    .status-left { display: flex; align-items: center; gap: 0.5rem; }
    .status-pill { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981; }
    .status-right { color: var(--text-secondary); font-size: 0.825rem; }
    .section-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    .grid-forms { display: flex; flex-direction: column; gap: 1.25rem; margin-bottom: 2.25rem; }
    .config-card { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 1.25rem 1.5rem; transition: border-color 0.15s; }
    .config-card.oficial { border-left: 4px solid var(--oficial-accent); }
    .config-card.audit { border-left: 4px solid var(--audit-accent); }
    .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; font-weight: 700; font-size: 0.95rem; }
    .card-top .env-tag { font-family: monospace; font-size: 0.8rem; background: rgba(255,255,255,0.05); padding: 0.2rem 0.5rem; border-radius: 4px; color: #94a3b8; }
    .form-row { display: grid; grid-template-columns: 2fr 3fr 1fr 1fr; gap: 1rem; align-items: flex-end; }
    .form-group { display: flex; flex-direction: column; gap: 0.35rem; }
    label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.03em; }
    input, select { background: #0f172a; border: 1px solid var(--border-subtle); color: #fff; padding: 0.65rem 0.85rem; border-radius: var(--radius-md); font-size: 0.875rem; width: 100%; outline: none; font-family: inherit; }
    input:focus, select:focus { border-color: #38bdf8; }
    .btn-test { background: #334155; color: #f8fafc; padding: 0.45rem 0.85rem; border-radius: var(--radius-md); text-decoration: none; font-size: 0.8rem; font-weight: 600; transition: background-color 0.15s; display: inline-flex; align-items: center; gap: 0.3rem; }
    .btn-test:hover { background: #475569; }
    .loading-card { background: var(--bg-card); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); padding: 2.5rem 1.5rem; text-align: center; color: var(--text-secondary); font-size: 0.9rem; }
    .error-card { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: var(--radius-lg); padding: 2rem 1.5rem; text-align: center; color: #fca5a5; }
    .error-card p { margin-bottom: 1rem; font-size: 0.9rem; }
    .action-bar { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(15, 23, 42, 0.96); backdrop-filter: blur(8px); border-top: 1px solid var(--border-subtle); padding: 1rem 1.5rem; display: flex; justify-content: center; z-index: 100; }
    .action-inner { max-width: 1100px; width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .btn-primary { background: var(--oficial-btn); color: #fff; border: none; padding: 0.75rem 1.5rem; border-radius: var(--radius-md); font-weight: 600; font-size: 0.9rem; cursor: pointer; transition: background-color 0.15s; display: inline-flex; align-items: center; gap: 0.4rem; }
    .btn-primary:hover:not(:disabled) { background: var(--oficial-btn-hover); }
    .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-secondary { background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 0.65rem 1.1rem; border-radius: var(--radius-md); text-decoration: none; font-size: 0.85rem; font-weight: 500; cursor: pointer; transition: background-color 0.15s, border-color 0.15s; display: inline-flex; align-items: center; gap: 0.4rem; }
    .btn-secondary:hover:not(:disabled) { background: #334155; border-color: #475569; }
    .btn-secondary:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-danger { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); padding: 0.65rem 1.1rem; border-radius: var(--radius-md); font-size: 0.85rem; font-weight: 500; cursor: pointer; transition: background-color 0.15s; }
    .btn-danger:hover:not(:disabled) { background: rgba(239, 68, 68, 0.25); color: #fff; }
    .btn-danger:disabled { opacity: 0.6; cursor: not-allowed; }
    #toast { position: fixed; bottom: 5.5rem; right: 2rem; padding: 1rem 1.5rem; border-radius: var(--radius-md); font-size: 0.875rem; font-weight: 500; display: none; z-index: 200; box-shadow: 0 10px 20px rgba(0,0,0,0.4); max-width: 420px; }
    #toast.success { background: #065f46; color: #a7f3d0; border: 1px solid #059669; }
    #toast.error { background: #991b1b; color: #fecaca; border: 1px solid #dc2626; }
    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: #fff; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @media (max-width: 850px) { .form-row { grid-template-columns: 1fr; } .action-inner { justify-content: center; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="top-nav">
      <div class="brand-group">
        <div class="brand-mark">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6"/><path d="M12 9v6"/></svg>
        </div>
        <div>
          <h1>Central Administrativa de Links</h1>
          <p class="subtitle">SISFAR — Usuário autenticado: <strong>` + safeEmail + `</strong></p>
        </div>
      </div>
      <a href="https://lukaslaurino.github.io/SISFAR-PORTAL/" class="btn-secondary">← Voltar ao Portal</a>
    </div>

    <div class="status-box">
      <div class="status-left">
        <span class="status-pill"></span>
        <span><strong>Status:</strong> Conectado com permissão de Administrador</span>
      </div>
      <div id="lastUpdate" class="status-right">Carregando configuração do servidor...</div>
    </div>

    <section>
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><rect width="20" height="14" x="2" y="5" rx="2"/><path d="M2 10h20"/></svg>
        Ambientes Oficiais de Operação
      </div>
      <div class="grid-forms" id="groupOficial">
        <div class="loading-card"><span class="spinner"></span> Carregando ambientes oficiais...</div>
      </div>
    </section>

    <section>
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10 2v7.31"/><path d="M14 9.3V1.99"/><path d="M8.5 2h7"/><path d="M14 9.3a6.5 6.5 0 1 1-4 0"/><path d="M5.52 16h12.96"/></svg>
        Ambientes de Homologação / AUDIT (Isolados)
      </div>
      <div class="grid-forms" id="groupAudit">
        <div class="loading-card"><span class="spinner"></span> Carregando ambientes audit...</div>
      </div>
    </section>
  </div>

  <div class="action-bar">
    <div class="action-inner">
      <div style="display:flex;gap:0.75rem;">
        <button type="button" id="btnReset" class="btn-danger">Restaurar Padrões</button>
        <button type="button" id="btnReload" class="btn-secondary">↻ Recarregar</button>
      </div>
      <button type="button" id="btnSave" class="btn-primary">💾 Salvar Todas as Alterações</button>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    var currentConfig = null;
    var isLoading = false;
    var isSaving = false;
    var loadTimeoutTimer = null;
    var toastTimer = null;

    function escapeHtml(str) {
      if (!str) return "";
      return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function showToast(msg, type) {
      var t = document.getElementById("toast");
      if (!t) return;
      clearTimeout(toastTimer);
      t.textContent = msg;
      t.className = type;
      t.style.display = "block";
      toastTimer = setTimeout(function() { t.style.display = "none"; }, 5000);
    }

    function setButtonsBusy(busy) {
      document.getElementById("btnSave").disabled = busy;
      document.getElementById("btnReset").disabled = busy;
      document.getElementById("btnReload").disabled = busy;
    }

    function render(ambientes) {
      var go = document.getElementById("groupOficial");
      var ga = document.getElementById("groupAudit");
      go.innerHTML = "";
      ga.innerHTML = "";

      var keys = Object.keys(ambientes).sort(function(a, b) {
        return (ambientes[a].ordem || 0) - (ambientes[b].ordem || 0);
      });

      keys.forEach(function(key) {
        var item = ambientes[key];
        var isOf = item.tipo === "oficial";
        var card = document.createElement("div");
        card.className = "config-card " + (isOf ? "oficial" : "audit");

        var safeId = escapeHtml(item.id);
        var safeNome = escapeHtml(item.nome || "");
        var safeUrl = escapeHtml(item.url || "");
        var safeOrdem = parseInt(item.ordem || 1, 10);
        var isAtivo = item.ativo !== false;

        card.innerHTML = 
          '<div class="card-top">' +
            '<div><span class="env-tag">' + safeId + '</span></div>' +
            '<a href="' + safeUrl + '" target="_blank" class="btn-test">Testar Link ↗</a>' +
          '</div>' +
          '<div class="form-row">' +
            '<div class="form-group">' +
              '<label>Nome da Unidade / Ambiente</label>' +
              '<input type="text" id="name_' + key + '" value="' + safeNome + '" placeholder="Nome institucional">' +
            '</div>' +
            '<div class="form-group">' +
              '<label>URL do Web App (HTTPS)</label>' +
              '<input type="url" id="url_' + key + '" value="' + safeUrl + '" placeholder="https://script.google.com/...">' +
            '</div>' +
            '<div class="form-group">' +
              '<label>Status</label>' +
              '<select id="status_' + key + '">' +
                '<option value="true"' + (isAtivo ? ' selected' : '') + '>Ativo</option>' +
                '<option value="false"' + (!isAtivo ? ' selected' : '') + '>Inativo</option>' +
              '</select>' +
            '</div>' +
            '<div class="form-group">' +
              '<label>Ordem</label>' +
              '<input type="number" id="order_' + key + '" value="' + safeOrdem + '" min="1" max="99">' +
            '</div>' +
          '</div>';

        if (isOf) {
          go.appendChild(card);
        } else {
          ga.appendChild(card);
        }
      });
    }

    function showLoadError(msg) {
      document.getElementById("lastUpdate").innerHTML = '<span style="color:#f87171;">⚠️ ' + escapeHtml(msg) + '</span>';
      var errHtml = 
        '<div class="error-card">' +
          '<p><strong>Erro ao carregar configuração do servidor:</strong><br>' + escapeHtml(msg) + '</p>' +
          '<button type="button" class="btn-secondary" onclick="loadData()">↻ Tentar Novamente</button>' +
        '</div>';
      document.getElementById("groupOficial").innerHTML = errHtml;
      document.getElementById("groupAudit").innerHTML = "";
    }

    function loadData() {
      if (isLoading || isSaving) return;
      isLoading = true;
      setButtonsBusy(true);

      document.getElementById("lastUpdate").innerHTML = '<span class="spinner"></span> Sincronizando com o servidor...';
      document.getElementById("groupOficial").innerHTML = '<div class="loading-card"><span class="spinner"></span> Carregando ambientes oficiais...</div>';
      document.getElementById("groupAudit").innerHTML = '<div class="loading-card"><span class="spinner"></span> Carregando ambientes audit...</div>';

      clearTimeout(loadTimeoutTimer);
      loadTimeoutTimer = setTimeout(function() {
        if (isLoading) {
          isLoading = false;
          setButtonsBusy(false);
          var errMsg = "Tempo limite de 15 segundos excedido ao comunicar com o servidor.";
          console.warn("[SISFAR Admin] Timeout em apiGetAdminConfig.");
          showLoadError(errMsg);
          showToast(errMsg, "error");
        }
      }, 15000);

      try {
        google.script.run
          .withSuccessHandler(function(res) {
            if (!isLoading) return;
            clearTimeout(loadTimeoutTimer);
            isLoading = false;
            setButtonsBusy(false);

            if (!res || !res.success || !res.data) {
              var msg = "Resposta inválida recebida do servidor.";
              console.error("[SISFAR Admin] Resposta inválida:", res);
              showLoadError(msg);
              showToast(msg, "error");
              return;
            }

            currentConfig = res.data;
            render(currentConfig);

            var dateStr = res.updatedAt ? new Date(res.updatedAt).toLocaleString("pt-BR") : "Agora";
            document.getElementById("lastUpdate").textContent = "Última sincronização: " + dateStr;
            console.log("[SISFAR Admin] Configuração carregada com sucesso.");
          })
          .withFailureHandler(function(err) {
            if (!isLoading) return;
            clearTimeout(loadTimeoutTimer);
            isLoading = false;
            setButtonsBusy(false);

            var errMsg = (err && err.message) ? err.message : "Falha na comunicação com o servidor.";
            console.error("[SISFAR Admin] Erro em apiGetAdminConfig:", errMsg);
            showLoadError(errMsg);
            showToast("Erro ao carregar: " + errMsg, "error");
          })
          .apiGetAdminConfig();
      } catch (clientErr) {
        clearTimeout(loadTimeoutTimer);
        isLoading = false;
        setButtonsBusy(false);
        var clientMsg = clientErr.message || "Erro na execução client-side.";
        console.error("[SISFAR Admin] Exceção ao chamar apiGetAdminConfig:", clientErr);
        showLoadError(clientMsg);
        showToast("Erro: " + clientMsg, "error");
      }
    }

    document.getElementById("btnSave").addEventListener("click", function() {
      if (!currentConfig || isLoading || isSaving) return;

      var payload = {};
      var keys = Object.keys(currentConfig);
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var nameInput = document.getElementById("name_" + key);
        var urlInput = document.getElementById("url_" + key);
        var statusInput = document.getElementById("status_" + key);
        var orderInput = document.getElementById("order_" + key);

        if (!nameInput || !urlInput) continue;

        var nome = nameInput.value.trim();
        var url = urlInput.value.trim();
        var ativo = statusInput ? (statusInput.value === "true") : true;
        var ordem = orderInput ? parseInt(orderInput.value, 10) : 1;

        if (!nome) {
          showToast("O nome do ambiente " + key + " não pode estar vazio.", "error");
          nameInput.focus();
          return;
        }

        if (!url.startsWith("https://")) {
          showToast("A URL do ambiente " + key + " deve começar com https://", "error");
          urlInput.focus();
          return;
        }

        payload[key] = {
          id: key,
          nome: nome,
          tipo: currentConfig[key].tipo,
          url: url,
          ativo: ativo,
          ordem: isNaN(ordem) ? 1 : ordem
        };
      }

      isSaving = true;
      setButtonsBusy(true);
      var saveBtn = document.getElementById("btnSave");
      var originalText = saveBtn.textContent;
      saveBtn.innerHTML = '<span class="spinner"></span> Salvando...';

      var saveTimer = setTimeout(function() {
        if (isSaving) {
          isSaving = false;
          setButtonsBusy(false);
          saveBtn.textContent = originalText;
          showToast("Tempo limite de 15s excedido ao salvar alterações.", "error");
        }
      }, 15000);

      try {
        google.script.run
          .withSuccessHandler(function(res) {
            clearTimeout(saveTimer);
            isSaving = false;
            setButtonsBusy(false);
            saveBtn.textContent = originalText;

            if (res && res.success) {
              showToast(res.message || "Configuração salva com sucesso!", "success");
              currentConfig = payload;
              loadData();
            } else {
              var err = (res && res.error) ? res.error : "Falha ao gravar.";
              showToast(err, "error");
              console.error("[SISFAR Admin] Falha ao salvar:", res);
            }
          })
          .withFailureHandler(function(err) {
            clearTimeout(saveTimer);
            isSaving = false;
            setButtonsBusy(false);
            saveBtn.textContent = originalText;
            var msg = (err && err.message) ? err.message : "Erro desconhecido ao salvar.";
            showToast("Erro: " + msg, "error");
            console.error("[SISFAR Admin] Erro em apiSaveAdminConfig:", msg);
          })
          .apiSaveAdminConfig(payload);
      } catch (saveErr) {
        clearTimeout(saveTimer);
        isSaving = false;
        setButtonsBusy(false);
        saveBtn.textContent = originalText;
        showToast("Erro client-side ao salvar: " + saveErr.message, "error");
      }
    });

    document.getElementById("btnReset").addEventListener("click", function() {
      if (isLoading || isSaving) return;
      if (!confirm("Tem certeza de que deseja restaurar as URLs e configurações originais dos 6 ambientes?")) return;

      isSaving = true;
      setButtonsBusy(true);
      var resetBtn = document.getElementById("btnReset");
      var originalText = resetBtn.textContent;
      resetBtn.innerHTML = '<span class="spinner"></span> Restaurando...';

      var resetTimer = setTimeout(function() {
        if (isSaving) {
          isSaving = false;
          setButtonsBusy(false);
          resetBtn.textContent = originalText;
          showToast("Tempo limite excedido ao restaurar padrões.", "error");
        }
      }, 15000);

      try {
        google.script.run
          .withSuccessHandler(function(res) {
            clearTimeout(resetTimer);
            isSaving = false;
            setButtonsBusy(false);
            resetBtn.textContent = originalText;
            showToast(res.message || "Padrões restaurados com sucesso!", "success");
            loadData();
          })
          .withFailureHandler(function(err) {
            clearTimeout(resetTimer);
            isSaving = false;
            setButtonsBusy(false);
            resetBtn.textContent = originalText;
            var msg = (err && err.message) ? err.message : "Falha ao restaurar padrões.";
            showToast("Erro: " + msg, "error");
            console.error("[SISFAR Admin] Erro em apiResetAdminConfig:", msg);
          })
          .apiResetAdminConfig();
      } catch (resetErr) {
        clearTimeout(resetTimer);
        isSaving = false;
        setButtonsBusy(false);
        resetBtn.textContent = originalText;
        showToast("Erro ao restaurar: " + resetErr.message, "error");
      }
    });

    document.getElementById("btnReload").addEventListener("click", function() {
      loadData();
    });

    // Diagnóstico via Console: window.sisfarHealthCheck()
    window.sisfarHealthCheck = function() {
      console.log("[SISFAR HealthCheck] Iniciando verificação RPC...");
      var start = Date.now();
      google.script.run
        .withSuccessHandler(function(res) {
          var latency = Date.now() - start;
          console.log("[SISFAR HealthCheck] ✓ SUCESSO (" + latency + "ms):", res);
          showToast("Health Check OK (" + latency + "ms): " + res.user, "success");
        })
        .withFailureHandler(function(err) {
          var latency = Date.now() - start;
          console.error("[SISFAR HealthCheck] ✗ FALHA (" + latency + "ms):", err);
          showToast("Health Check FALHOU: " + err.message, "error");
        })
        .apiHealthCheck();
    };

    // Inicialização segura
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", loadData);
    } else {
      loadData();
    }
  </script>
</body>
</html>`;

  return HtmlService.createHtmlOutput(htmlContent)
    .setTitle("SISFAR — Central Administrativa")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
