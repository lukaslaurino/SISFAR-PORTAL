/**
 * SISFAR — Backend Seguro e Portal Institucional (Google Apps Script)
 *
 * Arquitetura de Segurança e Hospedagem:
 * 1. Portal Público (HtmlService): Servido via ?view=portal ou rota raiz sem parâmetros, sem dependência externa do GitHub.
 * 2. Leitura Pública JSON (GET ?action=get): Acesso anônimo permitido exclusivamente para leitura dos links (Zero mutações).
 * 3. Operações Administrativas (POST / Server Functions / ?view=admin / ?admin=1): Estritamente restritas à autenticação via Conta Google (Session.getActiveUser().getEmail()) em allowlist explícita.
 * 4. Validação Fail-Closed: Validação estrita de schema dos 6 IDs canônicos, URLs HTTPS, tipos e integridade em CONFIG_LINKS.
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
    if (!raw) return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    const parsed = JSON.parse(raw);
    validatePayload(parsed);
    return parsed;
  } catch (e) {
    return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  }
}

function getConfigUpdatedAt() {
  try {
    const ts = PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT");
    if (ts) return ts;
  } catch (err) {}
  return new Date().toISOString();
}

function getWebAppBaseUrl() {
  try {
    const url = ScriptApp.getService().getUrl();
    return url || "";
  } catch (err) {
    return "";
  }
}

function buildAppViewUrl(viewQuery) {
  const base = getWebAppBaseUrl();
  if (!base) {
    return "?" + viewQuery;
  }
  const sep = base.indexOf("?") === -1 ? "?" : "&";
  return base + sep + viewQuery;
}

function safeJsonForHtmlScript(value) {
  return JSON.stringify(value)
    .replace(/&/g, "\\u0026")
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function escapeHtmlAttr(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
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
 * 1. ?admin=1 ou ?view=admin: Renderiza a Central Administrativa com verificação de autenticação Google.
 * 2. ?action=get ou ?format=json: Retorna JSON de leitura pública (somente leitura).
 * 3. ?view=portal ou sem parâmetros: Renderiza o Portal SISFAR via HtmlService sem dependência do GitHub.
 */
function doGet(e) {
  const params = (e && e.parameter) || {};

  if (params.admin === "1" || params.view === "admin") {
    return renderAdminHtml();
  }

  if (params.action === "get" || params.format === "json") {
    const responseData = {
      success: true,
      data: getConfig(),
      updatedAt: getConfigUpdatedAt()
    };

    return ContentService.createTextOutput(JSON.stringify(responseData))
      .setMimeType(ContentService.MimeType.JSON);
  }

  return renderPortalHtml();
}

/**
 * Leitura pública da configuração via RPC Google Apps Script (somente leitura)
 */
function apiGetPublicConfig() {
  return {
    success: true,
    data: getConfig(),
    updatedAt: getConfigUpdatedAt()
  };
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

function renderPortalHtml() {
  const initialConfig = getConfig();
  const updatedAt = getConfigUpdatedAt();
  const adminUrl = buildAppViewUrl("view=admin");
  const safeAdminUrl = escapeHtmlAttr(adminUrl);
  const initialPayloadJson = safeJsonForHtmlScript({
    ambientes: initialConfig,
    updatedAt: updatedAt
  });

  const htmlContent = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <base target="_top">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SISFAR — Sistema Integrado de Farmácia Prisional</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0f172a;
      --bg-surface: #1e293b;
      --bg-card: #1e293b;
      --border-subtle: #334155;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;

      --oficial-accent: #10b981;
      --oficial-bg: rgba(16, 185, 129, 0.08);
      --oficial-border: rgba(16, 185, 129, 0.25);
      --oficial-badge-bg: rgba(16, 185, 129, 0.15);
      --oficial-badge-text: #34d399;
      --oficial-btn: #059669;
      --oficial-btn-hover: #10b981;

      --audit-accent: #f59e0b;
      --audit-bg: rgba(245, 158, 11, 0.08);
      --audit-border: rgba(245, 158, 11, 0.25);
      --audit-badge-bg: rgba(245, 158, 11, 0.15);
      --audit-badge-text: #fbbf24;
      --audit-btn: #d97706;
      --audit-btn-hover: #f59e0b;

      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
      --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -2px rgba(0, 0, 0, 0.2);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .container {
      width: 100%;
      max-width: 1100px;
      margin: 0 auto;
      padding: 2rem 1.5rem 3rem;
      flex: 1;
    }

    header {
      text-align: center;
      margin-bottom: 2.5rem;
      padding-bottom: 1.75rem;
      border-bottom: 1px solid var(--border-subtle);
    }

    .brand-mark {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 48px;
      height: 48px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, #0284c7, #0369a1);
      color: #ffffff;
      margin-bottom: 1rem;
      box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
    }

    .brand-mark svg {
      width: 28px;
      height: 28px;
    }

    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text-primary);
      margin-bottom: 0.35rem;
    }

    .subtitle {
      font-size: 1rem;
      color: var(--text-secondary);
      font-weight: 400;
      margin-bottom: 0.75rem;
    }

    .header-action-wrap {
      display: flex;
      justify-content: center;
      margin-top: 0.75rem;
    }

    .btn-admin-header {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background-color: var(--bg-surface);
      color: var(--text-secondary);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 500;
      transition: background-color 0.15s, color 0.15s, border-color 0.15s;
    }

    .btn-admin-header:hover {
      background-color: #334155;
      color: var(--text-primary);
      border-color: #475569;
    }

    .section-title-wrap {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1.25rem;
    }

    .section-pill {
      font-size: 0.75rem;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.05em;
      padding: 0.25rem 0.6rem;
      border-radius: 9999px;
    }

    .section-pill.oficial {
      background: var(--oficial-badge-bg);
      color: var(--oficial-badge-text);
      border: 1px solid var(--oficial-border);
    }

    .section-pill.audit {
      background: var(--audit-badge-bg);
      color: var(--audit-badge-text);
      border: 1px solid var(--audit-border);
    }

    .section-heading {
      font-size: 1.15rem;
      font-weight: 600;
      color: var(--text-primary);
      letter-spacing: -0.01em;
    }

    .grid-units {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }

    .card {
      background-color: var(--bg-card);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      border: 1px solid var(--border-subtle);
      transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
      box-shadow: var(--shadow-sm);
    }

    .card:hover {
      transform: translateY(-2px);
      box-shadow: var(--shadow-md);
    }

    .card.oficial {
      border-color: var(--oficial-border);
      background: linear-gradient(180deg, var(--oficial-bg) 0%, var(--bg-card) 60%);
    }

    .card.oficial:hover {
      border-color: var(--oficial-accent);
    }

    .card.audit {
      border-color: var(--audit-border);
      background: linear-gradient(180deg, var(--audit-bg) 0%, var(--bg-card) 60%);
    }

    .card.audit:hover {
      border-color: var(--audit-accent);
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 0.75rem;
    }

    .unit-acronym {
      font-size: 1.35rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--text-primary);
    }

    .badge-status {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 0.2rem 0.5rem;
      border-radius: var(--radius-sm);
    }

    .badge-status.oficial {
      background-color: var(--oficial-badge-bg);
      color: var(--oficial-badge-text);
      border: 1px solid var(--oficial-border);
    }

    .badge-status.audit {
      background-color: var(--audit-badge-bg);
      color: var(--audit-badge-text);
      border: 1px solid var(--audit-border);
    }

    .badge-status.inactive {
      background-color: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .unit-name {
      font-size: 0.875rem;
      color: var(--text-secondary);
      margin-bottom: 1.5rem;
      min-height: 2.6rem;
    }

    .btn-action {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      font-weight: 600;
      text-decoration: none;
      border-radius: var(--radius-md);
      transition: background-color 0.15s ease, opacity 0.15s ease;
      color: #ffffff;
    }

    .btn-action.oficial {
      background-color: var(--oficial-btn);
    }

    .btn-action.oficial:hover {
      background-color: var(--oficial-btn-hover);
    }

    .btn-action.audit {
      background-color: var(--audit-btn);
    }

    .btn-action.audit:hover {
      background-color: var(--audit-btn-hover);
    }

    .btn-action.disabled {
      background-color: #334155;
      color: #64748b;
      cursor: not-allowed;
      pointer-events: none;
    }

    .btn-action svg {
      width: 16px;
      height: 16px;
      stroke-width: 2;
    }

    footer {
      text-align: center;
      padding: 1.5rem;
      border-top: 1px solid var(--border-subtle);
      color: var(--text-muted);
      font-size: 0.8rem;
    }

    footer p + p {
      margin-top: 0.35rem;
    }

    @media (max-width: 768px) {
      .container {
        padding: 1.5rem 1rem;
      }
      h1 {
        font-size: 1.5rem;
      }
      .grid-units {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>

  <div class="container">
    <header>
      <div class="brand-mark">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12h6"/>
          <path d="M12 9v6"/>
        </svg>
      </div>
      <h1>SISFAR</h1>
      <p class="subtitle">Sistema Integrado de Farmácia Prisional</p>

      <div class="header-action-wrap">
        <a id="btnAdminPortal" href="` + safeAdminUrl + `" class="btn-admin-header" title="Acessar Central Administrativa">
          <span>⚙️ Central Administrativa</span>
        </a>
      </div>
    </header>

    <section>
      <div class="section-title-wrap">
        <span class="section-pill oficial">Produção</span>
        <h2 class="section-heading">Operação Oficial</h2>
      </div>

      <div class="grid-units" id="gridOficial">
        <div class="card oficial" id="card-cppa-oficial">
          <div>
            <div class="card-header">
              <span class="unit-acronym">CPPA</span>
              <span class="badge-status oficial" id="badge-cppa-oficial">Oficial</span>
            </div>
            <p class="unit-name" id="name-cppa-oficial">Cadeia Pública de Porto Alegre</p>
          </div>
          <a id="link-cppa-oficial" href="#" target="_blank" rel="noopener noreferrer" class="btn-action oficial">
            <span id="label-cppa-oficial">Acessar Ambiente Oficial</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>

        <div class="card oficial" id="card-pepoa-oficial">
          <div>
            <div class="card-header">
              <span class="unit-acronym">PEPOA</span>
              <span class="badge-status oficial" id="badge-pepoa-oficial">Oficial</span>
            </div>
            <p class="unit-name" id="name-pepoa-oficial">Penitenciária Estadual de Porto Alegre</p>
          </div>
          <a id="link-pepoa-oficial" href="#" target="_blank" rel="noopener noreferrer" class="btn-action oficial">
            <span id="label-pepoa-oficial">Acessar Ambiente Oficial</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>

        <div class="card oficial" id="card-madre-oficial">
          <div>
            <div class="card-header">
              <span class="unit-acronym">MADRE</span>
              <span class="badge-status oficial" id="badge-madre-oficial">Oficial</span>
            </div>
            <p class="unit-name" id="name-madre-oficial">Presídio Estadual Feminino Madre Pelletier</p>
          </div>
          <a id="link-madre-oficial" href="#" target="_blank" rel="noopener noreferrer" class="btn-action oficial">
            <span id="label-madre-oficial">Acessar Ambiente Oficial</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>
      </div>
    </section>

    <section>
      <div class="section-title-wrap">
        <span class="section-pill audit">Homologação</span>
        <h2 class="section-heading">Ambientes de Homologação / AUDIT</h2>
      </div>

      <div class="grid-units" id="gridAudit">
        <div class="card audit" id="card-cppa-audit">
          <div>
            <div class="card-header">
              <span class="unit-acronym">CPPA</span>
              <span class="badge-status audit" id="badge-cppa-audit">AUDIT</span>
            </div>
            <p class="unit-name" id="name-cppa-audit">Cadeia Pública de Porto Alegre</p>
          </div>
          <a id="link-cppa-audit" href="#" target="_blank" rel="noopener noreferrer" class="btn-action audit">
            <span id="label-cppa-audit">Acessar Homologação</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>

        <div class="card audit" id="card-pepoa-audit">
          <div>
            <div class="card-header">
              <span class="unit-acronym">PEPOA</span>
              <span class="badge-status audit" id="badge-pepoa-audit">AUDIT</span>
            </div>
            <p class="unit-name" id="name-pepoa-audit">Penitenciária Estadual de Porto Alegre</p>
          </div>
          <a id="link-pepoa-audit" href="#" target="_blank" rel="noopener noreferrer" class="btn-action audit">
            <span id="label-pepoa-audit">Acessar Homologação</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>

        <div class="card audit" id="card-madre-audit">
          <div>
            <div class="card-header">
              <span class="unit-acronym">MADRE</span>
              <span class="badge-status audit" id="badge-madre-audit">AUDIT</span>
            </div>
            <p class="unit-name" id="name-madre-audit">Presídio Estadual Feminino Madre Pelletier</p>
          </div>
          <a id="link-madre-audit" href="#" target="_blank" rel="noopener noreferrer" class="btn-action audit">
            <span id="label-madre-audit">Acessar Homologação</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>
      </div>
    </section>
  </div>

  <footer>
    <p><strong>SISFAR</strong> — Sistema Integrado de Farmácia Prisional</p>
    <p>Acesso restrito e institucional aos serviços de saúde penitenciária.</p>
  </footer>

  <script>
    (function () {
      var INITIAL_PORTAL_DATA = ` + initialPayloadJson + `;

      var MAP = {
        cppaOficial: { card: 'card-cppa-oficial', link: 'link-cppa-oficial', name: 'name-cppa-oficial', badge: 'badge-cppa-oficial', label: 'label-cppa-oficial', type: 'oficial', grid: 'gridOficial', defaultOrder: 1 },
        pepoaOficial: { card: 'card-pepoa-oficial', link: 'link-pepoa-oficial', name: 'name-pepoa-oficial', badge: 'badge-pepoa-oficial', label: 'label-pepoa-oficial', type: 'oficial', grid: 'gridOficial', defaultOrder: 2 },
        madreOficial: { card: 'card-madre-oficial', link: 'link-madre-oficial', name: 'name-madre-oficial', badge: 'badge-madre-oficial', label: 'label-madre-oficial', type: 'oficial', grid: 'gridOficial', defaultOrder: 3 },
        cppaAudit: { card: 'card-cppa-audit', link: 'link-cppa-audit', name: 'name-cppa-audit', badge: 'badge-cppa-audit', label: 'label-cppa-audit', type: 'audit', grid: 'gridAudit', defaultOrder: 4 },
        pepoaAudit: { card: 'card-pepoa-audit', link: 'link-pepoa-audit', name: 'name-pepoa-audit', badge: 'badge-pepoa-audit', label: 'label-pepoa-audit', type: 'audit', grid: 'gridAudit', defaultOrder: 5 },
        madreAudit: { card: 'card-madre-audit', link: 'link-madre-audit', name: 'name-madre-audit', badge: 'badge-madre-audit', label: 'label-madre-audit', type: 'audit', grid: 'gridAudit', defaultOrder: 6 }
      };

      function reorderGrid(gridId, ambientes, targetType) {
        var grid = document.getElementById(gridId);
        if (!grid || !grid.appendChild) return;

        var keys = Object.keys(MAP).filter(function (k) {
          return MAP[k].type === targetType;
        });

        keys.sort(function (a, b) {
          var da = ambientes[a] || {};
          var db = ambientes[b] || {};
          var oa = typeof da.ordem === 'number' ? da.ordem : MAP[a].defaultOrder;
          var ob = typeof db.ordem === 'number' ? db.ordem : MAP[b].defaultOrder;
          if (oa !== ob) return oa - ob;
          return MAP[a].defaultOrder - MAP[b].defaultOrder;
        });

        for (var i = 0; i < keys.length; i++) {
          var elCard = document.getElementById(MAP[keys[i]].card);
          if (elCard) {
            grid.appendChild(elCard);
          }
        }
      }

      function applyConfig(cfg) {
        if (!cfg) return;
        var ambientes = cfg.ambientes || cfg;

        for (var key in MAP) {
          if (Object.prototype.hasOwnProperty.call(MAP, key)) {
            var m = MAP[key];
            var data = ambientes[key];
            var elLink = document.getElementById(m.link);
            var elName = document.getElementById(m.name);
            var elBadge = document.getElementById(m.badge);
            var elLabel = document.getElementById(m.label);

            if (data && elLink) {
              var url = (typeof data === 'string') ? data : data.url;
              var nome = data.nome;
              var ativo = (data.ativo !== false);

              if (nome && elName) {
                elName.textContent = nome;
              }

              if (!ativo) {
                elLink.href = '#';
                elLink.removeAttribute('target');
                elLink.removeAttribute('rel');
                elLink.setAttribute('aria-disabled', 'true');
                elLink.setAttribute('tabindex', '-1');
                elLink.classList.add('disabled');
                if (elLabel) elLabel.textContent = 'Indisponível no momento';
                if (elBadge) {
                  elBadge.textContent = 'Manutenção';
                  elBadge.className = 'badge-status inactive';
                }
              } else {
                if (url) {
                  elLink.href = url;
                  elLink.target = '_blank';
                  elLink.rel = 'noopener noreferrer';
                }
                elLink.removeAttribute('aria-disabled');
                elLink.removeAttribute('tabindex');
                elLink.classList.remove('disabled');
                if (elLabel) elLabel.textContent = (m.type === 'oficial' ? 'Acessar Ambiente Oficial' : 'Acessar Homologação');
                if (elBadge) {
                  elBadge.textContent = (m.type === 'oficial' ? 'Oficial' : 'AUDIT');
                  elBadge.className = 'badge-status ' + m.type;
                }
              }
            }
          }
        }

        reorderGrid('gridOficial', ambientes, 'oficial');
        reorderGrid('gridAudit', ambientes, 'audit');
      }

      applyConfig(INITIAL_PORTAL_DATA);

      if (typeof google !== 'undefined' && google.script && google.script.run) {
        try {
          google.script.run
            .withSuccessHandler(function (res) {
              if (res && res.success && res.data) {
                applyConfig({ ambientes: res.data });
              }
            })
            .withFailureHandler(function (err) {
              console.warn('[SISFAR Portal] Mantendo configuração inicial do servidor.', err);
            })
            .apiGetPublicConfig();
        } catch (err) {
          console.warn('[SISFAR Portal] RPC de atualização indisponível.', err);
        }
      }
    })();
  </script>
</body>
</html>`;

  return HtmlService.createHtmlOutput(htmlContent)
    .setTitle("SISFAR — Sistema Integrado de Farmácia Prisional")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function renderAdminHtml() {
  const userEmail = Session.getActiveUser().getEmail();
  const isAuth = isAuthorizedUser(userEmail);
  const portalUrl = buildAppViewUrl("view=portal");
  const safePortalUrl = escapeHtmlAttr(portalUrl);

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
      "<p>Conta conectada:<br><span class=\"email\">" + escapeHtmlAttr(userEmail || "Nenhuma conta Google detectada") + "</span></p>" +
      "<p>Solicite permissão ao administrador central do sistema caso necessite de acesso.</p>" +
      "<a href=\"" + safePortalUrl + "\">← Voltar ao Portal Público</a>" +
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
      <a href="` + safePortalUrl + `" class="btn-secondary">← Voltar ao Portal</a>
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
            '<a href="' + safeUrl + '" target="_blank" rel="noopener noreferrer" class="btn-test">Testar Link ↗</a>' +
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
