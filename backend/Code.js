/**
 * SISFAR-PORTAL 2.0 — Backend Seguro, Registro de Releases e Central Institucional
 *
 * Arquitetura de Segurança e Persistência:
 * 1. Portal Público (HtmlService): ?view=portal ou rota raiz sem parâmetros, sem dependência externa.
 * 2. Leitura Pública JSON: ?action=get (links canônicos) e ?action=bootstrap (links + releases + comunicados públicos).
 * 3. Ingestão de Releases/Rollbacks (POST action=publish_event): Autenticada por HMAC-SHA256
 *    (timestamp + eventId + payload canônico) com segredo privado em ScriptProperties, proteção
 *    contra replay, idempotência por eventId e proteção contra eventos atrasados.
 * 4. Central Administrativa (?view=admin / ?admin=1 e RPCs api*): Protegida por Conta Google
 *    em allowlist (ADMIN_EMAILS) ou, quando Session.getActiveUser().getEmail() vier vazio em
 *    execução pública, por credencial administrativa configurada (ADMIN_AUTH_HASH) com token
 *    temporário em CacheService. Zero escrita anônima.
 * 5. Persistência separada de CONFIG_LINKS: eventos limitados e segmentados em PropertiesService
 *    respeitando o limite de 9 KB por propriedade, comunicados e configurações operacionais.
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

const CANONICAL_IDS = [
  "cppaOficial",
  "pepoaOficial",
  "madreOficial",
  "cppaAudit",
  "pepoaAudit",
  "madreAudit"
];

const ENV_KEY_META = {
  cppaOficial:  { unidade: "CPPA",  ambiente: "OFICIAL", tipo: "oficial" },
  pepoaOficial: { unidade: "PEPOA", ambiente: "OFICIAL", tipo: "oficial" },
  madreOficial: { unidade: "MADRE", ambiente: "OFICIAL", tipo: "oficial" },
  cppaAudit:    { unidade: "CPPA",  ambiente: "AUDIT",   tipo: "audit" },
  pepoaAudit:   { unidade: "PEPOA", ambiente: "AUDIT",   tipo: "audit" },
  madreAudit:   { unidade: "MADRE", ambiente: "AUDIT",   tipo: "audit" }
};

const VALID_UNITS = ["CPPA", "PEPOA", "MADRE"];
const VALID_ENVS = ["OFICIAL", "AUDIT"];
const VALID_HOMOLOG_STATES = ["PENDENTE", "EM_HOMOLOGACAO", "HOMOLOGADO", "REJEITADO", "REVERTIDO"];
const VALID_EVENT_TYPES = ["publish", "rollback"];
const VALID_STAGES = ["git", "candidato", "publicado", "homologado"];
const VALID_ANNOUNCEMENT_CATEGORIES = ["Manutenção", "Atualização", "Operacional", "Segurança", "Informativo"];
const VALID_ANNOUNCEMENT_PRIORITIES = ["Alta", "Normal", "Baixa"];

const PROP_KEYS = {
  CONFIG_LINKS: "CONFIG_LINKS",
  CONFIG_UPDATED_AT: "CONFIG_UPDATED_AT",
  CONFIG_UPDATED_BY: "CONFIG_UPDATED_BY",
  ADMIN_EMAILS: "ADMIN_EMAILS",
  ADMIN_AUTH_HASH: "ADMIN_AUTH_HASH",
  ADMIN_AUTH_SALT: "ADMIN_AUTH_SALT",
  WEBHOOK_SECRET: "PORTAL_WEBHOOK_SECRET",
  RELEASE_STATE: "SISFAR_RELEASE_STATE_V2",
  RELEASE_HIST_META: "SISFAR_RELEASE_HIST_META_V2",
  RELEASE_HIST_SEG_PREFIX: "SISFAR_RELEASE_HIST_SEG_",
  RELEASE_DEDUPE: "SISFAR_RELEASE_DEDUPE_V2",
  ANNOUNCEMENTS_META: "SISFAR_ANNOUNCEMENTS_META_V2",
  ANNOUNCEMENTS_SEG_PREFIX: "SISFAR_ANNOUNCEMENTS_SEG_",
  PORTAL_SETTINGS: "SISFAR_PORTAL_SETTINGS_V2"
};

const DEFAULT_PORTAL_SETTINGS = {
  tituloCentral: "Central de trabalho",
  subtituloInstitucional: "Sistema Integrado de Farmácia Prisional",
  observacaoOperacional: "",
  maxHistoricoSegmentos: 6,
  maxEventosPorSegmento: 10,
  janelaReplaySegundos: 300
};

const MAX_PROPERTY_BYTES = 7800;
const MAX_DEDUPE_IDS = 120;
const ADMIN_SESSION_TTL_SECONDS = 1800;

/* ==================== UTILITÁRIOS INTERNOS ==================== */

function cloneJson_(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function getProps_() {
  return PropertiesService.getScriptProperties();
}

function getUtf8ByteLength_(str) {
  if (!str) return 0;
  return unescape(encodeURIComponent(String(str))).length;
}

function bytesToHex_(bytes) {
  var hex = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i] & 0xff;
    if (b < 16) hex += "0";
    hex += b.toString(16);
  }
  return hex;
}

function constantTimeEqual_(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  var len = Math.max(a.length, b.length);
  var diff = a.length ^ b.length;
  for (var i = 0; i < len; i++) {
    var ca = i < a.length ? a.charCodeAt(i) : 0;
    var cb = i < b.length ? b.charCodeAt(i) : 0;
    diff |= (ca ^ cb);
  }
  return diff === 0;
}

function sha256Hex_(input) {
  var bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    String(input || ""),
    Utilities.Charset.UTF_8
  );
  return bytesToHex_(bytes);
}

function hmacSha256Hex_(message, secret) {
  var bytes = Utilities.computeHmacSha256Signature(
    String(message || ""),
    String(secret || ""),
    Utilities.Charset.UTF_8
  );
  return bytesToHex_(bytes);
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

function withScriptLock_(fn) {
  if (typeof LockService === "undefined" || !LockService || typeof LockService.getScriptLock !== "function") {
    return fn();
  }
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    return fn();
  } finally {
    try {
      lock.releaseLock();
    } catch (e) {}
  }
}

function getTodayIsoSaoPaulo_() {
  try {
    return Utilities.formatDate(new Date(), "America/Sao_Paulo", "yyyy-MM-dd");
  } catch (e) {
    return new Date().toISOString().slice(0, 10);
  }
}

function getWebAppBaseUrl() {
  try {
    var url = ScriptApp.getService().getUrl();
    return url || "";
  } catch (err) {
    return "";
  }
}

function buildAppViewUrl(viewQuery) {
  var base = getWebAppBaseUrl();
  if (!base) {
    return "?" + viewQuery;
  }
  var sep = base.indexOf("?") === -1 ? "?" : "&";
  return base + sep + viewQuery;
}

function readHtmlTemplate_(fileName) {
  if (typeof HtmlService !== "undefined" && HtmlService && typeof HtmlService.createHtmlOutputFromFile === "function") {
    return HtmlService.createHtmlOutputFromFile(fileName).getContent();
  }
  throw new Error("Template HTML '" + fileName + "' indisponível neste contexto.");
}

/* ==================== AUTENTICAÇÃO E ALLOWLIST ==================== */

function getAdminAllowlist() {
  var props = getProps_();
  var raw = props.getProperty(PROP_KEYS.ADMIN_EMAILS);
  if (raw) {
    return raw.split(",").map(function (e) { return e.trim().toLowerCase(); }).filter(Boolean);
  }
  return ["lukaslaurino@gmail.com", "lukaslaurinocppa@gmail.com"];
}

function isAuthorizedUser(email) {
  if (!email || typeof email !== "string") return false;
  var allowlist = getAdminAllowlist();
  return allowlist.indexOf(email.trim().toLowerCase()) !== -1;
}

function isAdminPasscodeConfigured_() {
  var props = getProps_();
  var hash = props.getProperty(PROP_KEYS.ADMIN_AUTH_HASH);
  var salt = props.getProperty(PROP_KEYS.ADMIN_AUTH_SALT);
  return Boolean(hash && salt);
}

function getActiveGoogleEmail_() {
  try {
    return (Session.getActiveUser().getEmail() || "").trim();
  } catch (e) {
    return "";
  }
}

function getAdminSessionFromToken_(authToken) {
  if (!authToken || typeof authToken !== "string") return null;
  if (typeof CacheService === "undefined" || !CacheService || typeof CacheService.getScriptCache !== "function") {
    return null;
  }
  try {
    var cache = CacheService.getScriptCache();
    var raw = cache.get("ADMIN_SESS_" + sha256Hex_(authToken));
    if (!raw) return null;
    var parsed = JSON.parse(raw);
    if (!parsed || !parsed.email || !isAuthorizedUser(parsed.email)) return null;
    if (parsed.expiresAt && Date.now() > Number(parsed.expiresAt)) return null;
    return parsed;
  } catch (e) {
    return null;
  }
}

function requireAdminAuth_(authToken) {
  var googleEmail = getActiveGoogleEmail_();
  if (googleEmail) {
    if (isAuthorizedUser(googleEmail)) {
      return { email: googleEmail, method: "google_session" };
    }
    throw new Error("Acesso negado: Usuário " + googleEmail + " não possui permissão de administrador.");
  }

  var session = getAdminSessionFromToken_(authToken);
  if (session) {
    return { email: session.email, method: "admin_key_session" };
  }

  throw new Error("Acesso negado: Usuário não autenticado não possui permissão de administrador.");
}

function setAdminPasscodeInternal_(rawPasscode) {
  if (!rawPasscode || typeof rawPasscode !== "string" || rawPasscode.trim().length < 10) {
    throw new Error("A chave administrativa deve ter pelo menos 10 caracteres.");
  }
  var salt = Utilities.getUuid ? Utilities.getUuid() : (String(Date.now()) + "-" + String(Math.random()));
  var hash = sha256Hex_(salt + ":" + rawPasscode.trim());
  var props = getProps_();
  props.setProperty(PROP_KEYS.ADMIN_AUTH_SALT, salt);
  props.setProperty(PROP_KEYS.ADMIN_AUTH_HASH, hash);
  return true;
}

/**
 * Helper administrativo para execução manual única no Editor do Apps Script caso a
 * identificação Google não seja propagada em execução pública (ANYONE_ANONYMOUS).
 */
function configurarChaveAdminPortal_(chaveAdmin) {
  return setAdminPasscodeInternal_(chaveAdmin);
}

/**
 * Helper administrativo para execução manual única no Editor do Apps Script para
 * definir o segredo compartilhado HMAC-SHA256 do publicador (PORTAL_WEBHOOK_SECRET).
 */
function configurarSegredoWebhookPortal_(segredo) {
  if (!segredo || typeof segredo !== "string" || segredo.trim().length < 16) {
    throw new Error("O segredo HMAC deve ter pelo menos 16 caracteres.");
  }
  getProps_().setProperty(PROP_KEYS.WEBHOOK_SECRET, segredo.trim());
  return true;
}

/* ==================== CONFIG_LINKS (6 AMBIENTES CANÔNICOS) ==================== */

function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Payload inválido: formato de objeto esperado.");
  }

  var keys = Object.keys(payload);
  if (keys.length !== CANONICAL_IDS.length) {
    throw new Error("Payload inválido: esperado exatamente " + CANONICAL_IDS.length + " ambientes, recebido " + keys.length + ".");
  }

  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    var id = CANONICAL_IDS[i];
    if (!payload[id]) {
      throw new Error("Ambiente obrigatório ausente: " + id);
    }
    var item = payload[id];
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
    var expectedTipo = id.toLowerCase().indexOf("oficial") !== -1 ? "oficial" : "audit";
    if (item.tipo !== expectedTipo) {
      throw new Error("Tipo inválido para o ambiente " + id + ": esperado " + expectedTipo);
    }
  }

  return true;
}

function getConfig() {
  try {
    var props = getProps_();
    var raw = props.getProperty(PROP_KEYS.CONFIG_LINKS);
    if (!raw) return cloneJson_(DEFAULT_CONFIG);
    var parsed = JSON.parse(raw);
    validatePayload(parsed);
    return parsed;
  } catch (e) {
    return cloneJson_(DEFAULT_CONFIG);
  }
}

function getConfigUpdatedAt() {
  try {
    var ts = getProps_().getProperty(PROP_KEYS.CONFIG_UPDATED_AT);
    if (ts) return ts;
  } catch (err) {}
  return new Date().toISOString();
}

function saveConfigInternal_(data, author) {
  validatePayload(data);
  return withScriptLock_(function () {
    var props = getProps_();
    var timestamp = new Date().toISOString();
    props.setProperty(PROP_KEYS.CONFIG_LINKS, JSON.stringify(data));
    props.setProperty(PROP_KEYS.CONFIG_UPDATED_AT, timestamp);
    props.setProperty(PROP_KEYS.CONFIG_UPDATED_BY, author || "admin_autorizado");
    return {
      success: true,
      message: "Configuração persistida com sucesso!",
      updatedAt: timestamp,
      updatedBy: author || "admin_autorizado"
    };
  });
}

/* ==================== CONFIGURAÇÕES OPERACIONAIS DO PORTAL ==================== */

function getPortalSettings_() {
  var base = cloneJson_(DEFAULT_PORTAL_SETTINGS);
  try {
    var raw = getProps_().getProperty(PROP_KEYS.PORTAL_SETTINGS);
    if (!raw) return base;
    var parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      if (typeof parsed.tituloCentral === "string" && parsed.tituloCentral.trim()) {
        base.tituloCentral = parsed.tituloCentral.trim().slice(0, 80);
      }
      if (typeof parsed.subtituloInstitucional === "string" && parsed.subtituloInstitucional.trim()) {
        base.subtituloInstitucional = parsed.subtituloInstitucional.trim().slice(0, 140);
      }
      if (typeof parsed.observacaoOperacional === "string") {
        base.observacaoOperacional = parsed.observacaoOperacional.trim().slice(0, 300);
      }
      if (typeof parsed.maxHistoricoSegmentos === "number" && !isNaN(parsed.maxHistoricoSegmentos)) {
        base.maxHistoricoSegmentos = Math.max(2, Math.min(10, Math.floor(parsed.maxHistoricoSegmentos)));
      }
      if (typeof parsed.maxEventosPorSegmento === "number" && !isNaN(parsed.maxEventosPorSegmento)) {
        base.maxEventosPorSegmento = Math.max(5, Math.min(15, Math.floor(parsed.maxEventosPorSegmento)));
      }
      if (typeof parsed.janelaReplaySegundos === "number" && !isNaN(parsed.janelaReplaySegundos)) {
        base.janelaReplaySegundos = Math.max(60, Math.min(900, Math.floor(parsed.janelaReplaySegundos)));
      }
    }
  } catch (e) {}
  return base;
}

function savePortalSettingsInternal_(settings, author) {
  if (!settings || typeof settings !== "object") {
    throw new Error("Configurações do portal inválidas.");
  }
  var next = getPortalSettings_();
  if (typeof settings.tituloCentral === "string" && settings.tituloCentral.trim()) {
    next.tituloCentral = settings.tituloCentral.trim().slice(0, 80);
  }
  if (typeof settings.subtituloInstitucional === "string" && settings.subtituloInstitucional.trim()) {
    next.subtituloInstitucional = settings.subtituloInstitucional.trim().slice(0, 140);
  }
  if (typeof settings.observacaoOperacional === "string") {
    next.observacaoOperacional = settings.observacaoOperacional.trim().slice(0, 300);
  }
  if (settings.maxHistoricoSegmentos !== undefined) {
    var ms = Number(settings.maxHistoricoSegmentos);
    if (isNaN(ms) || ms < 2 || ms > 10) throw new Error("maxHistoricoSegmentos deve estar entre 2 e 10.");
    next.maxHistoricoSegmentos = Math.floor(ms);
  }
  if (settings.janelaReplaySegundos !== undefined) {
    var jr = Number(settings.janelaReplaySegundos);
    if (isNaN(jr) || jr < 60 || jr > 900) throw new Error("janelaReplaySegundos deve estar entre 60 e 900.");
    next.janelaReplaySegundos = Math.floor(jr);
  }
  next.atualizadoEm = new Date().toISOString();
  next.atualizadoPor = author || "admin";

  return withScriptLock_(function () {
    getProps_().setProperty(PROP_KEYS.PORTAL_SETTINGS, JSON.stringify(next));
    return next;
  });
}

/* ==================== BACKEND PERSISTENTE DE RELEASES (SEGMENTADO) ==================== */

function resolveEnvKey_(unidade, ambiente) {
  var u = String(unidade || "").trim().toUpperCase();
  var a = String(ambiente || "").trim().toUpperCase();
  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    var key = CANONICAL_IDS[i];
    var m = ENV_KEY_META[key];
    if (m.unidade === u && m.ambiente === a) {
      return key;
    }
  }
  return null;
}

function getReleaseStateCurrent_() {
  var emptyState = {
    schemaVersion: "2.0",
    updatedAt: null,
    environments: {}
  };
  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    emptyState.environments[CANONICAL_IDS[i]] = null;
  }
  try {
    var raw = getProps_().getProperty(PROP_KEYS.RELEASE_STATE);
    if (!raw) return emptyState;
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !parsed.environments) return emptyState;
    for (var j = 0; j < CANONICAL_IDS.length; j++) {
      var k = CANONICAL_IDS[j];
      emptyState.environments[k] = parsed.environments[k] || null;
    }
    emptyState.updatedAt = parsed.updatedAt || null;
    return emptyState;
  } catch (e) {
    return emptyState;
  }
}

function getReleaseHistMeta_() {
  var def = {
    schemaVersion: "2.0",
    segments: [],
    totalEverRecorded: 0
  };
  try {
    var raw = getProps_().getProperty(PROP_KEYS.RELEASE_HIST_META);
    if (!raw) return def;
    var parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.segments)) return def;
    return {
      schemaVersion: "2.0",
      segments: parsed.segments.slice(),
      totalEverRecorded: Number(parsed.totalEverRecorded || 0)
    };
  } catch (e) {
    return def;
  }
}

function getReleaseDedupeIds_() {
  try {
    var raw = getProps_().getProperty(PROP_KEYS.RELEASE_DEDUPE);
    if (!raw) return [];
    var parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function getReleaseHistory_(filters) {
  var props = getProps_();
  var meta = getReleaseHistMeta_();
  var all = [];
  for (var i = meta.segments.length - 1; i >= 0; i--) {
    var segKey = meta.segments[i];
    try {
      var rawSeg = props.getProperty(segKey);
      if (!rawSeg) continue;
      var items = JSON.parse(rawSeg);
      if (Array.isArray(items)) {
        for (var j = items.length - 1; j >= 0; j--) {
          all.push(items[j]);
        }
      }
    } catch (e) {}
  }

  all.sort(function (a, b) {
    var ta = Date.parse(a.publicadoEm || a.recebidoEm || 0) || 0;
    var tb = Date.parse(b.publicadoEm || b.recebidoEm || 0) || 0;
    if (tb !== ta) return tb - ta;
    return String(b.recebidoEm || "").localeCompare(String(a.recebidoEm || ""));
  });

  if (!filters || typeof filters !== "object") return all;

  var fUnit = filters.unidade ? String(filters.unidade).trim().toUpperCase() : "";
  var fEnv = filters.ambiente ? String(filters.ambiente).trim().toUpperCase() : "";
  var fVer = filters.versao ? String(filters.versao).trim().toLowerCase() : "";

  return all.filter(function (ev) {
    if (fUnit && fUnit !== "TODAS" && String(ev.unidade || "").toUpperCase() !== fUnit) return false;
    if (fEnv && fEnv !== "TODOS" && String(ev.ambiente || "").toUpperCase() !== fEnv) return false;
    if (fVer && String(ev.versao || "").toLowerCase().indexOf(fVer) === -1) return false;
    return true;
  });
}

function getReleaseStorageStats_() {
  var props = getProps_();
  var meta = getReleaseHistMeta_();
  var segmentStats = [];
  var totalBytes = 0;
  for (var i = 0; i < meta.segments.length; i++) {
    var k = meta.segments[i];
    var raw = props.getProperty(k) || "";
    var bytes = getUtf8ByteLength_(raw);
    totalBytes += bytes;
    var count = 0;
    try {
      var arr = raw ? JSON.parse(raw) : [];
      count = Array.isArray(arr) ? arr.length : 0;
    } catch (e) {}
    segmentStats.push({ key: k, bytes: bytes, events: count });
  }
  return {
    segmentsCount: meta.segments.length,
    totalBytes: totalBytes,
    totalEverRecorded: meta.totalEverRecorded,
    segments: segmentStats
  };
}

function validateReleaseEvent_(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Evento inválido: objeto esperado.");
  }

  var eventId = String(raw.eventId || "").trim();
  if (!eventId || eventId.length < 6 || eventId.length > 120) {
    throw new Error("eventId inválido ou ausente.");
  }

  var schemaVersion = String(raw.schemaVersion || "2.0").trim();
  var unidade = String(raw.unidade || "").trim().toUpperCase();
  if (VALID_UNITS.indexOf(unidade) === -1) {
    throw new Error("Unidade inválida: " + unidade);
  }

  var ambiente = String(raw.ambiente || "").trim().toUpperCase();
  if (VALID_ENVS.indexOf(ambiente) === -1) {
    throw new Error("Ambiente inválido: " + ambiente);
  }

  var envKey = resolveEnvKey_(unidade, ambiente);
  if (!envKey) {
    throw new Error("Combinação unidade/ambiente inválida.");
  }

  var versao = String(raw.versao || "").trim();
  if (!versao || versao.length > 40) {
    throw new Error("Versão inválida ou ausente.");
  }

  var commit = String(raw.commit || "").trim();
  if (!commit || commit.length > 64) {
    throw new Error("Commit inválido ou ausente.");
  }

  var deploymentId = String(raw.deploymentId || "").trim();
  if (!deploymentId || deploymentId.length > 140) {
    throw new Error("deploymentId inválido ou ausente.");
  }

  var deploymentVersion = String(raw.deploymentVersion || "").trim();
  if (!deploymentVersion || deploymentVersion.length > 32) {
    throw new Error("deploymentVersion inválida ou ausente.");
  }

  var url = String(raw.url || "").trim();
  if (!url || url.indexOf("https://") !== 0) {
    throw new Error("URL do evento inválida: deve iniciar com https://");
  }

  var publicadoEm = String(raw.publicadoEm || "").trim();
  var pubTs = Date.parse(publicadoEm);
  if (!publicadoEm || isNaN(pubTs)) {
    throw new Error("publicadoEm inválido: timestamp ISO-8601 esperado.");
  }

  var tipoEvento = String(raw.tipoEvento || "publish").trim().toLowerCase();
  if (VALID_EVENT_TYPES.indexOf(tipoEvento) === -1) {
    throw new Error("tipoEvento inválido: esperado publish ou rollback.");
  }

  var estadoHomologacao = String(raw.estadoHomologacao || (tipoEvento === "rollback" ? "REVERTIDO" : "PENDENTE")).trim().toUpperCase();
  if (VALID_HOMOLOG_STATES.indexOf(estadoHomologacao) === -1) {
    throw new Error("estadoHomologacao inválido: " + estadoHomologacao);
  }

  var estagio = String(raw.estagio || (estadoHomologacao === "HOMOLOGADO" ? "homologado" : "publicado")).trim().toLowerCase();
  if (VALID_STAGES.indexOf(estagio) === -1) {
    estagio = "publicado";
  }

  var notas = String(raw.notas || "").trim().slice(0, 320);
  var candidatoVersao = String(raw.candidatoVersao || versao).trim().slice(0, 40);
  var fonteVersao = String(raw.fonteVersao || "deployment+RELEASE_NOTES").trim().slice(0, 60);
  var origem = String(raw.origem || "post-deploy").trim().slice(0, 40);

  return {
    envKey: envKey,
    event: {
      eventId: eventId,
      schemaVersion: schemaVersion,
      unidade: unidade,
      ambiente: ambiente,
      versao: versao,
      candidatoVersao: candidatoVersao,
      commit: commit,
      deploymentId: deploymentId,
      deploymentVersion: deploymentVersion,
      url: url,
      publicadoEm: new Date(pubTs).toISOString(),
      notas: notas,
      estadoHomologacao: estadoHomologacao,
      tipoEvento: tipoEvento,
      estagio: estagio,
      fonteVersao: fonteVersao,
      origem: origem
    }
  };
}

function buildEventSigningPayload_(authTimestamp, event) {
  return [
    String(event.schemaVersion || "2.0"),
    String(event.eventId || ""),
    String(authTimestamp || ""),
    String(event.unidade || ""),
    String(event.ambiente || ""),
    String(event.tipoEvento || ""),
    String(event.versao || ""),
    String(event.commit || ""),
    String(event.deploymentId || ""),
    String(event.deploymentVersion || ""),
    String(event.url || ""),
    String(event.publicadoEm || ""),
    String(event.estadoHomologacao || "")
  ].join("\n");
}

function appendEventToHistorySegmentsLocked_(props, eventRecord, settings) {
  var meta = getReleaseHistMeta_();
  var maxPerSeg = (settings && settings.maxEventosPorSegmento) || DEFAULT_PORTAL_SETTINGS.maxEventosPorSegmento;
  var maxSegs = (settings && settings.maxHistoricoSegmentos) || DEFAULT_PORTAL_SETTINGS.maxHistoricoSegmentos;

  var compact = cloneJson_(eventRecord);
  if (compact.notas && compact.notas.length > 260) {
    compact.notas = compact.notas.slice(0, 257) + "...";
  }

  var currentSegKey = meta.segments.length > 0 ? meta.segments[meta.segments.length - 1] : null;
  var currentArr = [];
  if (currentSegKey) {
    try {
      var raw = props.getProperty(currentSegKey);
      currentArr = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(currentArr)) currentArr = [];
    } catch (e) {
      currentArr = [];
    }
  }

  var candidateArr = currentArr.concat([compact]);
  var candidateJson = JSON.stringify(candidateArr);

  if (!currentSegKey || currentArr.length >= maxPerSeg || getUtf8ByteLength_(candidateJson) > MAX_PROPERTY_BYTES) {
    var nextIndex = 0;
    if (currentSegKey) {
      var suffix = Number(currentSegKey.replace(PROP_KEYS.RELEASE_HIST_SEG_PREFIX, ""));
      nextIndex = isNaN(suffix) ? meta.segments.length : (suffix + 1);
    }
    var newSegKey = PROP_KEYS.RELEASE_HIST_SEG_PREFIX + nextIndex;
    var singleJson = JSON.stringify([compact]);
    props.setProperty(newSegKey, singleJson);
    meta.segments.push(newSegKey);
  } else {
    props.setProperty(currentSegKey, candidateJson);
  }

  while (meta.segments.length > maxSegs) {
    var oldestKey = meta.segments.shift();
    if (oldestKey && typeof props.deleteProperty === "function") {
      props.deleteProperty(oldestKey);
    } else if (oldestKey) {
      props.setProperty(oldestKey, "[]");
    }
  }

  meta.totalEverRecorded = Number(meta.totalEverRecorded || 0) + 1;
  props.setProperty(PROP_KEYS.RELEASE_HIST_META, JSON.stringify(meta));
}

function recordReleaseEventInternal_(rawEvent, actorLabel) {
  var validated = validateReleaseEvent_(rawEvent);
  var envKey = validated.envKey;
  var event = validated.event;
  var settings = getPortalSettings_();

  return withScriptLock_(function () {
    var props = getProps_();
    var dedupeIds = getReleaseDedupeIds_();

    if (dedupeIds.indexOf(event.eventId) !== -1) {
      return {
        success: true,
        duplicate: true,
        stale: false,
        appliedToCurrentState: false,
        eventId: event.eventId,
        envKey: envKey,
        message: "Evento já processado anteriormente (idempotente)."
      };
    }

    var state = getReleaseStateCurrent_();
    var currentEnv = state.environments[envKey];
    var newTs = Date.parse(event.publicadoEm);
    var currTs = currentEnv && currentEnv.publicadoEm ? Date.parse(currentEnv.publicadoEm) : -1;

    var isDelayed = false;
    if (currentEnv && !isNaN(currTs)) {
      if (newTs < currTs) {
        isDelayed = true;
      } else if (newTs === currTs && event.tipoEvento === "publish") {
        var newDepNum = Number(String(event.deploymentVersion).replace(/\D/g, "")) || 0;
        var currDepNum = Number(String(currentEnv.deploymentVersion || "").replace(/\D/g, "")) || 0;
        if (newDepNum <= currDepNum) {
          isDelayed = true;
        }
      }
    }

    var nowIso = new Date().toISOString();
    var record = cloneJson_(event);
    record.recebidoEm = nowIso;
    record.registradoPor = actorLabel || event.origem || "webhook";
    record.stale = isDelayed;
    record.appliedToCurrentState = !isDelayed;
    if (currentEnv && currentEnv.eventId) {
      record.previousEventId = currentEnv.eventId;
    }

    if (!isDelayed) {
      state.environments[envKey] = record;
      state.updatedAt = nowIso;
      props.setProperty(PROP_KEYS.RELEASE_STATE, JSON.stringify(state));
    }

    appendEventToHistorySegmentsLocked_(props, record, settings);

    dedupeIds.push(event.eventId);
    if (dedupeIds.length > MAX_DEDUPE_IDS) {
      dedupeIds = dedupeIds.slice(dedupeIds.length - MAX_DEDUPE_IDS);
    }
    props.setProperty(PROP_KEYS.RELEASE_DEDUPE, JSON.stringify(dedupeIds));

    return {
      success: true,
      duplicate: false,
      stale: isDelayed,
      appliedToCurrentState: !isDelayed,
      eventId: event.eventId,
      envKey: envKey,
      event: record,
      message: isDelayed
        ? "Evento atrasado registrado apenas no histórico; estado atual preservado."
        : "Evento de release registrado com sucesso."
    };
  });
}

function updateHomologationInternal_(envKey, estadoHomologacao, notas, author) {
  if (CANONICAL_IDS.indexOf(envKey) === -1) {
    throw new Error("Ambiente inválido: " + envKey);
  }
  var nextEstado = String(estadoHomologacao || "").trim().toUpperCase();
  if (VALID_HOMOLOG_STATES.indexOf(nextEstado) === -1) {
    throw new Error("Estado de homologação inválido: " + nextEstado);
  }

  return withScriptLock_(function () {
    var props = getProps_();
    var state = getReleaseStateCurrent_();
    var current = state.environments[envKey];
    if (!current) {
      throw new Error("Não há release publicada registrada para " + envKey + " para homologar.");
    }
    var nowIso = new Date().toISOString();
    current.estadoHomologacao = nextEstado;
    current.estagio = nextEstado === "HOMOLOGADO" ? "homologado" : (current.estagio || "publicado");
    current.homologadoEm = nowIso;
    current.homologadoPor = author || "admin";
    if (typeof notas === "string" && notas.trim()) {
      current.notasHomologacao = notas.trim().slice(0, 240);
    }
    state.updatedAt = nowIso;
    props.setProperty(PROP_KEYS.RELEASE_STATE, JSON.stringify(state));
    return {
      success: true,
      envKey: envKey,
      environmentState: current,
      message: "Estado de homologação atualizado para " + nextEstado + "."
    };
  });
}

/* ==================== COMUNICADOS (ANÚNCIOS ADMINISTRÁVEIS) ==================== */

function getAnnouncementsMeta_() {
  var def = { schemaVersion: "2.0", segments: [] };
  try {
    var raw = getProps_().getProperty(PROP_KEYS.ANNOUNCEMENTS_META);
    if (!raw) return def;
    var parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.segments)) return def;
    return { schemaVersion: "2.0", segments: parsed.segments.slice() };
  } catch (e) {
    return def;
  }
}

function getAllAnnouncements_() {
  var props = getProps_();
  var meta = getAnnouncementsMeta_();
  var items = [];
  for (var i = 0; i < meta.segments.length; i++) {
    try {
      var raw = props.getProperty(meta.segments[i]);
      if (!raw) continue;
      var parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (var j = 0; j < parsed.length; j++) {
          items.push(parsed[j]);
        }
      }
    } catch (e) {}
  }
  items.sort(function (a, b) {
    var prioOrder = { Alta: 0, Normal: 1, Baixa: 2 };
    var pa = prioOrder[a.prioridade] !== undefined ? prioOrder[a.prioridade] : 1;
    var pb = prioOrder[b.prioridade] !== undefined ? prioOrder[b.prioridade] : 1;
    if (pa !== pb) return pa - pb;
    return String(b.atualizadoEm || b.criadoEm || "").localeCompare(String(a.atualizadoEm || a.criadoEm || ""));
  });
  return items;
}

function getPublicActiveAnnouncements_() {
  var todayIso = getTodayIsoSaoPaulo_();
  return getAllAnnouncements_().filter(function (a) {
    if (a.ativo !== true) return false;
    if (a.validade && String(a.validade).trim()) {
      var valDate = String(a.validade).trim().slice(0, 10);
      if (valDate < todayIso) return false;
    }
    return true;
  });
}

function persistAnnouncementsLocked_(props, list) {
  var oldMeta = getAnnouncementsMeta_();
  var bounded = list.slice(0, 30);
  var chunks = [];
  var current = [];
  for (var i = 0; i < bounded.length; i++) {
    var candidate = current.concat([bounded[i]]);
    if (current.length >= 10 || getUtf8ByteLength_(JSON.stringify(candidate)) > MAX_PROPERTY_BYTES) {
      chunks.push(current);
      current = [bounded[i]];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) chunks.push(current);

  var newSegs = [];
  for (var c = 0; c < chunks.length; c++) {
    var key = PROP_KEYS.ANNOUNCEMENTS_SEG_PREFIX + c;
    props.setProperty(key, JSON.stringify(chunks[c]));
    newSegs.push(key);
  }
  for (var oldIdx = 0; oldIdx < oldMeta.segments.length; oldIdx++) {
    var oldKey = oldMeta.segments[oldIdx];
    if (newSegs.indexOf(oldKey) === -1) {
      if (typeof props.deleteProperty === "function") {
        props.deleteProperty(oldKey);
      } else {
        props.setProperty(oldKey, "[]");
      }
    }
  }
  props.setProperty(PROP_KEYS.ANNOUNCEMENTS_META, JSON.stringify({
    schemaVersion: "2.0",
    segments: newSegs
  }));
}

function saveAnnouncementInternal_(payload, author) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Comunicado inválido.");
  }
  var titulo = String(payload.titulo || "").trim();
  if (!titulo || titulo.length > 140) {
    throw new Error("Título do comunicado é obrigatório (máx. 140 caracteres).");
  }
  var descricao = String(payload.descricao || "").trim();
  if (!descricao || descricao.length > 800) {
    throw new Error("Descrição do comunicado é obrigatória (máx. 800 caracteres).");
  }
  var categoria = String(payload.categoria || "Informativo").trim();
  if (VALID_ANNOUNCEMENT_CATEGORIES.indexOf(categoria) === -1) {
    throw new Error("Categoria inválida: " + categoria);
  }
  var prioridade = String(payload.prioridade || "Normal").trim();
  if (VALID_ANNOUNCEMENT_PRIORITIES.indexOf(prioridade) === -1) {
    throw new Error("Prioridade inválida: " + prioridade);
  }
  var unidade = String(payload.unidade || "TODAS").trim().toUpperCase();
  if (["TODAS", "CPPA", "PEPOA", "MADRE"].indexOf(unidade) === -1) {
    throw new Error("Unidade inválida para comunicado: " + unidade);
  }
  var validade = payload.validade ? String(payload.validade).trim().slice(0, 10) : "";
  if (validade && !/^\d{4}-\d{2}-\d{2}$/.test(validade)) {
    throw new Error("Validade deve estar no formato YYYY-MM-DD.");
  }
  var ativo = payload.ativo !== false;

  return withScriptLock_(function () {
    var props = getProps_();
    var all = getAllAnnouncements_();
    var nowIso = new Date().toISOString();
    var id = payload.id ? String(payload.id).trim() : ("com-" + Date.now() + "-" + Math.floor(Math.random() * 10000));
    var existingIdx = -1;
    for (var i = 0; i < all.length; i++) {
      if (all[i].id === id) {
        existingIdx = i;
        break;
      }
    }
    var item = {
      id: id,
      titulo: titulo,
      descricao: descricao,
      categoria: categoria,
      prioridade: prioridade,
      validade: validade,
      unidade: unidade,
      ativo: ativo,
      criadoEm: existingIdx !== -1 ? all[existingIdx].criadoEm : nowIso,
      atualizadoEm: nowIso,
      autor: author || "admin"
    };
    if (existingIdx !== -1) {
      all[existingIdx] = item;
    } else {
      all.unshift(item);
    }
    persistAnnouncementsLocked_(props, all);
    return {
      success: true,
      item: item,
      announcements: getAllAnnouncements_(),
      message: existingIdx !== -1 ? "Comunicado atualizado com sucesso." : "Comunicado publicado com sucesso."
    };
  });
}

function deleteAnnouncementInternal_(id) {
  var targetId = String(id || "").trim();
  if (!targetId) throw new Error("ID do comunicado é obrigatório.");
  return withScriptLock_(function () {
    var props = getProps_();
    var all = getAllAnnouncements_();
    var filtered = all.filter(function (a) { return a.id !== targetId; });
    if (filtered.length === all.length) {
      throw new Error("Comunicado não encontrado: " + targetId);
    }
    persistAnnouncementsLocked_(props, filtered);
    return {
      success: true,
      announcements: getAllAnnouncements_(),
      message: "Comunicado removido com sucesso."
    };
  });
}

/* ==================== BOOTSTRAP PÚBLICO E ENDPOINTS ==================== */

function getPublicBootstrapPayload_() {
  var config = getConfig();
  var updatedAt = getConfigUpdatedAt();
  var releaseState = getReleaseStateCurrent_();
  var releaseHistory = getReleaseHistory_();
  var announcements = getPublicActiveAnnouncements_();
  var settings = getPortalSettings_();

  return {
    success: true,
    schemaVersion: "2.0",
    data: config,
    ambientes: config,
    updatedAt: updatedAt,
    releaseState: releaseState,
    releaseHistory: releaseHistory,
    announcements: announcements,
    settings: settings,
    serverNow: new Date().toISOString()
  };
}

function doGet(e) {
  var params = (e && e.parameter) || {};

  if (params.admin === "1" || params.view === "admin") {
    return renderAdminHtml();
  }

  if (params.action === "bootstrap") {
    return ContentService.createTextOutput(JSON.stringify(getPublicBootstrapPayload_()))
      .setMimeType(ContentService.MimeType.JSON);
  }

  if (params.action === "get" || params.format === "json") {
    var responseData = {
      success: true,
      data: getConfig(),
      updatedAt: getConfigUpdatedAt()
    };

    return ContentService.createTextOutput(JSON.stringify(responseData))
      .setMimeType(ContentService.MimeType.JSON);
  }

  return renderPortalHtml();
}

function apiGetPublicConfig() {
  return {
    success: true,
    data: getConfig(),
    updatedAt: getConfigUpdatedAt()
  };
}

function apiGetPublicBootstrap() {
  return getPublicBootstrapPayload_();
}

function verifyWebhookPostAuth_(body) {
  var secret = getProps_().getProperty(PROP_KEYS.WEBHOOK_SECRET);
  if (!secret) {
    return {
      ok: false,
      code: "SECRET_NOT_CONFIGURED",
      error: "403 Não Autorizado: Segredo HMAC (PORTAL_WEBHOOK_SECRET) não configurado no portal."
    };
  }

  var auth = (body && body.auth && typeof body.auth === "object") ? body.auth : {};
  var event = (body && body.event && typeof body.event === "object") ? body.event : body;
  var timestamp = String(auth.timestamp || body.timestamp || "").trim();
  var authEventId = String(auth.eventId || body.eventId || (event && event.eventId) || "").trim();
  var signature = String(auth.signature || body.signature || "").trim().toLowerCase();

  if (!timestamp || !authEventId || !signature) {
    return {
      ok: false,
      code: "MISSING_HMAC_FIELDS",
      error: "401 Não Autorizado: Campos timestamp, eventId e signature são obrigatórios no corpo do POST."
    };
  }

  if (event && event.eventId && String(event.eventId).trim() !== authEventId) {
    return {
      ok: false,
      code: "EVENT_ID_MISMATCH",
      error: "400 Inválido: eventId de autenticação diverge do evento."
    };
  }

  var tsMs = /^\d+$/.test(timestamp) ? Number(timestamp) : Date.parse(timestamp);
  if (isNaN(tsMs)) {
    return {
      ok: false,
      code: "INVALID_TIMESTAMP",
      error: "401 Não Autorizado: timestamp inválido."
    };
  }

  var settings = getPortalSettings_();
  var maxSkewMs = (settings.janelaReplaySegundos || 300) * 1000;
  if (Math.abs(Date.now() - tsMs) > maxSkewMs) {
    return {
      ok: false,
      code: "TIMESTAMP_EXPIRED",
      error: "401 Não Autorizado: timestamp fora da janela de replay permitida."
    };
  }

  var validated = validateReleaseEvent_(event);
  var signingPayload = buildEventSigningPayload_(timestamp, validated.event);
  var expectedSig = hmacSha256Hex_(signingPayload, secret);

  if (!constantTimeEqual_(signature, expectedSig)) {
    return {
      ok: false,
      code: "INVALID_SIGNATURE",
      error: "403 Não Autorizado: Assinatura HMAC-SHA256 inválida."
    };
  }

  return { ok: true, validated: validated };
}

function doPost(e) {
  var body = null;
  try {
    if (e && e.postData && e.postData.contents) {
      body = JSON.parse(e.postData.contents);
    } else if (e && e.parameter && e.parameter.data) {
      body = JSON.parse(e.parameter.data);
    }
  } catch (parseErr) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: "JSON inválido no corpo da requisição: " + parseErr.message
    })).setMimeType(ContentService.MimeType.JSON);
  }

  var isReleaseEventPost = Boolean(
    body && (body.action === "publish_event" || (body.event && body.auth))
  );

  if (isReleaseEventPost) {
    try {
      var authRes = verifyWebhookPostAuth_(body);
      if (!authRes.ok) {
        return ContentService.createTextOutput(JSON.stringify({
          success: false,
          code: authRes.code,
          error: authRes.error
        })).setMimeType(ContentService.MimeType.JSON);
      }
      var eventPayload = (body.event && typeof body.event === "object") ? body.event : body;
      var recorded = recordReleaseEventInternal_(eventPayload, "hmac-publisher");
      return ContentService.createTextOutput(JSON.stringify(recorded))
        .setMimeType(ContentService.MimeType.JSON);
    } catch (eventErr) {
      return ContentService.createTextOutput(JSON.stringify({
        success: false,
        code: "EVENT_VALIDATION_ERROR",
        error: "Erro ao registrar evento: " + eventErr.message
      })).setMimeType(ContentService.MimeType.JSON);
    }
  }

  if (body && typeof body.action === "string" && body.action.indexOf("admin_") === 0) {
    try {
      var adminAction = body.action;
      var adminRes;
      if (adminAction === "admin_authenticate") {
        adminRes = apiAdminAuthenticate(body.email, body.passcode);
      } else if (adminAction === "admin_health") {
        adminRes = apiHealthCheck(body.authToken);
      } else if (adminAction === "admin_bootstrap") {
        adminRes = apiGetAdminBootstrap(body.authToken);
      } else if (adminAction === "admin_save_settings") {
        adminRes = apiSaveAdminSettings(body.payload, body.authToken);
      } else if (adminAction === "admin_save_config") {
        adminRes = apiSaveAdminConfig(body.payload, body.authToken);
      } else {
        return ContentService.createTextOutput(JSON.stringify({
          success: false,
          error: "Ação administrativa desconhecida: " + adminAction
        })).setMimeType(ContentService.MimeType.JSON);
      }
      return ContentService.createTextOutput(JSON.stringify(adminRes))
        .setMimeType(ContentService.MimeType.JSON);
    } catch (adminErr) {
      return ContentService.createTextOutput(JSON.stringify({
        success: false,
        error: adminErr.message || String(adminErr)
      })).setMimeType(ContentService.MimeType.JSON);
    }
  }

  var userEmail = getActiveGoogleEmail_();
  if (!isAuthorizedUser(userEmail)) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: "403 Não Autorizado: Operações de escrita exigem autenticação de administrador autorizada via Conta Google em allowlist."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  try {
    var result = saveConfigInternal_(body, userEmail);
    return ContentService.createTextOutput(JSON.stringify(result))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: "Erro ao processar alteração: " + err.message
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

/* ==================== RPCS ADMINISTRATIVOS PROTEGIDOS ==================== */

function apiAdminAuthenticate(email, passcode) {
  var cleanEmail = String(email || "").trim().toLowerCase();
  var cleanPass = String(passcode || "").trim();
  if (!isAdminPasscodeConfigured_()) {
    throw new Error("Autenticação alternativa não configurada no servidor (ADMIN_AUTH_HASH ausente).");
  }
  if (!isAuthorizedUser(cleanEmail)) {
    throw new Error("Acesso negado: E-mail não está na allowlist de administradores.");
  }
  var props = getProps_();
  var salt = props.getProperty(PROP_KEYS.ADMIN_AUTH_SALT) || "";
  var expectedHash = props.getProperty(PROP_KEYS.ADMIN_AUTH_HASH) || "";
  var actualHash = sha256Hex_(salt + ":" + cleanPass);
  if (!constantTimeEqual_(actualHash, expectedHash)) {
    throw new Error("Credencial administrativa inválida.");
  }

  var token = (Utilities.getUuid ? Utilities.getUuid() : sha256Hex_(cleanEmail + ":" + Date.now() + ":" + Math.random())) +
    "-" + sha256Hex_(String(Math.random()) + ":" + Date.now()).slice(0, 16);
  var expiresAt = Date.now() + (ADMIN_SESSION_TTL_SECONDS * 1000);
  if (typeof CacheService !== "undefined" && CacheService && typeof CacheService.getScriptCache === "function") {
    CacheService.getScriptCache().put(
      "ADMIN_SESS_" + sha256Hex_(token),
      JSON.stringify({ email: cleanEmail, expiresAt: expiresAt }),
      ADMIN_SESSION_TTL_SECONDS
    );
  }

  return {
    success: true,
    user: cleanEmail,
    authToken: token,
    expiresAt: new Date(expiresAt).toISOString()
  };
}

function apiHealthCheck(authToken) {
  var auth = requireAdminAuth_(authToken);
  return {
    success: true,
    user: auth.email,
    method: auth.method,
    timestamp: new Date().toISOString()
  };
}

function apiGetAdminConfig(authToken) {
  var auth = requireAdminAuth_(authToken);
  return {
    success: true,
    user: auth.email,
    data: getConfig(),
    updatedAt: getConfigUpdatedAt()
  };
}

function apiGetAdminBootstrap(authToken) {
  var auth = requireAdminAuth_(authToken);
  var props = getProps_();
  return {
    success: true,
    user: auth.email,
    authMethod: auth.method,
    config: getConfig(),
    updatedAt: getConfigUpdatedAt(),
    updatedBy: props.getProperty(PROP_KEYS.CONFIG_UPDATED_BY) || "",
    releaseState: getReleaseStateCurrent_(),
    releaseHistory: getReleaseHistory_(),
    releaseStorage: getReleaseStorageStats_(),
    announcements: getAllAnnouncements_(),
    settings: getPortalSettings_(),
    securityStatus: {
      adminEmails: getAdminAllowlist(),
      webhookSecretConfigured: Boolean(props.getProperty(PROP_KEYS.WEBHOOK_SECRET)),
      adminPasscodeConfigured: isAdminPasscodeConfigured_(),
      googleEmailDetected: Boolean(getActiveGoogleEmail_())
    }
  };
}

function apiSaveAdminConfig(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  return saveConfigInternal_(payload, auth.email);
}

function apiResetAdminConfig(authToken) {
  var auth = requireAdminAuth_(authToken);
  return saveConfigInternal_(DEFAULT_CONFIG, auth.email + " (reset)");
}

function apiRecordAdminReleaseEvent(eventPayload, authToken) {
  var auth = requireAdminAuth_(authToken);
  var clone = cloneJson_(eventPayload || {});
  if (!clone.eventId) {
    clone.eventId = "adm-" + String(clone.unidade || "SYS").toLowerCase() + "-" + String(clone.ambiente || "ENV").toLowerCase() + "-" + Date.now();
  }
  if (!clone.publicadoEm) {
    clone.publicadoEm = new Date().toISOString();
  }
  if (!clone.origem) {
    clone.origem = "admin-manual";
  }
  return recordReleaseEventInternal_(clone, auth.email);
}

function apiUpdateAdminHomologation(envKey, estadoHomologacao, notas, authToken) {
  var auth = requireAdminAuth_(authToken);
  return updateHomologationInternal_(envKey, estadoHomologacao, notas, auth.email);
}

function apiSaveAdminAnnouncement(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  return saveAnnouncementInternal_(payload, auth.email);
}

function apiDeleteAdminAnnouncement(id, authToken) {
  requireAdminAuth_(authToken);
  return deleteAnnouncementInternal_(id);
}

function apiSaveAdminSettings(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  if (!payload || typeof payload !== "object") {
    throw new Error("Configurações inválidas.");
  }

  var updatedSettings = savePortalSettingsInternal_(payload, auth.email);
  var props = getProps_();

  if (Array.isArray(payload.adminEmails)) {
    var cleanEmails = payload.adminEmails
      .map(function (e) { return String(e || "").trim().toLowerCase(); })
      .filter(function (e) { return e.indexOf("@") > 0; });
    if (cleanEmails.length === 0) {
      throw new Error("A allowlist de administradores deve conter ao menos um e-mail válido.");
    }
    props.setProperty(PROP_KEYS.ADMIN_EMAILS, cleanEmails.join(","));
  }

  if (typeof payload.newWebhookSecret === "string" && payload.newWebhookSecret.trim()) {
    if (payload.newWebhookSecret.trim().length < 16) {
      throw new Error("O segredo HMAC deve ter ao menos 16 caracteres.");
    }
    props.setProperty(PROP_KEYS.WEBHOOK_SECRET, payload.newWebhookSecret.trim());
  }

  if (typeof payload.newAdminPasscode === "string" && payload.newAdminPasscode.trim()) {
    setAdminPasscodeInternal_(payload.newAdminPasscode.trim());
  }

  return {
    success: true,
    settings: updatedSettings,
    adminEmails: getAdminAllowlist(),
    webhookSecretConfigured: Boolean(props.getProperty(PROP_KEYS.WEBHOOK_SECRET)),
    adminPasscodeConfigured: isAdminPasscodeConfigured_(),
    message: "Configurações salvas com sucesso."
  };
}

/* ==================== RENDERIZAÇÃO HTMLSERVICE ==================== */

function renderPortalHtml() {
  var payload = getPublicBootstrapPayload_();
  var adminUrl = buildAppViewUrl("view=admin");
  var safeAdminUrl = escapeHtmlAttr(adminUrl);
  var template = readHtmlTemplate_("Portal");

  var htmlContent = template
    .replace(/__SISFAR_ADMIN_URL__/g, safeAdminUrl)
    .replace("\"__SISFAR_INITIAL_DATA__\"", safeJsonForHtmlScript(payload));

  return HtmlService.createHtmlOutput(htmlContent)
    .setTitle("SISFAR — Sistema Integrado de Farmácia Prisional")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function renderAdminHtml() {
  var userEmail = getActiveGoogleEmail_();
  var isGoogleAuth = isAuthorizedUser(userEmail);
  var passcodeConfigured = isAdminPasscodeConfigured_();
  var portalUrl = buildAppViewUrl("view=portal");
  var safePortalUrl = escapeHtmlAttr(portalUrl);

  // Caso Google identifique um e-mail não autorizado, ou caso venha vazio sem fallback configurado -> 403 fail-closed.
  if ((userEmail && !isGoogleAuth) || (!userEmail && !passcodeConfigured)) {
    return HtmlService.createHtmlOutput(
      "<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\"><base target=\"_top\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>SISFAR — Acesso Negado</title><style>" +
      "body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#F4F7F9;color:#0F172A;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1.5rem;box-sizing:border-box;}" +
      ".card{background:#FFFFFF;padding:2.25rem 2rem;border-radius:14px;border:1px solid #E2E8F0;text-align:center;max-width:520px;box-shadow:0 8px 24px rgba(15,23,42,0.06);}" +
      "h2{color:#B91C1C;margin:0 0 0.75rem;font-size:1.3rem;}p{color:#475569;font-size:0.92rem;line-height:1.55;margin:0.75rem 0;}" +
      ".email{font-family:monospace;background:#F8FAFC;padding:0.35rem 0.65rem;border-radius:6px;color:#0369A1;display:inline-block;margin:0.35rem 0;border:1px solid #E2E8F0;}" +
      ".hint{text-align:left;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px;padding:0.9rem 1rem;font-size:0.82rem;color:#334155;margin-top:1rem;}" +
      "code{background:#E2E8F0;padding:0.1rem 0.3rem;border-radius:4px;font-size:0.8rem;}" +
      "a{display:inline-block;margin-top:1.35rem;color:#0F766E;text-decoration:none;font-size:0.875rem;font-weight:600;}" +
      "a:hover{text-decoration:underline;}" +
      "</style></head><body><div class=\"card\">" +
      "<h2>403 — Acesso Restrito</h2>" +
      "<p>A Central Administrativa do SISFAR é restrita a administradores autorizados.</p>" +
      "<p>Conta conectada:<br><span class=\"email\">" + escapeHtmlAttr(userEmail || "Nenhuma conta Google detectada") + "</span></p>" +
      (!userEmail ? "<div class=\"hint\"><strong>Execução pública sem e-mail Google:</strong> Para habilitar autenticação administrativa em Web App público sem abrir escrita anônima, o proprietário deve executar <code>configurarChaveAdminPortal_(\"SUA_CHAVE_FORTE\")</code> uma vez no Editor do Apps Script.</div>" : "<p>Solicite permissão ao administrador central do sistema caso necessite de acesso.</p>") +
      "<a href=\"" + safePortalUrl + "\">← Voltar ao Portal Público</a>" +
      "</div></body></html>"
    ).setTitle("SISFAR — Acesso Negado");
  }

  var bootContext = {
    authenticatedByGoogle: isGoogleAuth,
    userEmail: isGoogleAuth ? userEmail : "",
    requirePasscodeLogin: !isGoogleAuth && passcodeConfigured,
    portalUrl: portalUrl
  };

  var template = readHtmlTemplate_("Admin");
  var htmlContent = template
    .replace(/__SISFAR_PORTAL_URL__/g, safePortalUrl)
    .replace(/__SISFAR_ADMIN_EMAIL__/g, escapeHtmlAttr(isGoogleAuth ? userEmail : "Autenticação requerida"))
    .replace("\"__SISFAR_ADMIN_BOOT__\"", safeJsonForHtmlScript(bootContext));

  return HtmlService.createHtmlOutput(htmlContent)
    .setTitle("SISFAR — Central Administrativa")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
