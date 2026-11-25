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
  PORTAL_SETTINGS: "SISFAR_PORTAL_SETTINGS_V2",
  MONITOR_SETTINGS: "MONITOR_SETTINGS",
  MONITOR_STATE: "MONITOR_STATE",
  MONITOR_HISTORY: "MONITOR_HISTORY",
  MONITOR_HISTORY_SEG_PREFIX: "MONITOR_HISTORY_SEG_",
  MONITOR_INCIDENTS: "MONITOR_INCIDENTS",
  MONITOR_MAINTENANCES: "MONITOR_MAINTENANCES"
};

const VALID_MONITOR_INTERVALS = [5, 10, 15, 30, 60];
const VALID_INCIDENT_STATES = ["INVESTIGACAO", "CONFIRMADO", "RESOLVIDO", "ENCERRADO_ADMIN"];
const VALID_MAINTENANCE_STATES = ["PROGRAMADA", "EM_ANDAMENTO", "ENCERRADA", "CANCELADA"];
const MONITOR_TRIGGER_HANDLER = "runScheduledMonitoringCheck";
const MONITOR_MIN_AVAIL_SAMPLES = 4;

const DEFAULT_MONITOR_SETTINGS = {
  schemaVersion: "2.1",
  enabled: true,
  intervalMinutes: 15,
  slowThresholdMs: 3000,
  failureThreshold: 2,
  recoverySuccessThreshold: 2,
  staleMinutes: 45,
  historyRetentionDays: 3,
  dailyRetentionDays: 21,
  incidentRetentionDays: 90,
  maxHistorySegments: 6,
  useFetchAll: false,
  environments: {
    cppaOficial: { enabled: true },
    pepoaOficial: { enabled: true },
    madreOficial: { enabled: true },
    cppaAudit: { enabled: true },
    pepoaAudit: { enabled: true },
    madreAudit: { enabled: true }
  }
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

/* ==================== MOTOR DE MONITORAMENTO OPERACIONAL (2.1) ==================== */

function parseSaoPauloIso_(raw) {
  if (!raw || typeof raw !== "string") return "";
  var s = raw.trim();
  if (!s) return "";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/.test(s)) {
    s = s + "-03:00";
  }
  var ts = Date.parse(s);
  if (isNaN(ts)) {
    throw new Error("Timestamp inválido (esperado ISO-8601 ou YYYY-MM-DDTHH:mm): " + raw);
  }
  return new Date(ts).toISOString();
}

function getDayIsoSaoPaulo_(dateObj) {
  try {
    return Utilities.formatDate(dateObj || new Date(), "America/Sao_Paulo", "yyyy-MM-dd");
  } catch (e) {
    return (dateObj || new Date()).toISOString().slice(0, 10);
  }
}

function sanitizeMonitorText_(str, maxLen) {
  if (!str) return "";
  var clean = String(str)
    .replace(/https?:\/\/[^\s"'<>]+/gi, function (u) {
      var m = u.match(/^https?:\/\/([^\/\?#]+)/i);
      return m ? ("[https://" + m[1] + "]") : "[URL]";
    })
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL]")
    .replace(/(token|key|secret|auth|code|ticket|session|cookie)=[^&\s]+/gi, "$1=[REDACTED]")
    .replace(/[\r\n\t]+/g, " ")
    .trim();
  return clean.slice(0, maxLen || 140);
}

function sanitizeRedirectHost_(locationHeader) {
  if (!locationHeader || typeof locationHeader !== "string") return "";
  var m = locationHeader.trim().match(/^https?:\/\/([^\/:\?#]+)/i);
  return m ? m[1].toLowerCase() : "";
}

function getMonitorSettings_() {
  var base = cloneJson_(DEFAULT_MONITOR_SETTINGS);
  try {
    var raw = getProps_().getProperty(PROP_KEYS.MONITOR_SETTINGS);
    if (!raw) return base;
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return base;
    if (typeof parsed.enabled === "boolean") base.enabled = parsed.enabled;
    if (VALID_MONITOR_INTERVALS.indexOf(Number(parsed.intervalMinutes)) !== -1) {
      base.intervalMinutes = Number(parsed.intervalMinutes);
    }
    if (typeof parsed.slowThresholdMs === "number" && !isNaN(parsed.slowThresholdMs)) {
      base.slowThresholdMs = Math.max(500, Math.min(30000, Math.floor(parsed.slowThresholdMs)));
    }
    if (typeof parsed.failureThreshold === "number" && !isNaN(parsed.failureThreshold)) {
      base.failureThreshold = Math.max(1, Math.min(10, Math.floor(parsed.failureThreshold)));
    }
    if (typeof parsed.recoverySuccessThreshold === "number" && !isNaN(parsed.recoverySuccessThreshold)) {
      base.recoverySuccessThreshold = Math.max(1, Math.min(5, Math.floor(parsed.recoverySuccessThreshold)));
    }
    if (typeof parsed.staleMinutes === "number" && !isNaN(parsed.staleMinutes)) {
      base.staleMinutes = Math.max(10, Math.min(1440, Math.floor(parsed.staleMinutes)));
    }
    if (typeof parsed.historyRetentionDays === "number" && !isNaN(parsed.historyRetentionDays)) {
      base.historyRetentionDays = Math.max(1, Math.min(14, Math.floor(parsed.historyRetentionDays)));
    }
    if (typeof parsed.dailyRetentionDays === "number" && !isNaN(parsed.dailyRetentionDays)) {
      base.dailyRetentionDays = Math.max(7, Math.min(30, Math.floor(parsed.dailyRetentionDays)));
    }
    if (typeof parsed.incidentRetentionDays === "number" && !isNaN(parsed.incidentRetentionDays)) {
      base.incidentRetentionDays = Math.max(7, Math.min(365, Math.floor(parsed.incidentRetentionDays)));
    }
    if (typeof parsed.maxHistorySegments === "number" && !isNaN(parsed.maxHistorySegments)) {
      base.maxHistorySegments = Math.max(2, Math.min(6, Math.floor(parsed.maxHistorySegments)));
    }
    if (typeof parsed.useFetchAll === "boolean") {
      base.useFetchAll = parsed.useFetchAll;
    }
    if (parsed.environments && typeof parsed.environments === "object") {
      for (var i = 0; i < CANONICAL_IDS.length; i++) {
        var k = CANONICAL_IDS[i];
        var envCfg = parsed.environments[k];
        if (envCfg && typeof envCfg.enabled === "boolean") {
          base.environments[k] = { enabled: envCfg.enabled };
        }
      }
    }
    if (parsed.triggerSyncedInterval) base.triggerSyncedInterval = Number(parsed.triggerSyncedInterval);
    if (parsed.triggerLastSyncedAt) base.triggerLastSyncedAt = String(parsed.triggerLastSyncedAt);
    if (parsed.atualizadoEm) base.atualizadoEm = String(parsed.atualizadoEm);
    if (parsed.atualizadoPor) base.atualizadoPor = String(parsed.atualizadoPor);
  } catch (e) {}
  return base;
}

function saveMonitorSettingsInternal_(payload, author, skipTriggerSync) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Configurações de monitoramento inválidas.");
  }
  var next = getMonitorSettings_();
  if (payload.enabled !== undefined) next.enabled = Boolean(payload.enabled);
  if (payload.intervalMinutes !== undefined) {
    var iv = Number(payload.intervalMinutes);
    if (VALID_MONITOR_INTERVALS.indexOf(iv) === -1) {
      throw new Error("Frequência inválida. Intervalos suportados: " + VALID_MONITOR_INTERVALS.join(", ") + " min.");
    }
    next.intervalMinutes = iv;
  }
  if (payload.slowThresholdMs !== undefined) {
    var slow = Number(payload.slowThresholdMs);
    if (isNaN(slow) || slow < 500 || slow > 30000) throw new Error("Limiar de lentidão deve estar entre 500 e 30000 ms.");
    next.slowThresholdMs = Math.floor(slow);
  }
  if (payload.failureThreshold !== undefined) {
    var ft = Number(payload.failureThreshold);
    if (isNaN(ft) || ft < 1 || ft > 10) throw new Error("Falhas consecutivas para incidente deve estar entre 1 e 10.");
    next.failureThreshold = Math.floor(ft);
  }
  if (payload.recoverySuccessThreshold !== undefined) {
    var rt = Number(payload.recoverySuccessThreshold);
    if (isNaN(rt) || rt < 1 || rt > 5) throw new Error("Sucessos consecutivos para recuperação deve estar entre 1 e 5.");
    next.recoverySuccessThreshold = Math.floor(rt);
  }
  if (payload.staleMinutes !== undefined) {
    var sm = Number(payload.staleMinutes);
    if (isNaN(sm) || sm < 10 || sm > 1440) throw new Error("Validade da amostra deve estar entre 10 e 1440 minutos.");
    next.staleMinutes = Math.floor(sm);
  }
  if (payload.historyRetentionDays !== undefined) {
    var hrd = Number(payload.historyRetentionDays);
    if (isNaN(hrd) || hrd < 1 || hrd > 14) throw new Error("Retenção detalhada deve estar entre 1 e 14 dias.");
    next.historyRetentionDays = Math.floor(hrd);
  }
  if (payload.dailyRetentionDays !== undefined) {
    var drd = Number(payload.dailyRetentionDays);
    if (isNaN(drd) || drd < 7 || drd > 30) throw new Error("Retenção diária deve estar entre 7 e 30 dias.");
    next.dailyRetentionDays = Math.floor(drd);
  }
  if (payload.incidentRetentionDays !== undefined) {
    var ird = Number(payload.incidentRetentionDays);
    if (isNaN(ird) || ird < 7 || ird > 365) throw new Error("Retenção de incidentes deve estar entre 7 e 365 dias.");
    next.incidentRetentionDays = Math.floor(ird);
  }
  if (payload.useFetchAll !== undefined) {
    next.useFetchAll = Boolean(payload.useFetchAll);
  }
  if (payload.environments && typeof payload.environments === "object") {
    for (var i = 0; i < CANONICAL_IDS.length; i++) {
      var k = CANONICAL_IDS[i];
      if (payload.environments[k] && typeof payload.environments[k].enabled === "boolean") {
        next.environments[k] = { enabled: payload.environments[k].enabled };
      }
    }
  }
  next.atualizadoEm = new Date().toISOString();
  next.atualizadoPor = author || "admin";

  withScriptLock_(function () {
    getProps_().setProperty(PROP_KEYS.MONITOR_SETTINGS, JSON.stringify(next));
  });

  var triggerSync = null;
  if (!skipTriggerSync) {
    triggerSync = syncMonitoringTriggerInternal_(false);
  }
  return {
    success: true,
    settings: getMonitorSettings_(),
    triggerSync: triggerSync,
    message: "Configurações de monitoramento salvas."
  };
}

function getMonitorState_() {
  var empty = {
    schemaVersion: "2.1",
    updatedAt: null,
    lastRunAt: null,
    lastRunDurationMs: 0,
    lastRunMode: null,
    lastRunSummary: null,
    environments: {}
  };
  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    empty.environments[CANONICAL_IDS[i]] = null;
  }
  try {
    var raw = getProps_().getProperty(PROP_KEYS.MONITOR_STATE);
    if (!raw) return empty;
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !parsed.environments) return empty;
    empty.updatedAt = parsed.updatedAt || null;
    empty.lastRunAt = parsed.lastRunAt || null;
    empty.lastRunDurationMs = Number(parsed.lastRunDurationMs || 0);
    empty.lastRunMode = parsed.lastRunMode || null;
    empty.lastRunSummary = parsed.lastRunSummary || null;
    for (var j = 0; j < CANONICAL_IDS.length; j++) {
      var k = CANONICAL_IDS[j];
      empty.environments[k] = parsed.environments[k] || null;
    }
    return empty;
  } catch (e) {
    return empty;
  }
}

function getMonitorHistoryMeta_() {
  var empty = {
    schemaVersion: "2.1",
    updatedAt: null,
    segments: [],
    totalEverRecorded: 0,
    daily: {}
  };
  try {
    var raw = getProps_().getProperty(PROP_KEYS.MONITOR_HISTORY);
    if (!raw) return empty;
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return empty;
    return {
      schemaVersion: "2.1",
      updatedAt: parsed.updatedAt || null,
      segments: Array.isArray(parsed.segments) ? parsed.segments.slice() : [],
      totalEverRecorded: Number(parsed.totalEverRecorded || 0),
      daily: (parsed.daily && typeof parsed.daily === "object" && !Array.isArray(parsed.daily)) ? parsed.daily : {}
    };
  } catch (e) {
    return empty;
  }
}

function getMonitorHistorySamples_(filters) {
  var props = getProps_();
  var meta = getMonitorHistoryMeta_();
  var samples = [];
  for (var i = 0; i < meta.segments.length; i++) {
    try {
      var raw = props.getProperty(meta.segments[i]);
      if (!raw) continue;
      var arr = JSON.parse(raw);
      if (Array.isArray(arr)) {
        for (var j = 0; j < arr.length; j++) {
          samples.push(arr[j]);
        }
      }
    } catch (e) {}
  }
  samples.sort(function (a, b) {
    return (Date.parse(b.t || 0) || 0) - (Date.parse(a.t || 0) || 0);
  });
  if (!filters || typeof filters !== "object") return samples;
  var fEnv = filters.envKey ? String(filters.envKey) : "";
  var fSinceMs = filters.sinceMs ? Number(filters.sinceMs) : 0;
  return samples.filter(function (s) {
    if (fEnv && s.e !== fEnv) return false;
    if (fSinceMs && (Date.parse(s.t || 0) || 0) < fSinceMs) return false;
    return true;
  });
}

function getMonitorIncidentsData_() {
  var empty = { schemaVersion: "2.1", updatedAt: null, totalEverRecorded: 0, items: [] };
  try {
    var raw = getProps_().getProperty(PROP_KEYS.MONITOR_INCIDENTS);
    if (!raw) return empty;
    var parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.items)) return empty;
    return {
      schemaVersion: "2.1",
      updatedAt: parsed.updatedAt || null,
      totalEverRecorded: Number(parsed.totalEverRecorded || 0),
      items: parsed.items.slice()
    };
  } catch (e) {
    return empty;
  }
}

function persistMonitorIncidentsLocked_(props, data, settings) {
  var retentionDays = (settings && settings.incidentRetentionDays) || DEFAULT_MONITOR_SETTINGS.incidentRetentionDays;
  var cutoffMs = Date.now() - (retentionDays * 86400000);
  var items = (data.items || []).filter(function (inc) {
    var isActive = inc.estado === "INVESTIGACAO" || inc.estado === "CONFIRMADO";
    if (isActive) return true;
    var refTs = Date.parse(inc.encerramento || inc.ultimaOcorrencia || inc.inicio || 0) || 0;
    return refTs >= cutoffMs;
  });

  items.sort(function (a, b) {
    var actA = (a.estado === "INVESTIGACAO" || a.estado === "CONFIRMADO") ? 0 : 1;
    var actB = (b.estado === "INVESTIGACAO" || b.estado === "CONFIRMADO") ? 0 : 1;
    if (actA !== actB) return actA - actB;
    return (Date.parse(b.ultimaOcorrencia || b.inicio || 0) || 0) - (Date.parse(a.ultimaOcorrencia || a.inicio || 0) || 0);
  });

  if (items.length > 30) items = items.slice(0, 30);

  var payload = {
    schemaVersion: "2.1",
    updatedAt: new Date().toISOString(),
    totalEverRecorded: Number(data.totalEverRecorded || 0),
    items: items
  };

  while (items.length > 1 && getUtf8ByteLength_(JSON.stringify(payload)) > MAX_PROPERTY_BYTES) {
    var removeIdx = -1;
    for (var i = items.length - 1; i >= 0; i--) {
      if (items[i].estado !== "INVESTIGACAO" && items[i].estado !== "CONFIRMADO") {
        removeIdx = i;
        break;
      }
    }
    if (removeIdx === -1) removeIdx = items.length - 1;
    items.splice(removeIdx, 1);
    payload.items = items;
  }

  props.setProperty(PROP_KEYS.MONITOR_INCIDENTS, JSON.stringify(payload));
  return payload;
}

function getMonitorMaintenancesData_() {
  var empty = { schemaVersion: "2.1", updatedAt: null, items: [] };
  try {
    var raw = getProps_().getProperty(PROP_KEYS.MONITOR_MAINTENANCES);
    if (!raw) return empty;
    var parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.items)) return empty;
    return {
      schemaVersion: "2.1",
      updatedAt: parsed.updatedAt || null,
      items: parsed.items.slice()
    };
  } catch (e) {
    return empty;
  }
}

function persistMonitorMaintenancesLocked_(props, data) {
  var items = (data.items || []).slice();
  items.sort(function (a, b) {
    return (Date.parse(b.inicio || 0) || 0) - (Date.parse(a.inicio || 0) || 0);
  });
  if (items.length > 25) items = items.slice(0, 25);
  var payload = {
    schemaVersion: "2.1",
    updatedAt: new Date().toISOString(),
    items: items
  };
  while (items.length > 1 && getUtf8ByteLength_(JSON.stringify(payload)) > MAX_PROPERTY_BYTES) {
    var idx = -1;
    for (var i = items.length - 1; i >= 0; i--) {
      if (items[i].estado === "ENCERRADA" || items[i].estado === "CANCELADA") {
        idx = i;
        break;
      }
    }
    if (idx === -1) idx = items.length - 1;
    items.splice(idx, 1);
    payload.items = items;
  }
  props.setProperty(PROP_KEYS.MONITOR_MAINTENANCES, JSON.stringify(payload));
  return payload;
}

function maintenanceCoversEnv_(maint, envKey, nowMs) {
  if (!maint) return false;
  var st = String(maint.estado || "").toUpperCase();
  if (st !== "PROGRAMADA" && st !== "EM_ANDAMENTO") return false;
  var startMs = Date.parse(maint.inicio || 0);
  var endMs = Date.parse(maint.fim || 0);
  if (isNaN(startMs) || isNaN(endMs)) return false;
  if (nowMs < startMs || nowMs > endMs) return false;
  var alvo = String(maint.alvo || "TODAS").trim();
  if (alvo === "TODAS") return true;
  if (alvo === envKey) return true;
  var meta = ENV_KEY_META[envKey];
  if (meta && alvo.toUpperCase() === meta.unidade) return true;
  return false;
}

function getActiveMaintenanceForEnv_(maintenances, envKey, nowMs) {
  var ts = nowMs || Date.now();
  var list = maintenances || [];
  for (var i = 0; i < list.length; i++) {
    if (maintenanceCoversEnv_(list[i], envKey, ts)) {
      return list[i];
    }
  }
  return null;
}

function classifyHttpResponse_(httpCode, locationHeader, bodySnippet, durationMs, slowThresholdMs) {
  var code = Number(httpCode || 0);
  var slowMs = Number(slowThresholdMs || DEFAULT_MONITOR_SETTINGS.slowThresholdMs);
  var ms = Math.max(0, Math.round(Number(durationMs || 0)));

  if (code === 401) {
    return {
      rawClassification: "AUTENTICACAO_NECESSARIA",
      category: "HTTP_401_UNAUTHORIZED",
      isFailure: false,
      isAuthRequired: true,
      isReachable: false,
      summary: "HTTP 401 — Autenticação necessária"
    };
  }

  if (code >= 300 && code < 400) {
    var locRaw = String(locationHeader || "");
    var locHost = sanitizeRedirectHost_(locRaw);
    var isLoginRedirect = /accounts\.google\.com|servicelogin|signin|oauth|login/i.test(locRaw);
    if (isLoginRedirect) {
      return {
        rawClassification: "AUTENTICACAO_NECESSARIA",
        category: "HTTP_" + code + "_AUTH_REDIRECT",
        isFailure: false,
        isAuthRequired: true,
        isReachable: false,
        summary: "HTTP " + code + " — Redireciona para login" + (locHost ? " (" + locHost + ")" : "")
      };
    }
    if (!locRaw) {
      return {
        rawClassification: "FALHA_VERIFICACAO",
        category: "HTTP_" + code + "_NO_LOCATION",
        isFailure: true,
        isAuthRequired: false,
        isReachable: false,
        summary: "HTTP " + code + " — Redirecionamento sem destino"
      };
    }
    var isSlowRedir = ms >= slowMs;
    return {
      rawClassification: isSlowRedir ? "RESPOSTA_LENTA" : "ACESSIVEL",
      category: isSlowRedir ? "HTTP_3XX_REDIRECT_SLOW" : "HTTP_3XX_REDIRECT_OK",
      isFailure: false,
      isAuthRequired: false,
      isReachable: true,
      summary: "HTTP " + code + " — Redirecionamento técnico" + (locHost ? " (" + locHost + ")" : "") + " · " + ms + " ms"
    };
  }

  if (code >= 200 && code < 300) {
    var snippet = String(bodySnippet || "").slice(0, 4096);
    var isAuthPage = /accounts\.google\.com|ServiceLogin|gaia_loginform|Sign in - Google Accounts|Fazer login|You need permission|Solicitar acesso|requestaccess/i.test(snippet);
    if (isAuthPage) {
      return {
        rawClassification: "AUTENTICACAO_NECESSARIA",
        category: "HTTP_" + code + "_AUTH_PAGE",
        isFailure: false,
        isAuthRequired: true,
        isReachable: false,
        summary: "HTTP " + code + " — Página de autenticação Google"
      };
    }
    var isErrorPage = /<title>\s*(error|erro|page not found|404)\s*<\/title>|sorry,\s*unable to open the file at this time/i.test(snippet);
    if (isErrorPage) {
      return {
        rawClassification: "FALHA_VERIFICACAO",
        category: "HTTP_" + code + "_ERROR_PAGE",
        isFailure: true,
        isAuthRequired: false,
        isReachable: false,
        summary: "HTTP " + code + " — Página de erro retornada"
      };
    }
    var isSlow = ms >= slowMs;
    return {
      rawClassification: isSlow ? "RESPOSTA_LENTA" : "ACESSIVEL",
      category: isSlow ? ("HTTP_" + code + "_SLOW") : ("HTTP_" + code + "_OK"),
      isFailure: false,
      isAuthRequired: false,
      isReachable: true,
      summary: "HTTP " + code + (isSlow ? " — Resposta lenta" : " — Acessível") + " (" + ms + " ms)"
    };
  }

  if (code === 403) {
    return {
      rawClassification: "FALHA_VERIFICACAO",
      category: "HTTP_403_FORBIDDEN",
      isFailure: true,
      isAuthRequired: false,
      isReachable: false,
      summary: "HTTP 403 — Acesso proibido"
    };
  }
  if (code === 404) {
    return {
      rawClassification: "FALHA_VERIFICACAO",
      category: "HTTP_404_NOT_FOUND",
      isFailure: true,
      isAuthRequired: false,
      isReachable: false,
      summary: "HTTP 404 — Não encontrado"
    };
  }
  if (code >= 400 && code < 500) {
    return {
      rawClassification: "FALHA_VERIFICACAO",
      category: "HTTP_" + code + "_CLIENT_ERROR",
      isFailure: true,
      isAuthRequired: false,
      isReachable: false,
      summary: "HTTP " + code + " — Erro de cliente"
    };
  }
  if (code >= 500) {
    return {
      rawClassification: "FALHA_VERIFICACAO",
      category: "HTTP_" + code + "_SERVER_ERROR",
      isFailure: true,
      isAuthRequired: false,
      isReachable: false,
      summary: "HTTP " + code + " — Erro no servidor"
    };
  }

  return {
    rawClassification: "FALHA_VERIFICACAO",
    category: "NETWORK_ERROR",
    isFailure: true,
    isAuthRequired: false,
    isReachable: false,
    summary: "Falha de rede na verificação"
  };
}

function classifyProbeException_(err) {
  var msg = sanitizeMonitorText_(err && err.message ? err.message : String(err || "Erro de rede"), 120);
  var cat = "NETWORK_ERROR";
  if (/timeout|timed out|exceeded/i.test(msg)) cat = "TIMEOUT_ERROR";
  else if (/dns|resolve|host/i.test(msg)) cat = "DNS_ERROR";
  else if (/ssl|tls|certificate/i.test(msg)) cat = "TLS_ERROR";
  return {
    httpStatus: 0,
    durationMs: 0,
    rawClassification: "FALHA_VERIFICACAO",
    category: cat,
    isFailure: true,
    isAuthRequired: false,
    isReachable: false,
    summary: cat + ": " + (msg || "Falha de conexão")
  };
}

function extractHeaderCaseInsensitive_(headers, targetName) {
  if (!headers || typeof headers !== "object") return "";
  var lower = targetName.toLowerCase();
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === lower) {
      return String(headers[keys[i]] || "");
    }
  }
  return "";
}

function probeSingleEndpoint_(url, slowThresholdMs) {
  var start = Date.now();
  try {
    var resp = UrlFetchApp.fetch(url, {
      method: "get",
      muteHttpExceptions: true,
      followRedirects: false,
      headers: {
        "User-Agent": "SISFAR-Portal-Monitor/2.1",
        "Cache-Control": "no-cache"
      }
    });
    var durationMs = Math.max(1, Date.now() - start);
    var httpCode = resp && typeof resp.getResponseCode === "function" ? resp.getResponseCode() : 0;
    var headers = resp && typeof resp.getHeaders === "function" ? resp.getHeaders() : {};
    var locHeader = extractHeaderCaseInsensitive_(headers, "Location");
    var bodySnippet = "";
    if (httpCode >= 200 && httpCode < 300 && resp && typeof resp.getContentText === "function") {
      bodySnippet = String(resp.getContentText() || "").slice(0, 4096);
    }
    var cls = classifyHttpResponse_(httpCode, locHeader, bodySnippet, durationMs, slowThresholdMs);
    cls.httpStatus = httpCode;
    cls.durationMs = durationMs;
    return cls;
  } catch (err) {
    var fail = classifyProbeException_(err);
    fail.durationMs = Math.max(0, Date.now() - start);
    return fail;
  }
}

function probeBatchEndpoints_(activeTargets, settings) {
  var results = {};
  var slowMs = settings.slowThresholdMs || DEFAULT_MONITOR_SETTINGS.slowThresholdMs;
  if (typeof UrlFetchApp === "undefined" || !UrlFetchApp) {
    for (var z = 0; z < activeTargets.length; z++) {
      results[activeTargets[z].envKey] = classifyProbeException_(new Error("UrlFetchApp indisponível neste runtime."));
    }
    return { modeUsed: "unavailable", results: results };
  }

  var useFetchAll = Boolean(settings.useFetchAll) && typeof UrlFetchApp.fetchAll === "function";
  if (!useFetchAll && typeof UrlFetchApp.fetch !== "function" && typeof UrlFetchApp.fetchAll === "function") {
    useFetchAll = true;
  }

  if (useFetchAll && activeTargets.length > 0) {
    var reqs = activeTargets.map(function (t) {
      return {
        url: t.url,
        method: "get",
        muteHttpExceptions: true,
        followRedirects: false,
        headers: {
          "User-Agent": "SISFAR-Portal-Monitor/2.1",
          "Cache-Control": "no-cache"
        }
      };
    });
    var batchStart = Date.now();
    try {
      var resps = UrlFetchApp.fetchAll(reqs);
      var batchDuration = Math.max(1, Date.now() - batchStart);
      for (var i = 0; i < activeTargets.length; i++) {
        var t = activeTargets[i];
        var resp = resps[i];
        var httpCode = resp && typeof resp.getResponseCode === "function" ? resp.getResponseCode() : 0;
        var headers = resp && typeof resp.getHeaders === "function" ? resp.getHeaders() : {};
        var locHeader = extractHeaderCaseInsensitive_(headers, "Location");
        var snippet = "";
        if (httpCode >= 200 && httpCode < 300 && resp && typeof resp.getContentText === "function") {
          snippet = String(resp.getContentText() || "").slice(0, 4096);
        }
        var cls = classifyHttpResponse_(httpCode, locHeader, snippet, batchDuration, slowMs);
        cls.httpStatus = httpCode;
        cls.durationMs = batchDuration;
        results[t.envKey] = cls;
      }
      return { modeUsed: "fetchAll", results: results };
    } catch (batchErr) {
      // Fallback isolado: se fetchAll lançar exceção por falha de rede em 1 endpoint, sonda individualmente
    }
  }

  for (var j = 0; j < activeTargets.length; j++) {
    var target = activeTargets[j];
    results[target.envKey] = probeSingleEndpoint_(target.url, slowMs);
  }
  return { modeUsed: "isolated_fetch", results: results };
}

function appendMonitorHistoryLocked_(props, newSamples, settings, nowDate) {
  if (!newSamples || newSamples.length === 0) return;
  var meta = getMonitorHistoryMeta_();
  var maxSegs = (settings && settings.maxHistorySegments) || DEFAULT_MONITOR_SETTINGS.maxHistorySegments;
  var histDays = (settings && settings.historyRetentionDays) || DEFAULT_MONITOR_SETTINGS.historyRetentionDays;
  var dailyDays = (settings && settings.dailyRetentionDays) || DEFAULT_MONITOR_SETTINGS.dailyRetentionDays;
  var nowMs = (nowDate || new Date()).getTime();
  var sampleCutoffMs = nowMs - (histDays * 86400000);
  var dayKey = getDayIsoSaoPaulo_(nowDate);

  if (!meta.daily[dayKey]) meta.daily[dayKey] = {};
  for (var i = 0; i < newSamples.length; i++) {
    var sm = newSamples[i];
    if (!meta.daily[dayKey][sm.e]) {
      meta.daily[dayKey][sm.e] = { ok: 0, slow: 0, fail: 0, auth: 0, maint: 0, sumMs: 0, count: 0 };
    }
    var bucket = meta.daily[dayKey][sm.e];
    bucket.count += 1;
    bucket.sumMs += Math.max(0, Number(sm.d || 0));
    if (sm.m === 1) {
      bucket.maint += 1;
    } else if (sm.s === "ACESSIVEL") {
      bucket.ok += 1;
    } else if (sm.s === "RESPOSTA_LENTA") {
      bucket.slow += 1;
    } else if (sm.s === "AUTENTICACAO_NECESSARIA") {
      bucket.auth += 1;
    } else {
      bucket.fail += 1;
    }
  }

  // Prune old daily keys
  var dayCutoffDate = new Date(nowMs - (dailyDays * 86400000));
  var dayCutoffStr = getDayIsoSaoPaulo_(dayCutoffDate);
  var dayKeys = Object.keys(meta.daily).sort();
  for (var d = 0; d < dayKeys.length; d++) {
    if (dayKeys[d] < dayCutoffStr) {
      delete meta.daily[dayKeys[d]];
    }
  }

  // Append compact samples into segmented properties
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

  currentArr = currentArr.filter(function (item) {
    return (Date.parse(item.t || 0) || 0) >= sampleCutoffMs;
  });

  for (var sIdx = 0; sIdx < newSamples.length; sIdx++) {
    var sample = newSamples[sIdx];
    var candidate = currentArr.concat([sample]);
    if (!currentSegKey || getUtf8ByteLength_(JSON.stringify(candidate)) > MAX_PROPERTY_BYTES) {
      if (currentSegKey) {
        props.setProperty(currentSegKey, JSON.stringify(currentArr));
      }
      var nextIndex = 0;
      if (currentSegKey) {
        var suffix = Number(currentSegKey.replace(PROP_KEYS.MONITOR_HISTORY_SEG_PREFIX, ""));
        nextIndex = isNaN(suffix) ? meta.segments.length : (suffix + 1);
      }
      currentSegKey = PROP_KEYS.MONITOR_HISTORY_SEG_PREFIX + nextIndex;
      currentArr = [sample];
      meta.segments.push(currentSegKey);
    } else {
      currentArr = candidate;
    }
  }
  if (currentSegKey) {
    props.setProperty(currentSegKey, JSON.stringify(currentArr));
  }

  while (meta.segments.length > maxSegs) {
    var oldestSeg = meta.segments.shift();
    if (oldestSeg && typeof props.deleteProperty === "function") {
      props.deleteProperty(oldestSeg);
    } else if (oldestSeg) {
      props.setProperty(oldestSeg, "[]");
    }
  }

  meta.totalEverRecorded = Number(meta.totalEverRecorded || 0) + newSamples.length;
  meta.updatedAt = (nowDate || new Date()).toISOString();

  // Enforce byte limit on MONITOR_HISTORY itself by pruning oldest daily keys if needed
  var remainingDays = Object.keys(meta.daily).sort();
  while (remainingDays.length > 1 && getUtf8ByteLength_(JSON.stringify(meta)) > MAX_PROPERTY_BYTES) {
    var oldestDay = remainingDays.shift();
    delete meta.daily[oldestDay];
  }

  props.setProperty(PROP_KEYS.MONITOR_HISTORY, JSON.stringify(meta));
}

function runMonitoringCycleInternal_(triggerSource, bypassEnabledFlag) {
  var cycleStartMs = Date.now();
  var config = getConfig();
  var settings = getMonitorSettings_();
  if (!settings.enabled && !bypassEnabledFlag) {
    return {
      success: true,
      skipped: true,
      reason: "Monitoramento global pausado em MONITOR_SETTINGS."
    };
  }

  var maintenances = getMonitorMaintenancesData_().items;
  var nowDate = new Date();
  var nowMs = nowDate.getTime();
  var nowIso = nowDate.toISOString();

  var activeTargets = [];
  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    var envKey = CANONICAL_IDS[i];
    var cfg = config[envKey];
    var monEnv = settings.environments && settings.environments[envKey];
    var isCfgActive = Boolean(cfg && cfg.ativo !== false);
    var isMonEnabled = !monEnv || monEnv.enabled !== false;
    if (isCfgActive && isMonEnabled && cfg.url) {
      activeTargets.push({ envKey: envKey, url: cfg.url });
    }
  }

  // Probe outside ScriptLock to avoid holding lock during network I/O
  var probeBatch = probeBatchEndpoints_(activeTargets, settings);

  return withScriptLock_(function () {
    var props = getProps_();
    var state = getMonitorState_();
    var incData = getMonitorIncidentsData_();
    var items = incData.items;
    var samplesToAppend = [];
    var summaryCounts = { accessible: 0, slow: 0, auth: 0, attention: 0, unavailable: 0, disabled: 0, maintenance: 0 };

    for (var j = 0; j < CANONICAL_IDS.length; j++) {
      var k = CANONICAL_IDS[j];
      var meta = ENV_KEY_META[k];
      var cfgItem = config[k];
      var monItem = settings.environments && settings.environments[k];
      var isEnabled = Boolean(cfgItem && cfgItem.ativo !== false) && (!monItem || monItem.enabled !== false);

      if (!isEnabled) {
        summaryCounts.disabled++;
        continue;
      }

      var probe = probeBatch.results[k];
      if (!probe) continue;

      var prev = state.environments[k] || {};
      var prevClass = prev.rawClassification || "DESCONHECIDO";
      var activeMaint = getActiveMaintenanceForEnv_(maintenances, k, nowMs);
      var inMaint = Boolean(activeMaint);
      if (inMaint) summaryCounts.maintenance++;

      var consecutiveFailures = Number(prev.consecutiveFailures || 0);
      var consecutiveSuccesses = Number(prev.consecutiveSuccesses || 0);
      var firstFailureAt = prev.firstFailureAt || null;
      var activeIncidentId = prev.activeIncidentId || null;
      var totalChecks = Number(prev.totalChecks || 0) + 1;
      var totalFailures = Number(prev.totalFailures || 0);
      var lastSuccessAt = prev.lastSuccessAt || null;
      var stateClassification = probe.rawClassification;
      var recoveringCount = 0;

      if (probe.isFailure) {
        totalFailures += 1;
        consecutiveFailures += 1;
        consecutiveSuccesses = 0;
        if (!firstFailureAt) firstFailureAt = nowIso;

        if (inMaint) {
          stateClassification = probe.rawClassification;
        } else if (consecutiveFailures >= settings.failureThreshold) {
          stateClassification = "INDISPONIVEL";
          var existingInc = null;
          if (activeIncidentId) {
            for (var x = 0; x < items.length; x++) {
              if (items[x].id === activeIncidentId && (items[x].estado === "INVESTIGACAO" || items[x].estado === "CONFIRMADO")) {
                existingInc = items[x];
                break;
              }
            }
          }
          if (existingInc) {
            existingInc.ultimaOcorrencia = nowIso;
            existingInc.falhasConsecutivas = consecutiveFailures;
            existingInc.categoria = probe.category;
            existingInc.duracaoObservadaMs = Math.max(0, nowMs - (Date.parse(existingInc.inicio) || nowMs));
            existingInc.descricao = sanitizeMonitorText_(consecutiveFailures + " falhas consecutivas (" + probe.summary + ")", 220);
            existingInc.atualizadoEm = nowIso;
          } else {
            var newId = "inc-" + nowMs + "-" + k.slice(0, 4).toLowerCase() + "-" + Math.floor(Math.random() * 1000);
            var startIso = firstFailureAt || nowIso;
            var newInc = {
              id: newId,
              envKey: k,
              unidade: meta.unidade,
              ambiente: meta.ambiente,
              categoria: probe.category,
              inicio: startIso,
              ultimaOcorrencia: nowIso,
              encerramento: null,
              duracaoObservadaMs: Math.max(0, nowMs - (Date.parse(startIso) || nowMs)),
              estado: "INVESTIGACAO",
              descricao: sanitizeMonitorText_(consecutiveFailures + " falhas consecutivas (" + probe.summary + ")", 220),
              observacao: "",
              falhasConsecutivas: consecutiveFailures,
              criadoEm: nowIso,
              atualizadoEm: nowIso,
              atualizadoPor: "monitor-engine"
            };
            items.unshift(newInc);
            incData.totalEverRecorded = Number(incData.totalEverRecorded || 0) + 1;
            activeIncidentId = newId;
          }
          summaryCounts.unavailable++;
        } else {
          stateClassification = "FALHA_VERIFICACAO";
          summaryCounts.attention++;
        }
      } else {
        consecutiveFailures = 0;
        firstFailureAt = null;
        consecutiveSuccesses += 1;
        if (probe.isReachable) lastSuccessAt = nowIso;

        var openInc = null;
        if (activeIncidentId) {
          for (var y = 0; y < items.length; y++) {
            if (items[y].id === activeIncidentId && (items[y].estado === "INVESTIGACAO" || items[y].estado === "CONFIRMADO")) {
              openInc = items[y];
              break;
            }
          }
        }

        if (openInc) {
          if (consecutiveSuccesses >= settings.recoverySuccessThreshold) {
            openInc.estado = "RESOLVIDO";
            openInc.encerramento = nowIso;
            openInc.duracaoObservadaMs = Math.max(0, nowMs - (Date.parse(openInc.inicio) || nowMs));
            openInc.atualizadoEm = nowIso;
            openInc.atualizadoPor = "monitor-recovery";
            openInc.descricao = sanitizeMonitorText_(openInc.descricao + " · Recuperado (" + consecutiveSuccesses + " checks OK)", 240);
            activeIncidentId = null;
            stateClassification = probe.rawClassification;
          } else {
            recoveringCount = consecutiveSuccesses;
            stateClassification = "INDISPONIVEL";
          }
        } else {
          activeIncidentId = null;
          stateClassification = probe.rawClassification;
        }

        if (stateClassification === "ACESSIVEL") summaryCounts.accessible++;
        else if (stateClassification === "RESPOSTA_LENTA") summaryCounts.slow++;
        else if (stateClassification === "AUTENTICACAO_NECESSARIA") summaryCounts.auth++;
        else if (stateClassification === "INDISPONIVEL") summaryCounts.unavailable++;
      }

      state.environments[k] = {
        envKey: k,
        unidade: meta.unidade,
        ambiente: meta.ambiente,
        lastCheckedAt: nowIso,
        durationMs: probe.durationMs,
        httpStatus: probe.httpStatus,
        category: probe.category,
        rawClassification: stateClassification,
        previousClassification: prevClass,
        lastErrorSanitized: probe.isFailure ? sanitizeMonitorText_(probe.summary, 140) : "",
        lastSummarySanitized: sanitizeMonitorText_(probe.summary, 140),
        lastSuccessAt: lastSuccessAt,
        consecutiveFailures: consecutiveFailures,
        consecutiveSuccesses: consecutiveSuccesses,
        recoveringCount: recoveringCount,
        firstFailureAt: firstFailureAt,
        activeIncidentId: activeIncidentId,
        totalChecks: totalChecks,
        totalFailures: totalFailures,
        inMaintenanceAtProbe: inMaint
      };

      samplesToAppend.push({
        t: nowIso,
        e: k,
        s: stateClassification,
        r: probe.rawClassification,
        d: probe.durationMs,
        c: probe.httpStatus,
        k: probe.category,
        m: inMaint ? 1 : 0
      });
    }

    var runDurationMs = Math.max(1, Date.now() - cycleStartMs);
    state.updatedAt = nowIso;
    state.lastRunAt = nowIso;
    state.lastRunDurationMs = runDurationMs;
    state.lastRunMode = probeBatch.modeUsed + " (" + (triggerSource || "scheduled") + ")";
    state.lastRunSummary = summaryCounts;

    props.setProperty(PROP_KEYS.MONITOR_STATE, JSON.stringify(state));
    persistMonitorIncidentsLocked_(props, incData, settings);
    appendMonitorHistoryLocked_(props, samplesToAppend, settings, nowDate);

    return {
      success: true,
      skipped: false,
      lastRunAt: nowIso,
      durationMs: runDurationMs,
      mode: probeBatch.modeUsed,
      checkedCount: samplesToAppend.length,
      summary: summaryCounts
    };
  });
}

/**
 * Handler público exigido pelo gatilho instalável de tempo (Clock Trigger) do Apps Script.
 */
function runScheduledMonitoringCheck() {
  return runMonitoringCycleInternal_("clock-trigger", false);
}

/**
 * Helper administrativo para execução manual no Editor do Apps Script para configurar
 * o gatilho periódico idempotente sem duplicatas.
 */
function configurarTriggerMonitoramento_() {
  return syncMonitoringTriggerInternal_(true);
}

function getTriggerDiagnostics_() {
  var settings = getMonitorSettings_();
  var info = {
    available: false,
    installedCount: 0,
    duplicateDetected: false,
    triggerIds: [],
    handler: MONITOR_TRIGGER_HANDLER,
    configuredIntervalMinutes: settings.intervalMinutes,
    syncedIntervalMinutes: settings.triggerSyncedInterval || null,
    lastSyncedAt: settings.triggerLastSyncedAt || null,
    errorMessage: ""
  };
  try {
    if (typeof ScriptApp === "undefined" || !ScriptApp || typeof ScriptApp.getProjectTriggers !== "function") {
      info.errorMessage = "ScriptApp.getProjectTriggers indisponível neste ambiente.";
      return info;
    }
    info.available = true;
    var triggers = ScriptApp.getProjectTriggers() || [];
    for (var i = 0; i < triggers.length; i++) {
      var t = triggers[i];
      if (t && typeof t.getHandlerFunction === "function" && t.getHandlerFunction() === MONITOR_TRIGGER_HANDLER) {
        info.installedCount++;
        if (typeof t.getUniqueId === "function") {
          info.triggerIds.push(t.getUniqueId());
        }
      }
    }
    info.duplicateDetected = info.installedCount > 1;
  } catch (err) {
    info.errorMessage = sanitizeMonitorText_(err && err.message ? err.message : String(err), 160);
  }
  return info;
}

function syncMonitoringTriggerInternal_(forceRecreate) {
  var settings = getMonitorSettings_();
  if (typeof ScriptApp === "undefined" || !ScriptApp || typeof ScriptApp.getProjectTriggers !== "function") {
    return {
      success: false,
      synced: false,
      error: "ScriptApp triggers API indisponível neste contexto."
    };
  }
  return withScriptLock_(function () {
    try {
      var triggers = ScriptApp.getProjectTriggers() || [];
      var existing = [];
      for (var i = 0; i < triggers.length; i++) {
        if (triggers[i] && triggers[i].getHandlerFunction && triggers[i].getHandlerFunction() === MONITOR_TRIGGER_HANDLER) {
          existing.push(triggers[i]);
        }
      }

      if (!settings.enabled) {
        for (var d = 0; d < existing.length; d++) {
          ScriptApp.deleteTrigger(existing[d]);
        }
        settings.triggerSyncedInterval = null;
        settings.triggerLastSyncedAt = new Date().toISOString();
        getProps_().setProperty(PROP_KEYS.MONITOR_SETTINGS, JSON.stringify(settings));
        return { success: true, synced: true, action: "removed_all", installedCount: 0 };
      }

      var matchesInterval = existing.length === 1 && Number(settings.triggerSyncedInterval) === Number(settings.intervalMinutes);
      if (matchesInterval && !forceRecreate) {
        return { success: true, synced: true, action: "kept_existing", installedCount: 1 };
      }

      for (var r = 0; r < existing.length; r++) {
        ScriptApp.deleteTrigger(existing[r]);
      }

      var builder = ScriptApp.newTrigger(MONITOR_TRIGGER_HANDLER).timeBased();
      if (settings.intervalMinutes === 60) {
        builder.everyHours(1).create();
      } else {
        builder.everyMinutes(settings.intervalMinutes).create();
      }

      settings.triggerSyncedInterval = settings.intervalMinutes;
      settings.triggerLastSyncedAt = new Date().toISOString();
      getProps_().setProperty(PROP_KEYS.MONITOR_SETTINGS, JSON.stringify(settings));
      return {
        success: true,
        synced: true,
        action: existing.length > 0 ? "recreated" : "created",
        installedCount: 1,
        intervalMinutes: settings.intervalMinutes
      };
    } catch (err) {
      return {
        success: false,
        synced: false,
        error: sanitizeMonitorText_(err && err.message ? err.message : String(err), 180)
      };
    }
  });
}

function getMonitoringStorageStats_() {
  var props = getProps_();
  var meta = getMonitorHistoryMeta_();
  var keys = [
    PROP_KEYS.MONITOR_SETTINGS,
    PROP_KEYS.MONITOR_STATE,
    PROP_KEYS.MONITOR_HISTORY,
    PROP_KEYS.MONITOR_INCIDENTS,
    PROP_KEYS.MONITOR_MAINTENANCES
  ].concat(meta.segments || []);

  var breakdown = [];
  var totalBytes = 0;
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var raw = props.getProperty(k) || "";
    var bytes = getUtf8ByteLength_(raw);
    totalBytes += bytes;
    breakdown.push({ key: k, bytes: bytes });
  }
  return {
    keysCount: keys.length,
    segmentsCount: (meta.segments || []).length,
    totalBytes: totalBytes,
    maxPerPropertyBytes: MAX_PROPERTY_BYTES,
    totalEverSamples: meta.totalEverRecorded || 0,
    breakdown: breakdown
  };
}

function resolveEffectiveEnvMonitoring_(envKey, config, settings, monState, maintenances, nowMs) {
  var cfg = config[envKey] || {};
  var meta = ENV_KEY_META[envKey] || {};
  var monEnv = settings.environments && settings.environments[envKey];
  var isCfgActive = cfg.ativo !== false;
  var isMonEnabled = !monEnv || monEnv.enabled !== false;
  var rawState = monState && monState.environments ? monState.environments[envKey] : null;
  var activeMaint = getActiveMaintenanceForEnv_(maintenances, envKey, nowMs);

  var effectiveStatus = "DESCONHECIDO";
  var statusReason = "Aguardando primeira coleta periódica";
  var isStale = false;

  if (!isCfgActive) {
    effectiveStatus = "DESATIVADO";
    statusReason = "Ambiente desativado em CONFIG_LINKS";
  } else if (!isMonEnabled) {
    effectiveStatus = "DESATIVADO";
    statusReason = "Monitoramento desativado administrativamente";
  } else if (activeMaint) {
    effectiveStatus = "MANUTENCAO";
    statusReason = "Manutenção: " + activeMaint.titulo;
  } else if (!rawState || !rawState.lastCheckedAt) {
    effectiveStatus = "DESCONHECIDO";
    statusReason = "Sem amostra coletada até o momento";
  } else {
    var checkedMs = Date.parse(rawState.lastCheckedAt);
    var staleMs = (settings.staleMinutes || DEFAULT_MONITOR_SETTINGS.staleMinutes) * 60000;
    if (isNaN(checkedMs) || (nowMs - checkedMs) > staleMs) {
      effectiveStatus = "DADOS_DESATUALIZADOS";
      isStale = true;
      statusReason = "Última amostra expirou (>" + settings.staleMinutes + " min)";
    } else {
      effectiveStatus = rawState.rawClassification || "DESCONHECIDO";
      statusReason = rawState.lastSummarySanitized || "";
    }
  }

  return {
    envKey: envKey,
    unidade: meta.unidade || "",
    ambiente: meta.ambiente || "",
    tipo: meta.tipo || "",
    configAtivo: isCfgActive,
    monitorEnabled: isMonEnabled,
    effectiveStatus: effectiveStatus,
    statusReason: statusReason,
    isStale: isStale,
    inMaintenance: Boolean(activeMaint),
    activeMaintenanceId: activeMaint ? activeMaint.id : null,
    activeMaintenanceTitle: activeMaint ? activeMaint.titulo : null,
    lastCheckedAt: rawState ? rawState.lastCheckedAt : null,
    durationMs: rawState ? rawState.durationMs : null,
    httpStatus: rawState ? rawState.httpStatus : null,
    category: rawState ? rawState.category : null,
    rawClassification: rawState ? rawState.rawClassification : null,
    previousClassification: rawState ? rawState.previousClassification : null,
    lastErrorSanitized: rawState ? (rawState.lastErrorSanitized || "") : "",
    lastSuccessAt: rawState ? rawState.lastSuccessAt : null,
    consecutiveFailures: rawState ? Number(rawState.consecutiveFailures || 0) : 0,
    consecutiveSuccesses: rawState ? Number(rawState.consecutiveSuccesses || 0) : 0,
    recoveringCount: rawState ? Number(rawState.recoveringCount || 0) : 0,
    activeIncidentId: rawState ? rawState.activeIncidentId : null,
    totalChecks: rawState ? Number(rawState.totalChecks || 0) : 0,
    totalFailures: rawState ? Number(rawState.totalFailures || 0) : 0
  };
}

function buildMonitoringPayload_(includeAdminDetails) {
  var config = getConfig();
  var settings = getMonitorSettings_();
  var monState = getMonitorState_();
  var histMeta = getMonitorHistoryMeta_();
  var samples = getMonitorHistorySamples_();
  var incData = getMonitorIncidentsData_();
  var maintData = getMonitorMaintenancesData_();
  var nowMs = Date.now();

  var environments = {};
  var summary = {
    total: CANONICAL_IDS.length,
    monitored: 0,
    accessible: 0,
    slow: 0,
    attention: 0,
    unavailable: 0,
    authRequired: 0,
    maintenance: 0,
    disabled: 0,
    unknown: 0,
    stale: 0,
    nonVerifiable: 0,
    activeIncidents: 0,
    lastRunAt: monState.lastRunAt,
    lastRunDurationMs: monState.lastRunDurationMs || 0
  };

  for (var i = 0; i < CANONICAL_IDS.length; i++) {
    var k = CANONICAL_IDS[i];
    var envEval = resolveEffectiveEnvMonitoring_(k, config, settings, monState, maintData.items, nowMs);
    environments[k] = envEval;

    if (envEval.configAtivo && envEval.monitorEnabled) summary.monitored++;
    var st = envEval.effectiveStatus;
    if (st === "ACESSIVEL") summary.accessible++;
    else if (st === "RESPOSTA_LENTA") { summary.slow++; summary.attention++; }
    else if (st === "FALHA_VERIFICACAO") summary.attention++;
    else if (st === "INDISPONIVEL") { summary.unavailable++; summary.attention++; }
    else if (st === "DADOS_DESATUALIZADOS") { summary.stale++; summary.attention++; }
    else if (st === "MANUTENCAO") { summary.maintenance++; summary.attention++; }
    else if (st === "AUTENTICACAO_NECESSARIA") { summary.authRequired++; summary.nonVerifiable++; }
    else if (st === "DESATIVADO") { summary.disabled++; summary.nonVerifiable++; }
    else { summary.unknown++; summary.nonVerifiable++; }
  }

  var activeIncidents = incData.items.filter(function (inc) {
    return inc.estado === "INVESTIGACAO" || inc.estado === "CONFIRMADO";
  });
  summary.activeIncidents = activeIncidents.length;

  var activeMaintenances = maintData.items.filter(function (m) {
    return (m.estado === "PROGRAMADA" || m.estado === "EM_ANDAMENTO") && (Date.parse(m.fim || 0) || 0) >= nowMs;
  });

  var checksPerDayNominal = summary.monitored * Math.floor(1440 / (settings.intervalMinutes || 15));
  var nextRunAt = null;
  if (settings.enabled && monState.lastRunAt) {
    var lastTs = Date.parse(monState.lastRunAt);
    if (!isNaN(lastTs)) {
      nextRunAt = new Date(lastTs + (settings.intervalMinutes * 60000)).toISOString();
    }
  }

  var sanitizedSettings = {
    enabled: settings.enabled,
    intervalMinutes: settings.intervalMinutes,
    slowThresholdMs: settings.slowThresholdMs,
    failureThreshold: settings.failureThreshold,
    recoverySuccessThreshold: settings.recoverySuccessThreshold,
    staleMinutes: settings.staleMinutes,
    historyRetentionDays: settings.historyRetentionDays,
    dailyRetentionDays: settings.dailyRetentionDays,
    incidentRetentionDays: settings.incidentRetentionDays,
    useFetchAll: settings.useFetchAll,
    environments: settings.environments
  };

  var publicMaintenances = activeMaintenances.map(function (m) {
    return {
      id: m.id,
      titulo: m.titulo,
      descricao: m.descricao,
      aviso: m.aviso,
      alvo: m.alvo,
      inicio: m.inicio,
      fim: m.fim,
      estado: m.estado
    };
  });

  var publicIncidents = incData.items.slice(0, 25).map(function (inc) {
    return {
      id: inc.id,
      envKey: inc.envKey,
      unidade: inc.unidade,
      ambiente: inc.ambiente,
      categoria: inc.categoria,
      inicio: inc.inicio,
      ultimaOcorrencia: inc.ultimaOcorrencia,
      encerramento: inc.encerramento,
      duracaoObservadaMs: inc.duracaoObservadaMs,
      estado: inc.estado,
      descricao: inc.descricao,
      observacao: inc.observacao,
      falhasConsecutivas: inc.falhasConsecutivas
    };
  });

  var payload = {
    schemaVersion: "2.1",
    minSamplesForAvailability: MONITOR_MIN_AVAIL_SAMPLES,
    settings: sanitizedSettings,
    summary: summary,
    environments: environments,
    samples: samples.slice(0, 600),
    daily: histMeta.daily || {},
    incidents: includeAdminDetails ? incData.items.slice(0, 25) : publicIncidents,
    maintenances: includeAdminDetails ? maintData.items : publicMaintenances,
    quotaEstimate: {
      monitoredActiveCount: summary.monitored,
      intervalMinutes: settings.intervalMinutes,
      checksPerDayNominal: checksPerDayNominal,
      gasConsumerDailyUrlFetchLimit: 20000,
      followRedirects: false,
      lastRunMode: monState.lastRunMode || null,
      nextEstimatedRunAt: nextRunAt
    }
  };

  if (includeAdminDetails) {
    payload.triggerDiagnostics = getTriggerDiagnostics_();
    payload.storageStats = getMonitoringStorageStats_();
  }
  return payload;
}

function updateMonitoringIncidentInternal_(payload, author) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Dados do incidente inválidos.");
  }
  var id = String(payload.id || "").trim();
  if (!id) throw new Error("ID do incidente é obrigatório.");
  var nextEstado = payload.estado ? String(payload.estado).trim().toUpperCase() : "";
  if (nextEstado && VALID_INCIDENT_STATES.indexOf(nextEstado) === -1) {
    throw new Error("Estado de incidente inválido: " + nextEstado);
  }
  var obs = payload.observacao !== undefined ? sanitizeMonitorText_(String(payload.observacao || ""), 280) : undefined;

  return withScriptLock_(function () {
    var props = getProps_();
    var settings = getMonitorSettings_();
    var incData = getMonitorIncidentsData_();
    var found = null;
    for (var i = 0; i < incData.items.length; i++) {
      if (incData.items[i].id === id) {
        found = incData.items[i];
        break;
      }
    }
    if (!found) throw new Error("Incidente não encontrado: " + id);

    var nowIso = new Date().toISOString();
    var nowMs = Date.now();
    if (nextEstado) {
      found.estado = nextEstado;
      if ((nextEstado === "RESOLVIDO" || nextEstado === "ENCERRADO_ADMIN") && !found.encerramento) {
        found.encerramento = nowIso;
        found.duracaoObservadaMs = Math.max(0, nowMs - (Date.parse(found.inicio) || nowMs));
      } else if (nextEstado === "INVESTIGACAO" || nextEstado === "CONFIRMADO") {
        found.encerramento = null;
      }
    }
    if (obs !== undefined) {
      found.observacao = obs;
    }
    found.atualizadoEm = nowIso;
    found.atualizadoPor = author || "admin";

    // If admin closes/resolves incident, clear activeIncidentId link in MONITOR_STATE while preserving lastProbe
    if (found.estado === "RESOLVIDO" || found.estado === "ENCERRADO_ADMIN") {
      var st = getMonitorState_();
      if (st.environments[found.envKey] && st.environments[found.envKey].activeIncidentId === found.id) {
        st.environments[found.envKey].activeIncidentId = null;
        st.environments[found.envKey].consecutiveFailures = 0;
        st.environments[found.envKey].firstFailureAt = null;
        props.setProperty(PROP_KEYS.MONITOR_STATE, JSON.stringify(st));
      }
    }

    persistMonitorIncidentsLocked_(props, incData, settings);
    return {
      success: true,
      item: found,
      message: "Incidente atualizado para " + found.estado + "."
    };
  });
}

function saveMonitoringMaintenanceInternal_(payload, author) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Dados de manutenção inválidos.");
  }
  var titulo = sanitizeMonitorText_(String(payload.titulo || ""), 120);
  if (!titulo) throw new Error("Título da manutenção é obrigatório.");
  var descricao = sanitizeMonitorText_(String(payload.descricao || ""), 400);
  var aviso = sanitizeMonitorText_(String(payload.aviso || ""), 220);

  var alvo = String(payload.alvo || "TODAS").trim();
  var validAlvos = ["TODAS", "CPPA", "PEPOA", "MADRE"].concat(CANONICAL_IDS);
  if (validAlvos.indexOf(alvo) === -1) {
    throw new Error("Alvo de manutenção inválido: " + alvo);
  }

  var inicioIso = parseSaoPauloIso_(String(payload.inicio || ""));
  var fimIso = parseSaoPauloIso_(String(payload.fim || ""));
  if (!inicioIso || !fimIso) {
    throw new Error("Datas de início e fim são obrigatórias.");
  }
  if (Date.parse(fimIso) <= Date.parse(inicioIso)) {
    throw new Error("A data/hora de término deve ser posterior ao início.");
  }

  var estado = String(payload.estado || "EM_ANDAMENTO").trim().toUpperCase();
  if (VALID_MAINTENANCE_STATES.indexOf(estado) === -1) {
    throw new Error("Estado de manutenção inválido: " + estado);
  }

  return withScriptLock_(function () {
    var props = getProps_();
    var data = getMonitorMaintenancesData_();
    var nowIso = new Date().toISOString();
    var id = payload.id ? String(payload.id).trim() : ("mnt-" + Date.now() + "-" + Math.floor(Math.random() * 10000));
    var existingIdx = -1;
    for (var i = 0; i < data.items.length; i++) {
      if (data.items[i].id === id) {
        existingIdx = i;
        break;
      }
    }

    var item = {
      id: id,
      titulo: titulo,
      descricao: descricao,
      aviso: aviso,
      alvo: alvo,
      inicio: inicioIso,
      fim: fimIso,
      estado: estado,
      criadoEm: existingIdx !== -1 ? data.items[existingIdx].criadoEm : nowIso,
      atualizadoEm: nowIso,
      autor: author || "admin"
    };

    if (existingIdx !== -1) data.items[existingIdx] = item;
    else data.items.unshift(item);

    persistMonitorMaintenancesLocked_(props, data);
    return {
      success: true,
      item: item,
      message: existingIdx !== -1 ? "Manutenção atualizada." : "Manutenção cadastrada."
    };
  });
}

function updateMonitoringMaintenanceStatusInternal_(id, nextEstado, author) {
  var targetId = String(id || "").trim();
  if (!targetId) throw new Error("ID da manutenção é obrigatório.");
  var st = String(nextEstado || "").trim().toUpperCase();
  if (VALID_MAINTENANCE_STATES.indexOf(st) === -1) {
    throw new Error("Estado inválido: " + st);
  }

  return withScriptLock_(function () {
    var props = getProps_();
    var data = getMonitorMaintenancesData_();
    var found = null;
    for (var i = 0; i < data.items.length; i++) {
      if (data.items[i].id === targetId) {
        found = data.items[i];
        break;
      }
    }
    if (!found) throw new Error("Manutenção não encontrada: " + targetId);

    var nowIso = new Date().toISOString();
    found.estado = st;
    if (st === "ENCERRADA" && Date.parse(found.fim) > Date.now()) {
      found.fim = nowIso;
    }
    found.atualizadoEm = nowIso;
    found.atualizadoPor = author || "admin";

    persistMonitorMaintenancesLocked_(props, data);
    return {
      success: true,
      item: found,
      message: "Manutenção alterada para " + st + ". Evidências reais preservadas."
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
  var monitoring = buildMonitoringPayload_(false);

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
    monitoring: monitoring,
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

  if (params.action === "status") {
    return ContentService.createTextOutput(JSON.stringify({
      success: true,
      schemaVersion: "2.1",
      monitoring: buildMonitoringPayload_(false),
      serverNow: new Date().toISOString()
    })).setMimeType(ContentService.MimeType.JSON);
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
      } else if (adminAction === "admin_monitoring_save_settings") {
        adminRes = apiSaveMonitoringSettings(body.payload, body.authToken);
      } else if (adminAction === "admin_monitoring_update_incident") {
        adminRes = apiUpdateMonitoringIncident(body.payload, body.authToken);
      } else if (adminAction === "admin_monitoring_save_maintenance") {
        adminRes = apiSaveMonitoringMaintenance(body.payload, body.authToken);
      } else if (adminAction === "admin_monitoring_maintenance_status") {
        adminRes = apiUpdateMonitoringMaintenanceStatus(body.id, body.estado, body.authToken);
      } else if (adminAction === "admin_monitoring_run_now") {
        adminRes = apiRunManualMonitoringCheck(body.authToken);
      } else if (adminAction === "admin_monitoring_sync_trigger") {
        adminRes = apiSyncMonitoringTrigger(body.authToken);
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
    monitoring: buildMonitoringPayload_(true),
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

function apiSaveMonitoringSettings(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  return saveMonitorSettingsInternal_(payload, auth.email, false);
}

function apiUpdateMonitoringIncident(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  return updateMonitoringIncidentInternal_(payload, auth.email);
}

function apiSaveMonitoringMaintenance(payload, authToken) {
  var auth = requireAdminAuth_(authToken);
  return saveMonitoringMaintenanceInternal_(payload, auth.email);
}

function apiUpdateMonitoringMaintenanceStatus(id, nextEstado, authToken) {
  var auth = requireAdminAuth_(authToken);
  return updateMonitoringMaintenanceStatusInternal_(id, nextEstado, auth.email);
}

function apiRunManualMonitoringCheck(authToken) {
  var auth = requireAdminAuth_(authToken);
  var res = runMonitoringCycleInternal_("manual-admin:" + auth.email, true);
  res.monitoring = buildMonitoringPayload_(true);
  return res;
}

function apiSyncMonitoringTrigger(authToken) {
  requireAdminAuth_(authToken);
  var res = syncMonitoringTriggerInternal_(true);
  res.triggerDiagnostics = getTriggerDiagnostics_();
  return res;
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
