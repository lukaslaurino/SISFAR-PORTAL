/**
 * SISFAR — Backend de Configuração de Links do Portal (Google Apps Script)
 *
 * Script ID: 1z0wcdELgvr-cnBUIIrhWKZjHZk_Mj_lR1ZbVpJ7tD0FADOFgjjHDxEau
 * Web App URL: https://script.google.com/macros/s/AKfycbzf-5xtSSGcePrWfxCeuDZ3zilUzt3NkVt8LR1uNvtuLdwTzpFWeqEKVbmFMwRYDogRuQ/exec
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

function getConfig() {
  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty("CONFIG_LINKS");
  if (!raw) return DEFAULT_CONFIG;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return DEFAULT_CONFIG;
  }
}

function saveConfig(data) {
  const props = PropertiesService.getScriptProperties();
  props.setProperty("CONFIG_LINKS", JSON.stringify(data));
  props.setProperty("CONFIG_UPDATED_AT", new Date().toISOString());
  return { success: true, message: "Configuração salva com sucesso!", updatedAt: new Date().toISOString() };
}

function doGet(e) {
  const action = (e && e.parameter && e.parameter.action) || "get";
  let responseData = {};
  
  if (action === "get") {
    responseData = {
      success: true,
      data: getConfig(),
      updatedAt: PropertiesService.getScriptProperties().getProperty("CONFIG_UPDATED_AT") || new Date().toISOString()
    };
  } else if (action === "reset") {
    saveConfig(DEFAULT_CONFIG);
    responseData = { success: true, message: "Restaurado para os padrões!", data: DEFAULT_CONFIG };
  } else {
    responseData = { success: false, error: "Ação inválida" };
  }

  return ContentService.createTextOutput(JSON.stringify(responseData))
    .setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  let responseData = {};
  try {
    let payload = null;
    if (e && e.postData && e.postData.contents) {
      payload = JSON.parse(e.postData.contents);
    } else if (e && e.parameter && e.parameter.data) {
      payload = JSON.parse(e.parameter.data);
    }

    if (!payload || typeof payload !== "object") {
      throw new Error("Payload inválido");
    }

    responseData = saveConfig(payload);
  } catch (err) {
    responseData = { success: false, error: err.message };
  }

  return ContentService.createTextOutput(JSON.stringify(responseData))
    .setMimeType(ContentService.MimeType.JSON);
}
