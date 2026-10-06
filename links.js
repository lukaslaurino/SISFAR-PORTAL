/**
 * SISFAR — Sistema Integrado de Farmácia Prisional
 * Configuração Centralizada de Links dos Ambientes (OFICIAL e AUDIT Isolado)
 *
 * Esta configuração serve como valor padrão/fallback imediato e define o endpoint
 * do backend dinâmico (Google Apps Script) para edição via Central Administrativa (/admin).
 */
const SISFAR_CONFIG = {
  // Endpoint da API de Configuração Persistente (Google Apps Script)
  apiEndpoint: "https://script.google.com/macros/s/AKfycbzf-5xtSSGcePrWfxCeuDZ3zilUzt3NkVt8LR1uNvtuLdwTzpFWeqEKVbmFMwRYDogRuQ/exec",

  // Configuração Padrão dos 6 Ambientes
  ambientes: {
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
  }
};

// Compatibilidade direta com o objeto plano anterior SISFAR_LINKS
const SISFAR_LINKS = {
  cppaOficial: SISFAR_CONFIG.ambientes.cppaOficial.url,
  pepoaOficial: SISFAR_CONFIG.ambientes.pepoaOficial.url,
  madreOficial: SISFAR_CONFIG.ambientes.madreOficial.url,
  cppaAudit: SISFAR_CONFIG.ambientes.cppaAudit.url,
  pepoaAudit: SISFAR_CONFIG.ambientes.pepoaAudit.url,
  madreAudit: SISFAR_CONFIG.ambientes.madreAudit.url
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SISFAR_CONFIG, SISFAR_LINKS };
}
