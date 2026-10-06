/**
 * SISFAR — Sistema Integrado de Farmácia Prisional
 * Configuração Centralizada de Links dos Ambientes (OFICIAL e AUDIT Isolado)
 *
 * Todas as alterações de links dos Web Apps devem ser feitas exclusivamente neste arquivo.
 */
const SISFAR_LINKS = {
  // Ambientes Oficiais de Produção
  cppaOficial: "https://script.google.com/macros/s/AKfycbwNoAHomZzaIT25QL7U7Tod9XA_uzX3qWnzhzixBylo2-Ri4WPVUIvXlQ-HA8_qIjww/exec",
  pepoaOficial: "https://script.google.com/macros/s/AKfycbyJC0gBSbzIBY_PCyPr4g4r_FcH2nF52qUE8q7Sv0pyu6pE70AnpQTY09Q77sSaZzhRlw/exec",
  madreOficial: "https://script.google.com/macros/s/AKfycbxtJ5mN2etzdWEsP1Q6krDJ4PNttERTEX3Nm8s1GP28CpVoxj6lEeEjWgZ_ssu6_ADb/exec",

  // Ambientes de Homologação / AUDIT (Projetos Apps Script e Sandboxes 100% Isolados)
  cppaAudit: "https://script.google.com/macros/s/AKfycbzrXoszhMpcjcigdqRRIJC6mZT-vSlqkICo9cDjeCa6Q80YhxmKSzNpTeOhC5ujrmwkvA/exec",
  pepoaAudit: "https://script.google.com/macros/s/AKfycbyx3tZUUB__KsFaZJSobePjt7ImZRNHF_bQK8U0pQDY-_LSdTppcrsqAFtLgpVSl3Mr/exec",
  madreAudit: "https://script.google.com/macros/s/AKfycbydhH8Vle_nakjHAlKU0_a2fBr6e0c5roker9IHxXAve48UqUhPG7VfWIvI0fNTyaWj/exec"
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SISFAR_LINKS;
}
