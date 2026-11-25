# SISFAR-PORTAL 2.0

Central institucional integrada do **SISFAR — Sistema Integrado de Farmácia Prisional**, hospedada diretamente no **Google Apps Script (`HtmlService`)** sem dependência externa obrigatória nem consultas a bases clínicas.

---

## Estrutura do Repositório

```text
/
├── .clasp.json           # Script ID exclusivo do portal (rootDir: backend)
├── .claspignore          # Filtro de arquivos enviados ao Apps Script
├── backend/
│   ├── appsscript.json   # Manifesto do Web App Apps Script (V8, ANYONE_ANONYMOUS)
│   ├── Code.js           # Rotas GET/POST, autenticação, HMAC-SHA256 e persistência segmentada
│   ├── Portal.html       # Interface pública Clinical Clean 2.0 (claro/escuro, 3 cards, releases, comunicados)
│   └── Admin.html        # Central Administrativa (Ambientes, Releases, Comunicados, Configurações)
├── tests/
│   └── portal.test.js    # Suíte automatizada de testes (Node test runner)
├── links.js              # Fallback estático dos 6 ambientes canônicos
├── favicon.svg           # Ícone vetorial oficial do SISFAR
└── README.md
```

---

## Rotas e Endpoints

- `?view=portal` (ou raiz `/exec`): **Portal Público 2.0** (`Início` com 3 cards CPPA/PEPOA/MADRE e acessos OFICIAL/AUDIT, `Atualizações` filtráveis por unidade/ambiente/versão, `Comunicados` vigentes e tema claro/escuro persistido).
- `?view=admin` ou `?admin=1`: **Central Administrativa** em 4 abas (`Ambientes`, `Releases`, `Comunicados`, `Configurações`).
- `?action=get` (ou `?format=json`): Leitura JSON pública somente-leitura dos 6 ambientes em `CONFIG_LINKS`.
- `?action=bootstrap`: Leitura JSON pública de links, estado atual por ambiente, histórico segmentado e comunicados vigentes.
- `POST` (`action: "publish_event"`): Ingestão autenticada por **HMAC-SHA256** (`timestamp` + `eventId` + campos canônicos no corpo do POST), com idempotência por `eventId`, proteção contra replay e preservação de links/estados mais novos contra eventos atrasados.

---

## Persistência em `PropertiesService`

- `CONFIG_LINKS`: Mantém exclusivamente os 6 IDs canônicos (`cppaOficial`, `pepoaOficial`, `madreOficial`, `cppaAudit`, `pepoaAudit`, `madreAudit`), URLs, `ordem` e `ativo`. Eventos de release não sobrescrevem links configurados.
- `SISFAR_RELEASE_STATE_V2`: Estado efetivo mais recente por ambiente (diferenciando `git`, `candidato`, `publicado` e `homologado`).
- `SISFAR_RELEASE_HIST_META_V2` + `SISFAR_RELEASE_HIST_SEG_*`: Histórico limitado e segmentado (respeitando o teto de 9 KB por propriedade) + `SISFAR_RELEASE_DEDUPE_V2`.
- `SISFAR_ANNOUNCEMENTS_META_V2` + `SISFAR_ANNOUNCEMENTS_SEG_*`: Comunicados administráveis com validade e filtro por unidade.
- `SISFAR_PORTAL_SETTINGS_V2`: Configurações operacionais da central.

---

## Segurança e Execução Pública

- Funções internas de escrita (`saveConfigInternal_`, `recordReleaseEventInternal_`, etc.) possuem sufixo `_` e são privadas no Apps Script.
- A Central Administrativa autentica via Conta Google em allowlist (`ADMIN_EMAILS`). Caso a execução pública (`ANYONE_ANONYMOUS`) não propague `Session.getActiveUser().getEmail()`, configure uma chave administrativa de fallback executando uma vez no Editor do Apps Script:
  ```js
  configurarChaveAdminPortal_("SUA_CHAVE_FORTE_MIN_10_CHARS");
  ```
- Para habilitar ingestão pós-deploy via HMAC-SHA256, defina o segredo privado compartilhado no Editor do Apps Script:
  ```js
  configurarSegredoWebhookPortal_("SEU_SEGREDO_HMAC_MIN_16_CHARS");
  ```
  E no ambiente do publicador (`SISFARPRISIONAL`), defina `SISFAR_PORTAL_WEBHOOK_SECRET` (ou `~/.sisfar-portal-publisher.json` com permissão `0600`, fora do Git).

---

## Testes e Deploy Exclusivo do Portal

```bash
node --test tests/portal.test.js
npx --yes @google/clasp@3.4.1 show-file-status
npx --yes @google/clasp@3.4.1 push
npx --yes @google/clasp@3.4.1 deploy -i AKfycbzKRSk7evTLpYUmktyE94Cs54w-F9NtJzo00HmeBSwgxG-C-gPxSNVflz1dX7sbuVg4 --description "SISFAR-PORTAL 2.0"
```
