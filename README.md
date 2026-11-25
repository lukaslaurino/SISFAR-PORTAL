# SISFAR-PORTAL

Portal oficial de acesso aos ambientes do **SISFAR — Sistema Integrado de Farmácia Prisional**.

O portal público e a Central Administrativa são hospedados diretamente no **Google Apps Script (`HtmlService`)**, com persistência dinâmica via `CONFIG_LINKS` (`PropertiesService`), sem dependência do GitHub Pages durante o acesso.

---

## Estrutura do Repositório

```text
/
├── .clasp.json           # Configuração CLASP própria do portal (rootDir: backend)
├── .claspignore          # Filtro de arquivos enviados ao Apps Script
├── backend/
│   ├── appsscript.json   # Manifesto do Web App Apps Script (V8, ANYONE_ANONYMOUS)
│   └── Code.js           # Portal (?view=portal), Admin (?view=admin / ?admin=1), API JSON (?action=get) e CONFIG_LINKS
├── tests/
│   └── portal.test.js    # Suíte automatizada de testes (Node test runner)
├── index.html            # Legado estático / referência visual
├── links.js              # Fallback estático dos 6 ambientes
├── favicon.svg           # Ícone oficial vetorial do SISFAR
├── admin/
│   └── index.html        # Gate legado de redirecionamento administrativo
├── admin.html            # Gate legado de redirecionamento administrativo
└── README.md
```

---

## Rotas do Web App (Google Apps Script)

- `?view=portal` (ou raiz `/exec` sem parâmetros): **Portal Público SISFAR** via `HtmlService`, carregando os 6 ambientes a partir de `CONFIG_LINKS` (com fallback para `DEFAULT_CONFIG`).
- `?view=admin` ou `?admin=1`: **Central Administrativa de Links** via `HtmlService`, protegida por autenticação via Conta Google (`Session.getActiveUser().getEmail()`) e allowlist.
- `?action=get` (ou `?format=json`): Leitura pública somente-leitura em JSON dos 6 ambientes.

---

## Configuração CLASP e Deploy (Exclusivo do Portal)

1. Preencha o `scriptId` do projeto Apps Script do portal em `.clasp.json`.
2. Valide os arquivos com:
   ```bash
   npx --yes @google/clasp@3.4.1 show-file-status
   ```
3. Envie o código e crie o deploy exclusivamente do projeto do portal:
   ```bash
   npx --yes @google/clasp@3.4.1 push
   npx --yes @google/clasp@3.4.1 deploy --description "Portal SISFAR HtmlService"
   ```

---

## Testes Locais

```bash
node --test tests/portal.test.js
```
