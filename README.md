# SISFAR-PORTAL 2.1

Central institucional integrada do **SISFAR — Sistema Integrado de Farmácia Prisional**, hospedada diretamente no **Google Apps Script (`HtmlService`)** com **Monitoramento Operacional Periódico Nativo**, sem dependência externa obrigatória nem consultas a bases clínicas.

---

## Estrutura do Repositório

```text
/
├── .clasp.json           # Script ID exclusivo do portal (rootDir: backend)
├── .claspignore          # Filtro de arquivos enviados ao Apps Script
├── backend/
│   ├── appsscript.json   # Manifesto do Web App Apps Script (V8, ANYONE_ANONYMOUS)
│   ├── Code.js           # Rotas GET/POST, autenticação, HMAC-SHA256, monitoramento e persistência
│   ├── Portal.html       # Interface pública Clinical Clean 2.1 (Início, Status, Atualizações, Comunicados)
│   └── Admin.html        # Central Administrativa (Ambientes, Monitoramento, Releases, Comunicados, Configurações)
├── tests/
│   └── portal.test.js    # Suíte automatizada de testes (Node test runner)
├── links.js              # Fallback estático dos 6 ambientes canônicos
├── favicon.svg           # Ícone vetorial oficial do SISFAR
└── README.md
```

---

## Rotas e Endpoints

- `?view=portal` (ou raiz `/exec`): **Portal Público 2.1** (`Início`, `Status` com timeline com lacunas explícitas e gráfico SVG leve, `Atualizações` e `Comunicados`).
- `?view=admin` ou `?admin=1`: **Central Administrativa** em 5 abas (`Ambientes`, `Monitoramento`, `Releases`, `Comunicados`, `Configurações`).
- `?action=get` (ou `?format=json`): Leitura JSON pública somente-leitura dos 6 ambientes em `CONFIG_LINKS`.
- `?action=bootstrap`: Leitura JSON pública de links, releases, comunicados vigentes e resumo/histórico de monitoramento.
- `?action=status`: Leitura JSON pública somente-leitura do módulo de monitoramento operacional.
- `POST` (`action: "publish_event"`): Ingestão autenticada por **HMAC-SHA256**.
- `POST` (`action: "admin_*"`): Operações administrativas autenticadas (Google allowlist ou `authToken` de sessão), incluindo `admin_monitoring_*`.

---

## Monitoramento Operacional 2.1 — Critérios, Cotas e Limitações

- **Escopo estritamente HTTP**: `UrlFetchApp` executa sondas periódicas apenas nos ambientes ativos em `CONFIG_LINKS` e habilitados no painel, com `followRedirects: false` e `muteHttpExceptions: true`. **HTTP 200 não comprova função clínica** (não realiza login clínico nem acessa pacientes, APAC, prescrições ou planilhas).
- **Classificações**:
  - `ACESSIVEL`: HTTP 2xx sem página de login ou erro abaixo do limiar de lentidão (`slowThresholdMs`, padrão 3000 ms).
  - `RESPOSTA_LENTA`: HTTP acessível com duração `>= slowThresholdMs`.
  - `FALHA_VERIFICACAO`: 1ª falha HTTP (404/5xx/página de erro) ou erro de rede/timeout antes de atingir o limiar de incidente.
  - `INDISPONIVEL`: após falhas consecutivas `>= failureThreshold` (padrão 2), abrindo incidente agrupado (`INVESTIGACAO` → `CONFIRMADO` → `RESOLVIDO`/`ENCERRADO_ADMIN`). Recuperação configurável via `recoverySuccessThreshold` (padrão 2 sucessos).
  - `AUTENTICACAO_NECESSARIA`: HTTP 401, redirecionamento (3xx) para `accounts.google.com` ou página de login Google HTTP 200. Contabilizado em **Não verificáveis** (nunca como sucesso nem como queda).
  - `NAO_VERIFICAVEL`: redirecionamento técnico, HTTP 403, ou sonda sem permissão/cota. Sem inferência de disponibilidade ou homologação.
  - `MANUTENCAO`: janela ativa cadastrada (exibição `America/Sao_Paulo`). Preserva evidências reais em `MONITOR_STATE` e retorna a elas automaticamente ao encerrar ou expirar.
  - `DESATIVADO`: desativado em `CONFIG_LINKS` ou individualmente no monitoramento.
  - `DESCONHECIDO`: sem amostra coletada.
  - `DADOS_DESATUALIZADOS`: última amostra anterior a `staleMinutes` (padrão 45 min).
- **Avaliação `UrlFetchApp.fetchAll` vs `fetch` isolado**:
  - O padrão é `fetch` isolado, que mede a duração de cada requisição. Com `useFetchAll`, a duração individual fica sem valor. Uma exceção no lote aciona o fallback para sondas isoladas.
- **Cotas e Limites Reais (Google Apps Script)**:
  - **UrlFetchApp**: cota diária nominal de conta Google padrão = **20.000 chamadas/dia** (Workspace até 100.000/dia). Com 6 ambientes a cada **15 minutos** e `followRedirects: false`, o consumo nominal é **576 verificações/dia** (~2,88% da cota padrão).
  - **Triggers e Timeout**: limite de execução por invocação de time-based trigger = **6 minutos**; `UrlFetchApp` possui timeout interno de ~60s por requisição (não configurável por parâmetro no GAS).
  - **Concorrência**: uma concessão de sete minutos registrada sob `ScriptLock` impede ciclos simultâneos. A rede roda fora do lock. A gravação confere a concessão e a configuração de origem antes de persistir.
  - **Armazenamento `PropertiesService`**: teto de **9 KB por propriedade** (limite seguro adotado `7800` bytes) e **500 KB totais** por projeto. Estruturas separadas: `MONITOR_SETTINGS`, `MONITOR_STATE`, `MONITOR_HISTORY` (+ `MONITOR_HISTORY_SEG_0..5` e agregação diária limitada), `MONITOR_INCIDENTS` e `MONITOR_MAINTENANCES`, totalizando teto máximo ~70 KB.
- **Disponibilidade Observada**: exibida somente com `>= 4` amostras verificáveis na janela, mostrando cobertura real e critérios. Lacunas, autenticação, verificações inconclusivas e manutenção ficam fora do cálculo. Agregados diários legados sem classificação verificável aparecem como amostras inconclusivas. A métrica mede respostas HTTP.

- **Gatilho** — `runScheduledMonitoringCheck_` aceita o identificador do gatilho registrado. A conta publicadora pode executar `configurarTriggerMonitoramento_` no editor para conceder as permissões do Apps Script e sincronizar o gatilho. A sincronização migra os gatilhos antigos visíveis à conta instaladora. A coleta manual pelo portal exige administrador autenticado.

---

## Persistência em `PropertiesService`

- `CONFIG_LINKS`, `SISFAR_RELEASE_STATE_V2`, `SISFAR_RELEASE_HIST_*`, `SISFAR_ANNOUNCEMENTS_*`, `SISFAR_PORTAL_SETTINGS_V2`: preservados integralmente.
- `MONITOR_SETTINGS`, `MONITOR_STATE`, `MONITOR_HISTORY` (+ `MONITOR_HISTORY_SEG_*`), `MONITOR_INCIDENTS`, `MONITOR_MAINTENANCES`: estruturas isoladas do monitoramento.

---

## Testes e Deploy Exclusivo do Portal

```bash
node --test tests/portal.test.js
npx --yes @google/clasp@3.4.1 show-file-status
npx --yes @google/clasp@3.4.1 push
npx --yes @google/clasp@3.4.1 deploy -i AKfycbzKRSk7evTLpYUmktyE94Cs54w-F9NtJzo00HmeBSwgxG-C-gPxSNVflz1dX7sbuVg4 --description "SISFAR-PORTAL 2.1"
```
