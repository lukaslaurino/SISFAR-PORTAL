# SISFAR-PORTAL 2.2

Central institucional integrada do **SISFAR — Sistema Integrado de Farmácia Prisional**, hospedada diretamente no **Google Apps Script (`HtmlService`)** com **Monitoramento Operacional Periódico Nativo** e **Central de Suporte, Ocorrências e Sugestões**, sem dependência externa obrigatória nem consultas a bases clínicas.

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

- `?view=portal` (ou raiz `/exec`): **Portal Público 2.2** (`Início`, `Status`, `Atualizações`, `Comunicados`, `Suporte`).
- `?view=suporte` (ou `?tab=suporte`): **Central de Suporte Pública** (registro condicional de ocorrências/sugestões/suporte e acompanhamento individual por protocolo + token).
- `?view=admin` ou `?admin=1`: **Central Administrativa** em 6 abas (`Ambientes`, `Monitoramento`, `Suporte`, `Releases`, `Comunicados`, `Configurações`).
- `?action=get` (ou `?format=json`): Leitura JSON pública somente-leitura dos 6 ambientes em `CONFIG_LINKS`.
- `?action=bootstrap`: Leitura JSON pública de links, releases, comunicados vigentes, monitoramento e metadados públicos de configuração de suporte (sem incluir chamados).
- `?action=status`: Leitura JSON pública somente-leitura do módulo de monitoramento operacional.
- `POST` (`action: "support_create" | "support_lookup" | "support_reply"`): Fluxos públicos protegidos da Central de Suporte.
- `POST` (`action: "publish_event"`): Ingestão autenticada por **HMAC-SHA256**.
- `POST` (`action: "admin_*"`): Operações administrativas autenticadas (Google allowlist ou `authToken` de sessão), incluindo `admin_monitoring_*` e `admin_support_*`.

---

## Central de Suporte 2.2 — Privacidade, Acesso, Ciclo e Retenção

- **Zero envios anônimos irrestritos**: exige sessão Google identificada (quando habilitada) ou **credencial limitada de suporte** / **convite limitado** (`SUPPORT_AUTH_HASH` / `SUPPORT_INVITES`), completamente distintos de `ADMIN_AUTH_HASH` e `PORTAL_WEBHOOK_SECRET`.
- **Privacidade clínica**: proíbe anexos, base64, CPF, INFOPEN, prontuário e dados de pacientes; exige confirmação explícita; notas internas ficam isoladas do acompanhamento público e do bootstrap.
- **Módulo APAC**: habilitado e validado exclusivamente para a unidade `PEPOA`.
- **Acompanhamento individual**: protocolo não sequencial (`SUP-YYYYMMDD-XXXXXX`) + token aleatório forte (`stk_...`, persistido apenas em hash SHA-256) com rate limit, sem lista pública e sem polling automático agressivo.
- **Ciclo de vida e exportação**: estados `RECEBIDO`, `EM_ANALISE`, `AGUARDANDO_INFORMACOES`, `EM_DESENVOLVIMENTO`, `EM_HOMOLOGACAO`, `RESOLVIDO`, `ENCERRADO`, prioridades administrativas (`baixa`, `normal`, `alta`, `crítica`), reabertura, duplicatas e exportação consolidada local em Markdown/JSON sem serviços externos.
- **Persistência segmentada**: `SUPPORT_SETTINGS`, `SUPPORT_INDEX`, `SUPPORT_DEDUPE`, `SUPPORT_INVITES`, `SUPPORT_SEG_*` e `SUPPORT_ARCH_*` respeitando o limite de `7800` bytes por propriedade e a cota total do projeto Apps Script, com retenção e arquivamento administráveis.

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
