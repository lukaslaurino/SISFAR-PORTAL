# SISFAR-PORTAL

Portal oficial de acesso aos ambientes do **SISFAR — Sistema Integrado de Farmácia Prisional**.

O projeto contém a interface estática do portal público e a central administrativa para gestão dinâmica dos links dos 6 ambientes prisionais.

---

## Estrutura do Repositório

```text
/
├── index.html        # Página pública institucional de acesso aos 6 ambientes
├── favicon.svg       # Ícone oficial vetorial do SISFAR
├── links.js          # Configuração padrão de fallback e endpoint da API
├── admin/
│   └── index.html    # Central Administrativa (/admin)
├── admin.html        # Central Administrativa (acesso direto /admin.html)
├── backend/
│   └── Code.js       # Código fonte da API Google Apps Script
└── README.md
```

---

## Como Acessar a Central Administrativa

Acesse pelo navegador:
- `https://lukaslaurino.github.io/SISFAR-PORTAL/admin/` (ou `admin.html`)
- Ou clique no rodapé da página principal em **"⚙ Central Administrativa de Links"**.

---

## Como Alterar uma URL Sem Editar Código

1. Acesse a **Central Administrativa**;
2. Localize a unidade desejada (CPPA, PEPOA ou MADRE — Oficial ou AUDIT);
3. Altere o campo **URL**, **Nome**, **Status** (Ativo/Inativo) ou **Ordem**;
4. Clique no botão **"Salvar Todas as Alterações"**;
5. A nova configuração é salva imediatamente no backend na nuvem e passa a valer para todos os operadores no portal público.
