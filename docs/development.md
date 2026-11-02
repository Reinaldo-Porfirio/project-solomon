# Desenvolvimento

## Instalação gratuita

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1 -Dev
```

O projeto usa Python 3.12+, Textual, psutil e dnspython. Dependências de desenvolvimento: pytest, Ruff e mypy. O arquivo requirements-tested.txt registra versões diretas verificadas; pyproject.toml define as faixas suportadas. Não integrar APIs pagas ou recursos com cobrança sem mudar a restrição explícita do projeto.

## Verificação

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q -m integration
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m ruff format --check src tests
.\.venv\Scripts\python.exe -m mypy src --ignore-missing-imports
.\.venv\Scripts\python.exe -m pip check
```

A suíte padrão exclui integration e usa mocks para rede/plataforma. O teste de integração cria somente um servidor loopback temporário, sem alterar firewall, registro, serviços ou conectividade do sistema.

O mypy atual verifica o código com imports de bibliotecas sem stubs tolerados. O modo strict para todos os handlers legados ainda não está concluído.

## Regras para novas funcionalidades

1. Coletores produzem Evidence e estados de cobertura; não fabricam vulnerabilidade a partir de serviço/porta.
2. Toda rede de pentest passa pelos transportes; scanners não abrem socket/urllib/ssl diretamente.
3. Novos transportes respeitam guard, IPs resolvidos, timeout, orçamento e redaction.
4. Regras analíticas são puras, com IDs estáveis e evidência suficiente; inclua casos negativos relevantes.
5. Achados documentam impacto, reprodução, correção e limites, além de gravidade/confiança.
6. Testes de falha, bloqueio, redaction e falsos positivos são tão importantes quanto os de sucesso.
7. Use saídas estruturadas dos provedores Windows; não use shell=True nem alvos interpolados em PowerShell.
8. Relatórios recebem conteúdo não confiável; mantenha escape e ausência de recursos externos.
9. Mantenha hardening separado da coleta. Não adicionar alterações reais sem plano/backup/rollback.

## Organização incremental

Prioridades e critérios da evolução estão em project-review.md. Preserve funcionalidades existentes, atualize documentação da capacidade real e não prometa módulos ainda reservados.
