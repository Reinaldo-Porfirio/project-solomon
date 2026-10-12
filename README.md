# Project Solomon — 0.2.0

Framework Python para **pentest autorizado, auditoria local e documentação de falhas**, com prioridade para Windows. Não usa IA, APIs comerciais, assinaturas, telemetria ou serviços pagos.

## Começar no Windows

Python 3.12 ou superior e PowerShell. Não precisa de WSL, Docker, Nmap ou administrador para iniciar.

Instale as dependências gratuitas na primeira utilização:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1
```

A opção Bypass vale somente para esse processo. O instalador não altera a política permanente do Windows, o firewall, serviços ou permissões.

Depois, confira o estado e abra a interface:

```powershell
.\solomon.cmd status
.\solomon.cmd
```

Abrir a aplicação **não inicia testes remotos**. O diagnóstico local usa somente leitura e executa em segundo plano. O ambiente virtual não faz parte do repositório.

## Ver o fluxo funcionando sem testar terceiros

```powershell
.\solomon.cmd demo
```

A demonstração cria um servidor temporário em **127.0.0.1**, define um escopo exclusivo para ele, coleta HTTP, tecnologia, uma porta e duas sondagens CORS. Gera relatórios JSON, HTML e Markdown em `reports/local-demo/SESS-*/` e encerra o servidor. Os dados são fictícios.

## Pentest de um alvo autorizado

Crie um arquivo de engagement com os ativos realmente autorizados:

```powershell
.\solomon.cmd pentest init --engagement engagements\programa.json --name "Meu programa" --include "https://alvo-autorizado.invalid/" --authorize --authorization-reference "Documento ou politica de autorizacao"
.\solomon.cmd pentest plan "https://alvo-autorizado.invalid/" --engagement engagements\programa.json --modules HTTP,TLS,TECHNOLOGY
.\solomon.cmd pentest scan "https://alvo-autorizado.invalid/" --engagement engagements\programa.json --modules HTTP,TLS,TECHNOLOGY --output reports\programa
```

O domínio acima é ilustrativo: substitua pelo alvo autorizado. A referência registra a declaração do operador; não verifica autorização externa. CORS, portas e identificação ativa de serviços exigem `active_testing=true`. As regras do programa continuam sendo a fonte do escopo.

## O que funciona

- Windows: CPU, memória, armazenamento, processos, interfaces, sockets, serviços, rotas e perfis de firewall.
- CLI e TUI, com planejamento offline e comandos individuais para DNS, HTTP, TLS, portas e CORS.
- Escopo real persistido em JSON: domínio, wildcard, URL exata, IP e CIDR; exclusões, janela temporal, portas permitidas e operações.
- Limites compartilhados de frequência, concorrência e orçamento; HTTPS validado; redirecionamentos verificados; IPs resolvidos excluídos ou locais sem autorização bloqueados.
- Regras determinísticas para atributos de cookies de sessão, headers, HSTS, enquadramento, certificado TLS inválido e configuração CORS.
- Achados com evidências, confiança, impacto, justificativa, reprodução, correção, limitações, referências e hashes SHA-256.
- Relatórios HTML locais sem recursos externos, Markdown para revisão/bug bounty e JSON para reanálise offline.

Porta aberta, versão anunciada e resposta inconclusiva não viram vulnerabilidade. Headers ausentes são observações informativas; reflexão CORS é um candidato que ainda exige confirmação do impacto.

## Auditoria e relatórios

```powershell
.\solomon.cmd diagnostics
.\solomon.cmd audit --output reports\auditoria
.\solomon.cmd pentest status --session "reports\SESS-ID\report.json"
.\solomon.cmd analyze --input "reports\SESS-ID\report.json" --output reports\reanalisados
.\solomon.cmd report --input "reports\SESS-ID\report.json" --output reports\exportados
```

`analyze`, `report`, `plan` e `scope check` não realizam operações de rede. Arquivos com evidências alteradas são rejeitados na verificação de hashes.

## Documentação

- [Instalação e operação no Windows](docs/windows.md)
- [Pentest e bug bounty](docs/pentest.md)
- [Catálogo de regras e limites](docs/rules.md)
- [Modelo de documentação de falhas](docs/bug-bounty-template.md)
- [Análise do projeto e evolução](docs/project-review.md)
- [Arquitetura](docs/architecture.md)
- [Modelo de segurança](docs/security-model.md)
- [Desenvolvimento e testes](docs/development.md)
- [Privacidade e preparação do repositório](docs/repository-security.md)
- [Política de segurança](SECURITY.md)

## Limites atuais

A versão é uma base funcional de avaliação e documentação. Exploração de SQLi/XSS/SSRF, lógica de negócio, autenticação, descoberta em massa, CVE/CVSS automático, coleta de drivers/logs/atualizações/contas e PDF ainda não estão implementados. Hardening, verificação de correções e rollback retornam explicitamente indisponível.

Linux conserva os coletores existentes e o núcleo compartilhado, mas a execução real desta entrega foi validada no Windows 11. A nota 0–100 representa somente as regras e evidências disponíveis; não certifica a segurança geral do alvo.

## Testes

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1 -Dev
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q -m integration
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy src --ignore-missing-imports
```

A suíte padrão usa mocks e não testa terceiros. O teste de integração é separado e usa exclusivamente loopback. `requirements-tested.txt` registra as versões diretas verificadas. Ambientes virtuais, relatórios, escopos reais e backups permanecem locais e não são versionados.
