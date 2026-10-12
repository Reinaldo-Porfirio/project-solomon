# Preparação do repositório

## O que é versionado

- src/solomon/: código do framework.
- tests/: testes e dados fictícios necessários à verificação.
- scripts/: instalador Windows.
- docs/: arquitetura, operação, regras, limites e validação sanitizada.
- examples/: modelo UNDECLARED com domínios reservados.
- README.md, SECURITY.md, pyproject.toml e requirements-tested.txt.
- solomon.cmd, .gitignore e .gitattributes.

## O que não é enviado

.venv, dependências instaladas, relatórios, escopos reais, evidências, backups, caches, logs, bancos, capturas de rede, arquivos .env, credenciais, certificados/chaves privadas e configurações pessoais do editor.

Esses arquivos permanecem no computador. O ambiente virtual é recriado pelo instalador a partir das dependências declaradas.

## Revisão antes de novos commits

```powershell
git status --short
git diff --cached --stat
git diff --cached --name-only
git check-ignore .venv/pyvenv.cfg reports/exemplo.json engagements/exemplo.json .solomon-backups/exemplo.zip
```

Revise o conteúdo localmente. Não cole diferenças contendo possíveis segredos em canais externos. Faça uma varredura com uma ferramenta gratuita como Gitleaks antes do envio.

O primeiro commit usa um e-mail noreply do GitHub configurado somente neste repositório. Verifique a identidade novamente antes de novos commits. O histórico também contém metadados de autoria, portanto retirar dados apenas dos arquivos não é suficiente.

## Exemplos e relatórios

O modelo de engagement distribuído está UNDECLARED, não contém um alvo de cliente e não autoriza contato de rede. Relatórios são gerados localmente com a demonstração e ficam ignorados pelo Git.

## Publicação e custos

O repositório começa privado. Nenhum workflow de GitHub Actions é incluído; Actions é desabilitado para impedir execuções automáticas. Não habilite recursos pagos sem autorização.

Uma futura publicação pública requer nova revisão do conteúdo, do histórico e da licença. A licença não foi escolhida automaticamente nesta preparação.
