# Análise e evolução do Project Solomon

Revisão realizada em **12 de outubro de 2026**, com prioridade Windows, pentest autorizado e documentação de falhas. Nenhum serviço pago, API comercial ou ferramenta com cobrança foi contratado.

## Estado encontrado

A estrutura já separava diagnósticos, provedores Windows/Linux, evidências, regras, escopo e transportes. Os 46 testes originais passavam, mas vários fluxos de uso eram demonstrações incompletas.

| Problema observado | Consequência | Tratamento |
|---|---|---|
| init/plan/status com respostas mockadas e escopo example.com fixo | Operador não conseguia trabalhar com escopo real | Arquivos JSON reais, init, status e plano por alvo |
| dns/http/tls/ports apontavam ao mesmo discovery completo | Comando individual podia rodar módulos adicionais | Seleção explícita e execução por módulo |
| TUI iniciava discovery de example.com ao montar | Conexão remota sem interação do operador | Nenhuma coleta remota ao abrir |
| HTTP verificava só hostname | URL exata, caminho e porta não eram respeitados | URL completa e política de portas, incluindo redirects |
| Limites de política não estavam aplicados | Configuração de frequência/orçamento não tinha efeito | Runtime compartilhado nos transportes |
| DNS resolvido não era confrontado com exclusões de IP | Nome incluído podia levar a IP excluído/local | Verificação e conexão ao endereço numérico conferido |
| TLS desativava verificação e fazia duas conexões | Certificado vazio em CERT_NONE e coleta inconsistente | Uma conexão verificada; falha documentada sem bypass |
| Set-Cookie virava um header único redigido | Atributos não podiam ser analisados corretamente | Múltiplos cookies, somente nomes/flags, sem valores |
| Não havia exportador profissional de falhas | Coleta não produzia documentação utilizável | JSON/HTML/Markdown, proveniência e reprodução |
| Regras locais não eram importadas pelo fluxo normal | Auditoria podia não avaliar nenhuma regra | Registro explícito independente dos testes |
| IDs aleatórios/sets sem ordenação na correlação | Reanálise difícil de comparar | IDs derivados, ordenação e confiança das evidências |
| Coleta Windows dependia do encoding implícito | Texto em português podia ser corrompido | UTF-8 explícito e PowerShell não interativo |
| Conclusões sobre alcance externo baseadas em bind | Gravidade/exposição exageradas | Reclassificação e limites expressos |

## Entrega 0.2.0

Windows dispõe de ambiente local, instalador PowerShell, launcher, CLI/TUI e coletores testados na máquina. O pentest usa escopo configurável e coleta limitada. O motor web tem oito regras conservadoras; os relatórios documentam evidência, impacto possível, limites e correção.

A demonstração local oferece um fluxo completo sem terceiros: servidor temporário em loopback → escopo → HTTP/tecnologia/porta/CORS → análise → três formatos de relatório → encerramento do servidor.

## Validação

- 46 testes iniciais preservados, com expectativas ajustadas para as correções de segurança.
- Suíte ampliada cobrindo escopo completo, redirecionamentos, orçamento, cookies, TLS, determinismo, hashes, segredos e TUI sem conexões remotas.
- Integração separada em loopback com coleta e relatórios reais.
- Ruff, mypy e consistência das dependências do ambiente local verificados.
- Auditoria de leitura no ambiente de validação Windows 11 com conta comum: serviços, rotas e firewall disponíveis. Armazenamento indisponível ou sem acesso fica PARTIAL, sem ocultar a lacuna. Inventários e identificadores reais permanecem fora do repositório.
- Linux mantido, com execução real pendente de validação em Linux.

Os totais finais de testes e versões do ambiente estão em `docs/validation.md`. Dados variáveis da máquina não são tratados como fatos permanentes.

## Próximas etapas incrementais

| Prioridade | Evolução | Critério de conclusão |
|---|---|---|
| 1 | Persistência de casos e comparação de sessões | Agrupar ativos/achados, acompanhar correção e exportar diffs |
| 2 | Coleta Windows de perfil ativo/regras, contas, updates e logs | Evidências estruturadas, permissões claras e testes de falsos positivos |
| 3 | Avaliação autenticada de APIs e autorização | Contas de laboratório, segredos fora de relatórios e provas de impacto permitidas |
| 4 | Validação controlada de classes web adicionais | Escopo e opt-in por operação, provas mínimas, nenhum impacto destrutivo |
| 5 | Modelagem de exposição/impacto e CVSS revisável | Fatores explícitos, eliminação das heurísticas textuais e vetores auditáveis |
| 6 | Sessões canceláveis e prazos totais | Cancelamento cooperativo da TUI, DNS com prazo e progresso persistido |
| 7 | Hardening | Plano, dry-run, backup, verificação e rollback em laboratório |
| 8 | SQLite/PDF e validação Linux | Migrações testadas, renderização revisada e execução real multiplataforma |

A ferramenta evoluiu para uma base funcional e verificável. Não foi apresentada como scanner universal, validador completo de aplicações ou sistema de exploração automática.
