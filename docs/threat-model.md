# Modelo de ameaças

## Fronteiras e ameaças tratadas

| Entrada/fronteira | Ameaça | Controle atual |
|---|---|---|
| Alvo/configuração | Expansão de escopo ou esquema indevido | Validação local e TargetGuard |
| Redirect | Host/porta/rota não autorizada; downgrade | Guard sobre URL completa e bloqueio HTTPS→HTTP |
| Resolução DNS | IP excluído ou rede privada inesperada; rebinding | Verificação dos endereços e conexão ao IP conferido |
| Operações de rede | Frequência/orçamento ignorados | Runtime compartilhado |
| Cookies/headers/query | Segredo no relatório | Redaction e coleta somente de atributos de cookies |
| Resposta do alvo | Injeção no HTML de relatório | Escape e CSP sem recursos externos |
| Arquivo salvo | Evidência alterada ou vínculo inválido | Hash e validação de IDs |
| Execução no Windows | Shell injection, janela interativa, encoding | Scripts estáticos, shell=False, UTF-8, CREATE_NO_WINDOW |
| Conclusão analítica | Porta/serviço/timeout tratado como vulnerabilidade | Regras conservadoras e classificação de limites |
| Abertura da TUI | Rede remota automática | Nenhum teste remoto no on_mount |

## Limites de confiança

Evidence é uma representação congelada, mas raw_data ainda é um objeto Python potencialmente mutável. A coleta não torna respostas de terceiros confiáveis. A análise usa campos específicos e valida proveniência; relatórios são sanitizados e escapados.

O arquivo de autorização é controlado pelo operador. Não há verificação jurídica, assinatura de autorização ou proteção contra um operador que altere o escopo deliberadamente.

O hash detecta alteração em relação ao conteúdo exportado, mas quem possui acesso de escrita pode recalculá-lo. Não há assinatura, armazenamento imutável, criptografia em repouso ou trilha forense inviolável.

Não há elevação automática de privilégios. O instalador usa pacotes gratuitos do índice Python; o processo depende da integridade do índice, do Python e do computador local.

## Limitações de rede conhecidas

- Resolução nativa do sistema não tem um deadline global controlado pelo Solomon.
- O orçamento representa operações, não pacotes/resoluções internas do sistema.
- Somente o primeiro endereço resolvido é tentado, após examinar todos.
- Operações já iniciadas não são canceladas instantaneamente ao sair da TUI.
- Não há scanner de todas as rotas, testes autenticados ou validação em navegador de impacto CORS.
- O fingerprint HTTP é uma declaração do servidor; não comprova versão instalada ou CVE.
