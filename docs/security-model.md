# Modelo de segurança

## Autorização e configuração

Diagnósticos e auditoria local são somente leitura. O pentest exige arquivo real de engagement com ACTIVE ou DECLARED, ativos explícitos e operação permitida. O arquivo registra a declaração do operador; não concede direitos nem verifica a política de um programa.

O TargetGuard verifica autorização, janela temporal, identidade do escopo, inclusões/exclusões, operações, active_testing e portas. O ScopeMatcher não utiliza DNS nem sockets. URLs usam correspondência exata e preservam caixa do caminho/query.

## Transporte

- Orçamento, intervalo e concorrência compartilhados no runtime do engagement.
- Autorização conferida antes da rede e novamente após espera.
- Cada redirect passa pelo guard, consome orçamento e preserva a cadeia sanitizada.
- Downgrade HTTPS→HTTP bloqueado.
- Proxies de ambiente desabilitados para impedir roteamento fora da fronteira prevista.
- Credenciais de headers removidas em redirects para outra origem.
- Endereços DNS confrontados com exclusões; IP privado/local exige inclusão explícita.
- Socket conecta ao endereço numérico já examinado; hostname original é usado para HTTPS/SNI.
- HTTPS e TLS mantêm validação de certificado habilitada.
- Somente GET/HEAD/OPTIONS e TCP connect; não há exploits, brute force ou alterações remotas implementadas.

GET/OPTIONS podem ter efeitos em aplicações mal projetadas. O operador deve excluir rotas que não tolerem a coleta e seguir a política do ambiente.

## Evidência e relatórios

Cookies são representados por nome e atributos, sem valores. Headers e parâmetros sensíveis são ocultados. Corpo HTTP tem leitura limitada a 4096 bytes e não é persistido no relatório. Dados de cmdline dos processos são ocultados.

HTML escapa conteúdo do alvo e usa uma política local sem carregamentos externos. Markdown/JSON recebem dados sanitizados. As evidências exportadas incluem hash verificado na leitura; o hash não é assinatura.

Redaction não é um classificador completo de dados pessoais ou segredos arbitrários. Revise o relatório antes de compartilhá-lo, especialmente nomes de ativos, caminhos e metadados de infraestrutura.

## Análise e limites

Portas abertas, fingerprints, timeouts e respostas inconclusivas não geram vulnerabilidades especulativas. Headers ausentes geram observações. A regra CORS correlaciona duas origens e registra candidato sem alegar vazamento de dados.

A nota é um resumo das verificações coletadas. Não existe garantia de detecção de todas as falhas. A classificação, confiança, fatores, justificativas e limites são visíveis.

Hardening não foi implementado. Uma futura implementação deve exigir plano, dry-run, backup, execução autorizada, verificação e rollback testado.
