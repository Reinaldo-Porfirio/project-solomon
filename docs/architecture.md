# Arquitetura

## Separação de responsabilidades

1. **Plataforma/diagnósticos:** psutil e provedores específicos coletam dados estruturados, com estados de cobertura.
2. **Evidência:** Evidence liga fonte, ativo, componente, timestamp, observação, dados e confiança.
3. **Análise local:** regras registradas → condições → correlação → achado → risco/saúde.
4. **Pentest:** engagement real → plano offline → transportes guardados → evidência → regras web determinísticas.
5. **Apresentação:** CLI/TUI e exportação JSON, HTML e Markdown.
6. **Hardening:** reservado; nenhuma alteração de segurança é aplicada pela versão atual.

## Componentes centrais

| Arquivo/módulo | Responsabilidade |
|---|---|
| core/scope.py | Ativos, exclusões e política |
| pentest/engagement.py | Persistência e validação do engagement JSON |
| pentest/scope_matcher.py | Correspondência local, sem DNS |
| pentest/guard.py | Autorização, janela temporal, operações, URL e portas |
| pentest/transport/base.py | Orçamento, frequência, concorrência, IPs resolvidos e redaction |
| pentest/transport/http.py | HTTP limitado, redirects, HTTPS verificado e cookies sem valores |
| pentest/transport/tls.py | Negociação verificada ou motivo exato de rejeição |
| pentest/engine.py | Seleção, coleta, cobertura, sessão e análise |
| pentest/security.py | Regras puras de web/TLS/CORS; nenhuma rede |
| analysis/correlation.py | Correlação local e proveniência determinística |
| reporting.py | Sanitização, hashes, exportação e leitura offline |
| lab.py | Demonstração em loopback, com encerramento garantido |
| tui/app.py | Interface, workers e leitura dos achados |

Os coletores de recon/discovery anteriores foram preservados para compatibilidade. A CLI 0.2 usa o engine com transportes diretamente para registrar bloqueios e falhas em vez de esconder erros em listas vazias.

## Fluxo de rede

```text
Arquivo JSON → Validação → Plano (sem rede)
                                ↓ execução explícita
TargetGuard → Rate/Budget/Semaphore → revalidação de autorização
                                ↓
DNS nativo → exclusões de IP + inclusão privada → socket numérico
                                ↓
HTTP/TLS/TCP/DNS → evidências limitadas → regras → relatórios
```

HTTP desabilita proxies de ambiente; redirects reaplicam escopo e orçamento e bloqueiam downgrade. A conexão ao IP resolvido preserva hostname/SNI para verificação TLS e o Host original da requisição.

## Reprodutibilidade

Findings têm IDs derivados de regra, ativo e contexto. Mesmas evidências e mesmas regras geram os mesmos achados e fatores. Timestamps, dados coletados e IDs de sessão novos podem diferir entre execuções reais; determinismo analítico não significa que duas coletas distintas terão conteúdo idêntico.

O relatório guarda a política e o escopo usados, cobertura e dados sanitizados. SHA-256 detecta alteração do conteúdo da evidência, sem fornecer assinatura ou prova independente de origem.

## Plataformas

O núcleo não modifica Windows nem Linux. PowerShell é usado somente em provedores Windows e recebe scripts estáticos, nunca interpolação do alvo de pentest. Comandos usam shell=False, timeout e janela oculta. Os workers da TUI executam coleta fora do loop de eventos, mantendo a interface responsiva.
