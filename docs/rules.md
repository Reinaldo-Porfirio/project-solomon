# Regras, evidências e limites analíticos

## Catálogo de pentest implementado

| Regra | Evidência necessária | Gravidade | Interpretação |
|---|---|---|---|
| TLS-001 | SSLCertVerificationError com motivo/código | MEDIUM | Certificado rejeitado pelo cliente local; trust store/relógio precisam de revisão |
| WEB-CORS-001 | Dois Origin distintos refletidos, ACAC=true e respostas 2xx | MEDIUM | Candidato; vazamento autenticado não demonstrado |
| WEB-COOKIE-001 | Cookie com nome conhecido de sessão, HTTPS e Secure ausente | LOW | Configuração; função do cookie e envio HTTP precisam de confirmação |
| WEB-COOKIE-002 | Cookie com nome conhecido de sessão e HttpOnly ausente | LOW | Configuração; não demonstra XSS ou captura de sessão |
| WEB-COOKIE-003 | Cookie com nome conhecido de sessão e SameSite ausente | INFORMATIONAL | Observação; não demonstra CSRF |
| WEB-HSTS-001 | HTTPS 2xx sem HSTS | INFORMATIONAL | Observação; preload ou política de outra rota não foram consultados |
| WEB-HEADERS-001 | HTML 2xx sem CSP e/ou X-Content-Type-Options | INFORMATIONAL | Ausência de defesa adicional; não demonstra XSS |
| WEB-FRAME-001 | HTML 2xx sem XFO válido e sem frame-ancestors restritivo identificado | INFORMATIONAL | Revisar enquadramento e ação sensível; clickjacking não demonstrado |

Cookies de sessão são reconhecidos por nomes conhecidos: session, sessionid, session_id, JSESSIONID, PHPSESSID, ASP.NET_SessionId, connect.sid e sid. Outros cookies não geram esses achados automaticamente. Os valores dos cookies não são persistidos.

A regra de headers não é um validador completo de CSP/HSTS. A regra TLS não enumera todos os protocolos/cifras disponíveis; identifica apenas a negociação realizada ou a falha de validação observada.

## Classificações

- `observation`: fato/configuração observado sem demonstração de falha explorável; prioridade informativa zero.
- `configuration`: problema de configuração sustentado por evidência, com impacto contextual a validar.
- `candidate`: condições indicam uma possível vulnerabilidade, mas falta confirmar impacto e pré-requisitos.

Confiança se refere às evidências utilizadas, não à certeza de exploração ou aceitação pelo programa. Achados duplicados da mesma regra/ativo/cookie não aumentam a pontuação.

## Auditoria Windows

| Regra | Correlação | Resultado |
|---|---|---|
| WIN-FW-001 | Perfil de firewall explicitamente desabilitado | MEDIUM; o perfil pode não estar ativo |
| WIN-RDP-001 | TermService running + TCP/3389 + bind não loopback + perfil permissivo/desabilitado | MEDIUM; alcance remoto e perfil aplicado não comprovados |
| WIN-SVC-001 | Spooler running + socket do processo em bind não loopback | INFORMATIONAL; disponibilidade não prova vulnerabilidade |
| WIN-ACC-001 | Reservada | Nenhuma avaliação de contas nesta versão |
| WIN-UPDATE-001 | Reservada | Nenhuma avaliação de atualizações nesta versão |

A correlação usa evidências vinculadas, mantém a menor confiança relevante e não cria achado quando a proveniência está ausente. Um listener em 127.0.0.0/8 ou ::1 não atende à condição de bind não loopback.

## Prioridade e nota

Prioridade é um indicador interno de triagem, **não CVSS**:

```text
risco = gravidade × exposição × impacto × confiança × 100
gravidade: INFO=0, LOW=0,3, MEDIUM=0,6, HIGH=0,8, CRITICAL=1
impacto: aproximação inicial igual ao fator de gravidade
exposição: heurística legada explicitada nos fatores; padrão 1,0
confiança: evidência/correlação, limitada a 0..1
```

O relatório inclui os fatores e a fórmula. A gravidade categórica de uma falha é independente do intervalo numérico da prioridade; MEDIUM pode ter prioridade 35. Não há vetores CVSS calculados automaticamente.

A nota de saúde aplica penalidades por gravidade/categoria às regras avaliadas. No pentest web, a categoria Web Security recebe todo o peso; não se incluem perfis locais de firewall/contas na nota de um site. É um resumo do conjunto de verificações, não uma medição de toda a superfície do alvo. Estados parciais/inconclusivos devem ser lidos junto com a nota. Sessões só de DNS/portas ou respostas HTTP de erro não recebem nota web.

## Referências técnicas

- [OWASP — HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP — Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP — TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [MDN — CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [Microsoft — PowerShell character encoding](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding)
