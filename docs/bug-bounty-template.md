# Modelo de documentação de falha

Use o report.md da sessão como base. Remova achados informativos sem impacto relevante ao programa. Nunca transforme um candidato em falha confirmada sem evidência adicional.

## Título

[Classe da falha] em [ativo/rota] permite [impacto demonstrado].

## Contexto e autorização

- Programa e referência de autorização:
- Ativo incluído e exclusões pertinentes:
- Janela e data do teste:
- Sessão Solomon e versão:
- Classificação atual: observação / configuração / candidato / confirmado manualmente:
- Gravidade proposta e justificativa:
- CWE, se aplicável:
- Vetor CVSS, somente se calculado e revisado separadamente:

## Resumo técnico

Descreva o comportamento observado em poucas frases. Diferencie o fato registrado da hipótese de impacto. Identifique método, esquema, host, porta e rota.

## Pré-requisitos

- Conta/papel necessário, quando aplicável:
- Dados fictícios utilizados:
- Estado de autenticação da evidência:
- Dependências de navegador, cookies e SameSite:
- Condições que ainda não foram testadas:

## Reprodução

1. Confirme o ativo autorizado e prepare as contas de teste permitidas.
2. Execute a requisição mínima que reproduz o comportamento.
3. Registre o status e os headers relevantes com credenciais ocultadas.
4. Demonstre o impacto permitido sem acessar dados de terceiros.
5. Repita para confirmar consistência, respeitando limites do programa.

Requisição sanitizada:

```http
GET /rota HTTP/1.1
Host: ativo-autorizado.invalid
Origin: https://origem-de-teste.invalid
Authorization: [REDACTED]
```

Resposta relevante:

```http
HTTP/1.1 200 OK
Content-Type: application/json
[headers estritamente necessários]
```

## Evidências

- IDs de evidência:
- Timestamps UTC:
- Arquivo JSON/HTML correspondente:
- SHA-256 das evidências sanitizadas:
- Capturas/provas de contexto, quando autorizadas:
- Valor esperado:
- Valor observado:
- Limitações da coleta:

Hashes não são assinaturas nem prova independente da origem. Preserve o material original em um local adequado às regras do programa.

## Impacto demonstrado

Explique qual operação ou informação fica acessível, para quem e em quais condições. Se o impacto ainda não foi comprovado, escreva explicitamente: **impacto não confirmado; candidato para investigação**.

Não atribua automaticamente account takeover, RCE, vazamento autenticado, XSS ou CSRF com base em header ausente, porta aberta ou versão anunciada.

## Correção sugerida

Descreva a alteração mínima pertinente ao comportamento observado e possíveis dependências do fluxo da aplicação.

## Verificação após correção

Repita a requisição mínima e compare a mesma evidência. Registre resultado esperado, resultado obtido e qualquer cobertura restante.

## Referências

Inclua fontes técnicas e política específica do programa. Não exponha tokens, cookies, passwords, dados pessoais ou informações de terceiros.
