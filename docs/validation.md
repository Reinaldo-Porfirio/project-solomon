# Validação da versão 0.2.0

Registro técnico sanitizado para o repositório. Relatórios, escopos reais, detalhes da máquina e identificadores de sessões permanecem somente no ambiente local e não fazem parte do Git.

## Ambiente de compatibilidade

| Componente | Versão verificada |
|---|---|
| Plataforma | Windows 11 |
| Python | 3.12.10 |
| Textual | 8.2.8 |
| psutil | 7.2.2 |
| dnspython | 2.9.0 |
| pytest | 9.1.1 |
| Ruff | 0.17.0 |
| mypy | 2.4.0 |

O ambiente virtual usa dependências próprias do projeto. A verificação de dependências não encontrou conflitos. As versões diretas estão registradas em requirements-tested.txt.

## Verificações concluídas

- **88 testes da suíte padrão aprovados**, com integração excluída por padrão.
- **1 teste de integração aprovado** em servidor exclusivamente loopback.
- **89 testes aprovados no total**.
- Ruff: sem erros e código formatado.
- mypy: sem problemas nos módulos de código.
- Launcher Windows, version, status, help, demo, audit, analyze e report executados.
- Planejamento com arquivo real e bloqueio de rede testados.
- TUI testada com o piloto do Textual, incluindo ausência de chamadas remotas ao abrir.
- Reanálise offline preservou IDs e regras.
- Exportação testada para integridade, vínculo de evidências, ocultação de valores sensíveis e escape de HTML.

## Laboratório reproduzível

O comando `solomon demo` inicia um servidor temporário exclusivamente em 127.0.0.1 e encerra o servidor após a coleta.

- HTTP, TECHNOLOGY, PORTS e CORS: SUCCESS.
- 4 operações: HTTP, uma conexão TCP e dois probes CORS.
- Tecnologia reutiliza a resposta HTTP.
- 5 evidências e 5 achados esperados.
- Um candidato CORS MEDIUM, uma configuração de cookie LOW e três observações INFORMATIONAL.
- Nota das verificações web: 93/100, sem certificação de segurança.
- Nenhum achado derivado apenas da porta aberta.
- Valores fictícios dos cookies não são persistidos.

Gere seus próprios relatórios com `solomon demo`. Eles ficam em uma pasta local ignorada pelo Git. Nenhum relatório da máquina de desenvolvimento é distribuído pelo repositório.

## Verificação dos coletores Windows

Coleta de leitura realizada em conta comum. CPU, memória, processos, interfaces, sockets, serviços, rotas e firewall funcionaram no ambiente testado. Armazenamento indisponível ou sem acesso foi tratado como PARTIAL, com motivo documentado localmente.

Esse resultado não demonstra alcance externo ou exploração de serviços. Nomes de dispositivos, caminhos, inventários, quantidades de processos e identificadores de sessões foram removidos deste registro distribuível.

## Limites

- Não foram testados alvos de terceiros.
- Nenhuma alteração de firewall, registro, serviços ou hardening foi realizada.
- Windows 10 e Linux não receberam execução física nessa validação.
- A inspeção visual do HTML no navegador integrado ficou pendente; geração, sanitização e integridade foram verificadas por testes.
- A TUI foi validada pelo ambiente de teste do Textual; sessões longas, cancelamento e diferentes tamanhos de terminal ainda exigem teste de uso.
- Hardening, exploração, autenticação, CVSS e cobertura completa de APIs permanecem fora da capacidade implementada.
