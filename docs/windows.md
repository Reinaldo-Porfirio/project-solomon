# Operação no Windows

## Requisitos e instalação

Validado em Windows 11, Python 3.12.10, PowerShell e usuário comum. O núcleo destina-se também a Windows 10; essa versão do Windows ainda não foi testada fisicamente nesta entrega.

Abra um terminal na pasta do projeto e execute:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1 -Dev
.\solomon.cmd status
```

O instalador cria `.venv` dentro do projeto e usa somente pacotes gratuitos do Python. Precisa de acesso ao índice de pacotes na primeira instalação. Não instala aplicações comerciais, não cadastra cobrança e não altera configurações do sistema.

Se o Python não estiver no PATH, forneça o caminho:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1 -Python "C:\caminho\python.exe"
```

Não é necessário ativar a virtualenv: `solomon.cmd` usa diretamente o interpretador local, habilita UTF-8 e preserva o código de saída.

## Interface

```powershell
.\solomon.cmd
```

- Máquina: diagnóstico local em segundo plano, estado por coletor e quantidade de evidências.
- Auditoria: resultado das regras locais; selecione uma linha para examinar o achado.
- Pentest: arquivo JSON de escopo, alvo, módulos e pasta de saída. **Validar plano** não usa rede; **Executar coleta** realiza somente operações permitidas pelo arquivo.
- `q`: sair; `r`: atualizar evidências locais.

A interface não assume um alvo externo, não cria autorização automaticamente e não testa `example.com` ao abrir.

## Coletores Windows

| Área | Coleta | Limitação |
|---|---|---|
| CPU/memória | psutil | Amostra pontual; não substitui monitoramento contínuo |
| Armazenamento | Partições e uso de espaço | Volume sem acesso fica como PARTIAL, com motivo |
| Processos | Dados de processos locais | Privilégios podem limitar informações; cmdline é ocultado nos relatórios |
| Interfaces/sockets | Endereços e listeners | Bind não prova alcance pela Internet |
| Serviços | Get-CimInstance Win32_Service | Inclui PID para correlação; não modifica serviço |
| Rotas | Get-NetRoute | Dados estruturados, sem alteração da tabela |
| Firewall | Get-NetFirewallProfile | Perfis; não enumera todas as regras efetivas/interface ativa |

Os processos PowerShell são não interativos, não abrem janelas, usam UTF-8 e tratam erros explicitamente. Não dependem de WMIC. Um executável detectado não garante que todos os cmdlets estejam disponíveis ou acessíveis.

## Diagnóstico rápido

```powershell
.\solomon.cmd diagnostics
.\solomon.cmd audit --output reports\windows
.\solomon.cmd demo
```

Os relatórios ficam em uma subpasta por sessão. Abra `report.html` no navegador local. Ele não usa CDN, fontes externas, scripts ou recursos remotos.

## Solução de problemas

| Sintoma | Ação |
|---|---|
| Ambiente local não encontrado | Execute setup-windows.ps1 |
| Python inferior a 3.12 | Instale uma versão gratuita compatível |
| Execução de ps1 bloqueada | Use o comando acima com Bypass apenas para o processo |
| FAILED/NOT_AVAILABLE em serviços/rotas/firewall | Confira PowerShell, cmdlets disponíveis e detalhes da coleta |
| INSUFFICIENT_PRIVILEGES | O coletor não tem acesso; use conta adequada somente quando necessário |
| PARTIAL em armazenamento | Confira o volume citado: mídia ausente, volume protegido ou falta de acesso |
| BLOCKED_POLICY com IP local | Inclua explicitamente o IP/CIDR e a porta no escopo |
| Erro de certificado HTTPS | Corrija cadeia/nome/relógio; o Solomon mantém a validação habilitada |
| Sessão parcial com DNS/portas bloqueados | Uma URL exata pode autorizar apenas HTTP/TLS naquela URL; ajuste os módulos |

Códigos de saída: `0` para execução concluída ou planejamento; `2` para erro/bloqueio/sessão remota parcial; `130` para interrupção pelo usuário. Uma auditoria local com lacunas termina com `0` e registra PARTIAL no relatório.
