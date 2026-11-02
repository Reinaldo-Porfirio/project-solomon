# Política de segurança

Solomon é destinado a diagnóstico local e testes de segurança em ativos explicitamente autorizados. As operações de coleta não aplicam hardening nem executam exploits.

## Relatar um problema no framework

Não inclua credenciais, relatórios de clientes, dados pessoais, inventários internos, nomes de alvos reais ou provas com dados de terceiros em issues, commits ou pull requests.

Para uma vulnerabilidade do próprio Solomon, utilize o canal privado de reporte de segurança do GitHub quando estiver disponível. Se não houver um canal privado habilitado, envie apenas uma descrição mínima para combinar um meio privado antes de compartilhar evidências sensíveis.

## Conteúdo permitido no repositório

Código, testes com mocks/dados fictícios, documentação sanitizada e exemplos de escopo desativados. Exemplos devem usar domínios reservados como example.invalid ou example.test, sem autorização de teste a terceiros.

## Dados que ficam locais

Ambientes virtuais, arquivos de ambiente, senhas, tokens, certificados/chaves privadas, escopos de clientes, evidências reais, relatórios, capturas de tráfego, bancos locais, logs, backups e caches não devem ser versionados.

O .gitignore é uma primeira barreira. Confira os arquivos preparados para commit e faça varredura de segredos antes de publicar. Arquivos que já tenham sido versionados não deixam o histórico apenas porque foram adicionados ao .gitignore.

## Em caso de exposição

Interrompa o compartilhamento do material, revogue ou substitua a credencial exposta e trate o histórico conforme a orientação oficial do provedor. Não copie o segredo para uma issue ou comentário para explicar o incidente.

## Custos e automações

Não habilitar serviços pagos, APIs comerciais, runners com cobrança ou funcionalidades de segurança pagas sem autorização explícita. Este repositório é criado sem workflows de CI e com GitHub Actions desabilitado.

O projeto é distribuído sob a licença MIT (ver LICENSE). A licença não autoriza testes contra sistemas de terceiros.
