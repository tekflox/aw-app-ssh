---
repo: architecture
path: docs/architecture/aw-app-ssh.md
source: generated
edited: false
checksum: sha256:5d0e3b35609c5970c461319a22a27866bcd4b59f625994e8d99b900fd31261f3
---
# SSH

- **repo**: aw-app-ssh
- **layer**: app
- **technologies**: python
- **health** (derived): planned

Contributes `aw-workspace-cli ssh` and `aw-workspace-cli rsync`: the real tools, with the private key or password fetched from the workspace vault (aw-app-secrets) and injected into an ephemeral ssh-agent, so the caller — usually an agent — connects without ever seeing the credential. Arguments are ssh's/rsync's own; this app only adds `--aw-*` flags.

## Connections
- `other` → **aw-app-secrets** — Every credential this app injects comes from aw-app-secrets' /api/apps/secrets/* — the vault, the approval gate and the per-secret auto-approve flag all live there

## MCP tools
_none exposed_

## Requirements
### Tudo que pode falhar sem incomodar ninguém falha antes do pedido de aprovação
- Given buscar a credencial coloca uma aprovação no telefone de alguém e gasta um grant one-shot, e o binário ssh/rsync pode simplesmente não existir neste container
- When a ordem das etapas é executada (repos/aw-app-ssh/ssh_app/cli.py:289, spawn.require antes do creds.fetch:297)
- Then a instalação/verificação do binário acontece antes de qualquer requisição de credencial — foi achado rodando de verdade: sem rsync no container o comando buscava a credencial, queimava uma aprovação e uma notificação, e só então morria no binário ausente. A pessoa era interrompida para nada, e o grant gasto não voltava
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-ssh/tests/test_cli.py` (passing)

### Dry-run e status não pedem aprovação, não instalam nada e não conectam
- Given alguém quer saber qual segredo seria usado, ou qual argv seria executado, sem pagar o custo de interromper uma pessoa
- When o status responde (repos/aw-app-ssh/ssh_app/cli.py::_cmd_status:150) ou o dry-run imprime e retorna (repos/aw-app-ssh/ssh_app/cli.py:267-277)
- Then os dois resolvem alvo, usuário, porta, nome do segredo e escopo sem buscar credencial nenhuma, e o dry-run retorna ANTES do spawn.require — a ordem é deliberada e o comentário do código explica: um dry-run promete não perguntar a ninguém e não fazer nada, e baixar um pacote não é nada. Um status em host desconhecido também falha sem perguntar, porque avisar que o host não existe não vale uma notificação
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-ssh/tests/test_cli.py` (passing)

### Uma aprovação já concedida é coletada, não pedida de novo
- Given um pedido de aprovação ainda pendente para aquele mesmo segredo, ou um id passado explicitamente em --aw-request
- When o estado pendente é consultado antes de anunciar qualquer coisa (repos/aw-app-ssh/ssh_app/cli.py:292, via repos/aw-app-ssh/ssh_app/pending.py)
- Then a mensagem passa a ser "coletando a aprovação que você já deu" e o fetch reusa aquele request_id, em vez de abrir um segundo pedido para a mesma coisa — cada requisição nova vira uma mensagem no Telegram de uma pessoa real, e duas para o mesmo segredo treinam quem recebe a aprovar sem ler. O id explícito ganha do pendente descoberto, para quem está coletando uma aprovação específica
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-ssh/tests/test_cli.py` (passing)

### O alvo é encontrado no argv sem confundir valor de flag com host
- Given um argv de ssh ou rsync onde o host pode vir depois de flags que consomem o próximo argumento, colado num -p2222, numa URI ssh://, ou seguido de um comando remoto
- When o argv é varrido contra a lista de flags-que-consomem-valor (repos/aw-app-ssh/ssh_app/target.py::_scan:76, parse_ssh:118, parse_rsync:133)
- Then o alvo achado é o host de verdade, o comando remoto não vira um segundo alvo, um -l explícito ganha do host cru, e um host sem usuário resulta em user None e não em string vazia — as flags booleanas estão deliberadamente FORA da lista (target.py:26-28), porque incluir uma faria o scanner engolir o alvo que vem logo depois dela. Do lado do rsync, uma palavra sem dois-pontos não é alvo remoto, e o valor de -e não é confundido com um
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-ssh/tests/test_target.py` (passing)

### Usuário e porta implícitos são preenchidos, mas o que veio explícito não é revisto
- Given um argv que não nomeia usuário nem porta, enquanto o nome do segredo carrega um usuário e o host tem uma porta lembrada
- When os dois são resolvidos com precedência do explícito (repos/aw-app-ssh/ssh_app/cli.py:262 via credentials.py::login_user_from_name, e cli.py:265 via repos/aw-app-ssh/ssh_app/hosts.py::port_for)
- Then o usuário do segredo só é passado quando o argv não trouxe nenhum, e target.port ganha da porta lembrada sempre que existe — sem preencher o usuário, o ssh entraria com a conta local e o servidor recusaria uma chave que teria aceitado, que é uma falha que se parece com credencial errada. E sobrescrever o que a pessoa escreveu explicitamente seria pior que não ajudar: o comando deixaria de fazer o que está escrito nele
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-ssh/tests/test_cli.py` (passing)
