# FIM com PowerShell: monitoramento de integridade de arquivos

Lab prático de Blue Team: construção, do zero, de um **File Integrity Monitoring (FIM)** usando apenas PowerShell nativo, com detecção por hash SHA-256, registro de alertas no Event Viewer e execução automática por tarefa agendada.

O objetivo não é substituir uma ferramenta comercial (Wazuh, Tripwire, EDR), e sim **entender o que elas fazem por baixo**: baseline, comparação e alerta.

---

## Sumário

1. [Conceito](#conceito)
2. [Ambiente](#ambiente)
3. [Arquitetura](#arquitetura)
4. [Estrutura do repositório](#estrutura-do-repositório)
5. [Execução passo a passo](#execução-passo-a-passo)
6. [Resultados](#resultados)
7. [Mapeamento MITRE ATT&CK](#mapeamento-mitre-attck)
8. [Eventos gerados](#eventos-gerados)
9. [Limitações](#limitações)
10. [Próximos passos](#próximos-passos)
11. [Aprendizados](#aprendizados)

---

## Conceito

Um FIM responde a uma pergunta: *"este arquivo é o mesmo de antes?"*. A lógica tem três peças:

| Etapa | O que acontece |
|---|---|
| **Baseline** | Fotografia do estado bom: caminho + hash SHA-256 de cada arquivo |
| **Comparação** | O estado atual é recalculado e confrontado com a baseline |
| **Alerta** | Toda diferença (novo, modificado, removido) vira um evento registrado |

O hash funciona como uma impressão digital: alterar **um único byte** do arquivo muda o hash inteiro. Por isso a detecção olha o *conteúdo*, e não apenas data ou tamanho.

---

## Ambiente

| Item | Detalhe |
|---|---|
| Virtualização | Oracle VirtualBox |
| Sistema | Windows Server 2022 Standard Evaluation (controlador de domínio do lab de Active Directory) |
| PowerShell | Windows PowerShell 5.1 (build 20348.558) |
| Privilégios | Sessão como Administrador |

A base do ambiente de Active Directory segue o lab do Josh Madakor.

---

## Arquitetura

```
 [Pasta monitorada]  ──►  Get-FileHash (SHA-256)  ──►  [Estado atual]
                                                            │
 [baseline.csv] ──► tabela caminho→hash ──► COMPARAÇÃO ◄───┘
                                                │
                        NOVO / MODIFICADO / REMOVIDO
                                                │
                                                ▼
                          Event Viewer (Application, origem FIM-Lab)
                                                ▲
                         Tarefa agendada (SYSTEM, a cada 5 min)
```

---

## Estrutura do repositório

```
fim-powershell-lab/
├── README.md
├── scripts/
│   ├── Gerar-Baseline.ps1     # tira a fotografia do estado bom
│   ├── Verificar-FIM.ps1      # compara, alerta e grava no Event Viewer
│   └── Agendar-Tarefa.ps1     # cria a tarefa agendada (5 em 5 min)
└── evidencias/                # prints do laboratório
```

Para reproduzir, copie os três scripts para `C:\FIM-Lab\` (os caminhos usados nos scripts partem dessa pasta).

---

## Execução passo a passo

### Fase 1: preparar o terreno e entender o hash

Criação da pasta vigiada (`C:\FIM-Lab\Monitorado`) com três arquivos de teste e verificação da versão do PowerShell (5.1).

```powershell
New-Item -ItemType Directory -Path C:\FIM-Lab\Monitorado -Force
1..3 | ForEach-Object { "conteudo original $_" | Out-File C:\FIM-Lab\Monitorado\arquivo$_.txt }
Get-FileHash C:\FIM-Lab\Monitorado\arquivo1.txt -Algorithm SHA256
```

![Criação do diretório e dos arquivos](evidencias/01-criacao-diretorio-e-arquivos.png)

Hash original do `arquivo1.txt`:

![Hash original](evidencias/02-hash-original.png)

### Fase 1b: prova do conceito (alterar uma letra muda o hash)

O conteúdo do `arquivo1.txt` foi editado no Bloco de Notas, trocando uma única letra:

![Alterando o conteúdo do arquivo](evidencias/03-alterando-conteudo.png)

Resultado: o hash recalculado é completamente diferente do original.

| | Hash SHA-256 |
|---|---|
| Original | `850BE42CF02CDB50313F18B3DC3474BF46ABC3A9B0C326774B72F8D5A1AB841D` |
| Após alteração | `9B04C7A6F214EE226AE245C2584E2B519EBDA2B41AD158E3A2B9371392F2E600` |

![Hash divergente após a alteração](evidencias/04-hash-divergente.png)

### Fase 2: gerar a baseline

Com os arquivos restaurados ao conteúdo original (estado conhecido como bom), o script `Gerar-Baseline.ps1` grava caminho e hash de cada arquivo em `baseline.csv`. A baseline é mantida **fora** da pasta monitorada, para que ela mesma não conte como arquivo vigiado.

### Fase 3: script de verificação

O `Verificar-FIM.ps1` carrega a baseline em uma hashtable (caminho → hash) e compara com o estado atual. São apenas três casos possíveis:

| Situação | Condição |
|---|---|
| **NOVO** | O caminho existe agora, mas não está na baseline |
| **MODIFICADO** | O caminho existe nos dois lados, mas o hash é diferente |
| **REMOVIDO** | O caminho está na baseline, mas não existe mais |

Execução sem alterações: `Nenhuma alteracao detectada.`

### Fase 4: simulação de ataque

Foram simulados três comportamentos típicos de um atacante:

```powershell
Add-Content C:\FIM-Lab\Monitorado\arquivo2.txt "linha inserida pelo atacante"   # adulteração
"conteudo suspeito" | Out-File C:\FIM-Lab\Monitorado\backdoor.txt                # arquivo plantado
Remove-Item C:\FIM-Lab\Monitorado\arquivo3.txt                                   # remoção de evidência
```

![Geração da baseline e simulação dos ataques](evidencias/05-baseline-e-simulacao-de-ataques.png)

O verificador detectou os três:

![Ataques detectados](evidencias/06-ataques-detectados.png)

#### Teste extra: timestomping

Além do conteúdo, foi alterada apenas a **data de modificação** do `arquivo1.txt` (técnica usada para esconder mudanças):

```powershell
(Get-Item C:\FIM-Lab\Monitorado\arquivo1.txt).LastWriteTime = "01/01/2020"
```

O FIM **não** acusou nada, comportamento esperado: o conteúdo não mudou, então o hash é idêntico. Isso demonstra que a detecção por hash olha o conteúdo e é independente de metadados. Também é uma limitação conhecida (veja abaixo): o FIM por hash não detecta, sozinho, a manipulação de metadados.

![Alteração de data não detectada](evidencias/07-timestomping-nao-detectado.png)

### Fase 5: registro no Event Viewer e automação

Os alertas deixam de ser apenas texto no terminal e passam a gerar eventos no log **Application**, com a origem `FIM-Lab`, que é o formato que um SIEM (Splunk, Wazuh) coleta. A execução foi automatizada com `Agendar-Tarefa.ps1` (conta SYSTEM, a cada 5 minutos).

Para validar a automação, um arquivo suspeito foi criado e **o script não foi executado manualmente**. O evento 1001 (`NOVO - backdoor.txt`) das 3:05:57 PM foi gerado pela tarefa agendada:

![Detecção automática pelo agendador](evidencias/08-deteccao-automatica-agendador.png)

Observação: os eventos das 3:02 PM se repetem para o mesmo arquivo porque o `backdoor.txt` permaneceu na pasta sem triagem. Num SOC isso é o *alert fatigue*: enquanto a mudança não for tratada (revertida ou aceita com atualização da baseline), o alerta se repete a cada ciclo.

---

## Resultados

| Ação do "atacante" | Detectado? | Evento |
|---|---|---|
| Linha adicionada em `arquivo2.txt` | Sim | 1002 (MODIFICADO) |
| `backdoor.txt` criado | Sim | 1001 (NOVO) |
| `arquivo3.txt` removido | Sim | 1003 (REMOVIDO) |
| Data de `arquivo1.txt` alterada | Não (esperado) | n/a |
| Novo arquivo criado e detectado pela tarefa agendada | Sim | 1001 (NOVO) |

---

## Mapeamento MITRE ATT&CK

| Ação simulada | Técnica |
|---|---|
| Adulteração de conteúdo de arquivo | [T1565.001](https://attack.mitre.org/techniques/T1565/001/): Stored Data Manipulation |
| Arquivo plantado na pasta vigiada (análogo a webshell/binário de persistência) | [T1505.003](https://attack.mitre.org/techniques/T1505/003/): Web Shell (por analogia) |
| Remoção de arquivo | [T1070.004](https://attack.mitre.org/techniques/T1070/004/): File Deletion |
| Alteração de data de modificação | [T1070.006](https://attack.mitre.org/techniques/T1070/006/): Timestomp (**não detectada**) |

As simulações usam arquivos de texto inofensivos; o mapeamento é conceitual, para contextualizar o que cada comportamento representaria em um incidente real.

---

## Eventos gerados

| Campo | Valor |
|---|---|
| Log | Application |
| Origem | `FIM-Lab` |
| Nível | Warning |

| Event ID | Significado |
|---|---|
| 1001 | Arquivo NOVO |
| 1002 | Arquivo MODIFICADO |
| 1003 | Arquivo REMOVIDO |

Consulta:

```powershell
Get-EventLog -LogName Application -Source "FIM-Lab" | Select-Object TimeGenerated, EventID, Message
```

Os IDs fixos permitem criar regras de detecção em um SIEM do tipo "alertar quando Event ID 1002 vier da origem FIM-Lab".

---

## Limitações

Este é um lab didático, e as limitações são parte do aprendizado:

- **A baseline não é protegida.** Está em um CSV comum. Um atacante com acesso a ela pode esconder a própria adulteração. Em produção ela ficaria em local com permissões restritas, em share separado ou assinada.
- **Verificação por polling, não em tempo real.** Uma alteração feita e revertida dentro da janela de 5 minutos passa despercebida.
- **O próprio script não é monitorado.** Alterar o `Verificar-FIM.ps1` ou desativar a tarefa agendada desliga o monitoramento sem alerta.
- **Metadados não são verificados.** O teste de timestomping mostrou que mudanças de data não geram alerta.
- **Sem rotina de atualização controlada da baseline.** Mudanças legítimas exigem regerar a baseline manualmente.
- **Sem identificação de autoria.** O FIM diz *o que* mudou, não *quem* mudou. Isso exigiria auditoria de acesso a objetos (Event ID 4663).

---

## Próximos passos

- Apontar o monitoramento para caminhos críticos do controlador de domínio, como `C:\Windows\SYSVOL\domain\Policies` (GPOs e scripts de logon), cenário relevante porque a adulteração de GPO é técnica real em ambientes de Active Directory.
- Ingerir os eventos 1001/1002/1003 em um SIEM (Splunk ou Wazuh) e criar regras de alerta.
- Habilitar auditoria de acesso a objetos para correlacionar a mudança com o usuário responsável.
- Comparar com o módulo FIM nativo do Wazuh.

---

## Aprendizados

- A baseline precisa ser gerada em um estado **conhecido como bom**; a qualidade do FIM depende dela.
- Detecção por hash é robusta contra alteração de conteúdo, mas cega a metadados.
- Alerta sem triagem vira ruído: o fluxo correto é investigar e então reverter ou aceitar (atualizando a baseline).
- IDs de evento padronizados são o que torna o dado útil para um SIEM.
- Automatizar com uma conta de serviço (SYSTEM) segue o mesmo modelo de agentes de monitoramento reais.

---

## Autor

**Ruan Carlos**: [GitHub](https://github.com/ruancarlosrc) · [LinkedIn](https://linkedin.com/in/ruan-carlos-4a9803379/) · [Portfólio](https://ruancarlosciber.com.br)
