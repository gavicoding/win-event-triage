# win-event-triage

**Português** | [English](README.md)

[![CI](https://github.com/gavicoding/win-event-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/win-event-triage/actions/workflows/ci.yml)
![PowerShell 5.1 | 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-dc2626)
![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-green)

**Arraste os logs `.evtx` do Windows para uma página e tenha a primeira triagem do incidente em segundos, sem instalar nada e sem os logs saírem do seu computador.** As mesmas 23 verificações mapeadas ao MITRE ATT&CK também rodam como linha de comando em Python, sem dependências (Windows, Linux e macOS), e como módulo PowerShell.

🌐 **[Abrir a bancada no navegador (nada é enviado)](https://gavicoding.github.io/win-event-triage/)**

![Bancada do win-event-triage no navegador](docs/screenshot.png)

## Para que serve

Quando há suspeita de incidente em Windows ou Active Directory, você precisa de respostas rápidas. Só que os logs são sensíveis e a maioria das ferramentas pede instalação, agente ou envio para a nuvem. O `win-event-triage` lê os arquivos `.evtx` direto (leitor próprio, sem depender da API do Windows), responde às primeiras perguntas de sempre e diz o que fazer em seguida:

- Houve tentativa de senha em massa (`4625`) seguida de logon aceito (`4624`)? Teve RDP vindo da internet (`4624` tipo 10, `1149`)?
- Kerberoasting com RC4 (`4769` `0x17`), dump de LSASS/NTDS, DCSync (`4662`)?
- Administrador novo (`4728`/`4732`), serviço suspeito (`7045`), tarefa agendada (`4698`), chave Run (Sysmon `13`)?
- PowerShell ofuscado (`4104`), LOLBins, shadow copies apagadas, Defender ou log de eventos desligados, nota de resgate criada?

Tudo é **somente leitura**. Nomes de máquinas e contas podem virar hashes SHA-256 (`--anonymize` / `-Anonymize`) antes de você compartilhar o relatório.

## Como usar

### No navegador

Abra a [bancada](https://gavicoding.github.io/win-event-triage/) e arraste um ou mais arquivos `.evtx`, `.xml` do Visualizador de Eventos ou JSON para a página. A leitura acontece na própria aba (cerca de 1 segundo para um log de 20 MB). O botão **Abrir .evtx de exemplo** mostra um cenário de ransomware.

### Linha de comando em Python (Windows, Linux e macOS)

```bash
pipx install git+https://github.com/gavicoding/win-event-triage

win-event-triage triage Security.evtx System.evtx --lang pt
win-event-triage triage C:\Logs\ --format html --output relatorio.html --lang pt   # uma pasta inteira
win-event-triage triage evidencias/ --anonymize --format json -o triagem.json
win-event-triage demo --lang pt
```

### PowerShell (Windows PowerShell 5.1 e PowerShell 7+)

```powershell
Import-Module .\WinEventTriage\WinEventTriage.psd1 -Force

Invoke-WinEventTriage -EvtxPath C:\Logs\Security.evtx -OutputDir .\relatorios -Language pt -Anonymize
Export-WinEventSnapshot -Hours 24 -OutputPath .\snapshot.json   # ao vivo, só leitura
Invoke-WinEventTriage -SnapshotPath .\snapshot.json -OutputDir .\relatorios -Language pt
```

## 23 regras de detecção (MITRE ATT&CK)

| Regra | Gravidade | Eventos | Tática / Técnica | O que indica |
|---|---|---|---|---|
| `WET001` | Alta | `4625` | Credential Access / `T1110.001` | Rajada de força bruta ou password spray |
| `WET002` | Crítica | `4625` -> `4624` | Credential Access / `T1110` | Várias falhas seguidas de logon aceito |
| `WET003` | Crítica | `4769` | Credential Access / `T1558.003` | Kerberoasting com RC4 (`0x17`) |
| `WET004` | Alta | `4740` | Credential Access / `T1110` | Onda de bloqueios de conta |
| `WET005` | Crítica | `4656, 4663, 4688, 4104`, Sysmon `1`, `10` | Credential Access / `T1003.001` | Dump de credenciais (LSASS / NTDS.dit) |
| `WET006` | Crítica | `4728, 4732, 4756` | Persistence / `T1098` | Grupo privilegiado alterado |
| `WET007` | Alta | `4720` + `4728/4732` | Persistence / `T1136` | Conta criada fora de hora ou promovida logo em seguida |
| `WET008` | Alta | `7045, 4697` | Persistence / `T1543.003` | Serviço apontando para pasta temporária ou gravável |
| `WET009` | Alta | `4698, 4702, 106` | Persistence / `T1053.005` | Tarefa agendada suspeita |
| `WET010` | Crítica | `1102, 104` | Defense Evasion / `T1070.001` | Log de eventos apagado |
| `WET011` | Crítica | `4688, 4104`, Sysmon `1` | Impact / `T1490` | Shadow copies apagadas / recuperação desligada |
| `WET012` | Crítica | `5001, 5007, 5010, 5012` | Defense Evasion / `T1562.001` | Proteção do Defender desligada |
| `WET013` | Alta | `4719` | Defense Evasion / `T1562.002` | Política de auditoria alterada |
| `WET014` | Crítica | `4104, 4688`, Sysmon `1` | Execution / `T1059.001` | PowerShell ofuscado ou baixando código |
| `WET015` | Alta | `4624, 4648` | Lateral Movement / `T1021.001` | RDP (tipo 10) vindo da internet ou credenciais explícitas |
| `WET016` | Alta | `4688`, Sysmon `1` | Defense Evasion / `T1218` | Abuso de LOLBin (`certutil`, `mshta`, `bitsadmin`, `wmic`) |
| `WET017` | Média | `4672` | Initial Access / `T1078` | Logon administrativo fora do expediente |
| `WET018` | Crítica | `4662` | Credential Access / `T1003.006` | DCSync a partir de conta que não é controlador de domínio |
| `WET019` | Alta | `1149, 4778` | Lateral Movement / `T1021.001` | RDP autenticado ou reconectado a partir de IP da internet |
| `WET020` | Alta | Sysmon `13`, `4657` | Persistence / `T1547.001` | Programa configurado para iniciar sozinho (Run / RunOnce / Winlogon) |
| `WET021` | Crítica | Sysmon `11` | Impact / `T1486` | Nota de resgate ou arquivo com extensão de ransomware |
| `WET022` | Alta | `1116, 1117` | Execution / `T1204.002` | Malware detectado pelo Defender |
| `WET023` | Alta | `7040, 7036` | Defense Evasion / `T1562.001` | Defender, log de eventos, firewall ou Sysmon parado ou desativado |

IDs de evento que vários programas reaproveitam (104, 106, 1/3/10/11/13, 5001, 7045...) só contam quando vêm do provedor certo. É isso que mantém os falsos alarmes baixos em máquinas reais.

## Como o leitor de `.evtx` foi conferido

O `src/win_event_triage/evtx.py` e o `docs/evtx.js` implementam o formato EVTX (cabeçalho, chunks de 64 KB, registros, BinXML com templates e substituições, listas de texto e BinXML embutido). Os dois foram comparados com o próprio `Get-WinEvent` do Windows em 83.950 eventos reais dos logs System, Application e PowerShell: ID, horário, computador, provedor, canal e todos os valores de `EventData` bateram em 100% dos casos. Trechos danificados do arquivo são pulados em vez de interromper a análise.

O `tools/make_sample_evtx.py` faz o caminho inverso: gera arquivos `.evtx` válidos a partir de um JSON (o Visualizador de Eventos do Windows abre). Os exemplos em `samples/` são fictícios e são gerados de novo no CI para provar que dá para reproduzir.

## Desenvolvimento e testes

```bash
PYTHONPATH=src python -m unittest discover -s tests/python -v
node tests/test_web_engine.mjs
pwsh -c "Invoke-Pester tests/powershell"
```

Licença MIT. Feito por [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
