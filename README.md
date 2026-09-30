# ForensicMCP
MCP server for Windows forensic disk imaging with ewftools.

# Windows Forensic MCP Server

Server [MCP](https://modelcontextprotocol.io) per l'acquisizione forense di dischi e volumi Windows, basato su **ewftools** (libewf). Espone a un agente LLM (Claude Desktop, Cursor, ecc.) una serie di tool controllati per:

- inventariare dischi fisici, partizioni e volumi logici (read-only);
- pianificare e validare un'acquisizione forense prima di eseguirla;
- acquisire un disco/volume in formato **E01** con `ewfacquire`;
- verificare l'integrità dell'immagine con `ewfverify`;
- estrarre metadati dell'immagine con `ewfinfo`;
- produrre report human-readable in Markdown, JSON e HTML.

L'acquisizione è **guarded**: nessuna operazione di copia parte senza un piano validato e un flag esplicito di esecuzione. La copia avviene sempre su un disco fisico **diverso** da quello sorgente.

---

## Cos'è ewftools

`ewftools` è la suite di utilità a riga di comando che accompagna la libreria open source [libewf](https://github.com/libyal/libewf), che implementa la lettura e scrittura del formato **EWF (Expert Witness Compression Format)** — il formato `.E01` usato da EnCase, FTK Imager e praticamente tutti gli strumenti forensi.

I binari usati da questo server sono presi dalla release Windows precompilata:

> **https://github.com/alpine-sec/ewf-tools/releases/tag/v20230405**

La release include:

| Binario | Ruolo |
|---|---|
| `ewfacquire` | acquisisce un device/disco in un'immagine E01 |
| `ewfacquirestream` | acquisisce da standard input |
| `ewfinfo` | mostra i metadati di un'immagine E01 |
| `ewfverify` | verifica gli hash dell'immagine rispetto alla sorgente |
| `ewfexport` | esporta un'immagine E01 in altri formati |

---

## Prerequisiti

- **Windows 10/11** (testato su Windows PowerShell 5.1)
- **Python 3.10+**
- **Privilegi di amministratore** — necessari per aprire `\\.\PHYSICALDRIVEn` in lettura
- **`ewftools` (release v20230405)** — scaricati dal link sopra
- Un agente LLM compatibile MCP (Claude Desktop, Cursor, ecc.)

---

## Installazione

### 1. Scarica ewftools

Scarica lo zip della release:

```
https://github.com/alpine-sec/ewf-tools/releases/tag/v20230405
```

Estrailo in una cartella, ad esempio:

```
C:\ewftools-x64\
```

Dentro troverai `ewfacquire.exe`, `ewfverify.exe`, `ewfinfo.exe`, ecc.

### 2. Copia il server MCP

Metti **`forensic_mcp_server.py`** nella **stessa cartella** `C:\ewftools-x64\`.

Il server cerca i binari `ewf*.exe` nella propria directory (`BASE_DIR`) prima che nel `PATH` di sistema:

```python
def locate_ewf_tool(tool_name: str) -> Path | None:
    # 1) cerca in BASE_DIR (la cartella del server)
    # 2) fallback su shutil.which() (PATH di sistema)
```

Quindi la struttura finale sarà:

```
C:\ewftools-x64\
├── ewfacquire.exe
├── ewfacquirestream.exe
├── ewfinfo.exe
├── ewfverify.exe
├── ewfexport.exe
└── forensic_mcp_server.py   ← il server MCP
```

### 3. Configura il client MCP

Aggiungi al file di configurazione del tuo client MCP (es. `claude_desktop_config.json`) il seguente blocco, sostituendo `PUT_YOUR_PYTHON_PATH` con il percorso reale del tuo `python.exe`:

```json
{
  "mcpServers": {
    "forensic_mcp_server": {
      "command": "C:\\PUT_YOUR_PYTHON_PATH\\python.exe",
      "args": [
        "C:\\ewftools-x64\\forensic_mcp_server.py"
      ]
    }
  }
}
```

> **Importante**: il server deve essere lanciato con privilegi di amministratore, altrimenti `ewfacquire` non potrà accedere ai device fisici. Avvia il client MCP (o la shell da cui lo lanci) come amministratore.

### 4. Verifica l'installazione

All'avvio del server, controlla il log `forensic_mcp_debug.log` nella cartella `C:\ewftools-x64\`. Dovresti vedere:

```
Starting Windows Forensic MCP server (ewftools version)
Python executable: C:\...\python.exe
Python version: 3.10.x ...
Server file: C:\ewftools-x64\forensic_mcp_server.py
```

Poi, dall'agente, chiedi:

> "Elenca i dischi fisici disponibili"

L'agente chiamerà `list_physical_disks` e ti restituirà l'inventario.

---

## Tool disponibili

### Inventario (read-only)

| Tool | Descrizione |
|---|---|
| `list_physical_disks` | Elenca dischi fisici, partizioni e volumi logici |
| `list_logical_volumes` | Elenca volumi logici mappati sui dischi fisici |
| `inspect_disk` | Dettagli di un singolo disco fisico |
| `inspect_source` | Snapshot dettagliato di un disco o volume selezionato |
| `inspect_destination` | Verifica spazio libero e disco che ospita la destinazione |
| `check_write_block` | Controlla lo stato write-block a livello OS |
| `inspect_ewftools` | Verifica disponibilità dei binari `ewfacquire`, `ewfverify`, `ewfinfo` |

### Acquisizione forense (guarded)

| Tool | Descrizione |
|---|---|
| `plan_acquisition` | Valida un piano di acquisizione senza eseguirlo |
| `acquire_ewf` | Avvia l'acquisizione E01 (richiede `execute=true` e `human_confirmation=plan_id`) |
| `acquisition_status` | Stato corrente dell'acquisizione + report Markdown |
| `tail_acquisition_output` | Tail in tempo reale dell'output di `ewfacquire` |
| `create_acquisition_report` | Genera il report Markdown leggibile |
| `generate_report` | Rigenera report JSON/HTML |
| `verify_ewf` | Verifica un'immagine E01 con `ewfverify` |
| `info_ewf` | Estrae metadati da un'immagine E01 con `ewfinfo` |

---

## Flusso tipico d'uso

### 1. Inventario

> "Mostrami i dischi fisici collegati"

L'agente chiama `list_physical_disks` e ti mostra la lista.

### 2. Ispezione della sorgente

> "Ispeziona il disco fisico 1"

L'agente chiama `inspect_disk(disk_number=1)` e ti mostra modello, seriale, dimensioni, interfaccia, ecc.

### 3. Pianificazione

> "Pianifica l'acquisizione del disco 1 verso `C:\testcopia\`, con case number CASE-2026-001"

L'agente chiama `plan_acquisition(...)` e ti restituisce un **plan_id** (es. `PLAN-6FEC6A7EDE62`) e una serie di check di validazione:

- sorgente trovata;
- destinazione scrivibile;
- spazio libero sufficiente;
- sorgente e destinazione su dischi fisici distinti;
- write blocker attestato (per dischi fisici).

Se un check fallisce, il piano è `valid: false` e l'acquisizione non può partire.

### 4. Esecuzione

> "Esegui l'acquisizione PLAN-6FEC6A7EDE62"

L'agente chiama:

```python
acquire_ewf(
    plan_id="PLAN-6FEC6A7EDE62",
    execute=True,
    human_confirmation="PLAN-6FEC6A7EDE62"
)
```

Il campo `human_confirmation` deve **coincidere esattamente** con il `plan_id`: è un guardrail contro avvii accidentali.

### 5. Monitoraggio

> "Mostrami l'avanzamento"

L'agente chiama `tail_acquisition_output(acquisition_id, lines=30)` e ti mostra le ultime righe del file di output di `ewfacquire` in tempo reale.

### 6. Report finale

Al termine, il server produce automaticamente:

- `forensic_reports/ACQ-XXXX_YYYYMMDD_HHMMSS.json` — record machine-readable completo
- `forensic_reports/ACQ-XXXX_YYYYMMDD_HHMMSS.html` — report stampabile da browser
- `forensic_reports/forensic_audit.jsonl` — audit log append-only di tutte le operazioni

> "Crea il report per ACQ-XXXX"

L'agente chiama `create_acquisition_report` e ti restituisce un report Markdown con tabelle human-readable, inclusa la sezione **Digest hash** con MD5 e SHA256 affiancati e l'esito della verifica (✅ OK / ❌ MISMATCH).

---

## Sicurezza e guardrail

Il server implementa diversi livelli di protezione:

1. **Piano obbligatorio**: nessuna acquisizione parte senza un `plan_acquisition` valido.
2. **Flag espliciti**: `execute=true` e `human_confirmation == plan_id`.
3. **Dischi distinti**: sorgente e destinazione devono trovarsi su dischi fisici diversi (blocco hard-coded).
4. **Write blocker attestato**: per l'acquisizione di dischi fisici, l'operatore deve attestare la presenza di un hardware write blocker (`hardware_write_blocker_attested=True`). Windows non può verificarlo da solo.
5. **Audit log**: ogni operazione viene registrata in `forensic_audit.jsonl` con timestamp UTC.
6. **Server elevated**: il server MCP deve girare con privilegi di amministratore; l'acquisizione non tenta elevazioni UAC a runtime.

---

## Struttura dei file prodotti

```
C:\ewftools-x64\
├── forensic_mcp_server.py
├── forensic_mcp_debug.log            ← log di debug del server
├── forensic_reports\                 ← directory di output
│   ├── PLAN-XXXX.json                ← piani di acquisizione
│   ├── ACQ-XXXX_YYYYMMDD_HHMMSS.json ← report JSON
│   ├── ACQ-XXXX_YYYYMMDD_HHMMSS.html ← report HTML
│   └── forensic_audit.jsonl          ← audit log append-only
├── ewfacquire.exe
├── ewfverify.exe
└── ewfinfo.exe
```

I file `*_output.txt` e `*_errors.txt` generati durante l'acquisizione si trovano nella **cartella di destinazione** scelta nel piano (es. `C:\testcopia\`).

---

## Note

- Il server usa il formato **E01** con hash **MD5 + SHA256** calcolati durante l'acquisizione.
- La verifica post-acquisizione (`ewfverify`) è opzionale ma consigliata: può richiedere ore su immagini grandi.
- Il server non modifica mai la sorgente: l'apertura di `\\.\PHYSICALDRIVEn` avviene solo in lettura tramite `ewfacquire`.
- Per ambienti di produzione si raccomanda di lanciare il server su una workstation forense dedicata, con write blocker hardware collegato alla sorgente.

---

## Licenza

Il codice del server MCP è distribuito sotto licenza MIT. I binari `ewftools` sono distribuiti da [alpine-sec/ewf-tools](https://github.com/alpine-sec/ewf-tools) e seguono la licenza di libewf (LGPL).
