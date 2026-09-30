# ForensicMCP
MCP server for Windows forensic disk imaging with ewftools.

# Windows Forensic MCP Server

**[ENGLISH](#english) | [ITALIANO](#italiano)**

---
<a id="italiano"></a>
# Windows Forensic MCP Server
# ATTENZIONE: il programma non ha nessuna garanzia, fate i test su macchine di prova, sotto la vostra completa responsabilità.

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
- Un agente LLM compatibile MCP (Claude Desktop, Cursor, Unsloth, ecc.)
- pip install -r requirements.txt

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

Il codice del server MCP è distribuito sotto licenza Apache 2.0. I binari `ewftools` sono distribuiti da [alpine-sec/ewf-tools](https://github.com/alpine-sec/ewf-tools) e seguono la licenza di libewf (LGPL).

<a id="english"></a>
## ENGLISH
# WARNING: The program comes with no warranty; perform tests on test machines at your own risk
```markdown
# Windows Forensic MCP Server
.

An MCP server for the forensic acquisition of Windows disks and volumes, built on `ewftools` (`libewf`). It exposes a set of controlled tools to LLM agents (Claude Desktop, Cursor, etc.) to:
- Inventory physical disks, partitions, and logical volumes (read-only).
- Plan and validate a forensic acquisition before execution.
- Acquire a disk/volume in E01 format using `ewfacquire`.
- Verify image integrity using `ewfverify`.
- Extract image metadata using `ewfinfo`.
- Generate human-readable reports in Markdown, JSON, and HTML formats.

Acquisition is **guarded**: no copy operation starts without a validated plan and an explicit execution flag. Copying is strictly restricted to a target physical disk different from the source.

---

## What is ewftools

`ewftools` is the command-line utility suite accompanying the open-source library `libewf`, which implements reading and writing for the EWF (Expert Witness Compression Format) — the `.E01` format used by EnCase, FTK Imager, and virtually all digital forensics tools.

The binaries used by this server are taken from the pre-compiled Windows release:  
👉 [ewf-tools Release v20230405](https://github.com/alpine-sec/ewf-tools/releases/tag/v20230405)

The release includes:

| Binary | Role |
| :--- | :--- |
| **`ewfacquire`** | Acquires a device/disk into an E01 image |
| **`ewfacquirestream`** | Acquires from standard input |
| **`ewfinfo`** | Displays metadata of an E01 image |
| **`ewfverify`** | Verifies image hashes against the source |
| **`ewfexport`** | Exports an E01 image to other formats |

---

## Prerequisites

- **Windows 10/11** (tested on Windows PowerShell 5.1)
- **Python 3.10+**
- **Administrator Privileges** — required to open `\\.\PHYSICALDRIVEn` for raw read access.
- **`ewftools` (v20230405 release)** — downloaded from the link above.
- An **MCP-compatible LLM Client** (Claude Desktop, Cursor, UnSloth, etc.)
- pip install -r requirements.txt
---

## Installation

### 1. Download ewftools
Download the release ZIP from:  
https://github.com/alpine-sec/ewf-tools/releases/tag/v20230405

Extract it into a folder, for example:
`C:\ewftools-x64\`

Inside, you will find `ewfacquire.exe`, `ewfverify.exe`, `ewfinfo.exe`, etc.

### 2. Copy the MCP Server
Place `forensic_mcp_server.py` inside the same directory (`C:\ewftools-x64\`).  
The server checks its own directory (`BASE_DIR`) for `ewf*.exe` binaries before falling back to the system `PATH`:

```python
def locate_ewf_tool(tool_name: str) -> Path | None:
    # 1) Look in BASE_DIR (server directory)
    # 2) Fallback to shutil.which() (system PATH)

```

The final directory structure should look like this:

```text
C:\ewftools-x64\
├── ewfacquire.exe
├── ewfacquirestream.exe
├── ewfinfo.exe
├── ewfverify.exe
├── ewfexport.exe
└── forensic_mcp_server.py   ← MCP Server

```

### 3. Configure the MCP Client

Add the following configuration block to your MCP client's config file (e.g., `claude_desktop_config.json`), replacing `PUT_YOUR_PYTHON_PATH` with the actual path to your `python.exe`:

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

> **Important:** The server must be executed with Administrator privileges, otherwise `ewfacquire` will not be able to access physical raw devices. Launch your MCP client (or terminal) as Administrator.

### 4. Verify Installation

Upon server startup, check the log file `forensic_mcp_debug.log` located at `C:\ewftools-x64\`. You should see lines like:

```text
Starting Windows Forensic MCP server (ewftools version)
Python executable: C:\...\python.exe
Python version: 3.10.x ...
Server file: C:\ewftools-x64\forensic_mcp_server.py

```

Then, ask the agent:

> *"List available physical disks"*

The agent will invoke `list_physical_disks` and return the drive inventory.

---

## Available Tools

### Inventory (Read-Only)

| Tool | Description |
| --- | --- |
| `list_physical_disks` | Lists physical disks, partitions, and logical volumes |
| `list_logical_volumes` | Lists logical volumes mapped to physical disks |
| `inspect_disk` | Displays detailed info about a single physical disk |
| `inspect_source` | Provides a detailed snapshot of a selected disk or volume |
| `inspect_destination` | Verifies target path free space and hosting disk |
| `check_write_block` | Checks system-level write-blocker state |
| `inspect_ewftools` | Verifies availability of `ewfacquire`, `ewfverify`, `ewfinfo` binaries |

### Forensic Acquisition (Guarded)

| Tool | Description |
| --- | --- |
| `plan_acquisition` | Validates an acquisition plan without executing it |
| `acquire_ewf` | Starts E01 acquisition (requires `execute=true` and `human_confirmation=plan_id`) |
| `acquisition_status` | Returns current acquisition status + Markdown report |
| `tail_acquisition_output` | Real-time tailing of `ewfacquire` output |
| `create_acquisition_report` | Generates a human-readable Markdown report |
| `generate_report` | Regenerates JSON/HTML reports |
| `verify_ewf` | Verifies an E01 image using `ewfverify` |
| `info_ewf` | Extracts metadata from an E01 image using `ewfinfo` |

---

## Typical Workflow

### 1. Inventory

> *"Show me connected physical disks"*
> The agent calls `list_physical_disks` and displays the inventory.

### 2. Inspect Source

> *"Inspect physical disk 1"*
> The agent calls `inspect_disk(disk_number=1)` and displays the drive model, serial number, size, interface, etc.

### 3. Planning

> *"Plan the acquisition of disk 1 to C:\testcopia, using case number CASE-2026-001"*
> The agent calls `plan_acquisition(...)` and returns a `plan_id` (e.g., `PLAN-6FEC6A7EDE62`) alongside a series of validation checks:

* Source found
* Target directory writable
* Sufficient free disk space
* Source and target reside on distinct physical disks
* Hardware write blocker attested (for physical disks)

If any check fails, `valid: false` is returned, and execution is blocked.

### 4. Execution

> *"Execute acquisition PLAN-6FEC6A7EDE62"*
> The agent calls:

```python
acquire_ewf(
    plan_id="PLAN-6FEC6A7EDE62",
    execute=True,
    human_confirmation="PLAN-6FEC6A7EDE62"
)

```

> **Note:** The `human_confirmation` string must match the `plan_id` exactly — acting as a safeguard against accidental execution.

### 5. Monitoring

> *"Show me the progress"*
> The agent calls `tail_acquisition_output(acquisition_id, lines=30)` to show real-time output lines from the active `ewfacquire` process.

### 6. Final Reporting

Upon completion, the server automatically produces:

* `forensic_reports/ACQ-XXXX_YYYYMMDD_HHMMSS.json` — complete machine-readable record
* `forensic_reports/ACQ-XXXX_YYYYMMDD_HHMMSS.html` — browser-printable HTML report
* `forensic_reports/forensic_audit.jsonl` — append-only audit log tracking all actions

> *"Create the report for ACQ-XXXX"*
> The agent calls `create_acquisition_report` and outputs a formatted Markdown report complete with tables, including side-by-side **MD5** and **SHA256** hash comparisons and verification status (✅ OK / ❌ MISMATCH).

---

## Security & Safeguards

The server incorporates several layers of protective guardrails:

* **Mandatory Planning:** No acquisition can run without a valid `plan_acquisition`.
* **Explicit Confirmation Flags:** Requires `execute=true` AND `human_confirmation == plan_id`.
* **Distinct Drives:** Source and target must reside on separate physical drives (hard-coded block).
* **Attested Write Blocker:** For physical disk acquisitions, operators must explicitly attest the presence of a hardware write blocker (`hardware_write_blocker_attested=True`).
* **Audit Logging:** Every single operation is appended to `forensic_audit.jsonl` with UTC timestamps.
* **Elevated Context Requirement:** The MCP server must run with Administrator privileges; it does not attempt runtime UAC elevation.

---

## Generated File Structure

```text
C:\ewftools-x64\
├── forensic_mcp_server.py
├── forensic_mcp_debug.log            ← Server debug logs
├── forensic_reports\                 ← Output directory
│   ├── PLAN-XXXX.json                ← Acquisition plans
│   ├── ACQ-XXXX_YYYYMMDD_HHMMSS.json ← Full JSON reports
│   ├── ACQ-XXXX_YYYYMMDD_HHMMSS.html ← Printable HTML reports
│   └── forensic_audit.jsonl          ← Append-only audit log
├── ewfacquire.exe
├── ewfverify.exe
└── ewfinfo.exe

```

> File outputs like `*_output.txt` and `*_errors.txt` created during raw acquisition are saved in the target destination path selected in the plan (e.g., `C:\testcopia\`).

---

## Notes

* The server utilizes the **E01 format** with **MD5 + SHA256** hash calculations calculated during acquisition.
* Post-acquisition verification (`ewfverify`) is optional but strongly recommended; it may take hours depending on image size.
* The server **never modifies source drives**: raw disk handles (`\\.\PHYSICALDRIVEn`) are opened exclusively in read-only mode via `ewfacquire`.
* For production environments, running the server on a dedicated forensic workstation equipped with a physical hardware write blocker connected to the source drive is highly recommended.

---

## License

The MCP server code is distributed under the **Apache 2.0 License**.

The `ewftools` binaries are distributed by `alpine-sec/ewf-tools` under the `libewf` **LGPL License**.

```

```
