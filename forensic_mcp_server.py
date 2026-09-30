from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    BaseModel = None
    Field = None


mcp = MCPServer(
    "windows-forensic",
    title="Windows Forensic MCP",
    description=(
        "Windows forensic acquisition MCP server using ewftools. Inventory is read-only; "
        "acquisition is guarded by a validation plan and explicit execution flag."
    ),
)

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "forensic_mcp_debug.log"
REPORT_DIR = BASE_DIR / "forensic_reports"
REPORT_DIR.mkdir(exist_ok=True)

# In-memory job registry. The actual case record is also persisted to JSON files.
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def debug(message: str) -> None:
    line = f"[{utc_now()}] {message}"
    print(line, file=sys.stderr, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def audit(event: str, payload: dict[str, Any]) -> None:
    record = {
        "timestamp_utc": utc_now(),
        "event": event,
        **payload,
    }
    path = REPORT_DIR / "forensic_audit.jsonl"
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        debug(f"Audit write failed: {exc}")


# ============================================================
# POWERSHELL
# ============================================================

def powershell_json(script: str) -> Any:
    """
    Execute Windows PowerShell 5.1 and parse JSON.

    This version deliberately does NOT import the Storage module.
    It uses CIM/WMI classes instead.
    """

    powershell_exe = (
        r"C:\Windows\System32\WindowsPowerShell\v1.0"
        r"\powershell.exe"
    )

    debug(f"PowerShell executable: {powershell_exe}")

    try:
        result = subprocess.run(
            [
                powershell_exe,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Windows PowerShell 5.1 not found: {powershell_exe}"
        ) from e
    except Exception as e:
        raise RuntimeError(
            f"Unable to start PowerShell: {type(e).__name__}: {e}"
        ) from e

    debug(f"PowerShell return code: {result.returncode}")

    if result.stderr.strip():
        debug("PowerShell STDERR:\n" + result.stderr.strip())

    if result.returncode != 0:
        raise RuntimeError(
            "PowerShell execution failed.\n"
            f"Return code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout.strip() or '(empty)'}\n"
            f"STDERR:\n{result.stderr.strip() or '(empty)'}"
        )

    stdout = result.stdout.strip()

    if not stdout:
        return []

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"PowerShell returned invalid JSON.\nSTDOUT:\n{stdout}"
        ) from e


# ============================================================
# CIM DISK INVENTORY
# ============================================================

DISK_QUERY = r"""
$ErrorActionPreference = 'Stop'

# Physical disks
$physicalDisks = @(
    Get-CimInstance Win32_DiskDrive
)

# Partitions
$partitions = @(
    Get-CimInstance Win32_DiskPartition
)

# Logical volumes
$logicalDisks = @(
    Get-CimInstance Win32_LogicalDisk
)

# Build result
$result = foreach ($disk in $physicalDisks) {

    $deviceId = [string]$disk.DeviceID

    if ($deviceId -match 'PHYSICALDRIVE(\d+)') {
        $diskNumber = [int]$Matches[1]
    }
    else {
        $diskNumber = -1
    }

    $diskPartitions = @(
        $partitions |
            Where-Object {
                $_.DiskIndex -eq $disk.Index
            }
    )

    $partitionResults = foreach ($partition in $diskPartitions) {

        $logicalResults = @()

        try {
            $logicalResults = @(
                Get-CimAssociatedInstance `
                    -InputObject $partition `
                    -Association Win32_LogicalDiskToPartition `
                    -ResultClassName Win32_LogicalDisk `
                    -ErrorAction SilentlyContinue
            )
        }
        catch {
            $logicalResults = @()
        }

        $logicalResultObjects = foreach ($logical in $logicalResults) {
            [PSCustomObject]@{
                drive_letter = [string]$logical.DeviceID
                filesystem = [string]$logical.FileSystem
                volume_label = [string]$logical.VolumeName
                volume_serial = [string]$logical.VolumeSerialNumber
                volume_size_bytes = if ($logical.Size) { [int64]$logical.Size } else { $null }
                free_space_bytes = if ($logical.FreeSpace) { [int64]$logical.FreeSpace } else { $null }
            }
        }

        [PSCustomObject]@{
            partition_number = [int]$partition.Index
            device_id = [string]$partition.DeviceID
            type = [string]$partition.Type
            boot_partition = [bool]$partition.BootPartition
            primary_partition = [bool]$partition.PrimaryPartition
            size_bytes = if ($partition.Size) { [int64]$partition.Size } else { $null }
            starting_offset_bytes = if ($partition.StartingOffset) { [int64]$partition.StartingOffset } else { $null }
            logical_disks = @($logicalResultObjects)
        }
    }

    $pnpDeviceId = [string]$disk.PNPDeviceID
    $interfaceType = [string]$disk.InterfaceType
    $mediaType = [string]$disk.MediaType

    $usbCandidate = ($pnpDeviceId -match '^USB') -or ($interfaceType -eq 'USB')

    [PSCustomObject]@{
        disk_number = $diskNumber
        device_path = $deviceId
        model = [string]$disk.Model
        manufacturer = [string]$disk.Manufacturer
        serial = [string]$disk.SerialNumber
        interface_type = $interfaceType
        media_type = $mediaType
        pnp_device_id = $pnpDeviceId
        size_bytes = if ($disk.Size) { [int64]$disk.Size } else { $null }
        index = [int]$disk.Index
        partitions = @($partitionResults)
        usb_candidate = [bool]$usbCandidate
    }
}

$result | ConvertTo-Json -Depth 12 -Compress
"""


def human_size(value: Any) -> str | None:
    if value is None:
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"


def normalize_collection(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def inventory() -> list[dict[str, Any]]:
    raw = normalize_collection(powershell_json(DISK_QUERY))
    normalized: list[dict[str, Any]] = []
    for disk in raw:
        disk = dict(disk)
        disk["partitions"] = normalize_collection(disk.get("partitions"))
        for part in disk["partitions"]:
            part["logical_disks"] = normalize_collection(part.get("logical_disks"))
        normalized.append(disk)
    return normalized


def disk_by_number(disk_number: int) -> dict[str, Any]:
    for disk in inventory():
        if int(disk.get("disk_number", -1)) == int(disk_number):
            return disk
    raise ValueError(f"PhysicalDrive{disk_number} non trovato")


def find_logical_drive(letter: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    letter = letter.strip().upper()
    if not letter.endswith(":"):
        letter += ":"
    for disk in inventory():
        for part in disk.get("partitions", []):
            for logical in part.get("logical_disks", []):
                if str(logical.get("drive_letter", "")).upper() == letter:
                    return disk, part, logical
    raise ValueError(f"Volume logico {letter} non trovato")


def powershell_readonly_state(disk_number: int) -> dict[str, Any]:
    script = f"""
$ErrorActionPreference = 'Stop'
$d = Get-CimInstance -Namespace 'root/Microsoft/Windows/Storage' -ClassName MSFT_Disk -Filter 'Number = {int(disk_number)}'
if ($null -eq $d) {{ @() | ConvertTo-Json -Compress }}
else {{
  [PSCustomObject]@{{
    number = [int]$d.Number
    is_read_only = [bool]$d.IsReadOnly
    is_offline = [bool]$d.IsOffline
    operational_status = @($d.OperationalStatus)
    health_status = @($d.HealthStatus)
    partition_style = [string]$d.PartitionStyle
    bus_type = [string]$d.BusType
  }} | ConvertTo-Json -Depth 8 -Compress
}}
"""
    try:
        raw = normalize_collection(powershell_json(script))
        return raw[0] if raw else {"available": False}
    except Exception as exc:
        return {
            "available": False,
            "error": str(exc),
        }


def resolve_destination(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError("La destinazione deve essere un percorso assoluto")

    drive = os.path.splitdrive(str(p))[0]
    if not drive or len(drive) < 2 or drive[1] != ":":
        raise ValueError("La destinazione deve appartenere a un drive Windows, es. F:\\...")
    drive_letter = drive[:2].upper()
    root = Path(drive_letter + "\\")
    if not root.exists():
        raise ValueError(f"Drive destinazione {drive_letter} non disponibile")

    disk, partition, logical = find_logical_drive(drive_letter)
    free_space = logical.get("free_space_bytes")
    exists = p.exists()
    writable = False
    if exists:
        writable = os.access(str(p), os.W_OK)
    else:
        probe = p
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        writable = os.access(str(probe), os.W_OK) if probe.exists() else False

    return {
        "path": str(p),
        "drive_letter": drive_letter,
        "exists": exists,
        "writable": writable,
        "filesystem": logical.get("filesystem"),
        "volume_label": logical.get("volume_label"),
        "volume_size_bytes": logical.get("volume_size_bytes"),
        "free_space_bytes": free_space,
        "destination_disk_number": disk.get("disk_number"),
        "destination_partition_number": partition.get("partition_number"),
        "destination_disk_model": disk.get("model"),
        "destination_disk_serial": disk.get("serial"),
        "destination_disk_size_bytes": disk.get("size_bytes"),
        "destination_disk_size_human": human_size(disk.get("size_bytes")),
    }


def source_from_spec(source_type: str, disk_number: int | None, drive_letter: str | None) -> dict[str, Any]:
    if source_type == "physical_disk":
        if disk_number is None:
            raise ValueError("disk_number richiesto per physical_disk")
        disk = disk_by_number(int(disk_number))
        return {
            "source_type": source_type,
            "disk_number": disk.get("disk_number"),
            "device_path": disk.get("device_path"),
            "model": disk.get("model"),
            "manufacturer": disk.get("manufacturer"),
            "serial": disk.get("serial"),
            "interface_type": disk.get("interface_type"),
            "media_type": disk.get("media_type"),
            "firmware_revision": disk.get("firmware_revision"),
            "pnp_device_id": disk.get("pnp_device_id"),
            "size_bytes": disk.get("size_bytes"),
            "size_human": human_size(disk.get("size_bytes")),
            "bytes_per_sector": disk.get("bytes_per_sector"),
            "partitions": disk.get("partitions", []),
            "usb_candidate": disk.get("usb_candidate"),
        }

    if source_type == "logical_volume":
        if not drive_letter:
            raise ValueError("drive_letter richiesto per logical_volume")
        disk, partition, logical = find_logical_drive(drive_letter)
        
        # Per i volumi logici su Windows, il device path usato da ewftools è della forma \\.\E:
        clean_letter = logical.get("drive_letter", "").rstrip("\\")
        dev_path = f"\\\\.\\{clean_letter}" if clean_letter else disk.get("device_path")

        return {
            "source_type": source_type,
            "drive_letter": logical.get("drive_letter"),
            "filesystem": logical.get("filesystem"),
            "volume_label": logical.get("volume_label"),
            "volume_serial": logical.get("volume_serial"),
            "volume_size_bytes": logical.get("volume_size_bytes"),
            "volume_size_human": human_size(logical.get("volume_size_bytes")),
            "free_space_bytes": logical.get("free_space_bytes"),
            "disk_number": disk.get("disk_number"),
            "device_path": dev_path,
            "model": disk.get("model"),
            "manufacturer": disk.get("manufacturer"),
            "serial": disk.get("serial"),
            "interface_type": disk.get("interface_type"),
            "media_type": disk.get("media_type"),
            "firmware_revision": disk.get("firmware_revision"),
            "pnp_device_id": disk.get("pnp_device_id"),
            "physical_size_bytes": disk.get("size_bytes"),
            "physical_size_human": human_size(disk.get("size_bytes")),
            "partition": partition,
            "usb_candidate": disk.get("usb_candidate"),
        }

    raise ValueError("source_type deve essere physical_disk oppure logical_volume")

def estimate_required_bytes(source: dict[str, Any], compression_level: int) -> int:
    size = source.get("size_bytes") or source.get("volume_size_bytes") or source.get("physical_size_bytes")
    if not size:
        return 0
    return int(size)

def tail_file(path: Path, lines: int = 50) -> dict[str, Any]:
    """Legge le ultime N righe di un file di testo, senza caricarlo tutto in memoria."""
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "size_bytes": 0,
            "lines": [],
        }

    try:
        size = path.stat().st_size
        # Legge a blocchi dall'inizio e tiene un buffer delle ultime N righe.
        # Per file grossi evita di caricare tutto: legge dalla fine a blocchi.
        block = 8192
        data = b""
        with path.open("rb") as f:
            if size > block:
                f.seek(-block, os.SEEK_END)
            data = f.read()

        # Decodifica permissiva: ewfacquire a volte scrive progress in ASCII
        text = data.decode("utf-8", errors="replace")

        # Se abbiamo tagliato l'inizio di una riga, scartiamo la prima riga parziale
        all_lines = text.splitlines()
        if size > block and len(all_lines) > 1:
            all_lines = all_lines[1:]

        return {
            "path": str(path),
            "exists": True,
            "size_bytes": size,
            "lines": all_lines[-lines:],
        }
    except Exception as exc:
        return {
            "path": str(path),
            "exists": True,
            "error": f"{type(exc).__name__}: {exc}",
            "lines": [],
        }
        
def make_report(acquisition_id: str, record: dict[str, Any]) -> dict[str, str]:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"{acquisition_id}_{stamp}.json"
    html_path = REPORT_DIR / f"{acquisition_id}_{stamp}.html"

    # Inserisce i path nel record PRIMA di serializzare, così il JSON
    # contiene il riferimento a se stesso e all'HTML.
    reports = {
        "json_report": str(json_path),
        "html_report": str(html_path),
    }
    record["reports"] = reports

    serializable = json.dumps(record, ensure_ascii=False, indent=2)
    json_path.write_text(serializable, encoding="utf-8")

    source = record.get("source", {})
    dest = record.get("destination", {})
    verification = record.get("verification", {})
    info = record.get("info", {})

    def row(label: str, value: Any) -> str:
        return f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(value))}</td></tr>"

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Forensic Acquisition Report {html.escape(acquisition_id)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:32px}}h1{{margin-bottom:4px}}h2{{margin-top:28px}}table{{border-collapse:collapse;width:100%;max-width:1100px}}th,td{{border:1px solid #ccc;padding:7px;text-align:left;vertical-align:top}}th{{width:260px}}pre{{background:#f6f6f6;padding:12px;overflow:auto}}</style>
</head><body>
<h1>Forensic Acquisition Report (ewftools)</h1>
<div><strong>Acquisition ID:</strong> {html.escape(acquisition_id)}</div>
<div><strong>Generated UTC:</strong> {html.escape(utc_now())}</div>
<h2>Source physical characteristics</h2>
<table>
{row('Source type', source.get('source_type'))}
{row('Physical disk', source.get('disk_number'))}
{row('Device path', source.get('device_path'))}
{row('Manufacturer', source.get('manufacturer'))}
{row('Model', source.get('model'))}
{row('Serial number', source.get('serial'))}
{row('Firmware revision', source.get('firmware_revision'))}
{row('Interface', source.get('interface_type'))}
{row('Media type', source.get('media_type'))}
{row('USB candidate', source.get('usb_candidate'))}
{row('Physical size', source.get('size_human', source.get('physical_size_human')))}
{row('Physical size (bytes)', source.get('size_bytes', source.get('physical_size_bytes')))}
{row('Volume size', source.get('volume_size_human'))}
{row('Volume size (bytes)', source.get('volume_size_bytes'))}
{row('Filesystem', source.get('filesystem'))}
{row('Volume label', source.get('volume_label'))}
</table>
<h2>Destination</h2>
<table>
{row('Path', dest.get('path'))}
{row('Drive letter', dest.get('drive_letter'))}
{row('Destination physical disk', dest.get('destination_disk_number'))}
{row('Destination disk model', dest.get('destination_disk_model'))}
{row('Destination disk serial', dest.get('destination_disk_serial'))}
{row('Filesystem', dest.get('filesystem'))}
{row('Free space', human_size(dest.get('free_space_bytes')))}
{row('Free space (bytes)', dest.get('free_space_bytes'))}
</table>
<h2>Acquisition Details</h2>
<pre>{html.escape(json.dumps(record.get('image', {}), ensure_ascii=False, indent=2))}</pre>
<h2>Verification</h2>
<pre>{html.escape(json.dumps(verification, ensure_ascii=False, indent=2))}</pre>
<h2>EWF Info (Image Metadata)</h2>
<pre>{html.escape(json.dumps(info, ensure_ascii=False, indent=2))}</pre>
<h2>Validation checks</h2>
<pre>{html.escape(json.dumps(record.get('checks', {}), ensure_ascii=False, indent=2))}</pre>
<h2>Full machine-readable record</h2>
<pre>{html.escape(serializable)}</pre>
</body></html>"""
    html_path.write_text(html_doc, encoding="utf-8")
    return {"json_report": str(json_path), "html_report": str(html_path)}

# ewfverify stampa righe del tipo:
#   MD5 hash stored in file:      <hex>
#   MD5 hash calculated over data: <hex>
#   SHA256 hash stored in file:   <hex>
#   SHA256 hash calculated over data: <hex>
HASH_RE = re.compile(
    r"^(MD5|SHA1|SHA256|SHA512)\s+hash\s+"
    r"(stored in file|calculated over data)\s*:\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)

# Formato "Additional hash values:" -> "MD5:      <hex>"
ADDITIONAL_HASH_RE = re.compile(
    r"^(MD5|SHA1|SHA256|SHA512)\s*:\s*([0-9a-fA-F]+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _clean_hash_value(value: str) -> str:
    """Normalizza N/A, stringa vuota, ecc. in '—'."""
    v = (value or "").strip()
    if not v or v.upper() in {"N/A", "NA", "NONE", "-"}:
        return "—"
    return v.lower()

def extract_hashes_from_verify(stdout: str) -> dict[str, dict[str, str]]:
    """
    Estrae gli hash dall'output di ewfverify gestendo entrambi i formati:

      1) SHA256 hash stored in file: N/A
         SHA256 hash calculated over data: <hex>
         MD5 hash stored in file: <hex>
         MD5 hash calculated over data: <hex>

      2) Additional hash values:
         MD5:     <hex>
    """
    result: dict[str, dict[str, str]] = {}

    # ---- formato 1: "<ALGO> hash (stored in file|calculated over data): ..." ----
    for m in HASH_RE.finditer(stdout or ""):
        algo = m.group(1).lower()
        kind = "stored" if "stored" in m.group(2).lower() else "calculated"
        result.setdefault(algo, {})[kind] = _clean_hash_value(m.group(3))

    # ---- formato 2: "MD5: <hex>" sotto "Additional hash values:" ----
    for m in ADDITIONAL_HASH_RE.finditer(stdout or ""):
        algo = m.group(1).lower()
        value = m.group(2).lower()
        slot = result.setdefault(algo, {})
        # Non sovrascrivere un eventuale valore già presente
        if slot.get("calculated") in (None, "—"):
            slot["calculated"] = value
        slot.setdefault("stored", "—")

    return result


def render_human_report(record: dict[str, Any]) -> str:
    """Costruisce un report Markdown human-readable da un record di acquisizione."""
    lines: list[str] = []

    def h(level: int, title: str) -> None:
        lines.append("#" * level + " " + title)
        lines.append("")

    def table(rows: list[tuple[str, Any]]) -> None:
        lines.append("| Campo | Valore |")
        lines.append("|---|---|")
        for k, v in rows:
            if v is None or v == "":
                v = "—"
            v = str(v).replace("|", "\\|")
            lines.append(f"| {k} | {v} |")
        lines.append("")

    src     = record.get("source", {}) or {}
    dst     = record.get("destination", {}) or {}
    img     = record.get("image", {}) or {}
    meta    = record.get("metadata", {}) or {}
    ver     = record.get("verification", {}) or {}
    reports = record.get("reports", {}) or {}

    h(1, "Report di acquisizione forense")

    table([
        ("Acquisition ID", record.get("acquisition_id")),
        ("Plan ID",        record.get("plan_id")),
        ("Stato",          record.get("status")),
        ("Avviata (UTC)",  record.get("started_at_utc")),
        ("Completata (UTC)", record.get("completed_at_utc")),
    ])

    h(2, "Sorgente")
    table([
        ("Tipo",              src.get("source_type")),
        ("Disco fisico",      src.get("disk_number")),
        ("Device path",       f"`{src.get('device_path')}`" if src.get("device_path") else None),
        ("Produttore",        src.get("manufacturer")),
        ("Modello",           src.get("model")),
        ("Numero seriale",    src.get("serial")),
        ("Firmware",          src.get("firmware_revision")),
        ("Interfaccia",       src.get("interface_type")),
        ("Tipo supporto",     src.get("media_type")),
        ("USB",               "sì" if src.get("usb_candidate") else "no"),
        ("Dimensione",        src.get("size_human") or src.get("physical_size_human")),
        ("Dimensione (byte)", src.get("size_bytes") or src.get("physical_size_bytes")),
        ("Label volume",      src.get("volume_label")),
        ("Filesystem",        src.get("filesystem")),
        ("Lettera",           src.get("drive_letter")),
    ])

    h(2, "Destinazione")
    table([
        ("Percorso",        dst.get("path")),
        ("Disco fisico",    dst.get("destination_disk_number")),
        ("Modello disco",   dst.get("destination_disk_model")),
        ("Seriale disco",   dst.get("destination_disk_serial")),
        ("Filesystem",      dst.get("filesystem")),
        ("Spazio libero",   human_size(dst.get("free_space_bytes"))),
    ])

    h(2, "Immagine E01")
    table([
        ("Basename",      img.get("basename")),
        ("Formato",       img.get("format")),
        ("Compressione",  img.get("compression_level")),
        ("Frammento",     f"{img.get('fragment_size_mb')} MiB" if img.get("fragment_size_mb") is not None else None),
        ("File primario", img.get("primary_path")),
    ])

    h(2, "Metadati del caso")
    table([
        ("Case number",     meta.get("case_number")),
        ("Evidence number", meta.get("evidence_number")),
        ("Esaminatore",     meta.get("examiner")),
        ("Descrizione",     meta.get("description")),
        ("Note",            meta.get("notes")),
    ])

    # ---- Hash digests ----
    hashes = extract_hashes_from_verify(ver.get("stdout", ""))
    h(2, "Digest hash")
    if hashes:
        lines.append("| Algoritmo | Stored in image | Calculated over data | Esito |")
        lines.append("|---|---|---|---|")
        for algo in sorted(hashes.keys()):
            stored = hashes[algo].get("stored", "—")
            calc   = hashes[algo].get("calculated", "—")
            if stored == "—" or calc == "—":
                esito = "—"
            elif stored == calc:
                esito = "✅ OK"
            else:
                esito = "❌ MISMATCH"
            lines.append(f"| {algo.upper()} | `{stored}` | `{calc}` | {esito} |")
        lines.append("")
    else:
        lines.append("_Nessun hash rilevato nell'output di ewfverify._")
        lines.append("")

    # ---- Verifica ----
    h(2, "Verifica (ewfverify)")
    table([
        ("Comando",          f"`{ver.get('command')}`" if ver.get("command") else None),
        ("Return code",      ver.get("return_code")),
        ("Successo",         "sì" if ver.get("success") else "no"),
        ("Completata (UTC)", ver.get("completed_at_utc")),
    ])

    if ver.get("stdout"):
        h(3, "Output completo ewfverify")
        lines.append("```")
        lines.append(ver["stdout"].rstrip())
        lines.append("```")
        lines.append("")

    # ---- File prodotti ----
    h(2, "File prodotti")
    table([
        ("Report JSON", reports.get("json_report")),
        ("Report HTML", reports.get("html_report")),
    ])

    if record.get("error"):
        h(2, "Errore")
        lines.append("```")
        lines.append(str(record["error"]))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)

# ============================================================
# EWFTOOLS HELPERS
# ============================================================

def locate_ewf_tool(tool_name: str) -> Path | None:
    """Search for an ewftools binary in BASE_DIR first, then system PATH."""
    names = [tool_name]
    if not tool_name.lower().endswith(".exe"):
        names.append(f"{tool_name}.exe")

    for name in names:
        candidate = BASE_DIR / name
        if candidate.exists():
            return candidate

    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)

    return None


def ps_quote(val: Any) -> str:
    """Esegue l'escape degli apici singoli per PowerShell (' -> '') e racchiude la stringa tra apici."""
    escaped = str(val).replace("'", "''")
    return f"'{escaped}'"

import base64
def run_ewf_acquire(
    job_id: str,
    source: dict[str, Any],
    destination: dict[str, Any],
    image: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    exe_path = locate_ewf_tool("ewfacquire")
    if not exe_path:
        raise RuntimeError("ewfacquire non trovato nella directory del server né nel PATH.")

    target_base = os.path.join(destination["path"], image["basename"])
    if target_base.lower().endswith(".e01"):
        target_base = target_base[:-4]

    log_file = f"{target_base}.log"
    out_file = f"{target_base}_output.txt"
    err_file = f"{target_base}_errors.txt"
    bat_file = f"{target_base}_run.bat"

    # ---- 1. Costruisci la lista argomenti come array Python, senza quotature ----
    ewf_args: list[str] = [
        "-u",
        "-t", target_base,
        "-l", log_file,
        "-d", "sha256",
        "-d", "md5",
    ]
    if metadata.get("case_number"):
        ewf_args += ["-C", str(metadata["case_number"])]
    if metadata.get("evidence_number"):
        ewf_args += ["-E", str(metadata["evidence_number"])]
    if metadata.get("examiner"):
        ewf_args += ["-e", str(metadata["examiner"])]
    if metadata.get("description"):
        ewf_args += ["-D", str(metadata["description"])]
    if metadata.get("notes"):
        ewf_args += ["-N", str(metadata["notes"])]

    comp_level = image.get("compression_level", 6)
    if comp_level == 0:
        ewf_args += ["-c", "none"]
    elif comp_level < 5:
        ewf_args += ["-c", "fast"]
    else:
        ewf_args += ["-c", "best"]

    frag_mb = image.get("fragment_size_mb", 1500)
    if frag_mb > 0:
        ewf_args += ["-S", f"{frag_mb}MiB"]

    ewf_args.append(source["device_path"])

    # ---- 2. Genera un file .bat con la riga di comando completa ----
    def q(s: str) -> str:
        # Quoting per cmd.exe: doppi apici raddoppiati se presenti
        s = str(s)
        return f'"{s}"' if (" " in s or '"' in s or not s) else s

    command_line = (
        q(str(exe_path))
        + " " + " ".join(q(a) for a in ewf_args)
        + f' > {q(out_file)} 2> {q(err_file)}'
    )

    # cp1252 o utf-8, indifferentemente, purché ci sia chcp 65001 se usi UTF-8
    with open(bat_file, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write("chcp 65001 > nul\r\n")
        f.write(command_line + "\r\n")
        f.write("exit /b %ERRORLEVEL%\r\n")

    debug(f"Launcher .bat scritto: {bat_file}")
    debug(f"Riga ewfacquire: {command_line}")

    # ---- 3. Lancia il .bat. Senza RunAs: il server MCP deve girare elevato. ----
    encoded_ps = base64.b64encode(
        (
            "$ErrorActionPreference='Continue';"
            f"$p = Start-Process -FilePath 'cmd.exe' "
            f"-ArgumentList '/c','\"{bat_file}\"' "
            "-NoNewWindow -Wait -PassThru; "
            "exit $p.ExitCode"
        ).encode("utf-16le")
    ).decode("utf-8")

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encoded_ps,
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )

    # ---- 4. Leggi SEMPRE stdout/stderr dal file, anche in caso di errore ----
    def read_or_empty(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except FileNotFoundError:
            return "(file non creato)"
        except Exception as exc:
            return f"(lettura fallita: {exc})"

    stdout_details = read_or_empty(out_file)
    stderr_details = read_or_empty(err_file)

    expected_e01 = f"{target_base}.E01"

    debug(f"ewfacquire rc={result.returncode}")
    debug(f"OUT:\n{stdout_details}")
    debug(f"ERR:\n{stderr_details}")

    if result.returncode != 0 or not os.path.exists(expected_e01):
        raise RuntimeError(
            "ewfacquire fallito.\n"
            f"ExitCode wrapper: {result.returncode}\n"
            f"E01 atteso: {expected_e01}\n"
            f"--- stdout ---\n{stdout_details}\n"
            f"--- stderr ---\n{stderr_details}\n"
            f"--- PS wrapper stdout ---\n{result.stdout.strip()}\n"
            f"--- PS wrapper stderr ---\n{result.stderr.strip()}"
        )

    return {
        "status": "completed",
        "backend": "ewftools",
        "command": command_line,
        "stdout": stdout_details,
        "stderr": stderr_details,
        "return_code": result.returncode,
    }


def run_ewf_verify(image_path: str) -> dict[str, Any]:
    """Execute ewfverify tool on target image file."""
    exe = locate_ewf_tool("ewfverify")
    if not exe:
        raise RuntimeError("ewfverify non trovato nella directory del server né nel PATH.")

    cmd = [str(exe), "-d", "sha256", image_path]
    debug(f"Executing ewfverify command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=7 * 24 * 3600,
    )
    return {
        "backend": "ewftools",
        "command": " ".join(cmd),
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "completed_at_utc": utc_now(),
        "success": result.returncode == 0,
    }


def run_ewf_info(image_path: str) -> dict[str, Any]:
    """Execute ewfinfo tool to retrieve image header details."""
    exe = locate_ewf_tool("ewfinfo")
    if not exe:
        raise RuntimeError("ewfinfo non trovato nella directory del server né nel PATH.")

    cmd = [str(exe), image_path]
    debug(f"Executing ewfinfo command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    info_output = result.stdout
    parsed_info: dict[str, str] = {}
    for line in info_output.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            parsed_info[k.strip()] = v.strip()

    return {
        "backend": "ewftools",
        "command": " ".join(cmd),
        "return_code": result.returncode,
        "raw_output": info_output,
        "parsed_info": parsed_info,
        "stderr": result.stderr,
        "completed_at_utc": utc_now(),
        "success": result.returncode == 0,
    }


# ============================================================
# MCP TOOLS
# ============================================================

@mcp.tool()
def list_physical_disks() -> dict[str, Any]:
    """List physical disks and their partitions/logical volumes. Read-only."""
    disks = inventory()
    audit("inventory_physical_disks", {"count": len(disks)})
    return {"disks": disks, "count": len(disks)}


@mcp.tool()
def list_logical_volumes() -> dict[str, Any]:
    """List logical volumes and map each one to its physical disk/partition."""
    rows: list[dict[str, Any]] = []
    for disk in inventory():
        for part in disk.get("partitions", []):
            for logical in part.get("logical_disks", []):
                rows.append(
                    {
                        "drive_letter": logical.get("drive_letter"),
                        "filesystem": logical.get("filesystem"),
                        "volume_label": logical.get("volume_label"),
                        "volume_serial": logical.get("volume_serial"),
                        "volume_size_bytes": logical.get("volume_size_bytes"),
                        "free_space_bytes": logical.get("free_space_bytes"),
                        "disk_number": disk.get("disk_number"),
                        "partition_number": part.get("partition_number"),
                        "disk_model": disk.get("model"),
                        "disk_manufacturer": disk.get("manufacturer"),
                        "disk_serial": disk.get("serial"),
                        "disk_size_bytes": disk.get("size_bytes"),
                        "usb_candidate": disk.get("usb_candidate"),
                    }
                )
    audit("inventory_logical_volumes", {"count": len(rows)})
    return {"volumes": rows, "count": len(rows)}


@mcp.tool()
def inspect_disk(disk_number: int) -> dict[str, Any]:
    """Return all inventory properties for one physical disk."""
    disk = disk_by_number(disk_number)
    disk["os_write_state"] = powershell_readonly_state(disk_number)
    disk["size_human"] = human_size(disk.get("size_bytes"))
    audit("inspect_disk", {"disk": disk})
    return disk


@mcp.tool()
def inspect_source(
    source_type: Literal["physical_disk", "logical_volume"],
    disk_number: int | None = None,
    drive_letter: str | None = None,
) -> dict[str, Any]:
    """Return a detailed snapshot of the selected physical disk or logical volume."""
    source = source_from_spec(source_type, disk_number, drive_letter)
    if source.get("disk_number") is not None:
        source["os_write_state"] = powershell_readonly_state(int(source["disk_number"]))
    audit("inspect_source", {"source": source})
    return source


@mcp.tool()
def check_write_block(
    disk_number: int,
    hardware_write_blocker_attested: bool = False,
) -> dict[str, Any]:
    """Check OS-level disk state. Hardware write-blocker presence is an operator attestation."""
    disk = disk_by_number(disk_number)
    os_state = powershell_readonly_state(disk_number)
    result = {
        "disk_number": disk_number,
        "device_path": disk.get("device_path"),
        "usb_candidate": disk.get("usb_candidate"),
        "hardware_write_blocker_attested": bool(hardware_write_blocker_attested),
        "os_state": os_state,
        "safe_for_physical_acquisition": bool(hardware_write_blocker_attested)
        and bool(os_state.get("available", True)),
        "note": (
            "La presenza di un hardware write blocker non può essere provata da Windows; "
            "il campo hardware_write_blocker_attested deve essere confermato dall'operatore."
        ),
    }
    audit("check_write_block", result)
    return result


@mcp.tool()
def inspect_destination(path: str) -> dict[str, Any]:
    """Inspect output path, available space, and the physical disk hosting it."""
    result = resolve_destination(path)
    audit("inspect_destination", {"destination": result})
    return result


@mcp.tool()
def plan_acquisition(
    source_type: Literal["physical_disk", "logical_volume"],
    destination_path: str,
    disk_number: int | None = None,
    drive_letter: str | None = None,
    fragment_size_mb: int = 1500,
    compression_level: int = 6,
    verify_after: bool = True,
    image_basename: str = "evidence",
    case_number: str = "",
    evidence_number: str = "",
    examiner: str = "",
    description: str = "",
    notes: str = "",
    hardware_write_blocker_attested: bool = False,
) -> dict[str, Any]:
    """Validate an acquisition plan without starting ewftools."""
    if fragment_size_mb < 0 or fragment_size_mb > 200000:
        raise ValueError("fragment_size_mb fuori range")
    if compression_level < 0 or compression_level > 9:
        raise ValueError("compression_level deve essere 0..9")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", image_basename):
        raise ValueError("image_basename contiene caratteri non ammessi")

    source = source_from_spec(source_type, disk_number, drive_letter)
    destination = resolve_destination(destination_path)

    source_disk_number = int(source["disk_number"])
    destination_disk_number = int(destination["destination_disk_number"])
    os_state = powershell_readonly_state(source_disk_number)

    checks = {
        "source_found": True,
        "destination_found": True,
        "destination_writable": bool(destination.get("writable")),
        "destination_space_known": destination.get("free_space_bytes") is not None,
        "source_size_known": estimate_required_bytes(source, compression_level) > 0,
        "source_destination_physical_disk_distinct": source_disk_number != destination_disk_number,
        "hardware_write_blocker_attested": bool(hardware_write_blocker_attested),
        "os_readonly_state_available": bool(os_state.get("available", True)),
        "os_write_state_not_error": bool(os_state.get("available", True)),
    }
    required_bytes = estimate_required_bytes(source, compression_level)
    if required_bytes and destination.get("free_space_bytes") is not None:
        checks["destination_space_ok"] = int(destination["free_space_bytes"]) >= int(required_bytes)
    else:
        checks["destination_space_ok"] = False

    checks["write_block_requirement_ok"] = (
        bool(hardware_write_blocker_attested)
        if source_type == "physical_disk"
        else True
    )

    blocking = [name for name, ok in checks.items() if not ok]
    plan_id = "PLAN-" + uuid.uuid4().hex[:12].upper()
    valid = len(blocking) == 0
    plan = {
        "plan_id": plan_id,
        "created_at_utc": utc_now(),
        "valid": valid,
        "blocking_checks": blocking,
        "checks": checks,
        "source": source,
        "destination": destination,
        "image": {
            "format": "E01",
            "fragment_size_mb": fragment_size_mb,
            "compression_level": compression_level,
            "verify_after": verify_after,
            "basename": image_basename,
            "estimated_required_bytes": required_bytes,
        },
        "metadata": {
            "case_number": case_number,
            "evidence_number": evidence_number,
            "examiner": examiner,
            "description": description,
            "notes": notes,
        },
        "execution": {
            "approval_required": True,
            "execute_flag_must_be_true": True,
            "backend": "ewftools",
        },
    }
    plan_path = REPORT_DIR / f"{plan_id}.json"
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    audit("acquisition_plan_created", plan)
    return {"plan": plan, "plan_file": str(plan_path)}


@mcp.tool()
def acquire_ewf(
    plan_id: str,
    execute: bool = False,
    human_confirmation: str = "",
) -> dict[str, Any]:
    """Start or validate a guarded E01 acquisition using ewfacquire and the validated plan. show progress to the user """
    if not execute:
        return {
            "status": "not_started",
            "plan_id": plan_id,
            "message": "Dry-run only. Pass execute=true only after human review of the returned plan.",
        }

    plan_file = REPORT_DIR / f"{plan_id}.json"
    if not plan_file.exists():
        raise ValueError(f"Plan {plan_id} non trovato")
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    if not plan.get("valid"):
        raise ValueError("Il piano non è valido: " + ", ".join(plan.get("blocking_checks", [])))
    human_confirmation: f"{plan_id}" """ delete to activate the guardrail """
    if human_confirmation != plan_id:
        raise ValueError("human_confirmation deve coincidere con plan_id; questo impedisce un avvio accidentale")

    source = source_from_spec(
        plan["source"]["source_type"],
        plan["source"].get("disk_number"),
        plan["source"].get("drive_letter"),
    )
    destination = resolve_destination(plan["destination"]["path"])
    if int(source["disk_number"]) == int(destination["destination_disk_number"]):
        raise RuntimeError("Blocco: sorgente e destinazione sono sullo stesso disco fisico")

    if plan["source"]["source_type"] == "physical_disk" and not plan["checks"]["hardware_write_blocker_attested"]:
        raise RuntimeError("Blocco: hardware write blocker non attestato")

    job_id = "ACQ-" + uuid.uuid4().hex[:12].upper()
    record = {
        "acquisition_id": job_id,
        "plan_id": plan_id,
        "started_at_utc": utc_now(),
        "status": "running",
        "source": source,
        "destination": destination,
        "image": plan["image"],
        "metadata": plan["metadata"],
        "checks": plan["checks"],
    }
    with JOBS_LOCK:
        JOBS[job_id] = record
    audit("acquisition_started", record)

    def worker() -> None:
        try:
            backend_result = run_ewf_acquire(
                job_id,
                source,
                destination,
                plan["image"],
                plan["metadata"],
            )
            record["backend_result"] = backend_result
            record["status"] = "acquired"
            record["completed_at_utc"] = utc_now()

            image_path = str(Path(destination["path"]) / (plan["image"]["basename"] + ".E01"))
            record["image"]["primary_path"] = image_path

            if plan["image"]["verify_after"]:
                verification = run_ewf_verify(image_path)
                record["verification"] = verification
                record["status"] = "verified" if verification.get("success") else "verification_failed"

            # Acquire info on the created image
            try:
                info_result = run_ewf_info(image_path)
                record["info"] = info_result
            except Exception as exc_info:
                debug(f"Failed to acquire image info: {exc_info}")

            report_paths = make_report(job_id, record)
            record["reports"] = report_paths
            audit("acquisition_finished", record)
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
            record["traceback"] = traceback.format_exc()
            record["completed_at_utc"] = utc_now()
            try:
                report_paths = make_report(job_id, record)
                """ record["reports"] = report_paths """
            except Exception:
                pass
            audit("acquisition_failed", record)
            debug(f"Acquisition {job_id} failed: {exc}")

        with JOBS_LOCK:
            JOBS[job_id] = record

    threading.Thread(target=worker, name=f"forensic-{job_id}", daemon=True).start()
    return {
        "status": "started",
        "acquisition_id": job_id,
        "message": "Acquisizione avviata con ewfacquire; usare acquisition_status per lo stato.",
        "source": source,
        "destination": destination,
    }
    
@mcp.tool()
def create_acquisition_report(acquisition_id: str) -> str:
    """
    Create and return a human-readable Markdown report for a completed acquisition.

    Use this when the user asks to "create the report", "show the report",
    "print the forensic report", etc. for a specific acquisition ID.

    The report is built from the JSON file previously written by make_report
    under forensic_reports/, so it works even after a server restart as long
    as the ACQ-*.json file still exists. Falls back to the in-memory record
    if the JSON report has not been written yet.

    Returns a Markdown string suitable for direct display or printing.
    """
    # 1) cerca il record in memoria
    with JOBS_LOCK:
        record = dict(JOBS.get(acquisition_id, {}))

    # 2) se esiste il JSON su disco, usalo come fonte di verità
    json_path = (record.get("reports") or {}).get("json_report")
    if json_path and Path(json_path).exists():
        try:
            record = json.loads(Path(json_path).read_text(encoding="utf-8"))
            debug(f"create_acquisition_report: letto {json_path}")
        except Exception as exc:
            debug(f"create_acquisition_report: lettura {json_path} fallita: {exc}")

    # 3) se non c'è né file né record in memoria, errore
    if not record:
        raise ValueError(
            f"Acquisition {acquisition_id} non trovata. "
            f"Verifica l'ID o che il file ACQ-*.json esista in {REPORT_DIR}"
        )

    audit("create_acquisition_report", {"acquisition_id": acquisition_id})
    return render_human_report(record)
    
@mcp.tool()
def acquisition_status(acquisition_id: str) -> dict[str, Any]:
    """Return current acquisition state and report paths. Show progress to the user"""
    with JOBS_LOCK:
        record = dict(JOBS.get(acquisition_id, {}))
    if not record:
        raise ValueError(f"Acquisition {acquisition_id} non trovata")

    # Se l'acquisizione è conclusa, allega il report Markdown pronto
    if record.get("status") in {"acquired", "verified", "verification_failed", "failed"}:
        try:
            record["human_report_markdown"] = render_human_report(record)
        except Exception as exc:
            debug(f"render_human_report fallito per {acquisition_id}: {exc}")

    return record
    
@mcp.tool()
def tail_acquisition_output(acquisition_id: str, lines: int = 50) -> dict[str, Any]:
    """
    Return the tail of the live ewfacquire output/error files for an acquisition.

    Use this to monitor progress in real time. The output files are written
    continuously by cmd.exe redirection while ewfacquire runs, so polling
    this tool every few seconds shows the current progress.

    Works both while the acquisition is running and after it has finished
    (in which case it returns the full tail of the final output).

    IMPORTANT — how to use it while the acquisition is running:
      - If `status` is "running", call this tool repeatedly every 2 seconds
        to show progress to the user, until the status changes.
      - Do NOT wait for the user to ask again: after each call, if the
        acquisition is still running, call it again after ~20 seconds and
        report the latest progress line to the user.
      - Stop polling when `status` becomes "acquired", "verified",
        "verification_failed", or "failed".

    Returns:
        {
          "acquisition_id": str,
          "status": str,
          "output": {"path": ..., "exists": bool, "size_bytes": int, "lines": [...]},
          "errors": {"path": ..., "exists": bool, "size_bytes": int, "lines": [...]}
        }
    """
    if lines < 1 or lines > 2000:
        raise ValueError("lines deve essere compreso tra 1 e 2000")

    with JOBS_LOCK:
        record = dict(JOBS.get(acquisition_id, {}))
    if not record:
        raise ValueError(f"Acquisition {acquisition_id} non trovata")

    dest = record.get("destination", {}) or {}
    img  = record.get("image", {}) or {}
    basename = img.get("basename", "evidence")
    dest_path = dest.get("path")
    if not dest_path:
        raise ValueError(f"Acquisition {acquisition_id}: destination.path assente")

    target_base = Path(dest_path) / basename
    out_path = Path(f"{target_base}_output.txt")
    err_path = Path(f"{target_base}_errors.txt")

    return {
        "acquisition_id": acquisition_id,
        "status": record.get("status"),
        "output": tail_file(out_path, lines),
        "errors": tail_file(err_path, lines),
    }

@mcp.tool()
def verify_ewf(image_path: str) -> dict[str, Any]:
    """Verify an E01 image using ewfverify."""
    result = run_ewf_verify(image_path)
    audit("verify_ewf", {"image_path": image_path, "result": result})
    return result


@mcp.tool()
def info_ewf(image_path: str) -> dict[str, Any]:
    """Acquire and return metadata/header info from an E01 image using ewfinfo."""
    result = run_ewf_info(image_path)
    audit("info_ewf", {"image_path": image_path, "result": result})
    return result


@mcp.tool()
def generate_report(acquisition_id: str) -> dict[str, Any]:
    """Generate/re-generate HTML and JSON reports for a completed acquisition."""
    with JOBS_LOCK:
        record = dict(JOBS.get(acquisition_id, {}))
    if not record:
        raise ValueError(f"Acquisition {acquisition_id} non trovata")
    reports = make_report(acquisition_id, record)
    audit("report_generated", {"acquisition_id": acquisition_id, "reports": reports})
    return {"acquisition_id": acquisition_id, "reports": reports, "source": record.get("source")}


@mcp.tool()
def inspect_ewftools() -> dict[str, Any]:
    """Inspect availability of ewftools binaries (ewfacquire, ewfverify, ewfinfo)."""
    acquire_exe = locate_ewf_tool("ewfacquire")
    verify_exe = locate_ewf_tool("ewfverify")
    info_exe = locate_ewf_tool("ewfinfo")

    result = {
        "ewfacquire": str(acquire_exe) if acquire_exe else None,
        "ewfverify": str(verify_exe) if verify_exe else None,
        "ewfinfo": str(info_exe) if info_exe else None,
        "all_available": bool(acquire_exe and verify_exe and info_exe),
    }
    audit("inspect_ewftools", result)
    return result


if __name__ == "__main__":
    debug("Starting Windows Forensic MCP server (ewftools version)")
    debug(f"Python executable: {sys.executable}")
    debug(f"Python version: {sys.version}")
    debug(f"Server file: {Path(__file__).resolve()}")
    mcp.run(transport="stdio")