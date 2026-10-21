<#
 ProjectGuard.ps1  v2  -  who deleted what inside a project folder, and keep every deleted file recoverable.

 Install   : .\ProjectGuard.ps1 -Mode Install   -ProjectPath D:\Projects\Alpha      (elevated PowerShell)
 SelfTest  : .\ProjectGuard.ps1 -Mode SelfTest                                       (run once on the real server)
 Restore   : .\ProjectGuard.ps1 -Mode Restore   -ProjectPath D:\Projects\Alpha -EventId <id>[,<id>] | '*'  [-Since "2026-10-21 09:00"] [-User "DOMAIN\bob"] [-Under "Design"] [-Preview]
 Uninstall : .\ProjectGuard.ps1 -Mode Uninstall -ProjectPath D:\Projects\Alpha
 Run       : started by the scheduled task (SYSTEM, at startup + every 5 min watchdog)
 Keep this file and dashboard.html in the same folder when installing.

 How it works (short):
  * vault\   = NTFS HARD LINKS of every project file (no extra disk space). When a file is deleted the data survives
               because the vault name still points to it; the link is then moved to deleted\<time>\.
  * Windows Security log (4663 local / 5145 SMB) tells WHO deleted it; looked up in batches, retried later if not found yet.
  * A reconcile scan (startup + every N minutes) compares vault vs project, so deletions that happened while the
    script/server was down are still detected, moved, and attributed from the Security log.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Install', 'Run', 'Uninstall', 'Restore', 'SelfTest')][string]$Mode,
    [string]$ProjectPath,
    [string]$GuardRoot,            # default <drive>:\ProjectGuard  (MUST be on the same volume as the project, and NOT inside the shared folder)
    [int]$ScanMinutes = 5,
    [int]$RetentionDays = 0,       # 0 = keep deleted files forever
    [string[]]$EventId,
    [datetime]$Since,
    [string]$User,
    [string]$Under,
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------------------------------------------
# Native helper (C# 5 compatible): watcher queue, hard links, long-path safe file ops, tree walk
# ----------------------------------------------------------------------------------------------------------------
$CS = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace PG
{
    public class FsEvt { public string Kind; public string Path; public string Old; public DateTime Time; }

    public class FInfo
    {
        public bool Ok; public int Err; public string Key; public uint Links; public long Length; public long Mtime; public uint Attr;
    }

    public static class Nat
    {
        const uint READ_ATTR = 0x80, SHARE_ALL = 7, OPEN_EXISTING = 3, BACKUP = 0x02000000, OPEN_REPARSE = 0x00200000;
        static readonly IntPtr BAD = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        struct BHFI
        {
            public uint Attr;
            public System.Runtime.InteropServices.ComTypes.FILETIME Cr, La, Lw;
            public uint Vol, SzHi, SzLo, Links, IdHi, IdLo;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WFD
        {
            public uint Attr;
            public System.Runtime.InteropServices.ComTypes.FILETIME Cr, La, Lw;
            public uint SzHi, SzLo, R0, R1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string Alt;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string n, uint acc, uint share, IntPtr sa, uint disp, uint flags, IntPtr t);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out BHFI i);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool MoveFileExW(string a, string b, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CopyFileW(string a, string b, bool failIfExists);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool DeleteFileW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool RemoveDirectoryW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateDirectoryW(string p, IntPtr sa);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFileAttributesW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetFileAttributesW(string p, uint a);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstFileW(string p, out WFD d);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextFileW(IntPtr h, out WFD d);
        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr h);

        public static string P(string p)
        {
            if (p.StartsWith("\\\\?\\")) return p;
            if (p.StartsWith("\\\\")) return "\\\\?\\UNC\\" + p.Substring(2);
            return "\\\\?\\" + p;
        }

        // names we never track (Office lock files, temp files)
        public static bool SkipName(string leaf)
        {
            return leaf.StartsWith("~$") || leaf.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
        }

        public static bool Exists(string p) { return GetFileAttributesW(P(p)) != 0xFFFFFFFF; }
        public static bool IsDir(string p) { uint a = GetFileAttributesW(P(p)); return a != 0xFFFFFFFF && (a & 0x10) != 0; }

        public static FInfo Probe(string p)
        {
            FInfo r = new FInfo();
            SafeFileHandle h = CreateFileW(P(p), READ_ATTR, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            try
            {
                if (h.IsInvalid) { r.Err = Marshal.GetLastWin32Error(); return r; }
                BHFI i;
                if (!GetFileInformationByHandle(h, out i)) { r.Err = Marshal.GetLastWin32Error(); return r; }
                r.Ok = true;
                r.Key = i.Vol.ToString("x") + ":" + i.IdHi.ToString("x") + ":" + i.IdLo.ToString("x");
                r.Links = i.Links; r.Attr = i.Attr;
                r.Length = ((long)i.SzHi << 32) | i.SzLo;
                r.Mtime = ((long)(uint)i.Lw.dwHighDateTime << 32) | (uint)i.Lw.dwLowDateTime;
            }
            finally { h.Dispose(); }
            return r;
        }

        public static int Link(string existing, string link) { return CreateHardLinkW(P(link), P(existing), IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error(); }
        public static int Move(string a, string b) { return MoveFileExW(P(a), P(b), 1) ? 0 : Marshal.GetLastWin32Error(); }
        public static int Copy(string a, string b) { return CopyFileW(P(a), P(b), false) ? 0 : Marshal.GetLastWin32Error(); }
        public static int RmDir(string p) { return RemoveDirectoryW(P(p)) ? 0 : Marshal.GetLastWin32Error(); }

        public static int Del(string p)
        {
            if (DeleteFileW(P(p))) return 0;
            int e = Marshal.GetLastWin32Error();
            if (e == 5)
            {
                // read-only flag: clear it only when this name is the LAST link (never touch a file that is still alive elsewhere)
                FInfo f = Probe(p);
                if (f.Ok && f.Links <= 1 && (f.Attr & 1) != 0)
                {
                    SetFileAttributesW(P(p), 0x80);
                    if (DeleteFileW(P(p))) return 0;
                    e = Marshal.GetLastWin32Error();
                }
            }
            return e;
        }

        public static int Mkdirs(string p)
        {
            p = p.TrimEnd('\\');
            if (p.Length < 3) return 0;
            if (IsDir(p)) return 0;
            int i = p.LastIndexOf('\\');
            if (i > 2) { int r = Mkdirs(p.Substring(0, i)); if (r != 0) return r; }
            if (CreateDirectoryW(P(p), IntPtr.Zero)) return 0;
            int e = Marshal.GetLastWin32Error();
            return (e == 183) ? 0 : e;
        }

        // 0 = nothing to do / already protected, 1 = linked, 3 = copied (fallback), negative = error (retry later)
        public static int SyncOne(string full, string vault)
        {
            FInfo p = Probe(full);
            if (!p.Ok) return (p.Err == 2 || p.Err == 3) ? 0 : -p.Err;
            if ((p.Attr & 0x10) != 0) return 0;
            FInfo v = Probe(vault);
            if (v.Ok)
            {
                if (v.Key == p.Key) return 0;
                if (v.Links == 1 && p.Links == 1 && v.Length == p.Length && v.Mtime == p.Mtime) return 0;   // copy-mode mirror, unchanged
                int d = Del(vault);
                if (d != 0) return -d;
            }
            int k = Mkdirs(vault.Substring(0, vault.LastIndexOf('\\')));
            if (k != 0) return -k;
            int e = Link(full, vault);
            if (e == 0) return 1;
            if (e == 17 || e == 1 || e == 50)   // different volume / not supported -> fall back to a real copy
            {
                int c = Copy(full, vault);
                return c == 0 ? 3 : -c;
            }
            return -e;
        }

        // skipFull: several full paths separated by '|' (directories not entered)
        public static void Walk(string root, string skipFull, List<string> files, List<string> dirs)
        {
            string[] skips = skipFull == null ? new string[0] : skipFull.Split('|');
            WalkRec(root.TrimEnd('\\'), "", skips, files, dirs);
        }

        static void WalkRec(string abs, string rel, string[] skips, List<string> files, List<string> dirs)
        {
            WFD d;
            IntPtr h = FindFirstFileW(P(abs) + "\\*", out d);
            if (h == BAD) return;
            try
            {
                do
                {
                    string n = d.Name;
                    if (n == "." || n == "..") continue;
                    string r = rel.Length == 0 ? n : rel + "\\" + n;
                    string a = abs + "\\" + n;
                    if ((d.Attr & 0x10) != 0)
                    {
                        if ((d.Attr & 0x400) != 0) continue;            // junction / symlink directory: do not follow
                        bool skip = false;
                        foreach (string s in skips) { if (string.Equals(a, s, StringComparison.OrdinalIgnoreCase)) { skip = true; break; } }
                        if (skip) continue;
                        dirs.Add(r);
                        WalkRec(a, r, skips, files, dirs);
                    }
                    else files.Add(r);
                } while (FindNextFileW(h, out d));
            }
            finally { FindClose(h); }
        }
    }

    public class Watch : IDisposable
    {
        public ConcurrentQueue<FsEvt> Q = new ConcurrentQueue<FsEvt>();                                                       // deletes + renames (order matters)
        public ConcurrentDictionary<string, DateTime> Dirty = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);   // created/changed paths
        public ConcurrentDictionary<string, byte> Fresh = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);        // linked instantly by the fast path
        public volatile bool Overflow;
        public string Fault;
        FileSystemWatcher w;
        BlockingCollection<string> fast = new BlockingCollection<string>();
        Thread th;
        string root, guard, vault;

        public Watch(string rootPath, string guardPath, string vaultPath)
        {
            root = rootPath.TrimEnd('\\'); guard = guardPath.TrimEnd('\\'); vault = vaultPath.TrimEnd('\\');
            th = new Thread(FastLoop);
            th.IsBackground = true;
            th.Start();
            w = new FileSystemWatcher(root);
            w.IncludeSubdirectories = true;
            w.InternalBufferSize = 1048576;
            w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size;
            w.Created += delegate(object s, FileSystemEventArgs e) { OnCM("C", e.FullPath); };
            w.Changed += delegate(object s, FileSystemEventArgs e) { OnCM("M", e.FullPath); };
            w.Deleted += delegate(object s, FileSystemEventArgs e) { OnDel(e.FullPath); };
            w.Renamed += delegate(object s, RenamedEventArgs e) { OnRen(e.OldFullPath, e.FullPath); };
            w.Error += delegate(object s, ErrorEventArgs e) { Overflow = true; Fault = e.GetException().Message; };
            w.EnableRaisingEvents = true;
        }

        bool InGuard(string p)
        {
            return p.Equals(guard, StringComparison.OrdinalIgnoreCase) || p.StartsWith(guard + "\\", StringComparison.OrdinalIgnoreCase);
        }
        bool Skip(string p) { return InGuard(p) || Nat.SkipName(p.Substring(p.LastIndexOf('\\') + 1)); }

        void OnCM(string kind, string p)
        {
            if (Skip(p)) return;
            Dirty[p] = DateTime.Now;
            if (kind == "C") fast.Add(p);      // link new files immediately (catches files deleted seconds after creation)
        }
        void OnDel(string p)
        {
            if (Skip(p)) return;
            FsEvt e = new FsEvt(); e.Kind = "D"; e.Path = p; e.Time = DateTime.Now; Q.Enqueue(e);
        }
        void OnRen(string o, string n)
        {
            if (InGuard(o) || InGuard(n)) return;
            FsEvt e = new FsEvt(); e.Kind = "R"; e.Path = n; e.Old = o; e.Time = DateTime.Now; Q.Enqueue(e);
        }

        void FastLoop()
        {
            try
            {
                foreach (string p in fast.GetConsumingEnumerable())
                {
                    try
                    {
                        string v = vault + p.Substring(root.Length);
                        int r = Nat.SyncOne(p, v);
                        if (r == 1 || r == 3) Fresh[p] = 1;
                    }
                    catch { }
                }
            }
            catch { }
        }

        public void Dispose()
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            try { fast.CompleteAdding(); } catch { }
        }
    }
}
'@

function Initialize-Native {
    if (-not ('PG.Nat' -as [type])) { Add-Type -TypeDefinition $CS -Language CSharp }
}

# ----------------------------------------------------------------------------------------------------------------
# Context / small helpers
# ----------------------------------------------------------------------------------------------------------------
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Events = [ordered]@{}
$script:DataDirty = $false
$script:LastFlush = Get-Date '2000-01-01'
$script:LastBeat = Get-Date '2000-01-01'
$script:LastScan = Get-Date '2000-01-01'
$script:LastHealth = Get-Date
$script:LastPurge = Get-Date
$script:Orphans = @{}
$script:DelQ = @{}
$script:Tries = @{}
$script:Dns = @{}
$script:Unk = New-Object System.Collections.ArrayList
$script:UnkDelays = 10, 30, 120, 600, 3600
$script:AuditGood = @{}
$script:NeedScan = $false
$script:ScanVerify = $false
$script:Initialized = $false
$script:PrevScan = Get-Date
$script:W = $null
$script:Health = @{ version = 2; started = ''; heartbeat = ''; auditFlips = 0; auditNote = ''; lastError = ''; gaps = @(); copyFallbacks = 0; unknown = 0; project = '' }
$script:AuditGuids = '{0CCE921D-69AE-11D9-BED3-505054503030}', '{0CCE9244-69AE-11D9-BED3-505054503030}'   # File System, Detailed File Share

function J([string]$a, [string]$b) {
    if (-not $b) { return $a }
    if (-not $a) { return $b }
    return $a.TrimEnd('\') + '\' + $b.TrimStart('\')
}
function Parent([string]$p) { $i = $p.LastIndexOf('\'); if ($i -lt 0) { return '' }; return $p.Substring(0, $i) }
function To-Date($v) {
    if ($v -is [datetime]) { return $v }
    try { return [datetime]::ParseExact([string]$v, 's', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}
function Assert-Admin {
    $ok = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $ok) { throw 'Run PowerShell as Administrator.' }
}

function Initialize-Context([string]$path, [string]$guardRoot) {
    if (-not $path) { throw 'ProjectPath is required.' }
    $pp = (Resolve-Path -LiteralPath $path).Path.TrimEnd('\')
    if ($pp.Length -le 3) { throw 'Choose a project folder, not a drive root.' }
    $script:PP = $pp
    if (-not $guardRoot) { $guardRoot = (Split-Path -Qualifier $pp) + '\ProjectGuard' }
    $md5 = [Security.Cryptography.MD5]::Create()
    $h = (($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($pp.ToLowerInvariant())) | Select-Object -First 3 | ForEach-Object { $_.ToString('x2') }) -join '')
    $leaf = (Split-Path $pp -Leaf) -replace '[^\w\.\-]', '_'
    $script:Hash = $h
    $script:GR = $guardRoot.TrimEnd('\')
    $script:G = J $script:GR "${leaf}_$h"
    $script:V = J $script:G 'vault'
    $script:D = J $script:G 'deleted'
    $script:LogFile = J $script:G 'events.jsonl'
    $script:DataJs = J $script:G 'data.js'
    $script:HealthJs = J $script:G 'health.js'
    $script:StateFile = J $script:G 'state.json'
    $script:ErrLog = J $script:G 'errors.log'
    $script:TaskName = 'ProjectGuard_' + ($leaf -replace '[^\w]', '_')
    $legacy = J $pp '.guard'                                  # v1 guard folder (if any) is never mirrored
    $script:SkipDirs = @($script:G, $legacy)
    $script:SkipArg = $script:SkipDirs -join '|'
    $script:GuardMarks = @(('\' + (Split-Path $script:GR -Leaf) + '\'), '\.guard\')
    $script:Health.project = $pp
}

function Get-Rel([string]$p) {
    if ($p.Length -le $script:PP.Length) { return '' }
    return $p.Substring($script:PP.Length).TrimStart('\')
}
function Test-Skip([string]$p) {
    foreach ($s in $script:SkipDirs) {
        if ($p -ieq $s -or $p.StartsWith($s + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return [PG.Nat]::SkipName($p.Substring($p.LastIndexOf('\') + 1))
}

function Log-Err([string]$m) {
    $script:Health.lastError = "$(Get-Date -f s) $m"
    try { [IO.File]::AppendAllText($script:ErrLog, "$(Get-Date -f s) $m`r`n", $script:Utf8) } catch { }
}
function Write-Atomic([string]$path, [string]$text) {
    $tmp = "$path.new"
    [IO.File]::WriteAllText($tmp, $text, $script:Utf8)
    # استخدام Native Move بدل [IO.File]::Replace عشان يدعم المسارات الطويلة ويتجنب خطأ "path is not a legal form"
    if (Test-Path -LiteralPath $path) { 
        [void][PG.Nat]::Del($path) 
    }
    [void][PG.Nat]::Move($tmp, $path)
}

# ----------------------------------------------------------------------------------------------------------------
# Event store: events.jsonl is append-only (events + "patch" lines); data.js is rebuilt from memory (throttled)
# ----------------------------------------------------------------------------------------------------------------
function Load-Events {
    $script:Events = [ordered]@{}
    if (-not (Test-Path -LiteralPath $script:LogFile)) { return }
    foreach ($line in [IO.File]::ReadLines($script:LogFile)) {
        $line = $line.Trim([char]0xFEFF).Trim()
        if (-not $line) { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        if ($o.patch) {
            if ($script:Events.Contains([string]$o.id)) {
                foreach ($p in $o.PSObject.Properties) { if ($p.Name -ne 'patch' -and $p.Name -ne 'id') { $script:Events[[string]$o.id][$p.Name] = $p.Value } }
            }
        }
        else {
            $h = @{}
            foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
            if (-not $h.id) { $h.id = 'old' + $script:Events.Count }
            $script:Events[[string]$h.id] = $h
        }
    }
}
function Append-Line([string]$json) { [IO.File]::AppendAllText($script:LogFile, $json + "`n", $script:Utf8) }
function Add-Ev([hashtable]$h) {
    $h.id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    Append-Line ($h | ConvertTo-Json -Compress -Depth 3)
    $script:Events[$h.id] = $h
    $script:DataDirty = $true
    return $h.id
}
function Patch-Ev([string]$id, [hashtable]$p) {
    $line = @{ patch = $true; id = $id }
    foreach ($k in $p.Keys) { $line[$k] = $p[$k] }
    Append-Line (ConvertTo-Json -InputObject $line -Compress -Depth 3)
    if ($script:Events.Contains($id)) { foreach ($k in $p.Keys) { $script:Events[$id][$k] = $p[$k] } }
    $script:DataDirty = $true
}
function Flush-Data([bool]$force = $false) {
    if (-not $script:DataDirty) { return }
    if (-not $force -and ((Get-Date) - $script:LastFlush).TotalSeconds -lt 3) { return }
    try {
        Write-Atomic $script:DataJs ('window.GUARD_DATA = ' + (ConvertTo-Json -InputObject @($script:Events.Values) -Compress -Depth 3) + ';')
        $script:DataDirty = $false; $script:LastFlush = Get-Date
    }
    catch { Log-Err "data.js: $_" }
}
function Beat([bool]$force = $false) {
    $now = Get-Date
    if (-not $force -and ($now - $script:LastBeat).TotalSeconds -lt 15) { return }
    $script:LastBeat = $now
    $script:Health.heartbeat = $now.ToString('s')
    $script:Health.unknown = @($script:Unk).Count
    try { Write-Atomic $script:HealthJs ('window.GUARD_HEALTH = ' + (ConvertTo-Json -InputObject $script:Health -Compress -Depth 4) + ';') } catch { }
    try { Write-Atomic $script:StateFile (ConvertTo-Json -InputObject @{ heartbeat = $now.ToString('s'); initialized = $script:Initialized } -Compress) } catch { }
}

# ----------------------------------------------------------------------------------------------------------------
# Auditing (who deleted it)
# ----------------------------------------------------------------------------------------------------------------
function Get-AuditSetting([string]$g) {
    try { $o = @(& auditpol /get /subcategory:"$g" /r); $l = @($o | Where-Object { $_ -and $_.Trim() })[-1]; return ($l -split ',')[4] } catch { return '?' }
}
function Ensure-Audit {
    foreach ($g in $script:AuditGuids) {
        $cur = Get-AuditSetting $g
        if ($script:AuditGood.ContainsKey($g) -and $cur -ne $script:AuditGood[$g]) {
            $script:Health.auditFlips++
            $script:Health.auditNote = "Audit policy was changed from outside (GPO?) at $(Get-Date -f s) and was re-enabled. If this repeats, enable File System + Detailed File Share (Success) in the GPO."
            Log-Err $script:Health.auditNote
        }
        & auditpol /set /subcategory:"$g" /success:enable | Out-Null
        $script:AuditGood[$g] = Get-AuditSetting $g
    }
}
function Test-RootSacl {
    $sec = [IO.Directory]::GetAccessControl($script:PP, [Security.AccessControl.AccessControlSections]::Audit)
    foreach ($r in $sec.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($r.IdentityReference.Value -eq 'S-1-1-0' -and ($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Delete) -and
            ($r.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -and ($r.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit)) { return $true }
    }
    return $false
}
# IMPORTANT: only the AUDIT section is written (never the DACL), so file permissions are never touched / re-propagated.
function Set-RootSacl {
    $sec = [IO.Directory]::GetAccessControl($script:PP, [Security.AccessControl.AccessControlSections]::Audit)
    $sid = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object Security.AccessControl.FileSystemAuditRule($sid, 'Delete,DeleteSubdirectoriesAndFiles', 'ContainerInherit,ObjectInherit', 'None', 'Success')
    $sec.AddAuditRule($rule)
    [IO.Directory]::SetAccessControl($script:PP, $sec)
}
function Ensure-RootSacl {
    try {
        if (-not (Test-RootSacl)) {
            Set-RootSacl
            $script:Health.auditNote = "Audit rule (SACL) on the project folder was missing at $(Get-Date -f s) and was re-applied."
            Log-Err $script:Health.auditNote
        }
    }
    catch { Log-Err "SACL check: $_" }
}
# files moved into the project from elsewhere on the same volume keep their old security descriptor (no audit rule): fix on first sight
function Ensure-FileSacl([string]$p) {
    try {
        $sec = [IO.File]::GetAccessControl($p, [Security.AccessControl.AccessControlSections]::Audit)
        $has = $false
        foreach ($r in $sec.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.IdentityReference.Value -eq 'S-1-1-0' -and ($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Delete) -and ($r.AuditFlags -band [Security.AccessControl.AuditFlags]::Success)) { $has = $true; break }
        }
        if (-not $has) {
            $sid = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
            $sec.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule($sid, 'Delete', 'None', 'None', 'Success')))
            [IO.File]::SetAccessControl($p, $sec)
        }
    }
    catch { }
}
function Set-SecLogSize {
    try {
        $o = (& wevtutil gl Security) -join "`n"
        if ($o -match 'maxSize:\s*(\d+)') { if ([int64]$Matches[1] -lt 1GB) { & wevtutil sl Security /ms:1073741824 } }
    }
    catch { }
}

function Unesc([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Replace('&apos;', "'").Replace('&quot;', '"').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&amp;', '&')
}
function Read-SecLog([datetime]$from, [datetime]$to) {
    $f = $from.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    $t = $to.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.999Z')
    $xp = "*[System[(EventID=4663 or EventID=5145) and TimeCreated[@SystemTime>='$f' and @SystemTime<='$t']]]"
    try { return @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        try { return @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663, 5145; StartTime = $from; EndTime = $to } -ErrorAction Stop) }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Log-Err "Security log read failed: $_" }
            return @()
        }
    }
}
# One Security-log query per batch, indexed by file name -> fast matching even for thousands of deletions.
function Get-AuditIndex([datetime]$from, [datetime]$to) {
    $idx = @{}
    foreach ($e in (Read-SecLog $from $to)) {
        $x = $e.ToXml(); $d = @{}
        foreach ($m in [regex]::Matches($x, "<Data Name='([^']+)'>([^<]*)</Data>")) { $d[$m.Groups[1].Value] = $m.Groups[2].Value }
        $mask = 0
        try { $mask = [Convert]::ToInt32(([string]$d['AccessMask'] -replace '^0x', ''), 16) } catch { }
        $isDel = (($mask -band 0x10000) -ne 0) -or ([string]$d['AccessList'] -match '%%1537')
        $isDc = (-not $isDel) -and (($mask -band 0x40) -ne 0)          # delete authorised through the PARENT folder (FILE_DELETE_CHILD)
        if (-not ($isDel -or $isDc)) { continue }
        $dom = Unesc $d['SubjectDomainName']; $usr = Unesc $d['SubjectUserName']
        if ($e.Id -eq 5145) {
            $name = Unesc $d['RelativeTargetName']; $full = ''
            $slp = (Unesc $d['ShareLocalPath']) -replace '^\\\\\?\\', ''
            if ($slp -and $name) { $full = $slp.TrimEnd('\') + '\' + $name.TrimStart('\') }
            $kind = 'S'; $ip = (Unesc $d['IpAddress']) -replace '^::ffff:', ''; $procId = -1; $app = ''
        }
        else {
            $name = Unesc $d['ObjectName']; $full = $name
            $kind = 'L'; $ip = ''; $app = Unesc $d['ProcessName']
            $procId = -1; try { $procId = [Convert]::ToInt32(([string]$d['ProcessId'] -replace '^0x', ''), 16) } catch { }
        }
        if (-not $name) { continue }
        $nn = '\' + $name.TrimStart('\')
        $mine = $false
        foreach ($gm in $script:GuardMarks) { if ($nn.IndexOf($gm, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $mine = $true } }
        if ($mine) { continue }                                           # our own vault/deleted moves are not user actions
        $ent = @{ t = [datetime]$e.TimeCreated; k = $kind; name = $name; full = $full; user = "$dom\$usr"; ip = $ip; procId = $procId; app = $app; dc = $isDc }
        $leaf = ($name.TrimEnd('\') -split '\\')[-1].ToLowerInvariant()
        if (-not $idx.ContainsKey($leaf)) { $idx[$leaf] = New-Object System.Collections.ArrayList }
        [void]$idx[$leaf].Add($ent)
    }
    return $idx
}
function Pick-Best($pool, [datetime]$when, [bool]$latest) {
    $smb = @($pool | Where-Object { $_.k -eq 'S' })
    $p = $pool
    if ($smb.Count -gt 0) { $p = $smb }
    if ($latest) { return ($p | Sort-Object { $_.t } -Descending | Select-Object -First 1) }
    return ($p | Sort-Object { [math]::Abs(($_.t - $when).TotalSeconds) } | Select-Object -First 1)
}
# exact full-path match first, then project-relative tail match; file itself first, then parent folders (folder-level delete events)
function Find-Who([string]$rel, [datetime]$when, $idx, [bool]$latest, [int]$maxDiff) {
    $segs = $rel -split '\\'
    for ($k = $segs.Count; $k -ge 1; $k--) {
        $leaf = $segs[$k - 1].ToLowerInvariant()
        if (-not $idx.ContainsKey($leaf)) { continue }
        $prefix = ($segs[0..($k - 1)]) -join '\'
        $pfull = J $script:PP $prefix
        $exact = @(); $tail = @()
        foreach ($c in $idx[$leaf]) {
            if ($k -eq $segs.Count -and $c.dc) { continue }
            if ($maxDiff -gt 0 -and [math]::Abs(($c.t - $when).TotalSeconds) -gt $maxDiff) { continue }
            if ($c.full -and ($c.full -ieq $pfull)) { $exact += $c; continue }
            $nm = '\' + $c.name.TrimStart('\')
            if ($nm.EndsWith('\' + $prefix, [StringComparison]::OrdinalIgnoreCase)) { $tail += $c }
        }
        $pool = $tail
        if ($exact.Count -gt 0) { $pool = $exact }
        if ($pool.Count -gt 0) { return (Pick-Best $pool $when $latest) }
    }
    return $null
}
function Resolve-Machine([string]$ip) {
    if (-not $ip) { return '' }
    $ip = $ip -replace '^::ffff:', ''
    if ($ip -eq '::1' -or $ip -eq '127.0.0.1') { return $env:COMPUTERNAME }
    if ($script:Dns.ContainsKey($ip)) { return $script:Dns[$ip] }
    $n = 'unresolved'
    try { $n = ([Net.Dns]::GetHostEntry($ip)).HostName } catch { }
    $script:Dns[$ip] = $n
    return $n
}
function Resolve-Who($c) {
    $r = @{ user = 'Unknown'; ip = ''; machine = ''; source = 'Unknown'; app = '' }
    if ($null -eq $c) { return $r }
    $r.user = $c.user
    if ($c.k -eq 'S') { $r.source = 'SMB'; $r.ip = $c.ip; $r.machine = Resolve-Machine $c.ip }
    elseif ($c.procId -eq 4 -or -not $c.app -or $c.app -eq 'System') { $r.source = 'SMB' }          # network access without a share event: user known, IP not
    else { $r.source = 'Local'; $r.machine = $env:COMPUTERNAME; $r.app = $c.app }
    return $r
}

# Events that were saved as Unknown are looked up again later (audit event may be flushed late)
function Add-Unk([string]$id, [string]$full, [string]$rel, [datetime]$when, [int]$tries, [bool]$late) {
    [void]$script:Unk.Add(@{ id = $id; full = $full; rel = $rel; when = $when; tries = $tries; late = $late; next = (Get-Date).AddSeconds($script:UnkDelays[[math]::Min($tries, 4)]) })
}
function Retry-Unknown {
    if ($script:Unk.Count -eq 0) { return }
    $now = Get-Date
    $due = @($script:Unk | Where-Object { $_.next -le $now })
    if ($due.Count -eq 0) { return }
    $min = [datetime]::MaxValue
    foreach ($u in $due) { $s = $u.when.AddSeconds(-30); if ($u.late) { $s = $u.when.AddMinutes(-30) }; if ($s -lt $min) { $min = $s } }
    $idx = Get-AuditIndex $min $now.AddSeconds(5)
    foreach ($u in $due) {
        $md = 120; if ($u.late) { $md = 0 }
        $c = Find-Who $u.rel $u.when $idx $u.late $md
        if ($c) {
            $w = Resolve-Who $c
            Patch-Ev $u.id @{ user = $w.user; ip = $w.ip; machine = $w.machine; source = $w.source; app = $w.app }
            $script:Unk.Remove($u)
        }
        else {
            $u.tries++
            if ($u.tries -ge 5) { $script:Unk.Remove($u); Patch-Ev $u.id @{ note = 'auditNotFound' } }
            else { $u.next = $now.AddSeconds($script:UnkDelays[$u.tries]) }
        }
    }
}

# ----------------------------------------------------------------------------------------------------------------
# Vault sync (hard links)
# ----------------------------------------------------------------------------------------------------------------
function Sync-Tree([string]$dir) {
    $fl = New-Object 'System.Collections.Generic.List[string]'; $dl = New-Object 'System.Collections.Generic.List[string]'
    [PG.Nat]::Walk($dir, $script:SkipArg, $fl, $dl)
    $rel = Get-Rel $dir
    [void][PG.Nat]::Mkdirs((J $script:V $rel))
    foreach ($d in $dl) { [void][PG.Nat]::Mkdirs((J $script:V (J $rel $d))) }
    foreach ($f in $fl) { $p = J $dir $f; if (-not (Test-Skip $p)) { [void](Sync-Path $p) } }
}
function Sync-Path([string]$p) {
    if (Test-Skip $p) { return $true }
    if (-not [PG.Nat]::Exists($p)) { return $true }
    if ([PG.Nat]::IsDir($p)) { Sync-Tree $p; return $true }
    $r = [PG.Nat]::SyncOne($p, (J $script:V (Get-Rel $p)))
    $fresh = $false
    if ($script:W) { $b = [byte]0; $fresh = $script:W.Fresh.TryRemove($p, [ref]$b) }
    if ($r -lt 0) { return $false }
    if ($r -eq 3) { $script:Health.copyFallbacks++ }
    if ($r -eq 1 -or $r -eq 3 -or $fresh) { Ensure-FileSacl $p }
    return $true
}
function Handle-Rename($e) {
    $old = $e.Old; $new = $e.Path
    $so = Test-Skip $old; $sn = Test-Skip $new
    if ($so -and $sn) { return }
    if ((-not $so) -and $sn) { if (-not $script:DelQ.ContainsKey($old)) { $script:DelQ[$old] = $e.Time }; return }     # renamed to an ignored name = gone
    if ($so -and (-not $sn)) { $script:W.Dirty[$new] = Get-Date; return }                                                # temp -> real name (Office save)
    $vo = J $script:V (Get-Rel $old); $vn = J $script:V (Get-Rel $new)
    if ([PG.Nat]::Exists($vo)) {
        if ([PG.Nat]::Exists($vn) -and -not [PG.Nat]::IsDir($vn)) { [void][PG.Nat]::Del($vn) }
        [void][PG.Nat]::Mkdirs((Parent $vn))
        $rc = [PG.Nat]::Move($vo, $vn)
        if ($rc -ne 0) { $script:NeedScan = $true; $script:ScanVerify = $true }
    }
    elseif ([PG.Nat]::IsDir($new)) { Sync-Tree $new }
    if (-not [PG.Nat]::IsDir($new)) { $script:W.Dirty[$new] = Get-Date }       # verify identity (replace-by-rename gives a new file)
}

function Remove-VaultDir([string]$vp) {
    $fl = New-Object 'System.Collections.Generic.List[string]'; $dl = New-Object 'System.Collections.Generic.List[string]'
    [PG.Nat]::Walk($vp, $null, $fl, $dl)
    if ($fl.Count -gt 0) { return }
    $dl.Sort()
    for ($i = $dl.Count - 1; $i -ge 0; $i--) { [void][PG.Nat]::RmDir((J $vp $dl[$i])) }
    [void][PG.Nat]::RmDir($vp)
}

# items: @{ full; rel; when }.  $late = discovered by a scan (deletion time unknown -> use the audit event time)
function Process-Deletes($items, [bool]$late, [datetime]$lateFrom) {
    $entries = New-Object System.Collections.ArrayList
    $dirs = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($it in $items) {
        if (-not $it.rel) { continue }
        if ([PG.Nat]::Exists($it.full)) { continue }                       # it is back: this was a replace, not a delete
        $vp = J $script:V $it.rel
        if ([PG.Nat]::IsDir($vp)) {
            $fl = New-Object 'System.Collections.Generic.List[string]'; $dl = New-Object 'System.Collections.Generic.List[string]'
            [PG.Nat]::Walk($vp, $null, $fl, $dl)
            foreach ($sub in $fl) {
                $r = J $it.rel $sub
                if ($seen.Add($r)) { [void]$entries.Add(@{ rel = $r; when = $it.when; inFolder = $true; nocopy = $false }) }
            }
            [void]$dirs.Add($vp)
        }
        elseif ([PG.Nat]::Exists($vp)) {
            if ($seen.Add($it.rel)) { [void]$entries.Add(@{ rel = $it.rel; when = $it.when; inFolder = $false; nocopy = $false }) }
        }
        elseif (-not $late) {
            if ($seen.Add($it.rel)) { [void]$entries.Add(@{ rel = $it.rel; when = $it.when; inFolder = $false; nocopy = $true }) }
        }
    }
    if ($entries.Count -gt 0) {
        $min = [datetime]::MaxValue
        foreach ($en in $entries) { if ($en.when -lt $min) { $min = $en.when } }
        $from = $min.AddSeconds(-30); if ($late) { $from = $lateFrom }
        $idx = Get-AuditIndex $from (Get-Date).AddSeconds(5)
        $n = 0
        foreach ($en in $entries) {
            $n++; if (($n % 50) -eq 0) { Beat; Flush-Data }
            $full = J $script:PP $en.rel
            $md = 120; if ($late) { $md = 0 }
            $c = Find-Who $en.rel $en.when $idx $late $md
            $who = Resolve-Who $c
            $t = $en.when
            if ($late) { if ($c) { $t = $c.t } else { $t = Get-Date } }
            $det = 'live'; if ($late) { $det = 'late' }
            $rec = @{ time = $t.ToString('s'); file = $full; relative = $en.rel; sizeBytes = $null; sizeKB = $null; backup = ''; user = $who.user; ip = $who.ip; machine = $who.machine; source = $who.source; app = $who.app; inFolder = $en.inFolder; detected = $det; note = '' }
            if ($en.nocopy) {
                $rec.note = 'nocopy'
                [void](Add-Ev $rec)
                continue
            }
            $vp = J $script:V $en.rel
            $fi = [PG.Nat]::Probe($vp)
            if (-not $fi.Ok) { continue }
            $base = $t.ToString('yyyyMMdd_HHmmss'); $stamp = $base; $i = 1
            $dst = J (J $script:D $stamp) $en.rel
            while ([PG.Nat]::Exists($dst)) { $i++; $stamp = "${base}_$i"; $dst = J (J $script:D $stamp) $en.rel }
            [void][PG.Nat]::Mkdirs((Parent $dst))
            $rc = [PG.Nat]::Move($vp, $dst)            # same-volume rename of the hard link: instant, no copy
            if ($rc -ne 0) { Log-Err "move to deleted failed ($rc): $vp (will be retried by the next scan)"; continue }
            $rec.sizeBytes = $fi.Length; $rec.sizeKB = [math]::Round($fi.Length / 1KB, 1)
            $rec.backup = "deleted/$stamp/" + ($en.rel -replace '\\', '/')
            $id = Add-Ev $rec
            if ($who.source -eq 'Unknown') { Add-Unk $id $full $en.rel $t 0 $late }
        }
    }
    foreach ($dv in $dirs) { Remove-VaultDir $dv }
}

function Process-Orphans {
    $now = Get-Date; $due = New-Object System.Collections.ArrayList; $from = $now
    foreach ($k in @($script:Orphans.Keys)) {
        $o = $script:Orphans[$k]; $full = J $script:PP $k
        if ([PG.Nat]::Exists($full) -or -not [PG.Nat]::Exists((J $script:V $k))) { $script:Orphans.Remove($k); continue }
        if (($now - $o.first).TotalSeconds -ge 15) {
            [void]$due.Add(@{ full = $full; rel = $k; when = $now })
            if ($o.from -lt $from) { $from = $o.from }
            $script:Orphans.Remove($k)
        }
    }
    if ($due.Count -gt 0) { Process-Deletes @($due) $true $from }
}

# Full reconcile: link anything unprotected, flag vault entries whose project file is gone (deleted while we were not watching)
function Run-Scan([bool]$verify) {
    $t0 = Get-Date
    $pf = New-Object 'System.Collections.Generic.List[string]'; $pd = New-Object 'System.Collections.Generic.List[string]'
    $vf = New-Object 'System.Collections.Generic.List[string]'; $vd = New-Object 'System.Collections.Generic.List[string]'
    [PG.Nat]::Walk($script:PP, $script:SkipArg, $pf, $pd)
    [PG.Nat]::Walk($script:V, $null, $vf, $vd)
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $pset = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
    foreach ($r in $pf) { [void]$pset.Add($r) }
    $vset = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
    foreach ($r in $vf) { [void]$vset.Add($r) }
    $vdset = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
    foreach ($r in $vd) { [void]$vdset.Add($r) }
    foreach ($d in $pd) { if (-not $vdset.Contains($d)) { [void][PG.Nat]::Mkdirs((J $script:V $d)) } }
    $orph = @{}
    foreach ($r in $vf) {
        if (-not $pset.Contains($r)) {
            $orph[$r] = 1
            if (-not $script:Orphans.ContainsKey($r)) { $script:Orphans[$r] = @{ first = $t0; from = $script:PrevScan.AddSeconds(-60) } }
        }
    }
    foreach ($k in @($script:Orphans.Keys)) { if (-not $orph.ContainsKey($k)) { $script:Orphans.Remove($k) } }
    $n = 0
    foreach ($r in $pf) {
        $n++; if (($n % 500) -eq 0) { Beat }
        if ([PG.Nat]::SkipName($r.Substring($r.LastIndexOf('\') + 1))) { continue }
        if ($verify -or -not $vset.Contains($r)) {
            $p = J $script:PP $r
            $ok = $false
            try { $ok = Sync-Path $p } catch { Log-Err "scan sync $p : $_" }
            if (-not $ok -and $script:W) { $script:W.Dirty[$p] = (Get-Date).AddSeconds(8) }
        }
    }
    $script:PrevScan = $t0
    $script:LastScan = Get-Date
}

# deleted\ files that have no event (crash between "move" and "log"): log them now
function Recover-Unlogged {
    $fl = New-Object 'System.Collections.Generic.List[string]'; $dl = New-Object 'System.Collections.Generic.List[string]'
    [PG.Nat]::Walk($script:D, $null, $fl, $dl)
    if ($fl.Count -eq 0) { return }
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $script:Events.Values) { if ($e.backup) { [void]$known.Add((([string]$e.backup) -replace '^deleted/', '' -replace '/', '\')) } }
    $miss = New-Object System.Collections.ArrayList
    foreach ($m in $fl) {
        if ($known.Contains($m)) { continue }
        $i = $m.IndexOf('\'); if ($i -lt 1) { continue }
        $t = $null
        try { $t = [datetime]::ParseExact($m.Substring(0, 15), 'yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture) } catch { continue }
        [void]$miss.Add(@{ m = $m; stamp = $m.Substring(0, $i); rel = $m.Substring($i + 1); t = $t })
    }
    if ($miss.Count -eq 0) { return }
    $min = [datetime]::MaxValue; $max = [datetime]::MinValue
    foreach ($x in $miss) { if ($x.t -lt $min) { $min = $x.t }; if ($x.t -gt $max) { $max = $x.t } }
    $idx = Get-AuditIndex $min.AddMinutes(-2) $max.AddMinutes(2)
    foreach ($x in $miss) {
        $c = Find-Who $x.rel $x.t $idx $false 180
        $who = Resolve-Who $c
        $fi = [PG.Nat]::Probe((J $script:D $x.m))
        $len = 0; if ($fi.Ok) { $len = $fi.Length }
        $rec = @{ time = $x.t.ToString('s'); file = (J $script:PP $x.rel); relative = $x.rel; sizeBytes = $len; sizeKB = [math]::Round($len / 1KB, 1); backup = "deleted/$($x.stamp)/" + ($x.rel -replace '\\', '/')
            user = $who.user; ip = $who.ip; machine = $who.machine; source = $who.source; app = $who.app; inFolder = $false; detected = 'recovered'; note = '' }
        $id = Add-Ev $rec
        if ($who.source -eq 'Unknown') { Add-Unk $id $rec.file $x.rel $x.t 1 $true }
    }
}

function Purge-Old {
    if ($RetentionDays -le 0) { return }
    foreach ($dir in [IO.Directory]::GetDirectories($script:D)) {
        $n = Split-Path $dir -Leaf
        $t = $null
        try { $t = [datetime]::ParseExact($n.Substring(0, 15), 'yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture) } catch { continue }
        if ($t -ge (Get-Date).AddDays(-$RetentionDays)) { continue }
        $fl = New-Object 'System.Collections.Generic.List[string]'; $dl = New-Object 'System.Collections.Generic.List[string]'
        [PG.Nat]::Walk($dir, $null, $fl, $dl)
        foreach ($f in $fl) { [void][PG.Nat]::Del((J $dir $f)) }
        Remove-VaultDir $dir
        foreach ($ev in @($script:Events.Values)) { if ($ev.backup -and ([string]$ev.backup).StartsWith("deleted/$n/")) { Patch-Ev $ev.id @{ backup = ''; note = 'purged' } } }
    }
}

# ----------------------------------------------------------------------------------------------------------------
# Core start/stop/tick
# ----------------------------------------------------------------------------------------------------------------
function New-Watcher { $script:W = New-Object PG.Watch($script:PP, $script:G, $script:V) }

function Start-Core {
    Initialize-Native
    Stop-Core                                                      # restart-safe: never leave an old watcher running
    foreach ($d in @($script:G, $script:V, $script:D)) { [void][PG.Nat]::Mkdirs($d) }
    $now = Get-Date
    $down = $null; $script:Initialized = $false
    if (Test-Path -LiteralPath $script:StateFile) {
        try { $s = Get-Content -Raw -LiteralPath $script:StateFile | ConvertFrom-Json; $script:Initialized = [bool]$s.initialized; $down = To-Date $s.heartbeat } catch { }
    }
    $script:Health.started = $now.ToString('s')
    $script:Health.gaps = @()
    $script:Orphans = @{}; $script:DelQ = @{}; $script:Tries = @{}; $script:AuditGood = @{}
    $script:PrevScan = $now.AddMinutes(-10); if ($down) { $script:PrevScan = $down }
    Load-Events
    $script:DataDirty = $true
    $gaps = @()
    if ($down -and (($now - $down).TotalSeconds -gt 60)) { $gaps += @{ from = $down.ToString('s'); to = $now.ToString('s') } }
    $script:Health.gaps = $gaps
    $script:Unk = New-Object System.Collections.ArrayList
    $cut = $now.AddHours(-24)
    foreach ($ev in $script:Events.Values) {
        if ($ev.source -eq 'Unknown' -and $ev.backup -and $ev.note -ne 'auditNotFound') {
            $t = To-Date $ev.time
            if ($t -and $t -gt $cut) { Add-Unk $ev.id $ev.file $ev.relative $t 2 ($ev.detected -ne 'live') }
        }
    }
    try { Ensure-Audit } catch { Log-Err "auditpol: $_" }
    Ensure-RootSacl
    New-Watcher                                                    # watcher first, scan second: nothing can be missed in between
    Run-Scan $true
    $script:Initialized = $true
    Recover-Unlogged
    $script:LastScan = Get-Date; $script:LastHealth = Get-Date; $script:LastPurge = Get-Date
    Flush-Data $true; Beat $true
}
function Stop-Core {
    if ($script:W) { $script:W.Dispose(); $script:W = $null }
}

function Tick {
    $w = $script:W
    try {
        if ($w.Overflow) {
            Log-Err ('watcher overflow/error -> full rescan. ' + $w.Fault)
            $w.Dispose(); New-Watcher; $w = $script:W
            $script:NeedScan = $true; $script:ScanVerify = $true
        }
        $e = $null; $n = 0
        while ($n -lt 20000 -and $w.Q.TryDequeue([ref]$e)) {
            $n++
            if ($e.Kind -eq 'D') { if (-not $script:DelQ.ContainsKey($e.Path)) { $script:DelQ[$e.Path] = $e.Time } }
            else { Handle-Rename $e }
        }
    }
    catch { Log-Err "queue: $_" }

    try {                                                           # created/changed files: link/relink after a 2s quiet period
        $now = Get-Date
        $sw = [Diagnostics.Stopwatch]::StartNew()
        foreach ($kv in $w.Dirty.ToArray()) {
            if (($now - $kv.Value).TotalSeconds -lt 2) { continue }
            $o = [DateTime]::MinValue
            if (-not $w.Dirty.TryRemove($kv.Key, [ref]$o)) { continue }
            if ($o -gt $kv.Value) { $w.Dirty[$kv.Key] = $o; continue }
            $ok = $false
            try { $ok = Sync-Path $kv.Key } catch { Log-Err "sync $($kv.Key): $_" }
            if ($ok) { $script:Tries.Remove($kv.Key) }
            else {
                $t = 1 + [int]$script:Tries[$kv.Key]; $script:Tries[$kv.Key] = $t
                if ($t -lt 30) { $w.Dirty[$kv.Key] = (Get-Date).AddSeconds(8) } else { $script:Tries.Remove($kv.Key); Log-Err "could not link now (next scan retries): $($kv.Key)" }
            }
            if ($sw.Elapsed.TotalSeconds -gt 8) { break }
        }
    }
    catch { Log-Err "dirty: $_" }

    try {                                                           # deletions: wait 2s so the audit event is in the Security log
        if ($script:DelQ.Count -gt 0) {
            $due = New-Object System.Collections.ArrayList
            foreach ($k in @($script:DelQ.Keys)) {
                $t = $script:DelQ[$k]
                if (((Get-Date) - $t).TotalSeconds -ge 2) { [void]$due.Add(@{ full = $k; rel = (Get-Rel $k); when = $t }); $script:DelQ.Remove($k) }
            }
            if ($due.Count -gt 0) { Process-Deletes @($due | Sort-Object { $_.full.Length } -Descending) $false ([datetime]::MinValue) }
        }
    }
    catch { Log-Err "deletes: $_" }

    try { if ($script:Orphans.Count -gt 0) { Process-Orphans } } catch { Log-Err "orphans: $_" }
    try { Retry-Unknown } catch { Log-Err "retry: $_" }
    try {
        $now = Get-Date
        if ($script:NeedScan -or (($now - $script:LastScan).TotalMinutes -ge $ScanMinutes)) { $v = $script:ScanVerify; $script:NeedScan = $false; $script:ScanVerify = $false; Run-Scan $v }
        if (($now - $script:LastHealth).TotalMinutes -ge 10) { $script:LastHealth = $now; try { Ensure-Audit } catch { Log-Err "auditpol: $_" }; Ensure-RootSacl }
        if (($now - $script:LastPurge).TotalHours -ge 24) { $script:LastPurge = $now; Purge-Old }
    }
    catch { Log-Err "periodic: $_" }
    Flush-Data
    Beat
}

function Run-Guard {
    $script:Mutex = New-Object Threading.Mutex($false, ('Global\PG_' + $script:Hash))
    $got = $false
    try { $got = $script:Mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { Write-Host 'Another ProjectGuard instance is already running for this project.'; return }
    while ($true) {
        try { Start-Core; break } catch { try { Log-Err "start failed: $_" } catch { }; Start-Sleep -Seconds 15 }
    }
    while ($true) {
        try { Tick } catch { Log-Err "tick: $_" }
        Start-Sleep -Milliseconds 1000
    }
}

# ----------------------------------------------------------------------------------------------------------------
# Restore (hard link back = no extra space, original permissions are kept)
# ----------------------------------------------------------------------------------------------------------------
function Restore-Events([string[]]$Ids, $SinceD, [string]$UserF, [string]$UnderF, [bool]$PreviewOnly) {
    Load-Events
    $list = @($script:Events.Values | Where-Object { $_.backup })
    if ($Ids -and ($Ids -notcontains '*')) { $list = @($list | Where-Object { $Ids -contains $_.id }) }
    if ($SinceD) { $list = @($list | Where-Object { $d = To-Date $_.time; $d -and $d -ge $SinceD }) }
    if ($UserF) { $list = @($list | Where-Object { $_.user -like $UserF }) }
    if ($UnderF) { $u = $UnderF.Trim('\').Replace('/', '\'); $list = @($list | Where-Object { ([string]$_.relative) -like "$u*" }) }
    $ok = 0; $bad = 0
    foreach ($ev in @($list | Sort-Object { $_.time })) {
        $src = J $script:G (([string]$ev.backup) -replace '/', '\')
        if (-not [PG.Nat]::Exists($src)) { Write-Warning "backup missing: $($ev.backup)"; $bad++; continue }
        $target = J $script:PP $ev.relative
        if ([PG.Nat]::Exists($target)) {
            $leaf = Split-Path $target -Leaf
            $nm = [IO.Path]::GetFileNameWithoutExtension($leaf); $ex = [IO.Path]::GetExtension($leaf)
            $target = J (Parent $target) ("$nm (restored $(Get-Date -f yyyyMMdd_HHmmss))$ex")
        }
        if ($PreviewOnly) { Write-Host "[preview] $($ev.relative)  <-  $($ev.backup)   (deleted by $($ev.user) at $($ev.time))"; continue }
        [void][PG.Nat]::Mkdirs((Parent $target))
        $rc = [PG.Nat]::Link($src, $target)
        if ($rc -ne 0) { $rc = [PG.Nat]::Copy($src, $target) }
        if ($rc -eq 0) { $ok++; Write-Host "restored: $target" } else { $bad++; Write-Warning "failed ($rc): $target" }
    }
    Write-Host "Restore finished. restored=$ok failed=$bad"
    return $ok
}

# ----------------------------------------------------------------------------------------------------------------
# Install / Uninstall
# ----------------------------------------------------------------------------------------------------------------
function Install-Guard {
    Assert-Admin
    $dash = Join-Path $PSScriptRoot 'dashboard.html'
    if (-not (Test-Path -LiteralPath $dash)) { throw 'dashboard.html must be next to this script.' }
    Initialize-Native
    Initialize-Context $ProjectPath $GuardRoot
    $drv = New-Object IO.DriveInfo ($script:PP.Substring(0, 1))
    if ($drv.DriveFormat -ne 'NTFS' -and $drv.DriveFormat -ne 'ReFS') { Write-Warning "Volume is $($drv.DriveFormat): hard links are not available, the vault will use real copies (double space)." }
    New-Item -ItemType Directory -Force $script:GR | Out-Null
    $fresh = -not (Test-Path -LiteralPath $script:G)
    New-Item -ItemType Directory -Force $script:G | Out-Null
    if ($fresh) {
        # Lock the guard folder BEFORE any hard link exists. NEVER change permissions on it afterwards:
        # vault entries are the same files as the project files, so an ACL change on the vault would propagate to the project files.
        icacls $script:G /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    New-Item -ItemType Directory -Force $script:V, $script:D | Out-Null

    # preflight: prove that a hard link project -> vault works on this volume
    $probe = J $script:PP ('.pg_probe_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $pv = J $script:V '.pg_probe'
    [IO.File]::WriteAllText($probe, 'x')
    try {
        $rc = [PG.Nat]::Link($probe, $pv)
        if ($rc -ne 0) { throw "Cannot create a hard link from the project to $($script:V) (Win32 error $rc). The guard folder must be on the SAME NTFS/ReFS volume as the project: use -GuardRoot <folder on that volume>." }
        $pi = [PG.Nat]::Probe($probe)
        if ($pi.Links -lt 2) { throw 'Hard link check failed (link count is not 2).' }
    }
    finally { [void][PG.Nat]::Del($pv); Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }

    Copy-Item $dash (J $script:G 'dashboard.html') -Force
    $self = J $script:G 'ProjectGuard.ps1'
    if ($PSCommandPath -ne $self) { Copy-Item $PSCommandPath $self -Force }
    if (-not (Test-Path (J $script:G 'data.js'))) { 'window.GUARD_DATA = [];' | Set-Content (J $script:G 'data.js') -Encoding UTF8 }
    if (-not (Test-Path (J $script:G 'health.js'))) { 'window.GUARD_HEALTH = null;' | Set-Content (J $script:G 'health.js') -Encoding UTF8 }

    Ensure-Audit
    Set-RootSacl
    Set-SecLogSize

    $arg = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$self`" -Mode Run -ProjectPath `"$($script:PP)`" -GuardRoot `"$($script:GR)`" -ScanMinutes $ScanMinutes -RetentionDays $RetentionDays"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $t1 = New-ScheduledTaskTrigger -AtStartup
    $t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)   # watchdog
    $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger @($t1, $t2) -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $script:TaskName
    Write-Host "Installed. Task: $($script:TaskName)" -ForegroundColor Green
    Write-Host "Guard folder: $($script:G)" -ForegroundColor Green
    Write-Host "Dashboard   : $(J $script:G 'dashboard.html')" -ForegroundColor Green
    Write-Host 'Run  .\ProjectGuard.ps1 -Mode SelfTest  once to verify everything on this server.' -ForegroundColor Yellow
}
function Uninstall-Guard {
    Assert-Admin
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Task removed. Guard folder kept: $($script:G)  (vault + deleted + logs). Delete it manually only if you no longer need the logs."
}

# ----------------------------------------------------------------------------------------------------------------
# SelfTest: runs the real engine on a temp folder (local deletes, replace-save, downtime, folder delete, restore)
# SMB attribution cannot be simulated here: test it once from a client PC (see guide).
# ----------------------------------------------------------------------------------------------------------------
function Invoke-SelfTest {
    Assert-Admin
    Initialize-Native
    $root = Join-Path $env:SystemDrive ('PG_SelfTest_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $root | Out-Null
    Initialize-Context $root (Join-Path $env:SystemDrive 'PG_SelfTest_Guard')
    $script:Results = @()
    function T([string]$name, [bool]$ok, [string]$info = '') {
        $script:Results += [pscustomobject]@{ Name = $name; Ok = $ok }
        if ($ok) { Write-Host "  PASS  $name" -ForegroundColor Green } else { Write-Host "  FAIL  $name  $info" -ForegroundColor Red }
    }
    function Pump([scriptblock]$cond, [int]$sec) {
        $end = (Get-Date).AddSeconds($sec)
        while ((Get-Date) -lt $end) { Tick; if (& $cond) { return $true }; Start-Sleep -Milliseconds 700 }
        return [bool](& $cond)
    }
    function EvOf([string]$rel) { return @($script:Events.Values | Where-Object { $_.relative -ieq $rel }) | Select-Object -First 1 }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    try {
        Write-Host "SelfTest folder: $root"
        New-Item -ItemType Directory -Force $script:GR | Out-Null
        New-Item -ItemType Directory -Force $script:G | Out-Null
        Set-Content (Join-Path $root 'a.txt') 'content-A'
        Set-Content (Join-Path $root 'c.txt') 'content-C'
        Set-Content (Join-Path $root 'r.txt') 'old-R'
        New-Item -ItemType Directory -Force (Join-Path $root 'dir1\sub') | Out-Null
        Set-Content (Join-Path $root 'dir1\x1.txt') 'X1'
        Set-Content (Join-Path $root 'dir1\sub\x2.txt') 'X2'
        Start-Core
        Write-Host "Auditing: $($script:Health.auditNote)"

        # 1. hard link, no extra space
        $pi = [PG.Nat]::Probe((Join-Path $root 'a.txt')); $vi = [PG.Nat]::Probe((J $script:V 'a.txt'))
        T 'vault entry is a HARD LINK (same file, link count 2 = no extra space)' ($pi.Ok -and $vi.Ok -and $pi.Key -eq $vi.Key -and $pi.Links -ge 2)
        Set-Content (Join-Path $root 'new.txt') 'brand new'
        $okNew = Pump { $a = [PG.Nat]::Probe((Join-Path $root 'new.txt')); $b = [PG.Nat]::Probe((J $script:V 'new.txt')); $a.Ok -and $b.Ok -and $a.Key -eq $b.Key } 15
        T 'new file is linked automatically' $okNew

        # 2. local delete: user must be known
        Remove-Item (Join-Path $root 'a.txt') -Force
        $ok = Pump { $e = EvOf 'a.txt'; $e -and $e.backup } 25
        $e = EvOf 'a.txt'
        T 'local delete is logged and recoverable' ([bool]$ok)
        T 'local delete: user is identified (not Unknown)' ($e -and $e.user -ieq $me) "got: $($e.user) / source $($e.source)"
        T 'local delete: source = Local' ($e -and $e.source -eq 'Local') "got: $($e.source)"
        $bk = if ($e) { J $script:G (($e.backup) -replace '/', '\') } else { '' }
        T 'backup content intact' ($bk -and (Get-Content $bk -Raw).Trim() -eq 'content-A')

        # 3. replace-save (new file under the same name) must refresh the vault
        $tmpn = Join-Path $root 'r_new_content'
        Set-Content $tmpn 'new-R'
        Move-Item $tmpn (Join-Path $root 'r.txt') -Force
        $ok = Pump { $a = [PG.Nat]::Probe((Join-Path $root 'r.txt')); $b = [PG.Nat]::Probe((J $script:V 'r.txt')); $a.Ok -and $b.Ok -and $a.Key -eq $b.Key } 15
        T 'replace-save: vault follows the new version' $ok
        Remove-Item (Join-Path $root 'r.txt') -Force
        $ok = Pump { $e2 = EvOf 'r.txt'; $e2 -and $e2.backup } 25
        $e2 = EvOf 'r.txt'
        $bk = if ($e2) { J $script:G (($e2.backup) -replace '/', '\') } else { '' }
        T 'replace-save: restored copy is the LATEST version' ($bk -and (Get-Content $bk -Raw).Trim() -eq 'new-R')

        # 4. folder delete
        Remove-Item (Join-Path $root 'dir1') -Recurse -Force
        $ok = Pump { (EvOf 'dir1\x1.txt') -and (EvOf 'dir1\sub\x2.txt') } 30
        $f1 = EvOf 'dir1\x1.txt'; $f2 = EvOf 'dir1\sub\x2.txt'
        T 'folder delete: every file logged with a backup' ($f1 -and $f2 -and $f1.backup -and $f2.backup)
        T 'folder delete: user identified' ($f1 -and $f2 -and $f1.user -ieq $me -and $f2.user -ieq $me) "got: $($f1.user) / $($f2.user)"

        # 5. downtime: script stopped, file deleted + another created, script started again
        Stop-Core
        Remove-Item (Join-Path $root 'c.txt') -Force
        Set-Content (Join-Path $root 'created_while_down.txt') 'D'
        Start-Core
        $ok = Pump { $e3 = EvOf 'c.txt'; $e3 -and $e3.backup } 45
        $e3 = EvOf 'c.txt'
        T 'downtime: file deleted while the guard was stopped is moved to deleted\ after restart' ([bool]$ok)
        T 'downtime: deleter identified from the Security log' ($e3 -and $e3.user -ieq $me) "got: $($e3.user)"
        $a = [PG.Nat]::Probe((Join-Path $root 'created_while_down.txt')); $b = [PG.Nat]::Probe((J $script:V 'created_while_down.txt'))
        T 'downtime: file created while stopped is protected after restart' ($a.Ok -and $b.Ok -and $a.Key -eq $b.Key)

        # 6. restore
        $n = Restore-Events @($e.id) $null '' '' $false
        T 'restore brings the file back' ((Test-Path (Join-Path $root 'a.txt')) -and (Get-Content (Join-Path $root 'a.txt') -Raw).Trim() -eq 'content-A')
    }
    catch { Write-Host "SelfTest aborted: $_" -ForegroundColor Red; $script:Results += [pscustomobject]@{ Name = 'aborted'; Ok = $false } }
    finally {
        try { Stop-Core } catch { }
        Start-Sleep -Seconds 1
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $env:SystemDrive 'PG_SelfTest_Guard') -Recurse -Force -ErrorAction SilentlyContinue
    }
    $fail = @($script:Results | Where-Object { -not $_.Ok }).Count
    Write-Host ''
    if ($fail -eq 0) { Write-Host "ALL $($script:Results.Count) CHECKS PASSED" -ForegroundColor Green } else { Write-Host "$fail CHECK(S) FAILED - see errors above and errors.log" -ForegroundColor Red }
}

switch ($Mode) {
    'Install' { Install-Guard }
    'Run' { Initialize-Native; Initialize-Context $ProjectPath $GuardRoot; Run-Guard }
    'Uninstall' { Initialize-Native; Initialize-Context $ProjectPath $GuardRoot; Uninstall-Guard }
    'Restore' {
        Assert-Admin; Initialize-Native; Initialize-Context $ProjectPath $GuardRoot
        $sd = $null; if ($PSBoundParameters.ContainsKey('Since')) { $sd = $Since }
        if (-not $EventId -and -not $sd -and -not $User -and -not $Under) { throw "Specify -EventId <id>|'*' and/or -Since / -User / -Under (add -Preview to only list)." }
        [void](Restore-Events $EventId $sd $User $Under $Preview.IsPresent)
    }
    'SelfTest' { Invoke-SelfTest }
}