namespace ProcessShield.Core;

public enum Verdict { Allow, Warn, Quarantine }

public enum SignalKind
{
    ProcessStart,
    ImageLoad,
    FileCreate,
    NetworkConnect,
    MemoryMatch
}

/// <summary>A single piece of telemetry emitted by any monitor.</summary>
public sealed record Signal
{
    public required SignalKind Kind { get; init; }
    public required int Pid { get; init; }
    public int ParentPid { get; init; }
    public string ProcessName { get; init; } = "";
    public string ImagePath { get; init; } = "";
    public string CommandLine { get; init; } = "";
    public string? FilePath { get; init; }          // FileCreate / ImageLoad
    public string? RemoteAddress { get; init; }      // NetworkConnect
    public int RemotePort { get; init; }
    public string? Detail { get; init; }
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>Result of a single OS action, with a human-readable reason on failure.</summary>
public readonly struct ActionResult
{
    public bool Ok { get; }
    public string Message { get; }
    private ActionResult(bool ok, string message) { Ok = ok; Message = message; }
    public static ActionResult Success(string message = "ok") => new(true, message);
    public static ActionResult Fail(string message) => new(false, message);
}

/// <summary>
/// Immutable copy of a profile's state, safe to hand to other threads (the console
/// and the response worker) without touching the live, owner-thread-only object.
/// </summary>
public sealed record ProfileSnapshot
{
    public required int Pid { get; init; }
    public required string ProcessName { get; init; }
    public required string ImagePath { get; init; }
    public required int Score { get; init; }
    public required bool Trusted { get; init; }
    public required bool Contained { get; init; }
    public required bool SuspendedByAnalyst { get; init; }
    public required bool Terminated { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
    public required IReadOnlyList<string> StagedArchives { get; init; }
    public required DateTime FirstSeenUtc { get; init; }
    public required DateTime LastUpdatedUtc { get; init; }
}

/// <summary>
/// Rolling risk state per process. Mutated ONLY by the single owner thread in
/// ShieldHost, so it needs no internal locking. Attack chains such as
/// collect -> archive -> exfil accumulate here so the combined score rises even
/// when each step looks benign alone.
/// </summary>
public sealed class ThreatProfile
{
    public int Pid { get; }
    public string ProcessName { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public int Score { get; set; }

    public bool Trusted { get; set; }
    public bool SignatureChecked { get; set; }
    public bool Contained { get; set; }
    public bool SuspendedByAnalyst { get; set; }
    public bool Terminated { get; set; }
    public bool MemoryScanned { get; set; }

    public readonly List<string> Reasons = new();

    public DateTime? SuspiciousSpawnUtc;
    public DateTime? CredentialAccessUtc;
    public DateTime? ArchiveStagedUtc;
    public readonly HashSet<string> StagedArchives = new(StringComparer.OrdinalIgnoreCase);

    public DateTime FirstSeenUtc { get; } = DateTime.UtcNow;
    public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;

    public ThreatProfile(int pid) => Pid = pid;

    public void Add(int points, string reason)
    {
        Score += points;
        Reasons.Add($"[+{points}] {reason}");
        LastUpdatedUtc = DateTime.UtcNow;
    }
}

/// <summary>
/// Editable indicator sets. Ordinary DETECTION artifacts (as found in AV
/// signatures, MITRE ATT&amp;CK, and public Sigma/YARA rules). Replace or extend
/// with your own threat-intel feed.
/// </summary>
public static class IocDatabase
{
    public static readonly string[] LolBins =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "installutil.exe", "msbuild.exe", "curl.exe"
    };

    public static readonly string[] UnusualParents =
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe"
    };

    public static readonly string[] CommandLineIocs =
    {
        "-enc", "-encodedcommand", "-nop", "-w hidden", "-windowstyle hidden",
        "downloadstring", "downloadfile", "net.webclient", "invoke-webrequest",
        "invoke-expression", "iex(", "frombase64string", "-urlcache", "/transfer",
        "-executionpolicy bypass"
    };

    public static readonly string[] SensitiveFileFragments =
    {
        @"\google\chrome\user data\", @"\microsoft\edge\user data\",
        @"\mozilla\firefox\profiles\", "login data", "cookies.sqlite",
        "local state", "key4.db", "logins.json",
        "wallet.dat", @"\electrum\wallets\", @"\exodus\", @"\discord\leveldb\"
    };

    public static readonly string[] ArchiveExtensions =
    { ".zip", ".7z", ".rar", ".tar", ".gz", ".cab" };

    public static readonly string[] StagingDirFragments =
    { @"\temp\", @"\appdata\local\temp\", @"\programdata\", @"\public\", @"\windows\temp\" };

    public static readonly string[] MemoryStringIocs =
    {
        "select * from logins", "encrypted_key", @"chrome\user data",
        "grabber", "stealer", "exfil", "keylog",
        "setwindowshookex", "getasynckeystate", "keybd_event"
    };

    public static readonly string[] SuspiciousModuleFragments =
    { "vnc", "tightvnc", "hvnc", "remcos", "quasar", "asyncrat", "njrat", "meterpreter" };
}
