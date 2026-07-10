using System.Text.Json;

namespace ProcessShield.Configuration;

public sealed class ShieldConfig
{
    public DetectionConfig Detection { get; set; } = new();
    public AllowlistConfig Allowlist { get; set; } = new();
    public TelemetryConfig Telemetry { get; set; } = new();
    public ServiceConfig Service { get; set; } = new();

    public void ClampAndValidate()
    {
        Detection.WarnThreshold = Math.Max(1, Detection.WarnThreshold);
        Detection.QuarantineThreshold = Math.Max(Detection.WarnThreshold + 1, Detection.QuarantineThreshold);
        if (Detection.CorrelationWindowSeconds <= 0) Detection.CorrelationWindowSeconds = 30;
        Detection.TrustDiscount = Math.Max(0, Detection.TrustDiscount);
        if (string.IsNullOrWhiteSpace(Detection.MemoryScanEngine)) Detection.MemoryScanEngine = "builtin";

        Service.HeartbeatIntervalSeconds = Math.Max(1, Service.HeartbeatIntervalSeconds);
        Service.WatchdogStaleSeconds = Math.Max(Service.HeartbeatIntervalSeconds * 3, Service.WatchdogStaleSeconds);
        if (string.IsNullOrWhiteSpace(Service.ServiceName)) Service.ServiceName = "ProcessShield";
    }
}

public sealed class DetectionConfig
{
    public int WarnThreshold { get; set; } = 40;
    public int QuarantineThreshold { get; set; } = 70;
    public int CorrelationWindowSeconds { get; set; } = 30;
    public bool AutoKill { get; set; } = false;
    public int TrustDiscount { get; set; } = 30;
    public string MemoryScanEngine { get; set; } = "builtin";   // "builtin" | "yara"
    public string YaraRulesPath { get; set; } = "rules";
    public bool KernelBlocking { get; set; } = false;           // enforce via minifilter if installed
}

public sealed class AllowlistConfig
{
    public string[] Publishers { get; set; } = { "Microsoft Windows", "Microsoft Corporation" };
    public string[] Thumbprints { get; set; } = Array.Empty<string>();
    public bool AllowSubjectMatch { get; set; } = true;
    public bool RequireValidChain { get; set; } = true;
    public bool CheckRevocation { get; set; } = false;
}

public sealed class TelemetryConfig
{
    public string JsonlPath { get; set; } = "incidents.jsonl";
    public string AuditPath { get; set; } = "audit.log";
    public SyslogConfig Syslog { get; set; } = new();
    public WebhookConfig Webhook { get; set; } = new();
}

public sealed class SyslogConfig
{
    public bool Enabled { get; set; } = false;
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public string Protocol { get; set; } = "udp";   // "udp" | "tcp"
    public string AppName { get; set; } = "ProcessShield";
}

public sealed class WebhookConfig
{
    public bool Enabled { get; set; } = false;
    public string Url { get; set; } = "";
}

public sealed class ServiceConfig
{
    public string ServiceName { get; set; } = "ProcessShield";
    public string HeartbeatPath { get; set; } =
        Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData",
                     "ProcessShield", "heartbeat");
    public int HeartbeatIntervalSeconds { get; set; } = 5;
    public int WatchdogStaleSeconds { get; set; } = 30;
}

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };

    public static ShieldConfig Load(string path, Action<string>? warn = null)
    {
        try
        {
            if (!File.Exists(path))
            {
                warn?.Invoke($"config '{path}' not found; using defaults");
                var def = new ShieldConfig();
                def.ClampAndValidate();
                return def;
            }
            var json = File.ReadAllText(path);
            var cfg = JsonSerializer.Deserialize<ShieldConfig>(json, Options) ?? new ShieldConfig();
            cfg.ClampAndValidate();
            return cfg;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"config load failed ({ex.Message}); using defaults");
            var def = new ShieldConfig();
            def.ClampAndValidate();
            return def;
        }
    }

    public static void WriteTemplate(string path)
    {
        try { File.WriteAllText(path, JsonSerializer.Serialize(new ShieldConfig(), Options)); }
        catch { /* best effort */ }
    }

    /// <summary>Debounced hot-reload watcher. Returns the watcher so the caller can dispose it.</summary>
    public static FileSystemWatcher? Watch(string path, Action<ShieldConfig> onReload, Action<string>? warn = null)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            var file = Path.GetFileName(path);
            if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(file)) return null;

            var w = new FileSystemWatcher(dir, file)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            DateTime last = DateTime.MinValue;
            void Handler(object _, FileSystemEventArgs __)
            {
                var now = DateTime.UtcNow;
                if (now - last < TimeSpan.FromMilliseconds(500)) return;   // debounce
                last = now;
                System.Threading.Thread.Sleep(150);                       // let the writer finish
                try { onReload(Load(path, warn)); }
                catch (Exception ex) { warn?.Invoke($"config reload failed: {ex.Message}"); }
            }
            w.Changed += Handler;
            w.Created += Handler;
            return w;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"config watch failed: {ex.Message}");
            return null;
        }
    }
}
