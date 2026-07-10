using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using ProcessShield.Configuration;
using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Driver;
using ProcessShield.Memory;
using ProcessShield.Response;
using ProcessShield.Security;
using ProcessShield.Telemetry;

namespace ProcessShield.Hosting;

public sealed record WorkerOptions(string ConfigPath);

/// <summary>
/// Composition root: builds every component from a ShieldConfig and wires hot
/// reload. Used by both the interactive console mode and the Windows Service.
/// </summary>
public sealed class Composition : IDisposable
{
    public ShieldHost Host { get; }
    public Logger Log { get; }
    public ShieldConfig Config { get; private set; }

    private readonly string _configPath;
    private readonly AuthenticodeVerifier _verifier;
    private readonly CompositeSink _sink;
    private readonly IMemoryScanner _scanner;
    private FileSystemWatcher? _configWatcher;
    private MinifilterClient? _minifilter;

    private Composition(string configPath, ShieldConfig config, Logger log,
        AuthenticodeVerifier verifier, CompositeSink sink, IMemoryScanner scanner, ShieldHost host)
    {
        _configPath = configPath;
        Config = config;
        Log = log;
        _verifier = verifier;
        _sink = sink;
        _scanner = scanner;
        Host = host;
    }

    public static Composition Build(string configPath)
    {
        var log = new Logger();
        var cfg = ConfigLoader.Load(configPath, m => log.Info("config: " + m));

        var sink = BuildSink(cfg.Telemetry);
        log.SetSink(sink);

        var verifier = new AuthenticodeVerifier(cfg.Allowlist);
        var scanner = BuildScanner(cfg.Detection, log);

        var options = new EngineOptions
        {
            WarnThreshold = cfg.Detection.WarnThreshold,
            QuarantineThreshold = cfg.Detection.QuarantineThreshold,
            CorrelationWindow = TimeSpan.FromSeconds(cfg.Detection.CorrelationWindowSeconds),
            AutoKillOnQuarantine = cfg.Detection.AutoKill,
            TrustDiscount = cfg.Detection.TrustDiscount
        };

        var response = new ResponseManager(log, verifier);
        var engine = new DetectionEngine(options, scanner, response.IsTrusted);
        var host = new ShieldHost(cfg.Detection.AutoKill, engine, response, log);

        var comp = new Composition(configPath, cfg, log, verifier, sink, scanner, host);
        comp._configWatcher = ConfigLoader.Watch(configPath, comp.Apply, m => log.Info("config: " + m));
        comp.ConnectMinifilter(cfg);
        return comp;
    }

    // Best-effort kernel enforcement. If the ShieldFilter driver isn't installed the
    // connect fails quietly and user-mode detection continues on its own.
    private void ConnectMinifilter(ShieldConfig cfg)
    {
        try
        {
            var client = new MinifilterClient(Log);
            if (!client.TryConnect()) { client.Dispose(); return; }

            client.ClearPolicy();
            foreach (var fragment in IocDatabase.SensitiveFileFragments)
                client.AddSensitivePath(fragment);
            client.SetBlocking(cfg.Detection.KernelBlocking);
            _minifilter = client;
            Log.Info($"kernel enforcement {(cfg.Detection.KernelBlocking ? "ENABLED" : "in monitor mode")}");
        }
        catch (Exception ex) { Log.Error("minifilter setup", ex); }
    }

    private static CompositeSink BuildSink(TelemetryConfig t)
    {
        var sinks = new List<IEventSink>
        {
            new JsonlSink(t.JsonlPath),
            new AuditLogSink(t.AuditPath)
        };
        if (t.Syslog.Enabled)
            sinks.Add(new SyslogSink(t.Syslog.Host, t.Syslog.Port, t.Syslog.Protocol, t.Syslog.AppName));
        if (t.Webhook.Enabled && !string.IsNullOrWhiteSpace(t.Webhook.Url))
            sinks.Add(new WebhookSink(t.Webhook.Url));
        return new CompositeSink(sinks);
    }

    private static IMemoryScanner BuildScanner(DetectionConfig d, Logger log)
    {
        if (string.Equals(d.MemoryScanEngine, "yara", StringComparison.OrdinalIgnoreCase))
        {
            var yara = new YaraMemoryScanner(d.YaraRulesPath, log.Info);
            if (yara.Available) return yara;
            yara.Dispose();
            log.Info("yara unavailable; using builtin scanner");
        }
        return new MemoryScanner(IocDatabase.MemoryStringIocs);
    }

    /// <summary>Manual reload trigger (console 'reload').</summary>
    public void ReloadConfig() => Apply(ConfigLoader.Load(_configPath, m => Log.Info("config: " + m)));

    /// <summary>Apply the hot-reloadable subset (posture + allowlist).</summary>
    private void Apply(ShieldConfig next)
    {
        try
        {
            _verifier.UpdateAllowlist(next.Allowlist);
            Host.ApplyDetectionConfig(
                next.Detection.WarnThreshold, next.Detection.QuarantineThreshold,
                next.Detection.CorrelationWindowSeconds, next.Detection.TrustDiscount,
                next.Detection.AutoKill);

            if (!string.Equals(next.Detection.MemoryScanEngine, Config.Detection.MemoryScanEngine, StringComparison.OrdinalIgnoreCase))
                Log.Info("note: scan-engine change takes effect after restart");

            Config = next;
        }
        catch (Exception ex) { Log.Error("apply config", ex); }
    }

    public string VerifyAudit()
        => AuditLogSink.Verify(Config.Telemetry.AuditPath, out var err)
            ? "audit log intact"
            : "AUDIT LOG TAMPERED/BROKEN: " + err;

    public void Dispose()
    {
        try { _configWatcher?.Dispose(); } catch { }
        try { _minifilter?.Dispose(); } catch { }
        try { Host.Dispose(); } catch { }
        try { _sink.Dispose(); } catch { }
        if (_scanner is IDisposable d) { try { d.Dispose(); } catch { } }
    }
}

/// <summary>Windows Service worker: runs the agent and writes a heartbeat the watchdog reads.</summary>
public sealed class ShieldWorker : BackgroundService
{
    private readonly WorkerOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    private Composition? _composition;

    public ShieldWorker(WorkerOptions options, IHostApplicationLifetime lifetime)
    {
        _options = options;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _composition = Composition.Build(_options.ConfigPath);
        if (!_composition.Host.Start())
        {
            _composition.Log.Error("startup", new InvalidOperationException("no monitor could start"));
            _lifetime.StopApplication();
            return;
        }

        _composition.Log.Info($"service running. monitors: {_composition.Host.ActiveMonitors}");
        var svc = _composition.Config.Service;
        var interval = TimeSpan.FromSeconds(svc.HeartbeatIntervalSeconds);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                WriteHeartbeat(svc.HeartbeatPath, _composition.Log);
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* normal stop */ }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _composition?.Dispose(); } catch { }
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void WriteHeartbeat(string path, Logger log)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        }
        catch (Exception ex) { log.Error("heartbeat", ex); }
    }
}

/// <summary>
/// Standalone watchdog (run with --watchdog, typically as a SYSTEM scheduled task).
/// Restarts the service if its heartbeat goes stale. NOTE: an attacker with admin
/// can still kill both the service and this watchdog; true kill-resistance requires
/// PPL/ELAM, which is gated behind Microsoft's anti-malware vendor program.
/// </summary>
public static class Watchdog
{
    public static int Run(string configPath)
    {
        var cfg = ConfigLoader.Load(configPath);
        var svc = cfg.Service.ServiceName;
        var hbPath = cfg.Service.HeartbeatPath;
        var stale = TimeSpan.FromSeconds(cfg.Service.WatchdogStaleSeconds);
        var interval = TimeSpan.FromSeconds(cfg.Service.HeartbeatIntervalSeconds);

        Console.WriteLine($"[watchdog] monitoring service '{svc}' via {hbPath} (stale>{stale.TotalSeconds}s)");

        using var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };

        while (!stop.IsSet)
        {
            try
            {
                if (HeartbeatAge(hbPath) is not { } age || age > stale)
                {
                    Console.WriteLine($"[watchdog] heartbeat stale; restarting '{svc}'");
                    ServiceControl.Start(svc);
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[watchdog] {ex.Message}"); }

            stop.Wait(interval);
        }
        return 0;
    }

    private static TimeSpan? HeartbeatAge(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            if (!long.TryParse(File.ReadAllText(path).Trim(), out var unix)) return null;
            var written = DateTimeOffset.FromUnixTimeSeconds(unix);
            return DateTimeOffset.UtcNow - written;
        }
        catch { return null; }
    }
}

/// <summary>Install/uninstall/start the Windows Service and its watchdog task via sc.exe / schtasks.</summary>
public static class ServiceControl
{
    private const string WatchdogTask = "ProcessShieldWatchdog";

    public static int Install(ShieldConfig cfg)
    {
        string exe = Environment.ProcessPath ?? "";
        string fileName = Path.GetFileName(exe).ToLowerInvariant();
        if (string.IsNullOrEmpty(exe) || fileName is "dotnet.exe" or "dotnet")
        {
            Console.Error.WriteLine(
                "Install requires a self-contained executable. Publish first:\n" +
                "  dotnet publish -c Release -r win-x64 --self-contained true\n" +
                "then run \"ProcessShield.exe --install\" from the publish folder.");
            return 1;
        }

        string svc = cfg.Service.ServiceName;
        int rc = 0;
        rc |= Sc("create", svc, "binPath=", exe, "start=", "auto", "DisplayName=", "ProcessShield EDR");
        Sc("description", svc, "User-mode behavioral shield for RAT / infostealer IOCs");
        Sc("failure", svc, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000");

        // Register the watchdog as a SYSTEM scheduled task that starts at boot.
        RunTool("schtasks", "/Create", "/TN", WatchdogTask,
            "/TR", $"\"{exe}\" --watchdog", "/SC", "ONSTART", "/RL", "HIGHEST", "/RU", "SYSTEM", "/F");

        Sc("start", svc);
        Console.WriteLine(rc == 0 ? $"Service '{svc}' installed and started." : "Install completed with warnings.");
        return rc;
    }

    public static int Uninstall(ShieldConfig cfg)
    {
        string svc = cfg.Service.ServiceName;
        Sc("stop", svc);
        int rc = Sc("delete", svc);
        RunTool("schtasks", "/Delete", "/TN", WatchdogTask, "/F");
        Console.WriteLine($"Service '{svc}' removed.");
        return rc;
    }

    public static int Start(string serviceName) => Sc("start", serviceName);

    private static int Sc(params string[] args) => RunTool("sc", args);

    private static int RunTool(string tool, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(tool)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p is null) return -1;
            string outp = p.StandardOutput.ReadToEnd();
            string errp = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            if (!string.IsNullOrWhiteSpace(outp)) Console.WriteLine(outp.Trim());
            if (!string.IsNullOrWhiteSpace(errp)) Console.Error.WriteLine(errp.Trim());
            return p.HasExited ? p.ExitCode : -1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{tool} failed: {ex.Message}");
            return -1;
        }
    }
}
