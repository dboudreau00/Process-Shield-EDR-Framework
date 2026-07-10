using System.Text;
using ProcessShield.Configuration;
using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Memory;
using ProcessShield.Response;
using ProcessShield.Telemetry;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>Deterministic memory scanner for engine tests (no real process reads).</summary>
internal sealed class FakeScanner : IMemoryScanner
{
    private readonly string[] _hits;
    public FakeScanner(params string[] hits) => _hits = hits;
    public IReadOnlyList<string> Scan(int pid) => _hits;
}

public class DetectionEngineTests
{
    private static DetectionEngine NewEngine(bool trusted = false, params string[] memHits)
        => new(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, CorrelationWindow = TimeSpan.FromSeconds(30), TrustDiscount = 30 },
            new FakeScanner(memHits),
            _ => trusted);

    [Fact]
    public void CollectThenArchive_Reaches_Quarantine()
    {
        var engine = NewEngine();
        var now = DateTime.UtcNow;

        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 100,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            TimestampUtc = now
        });

        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 100,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip",
            TimestampUtc = now
        });

        Assert.Contains(results, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void Trusted_Process_Does_Not_Quarantine()
    {
        var engine = NewEngine(trusted: true);
        var now = DateTime.UtcNow;

        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 101,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            TimestampUtc = now
        });
        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 101,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip",
            TimestampUtc = now
        });

        Assert.DoesNotContain(results, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void UnusualParent_And_CommandLine_Ioc_Warn()
    {
        var engine = NewEngine();
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 10, ProcessName = "winword.exe" });

        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 200, ParentPid = 10,
            ProcessName = "powershell.exe", CommandLine = "-enc SQBFAFgA"
        });

        var v = Assert.Single(results);
        Assert.Equal(Verdict.Warn, v.Verdict);
        Assert.Contains(v.Snapshot.Reasons, r => r.Contains("winword.exe -> powershell.exe"));
        Assert.Contains(v.Snapshot.Reasons, r => r.Contains("-enc"));
    }

    [Fact]
    public void ExfilChain_With_MemoryHit_Also_Quarantines()
    {
        var engine = NewEngine(memHits: "stealer");
        var now = DateTime.UtcNow;

        // The verdict can fire at any step once the score crosses the threshold, so
        // aggregate results across the whole chain rather than inspecting one call.
        var all = new List<DetectionResult>();
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 20, ProcessName = "winword.exe" }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 300, ParentPid = 20, ProcessName = "powershell.exe", CommandLine = "-nop -w hidden" }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 300, FilePath = @"C:\ProgramData\dump.zip", TimestampUtc = now }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.NetworkConnect, Pid = 300, RemoteAddress = "203.0.113.10", RemotePort = 443, TimestampUtc = now }));

        Assert.Contains(all, r => r.Verdict == Verdict.Quarantine);
    }
}

public class NetworkUtilTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("203.0.113.5", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("10.0.0.5", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("not-an-ip", false)]
    [InlineData("", false)]
    public void RoutableRemote(string ip, bool expected)
        => Assert.Equal(expected, NetworkUtil.IsRoutableRemote(ip));
}

public class PatternMatcherTests
{
    [Fact]
    public void Matches_Ascii_Case_Insensitive()
    {
        var m = new PatternMatcher(new[] { "login data" });
        var buf = Encoding.ASCII.GetBytes("junk  LOGIN DATA  junk");
        Assert.Contains("login data", m.FindAll(buf));
    }

    [Fact]
    public void Matches_Utf16()
    {
        var m = new PatternMatcher(new[] { "wallet.dat" });
        var buf = Encoding.Unicode.GetBytes("path=C:\\x\\wallet.dat;");
        Assert.Contains("wallet.dat", m.FindAll(buf));
    }

    [Fact]
    public void Matches_Across_Chunk_Boundary_With_Overlap()
    {
        var m = new PatternMatcher(new[] { "cookies.sqlite" });
        // Simulate the scanner's tail+chunk overlap window.
        var full = Encoding.ASCII.GetBytes("aaaacookies.sqlitebbbb");
        var tail = full[..7];           // "aaaacoo"
        var chunk = full[7..];          // "kies.sqlitebbbb"
        var window = new byte[tail.Length + chunk.Length];
        Buffer.BlockCopy(tail, 0, window, 0, tail.Length);
        Buffer.BlockCopy(chunk, 0, window, tail.Length, chunk.Length);
        var hits = new HashSet<string>();
        m.FindInto(window, window.Length, hits);
        Assert.Contains("cookies.sqlite", hits);
    }
}

public class FirewallRuleNameTests
{
    [Fact]
    public void Strips_Injection_Characters()
    {
        var s = FirewallRuleName.Sanitize("ProcessShield Block a\"b|c;d&e.exe 42");
        Assert.DoesNotContain('"', s);
        Assert.DoesNotContain('|', s);
        Assert.DoesNotContain(';', s);
        Assert.DoesNotContain('&', s);
        Assert.False(string.IsNullOrWhiteSpace(s));
    }

    [Fact]
    public void Falls_Back_When_Everything_Stripped()
        => Assert.Equal("ProcessShield Block", FirewallRuleName.Sanitize("!!!\"\";;"));
}

public class AuditLogTests
{
    [Fact]
    public void Intact_Chain_Verifies_And_Tampering_Is_Detected()
    {
        string path = Path.Combine(Path.GetTempPath(), "shield_audit_" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            var sink = new AuditLogSink(path);
            for (int i = 0; i < 3; i++)
                sink.Emit(new ShieldEvent { Level = "QUARANTINE", Category = "detection", Pid = i, Process = "p" + i, Score = 80 });
            sink.Dispose();

            Assert.True(AuditLogSink.Verify(path, out _));

            var lines = File.ReadAllLines(path);
            lines[1] = lines[1].Replace("\"Score\":80", "\"Score\":1");   // tamper a record
            File.WriteAllLines(path, lines);

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.False(string.IsNullOrEmpty(err));
        }
        finally { try { File.Delete(path); } catch { } }
    }
}

public class ConfigTests
{
    [Fact]
    public void Clamp_Enforces_Threshold_Ordering()
    {
        var cfg = new ShieldConfig();
        cfg.Detection.WarnThreshold = 40;
        cfg.Detection.QuarantineThreshold = 5;   // invalid: below warn
        cfg.ClampAndValidate();
        Assert.True(cfg.Detection.QuarantineThreshold > cfg.Detection.WarnThreshold);
    }

    [Fact]
    public void Clamp_Floors_Warn_At_One()
    {
        var cfg = new ShieldConfig();
        cfg.Detection.WarnThreshold = 0;
        cfg.ClampAndValidate();
        Assert.True(cfg.Detection.WarnThreshold >= 1);
    }
}

public class ActionResultTests
{
    [Fact]
    public void Success_And_Fail()
    {
        Assert.True(ActionResult.Success("ok").Ok);
        var f = ActionResult.Fail("nope");
        Assert.False(f.Ok);
        Assert.Equal("nope", f.Message);
    }
}
