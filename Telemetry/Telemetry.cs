using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProcessShield.Telemetry;

/// <summary>Structured event forwarded to every configured sink.</summary>
public sealed record ShieldEvent
{
    public string Level { get; init; } = "INFO";          // INFO | WARN | QUARANTINE | ACTION
    public string Category { get; init; } = "system";     // detection | response | system
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    public int Pid { get; init; }
    public string Process { get; init; } = "";
    public string Image { get; init; } = "";
    public int Score { get; init; }
    public string Trigger { get; init; } = "";
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> StagedArchives { get; init; } = Array.Empty<string>();
    public string Message { get; init; } = "";
}

public interface IEventSink : IDisposable
{
    void Emit(ShieldEvent e);
}

/// <summary>Fans an event out to many sinks, isolating per-sink failures.</summary>
public sealed class CompositeSink : IEventSink
{
    private readonly IEventSink[] _sinks;
    public CompositeSink(IEnumerable<IEventSink> sinks) => _sinks = sinks.ToArray();

    public void Emit(ShieldEvent e)
    {
        foreach (var s in _sinks)
        {
            try { s.Emit(e); } catch { /* isolate */ }
        }
    }

    public void Dispose()
    {
        foreach (var s in _sinks)
        {
            try { s.Dispose(); } catch { }
        }
    }
}

internal static class Json
{
    public static readonly JsonSerializerOptions Compact = new() { WriteIndented = false };
    public static string Event(ShieldEvent e) => JsonSerializer.Serialize(e, Compact);
}

/// <summary>Appends each event as one JSON line.</summary>
public sealed class JsonlSink : IEventSink
{
    private readonly object _gate = new();
    private readonly string _path;
    public JsonlSink(string path) => _path = path;

    public void Emit(ShieldEvent e)
    {
        var line = Json.Event(e);
        lock (_gate)
        {
            try { File.AppendAllText(_path, line + Environment.NewLine); } catch { }
        }
    }

    public void Dispose() { }
}

/// <summary>Base for network sinks: never blocks Emit; a worker drains a bounded queue.</summary>
public abstract class AsyncSinkBase : IEventSink
{
    private readonly BlockingCollection<ShieldEvent> _queue = new(boundedCapacity: 4096);
    private readonly Thread _worker;
    private long _errors;

    public long Errors => Interlocked.Read(ref _errors);

    protected AsyncSinkBase(string name)
    {
        _worker = new Thread(Loop) { IsBackground = true, Name = name };
        _worker.Start();
    }

    public void Emit(ShieldEvent e)
    {
        try { if (!_queue.TryAdd(e)) Interlocked.Increment(ref _errors); }
        catch (InvalidOperationException) { /* shutting down */ }
    }

    private void Loop()
    {
        try
        {
            foreach (var e in _queue.GetConsumingEnumerable())
            {
                try { Send(e); } catch { Interlocked.Increment(ref _errors); }
            }
        }
        catch { /* ignore */ }
    }

    protected abstract void Send(ShieldEvent e);

    public virtual void Dispose()
    {
        try { _queue.CompleteAdding(); } catch { }
        try { _worker.Join(TimeSpan.FromSeconds(3)); } catch { }
    }
}

/// <summary>RFC 5424 syslog over UDP or TCP (newline framing).</summary>
public sealed class SyslogSink : AsyncSinkBase
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _tcp;
    private readonly string _appName;
    private TcpClient? _tcpClient;

    public SyslogSink(string host, int port, string protocol, string appName) : base("Syslog")
    {
        _host = host;
        _port = port;
        _tcp = string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase);
        _appName = string.IsNullOrWhiteSpace(appName) ? "ProcessShield" : appName;
    }

    protected override void Send(ShieldEvent e)
    {
        int severity = e.Level switch
        {
            "QUARANTINE" => 1,   // alert
            "WARN" => 4,         // warning
            "ACTION" => 5,       // notice
            _ => 6               // info
        };
        int pri = (1 * 8) + severity;  // facility 1 (user)
        string ts = e.TimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        string host = Environment.MachineName;
        string msg = $"<{pri}>1 {ts} {host} {_appName} {e.Pid} {e.Category} - {Json.Event(e)}";
        byte[] bytes = Encoding.UTF8.GetBytes(msg);

        if (_tcp) SendTcp(bytes);
        else SendUdp(bytes);
    }

    private void SendUdp(byte[] bytes)
    {
        using var udp = new UdpClient();
        udp.Send(bytes, bytes.Length, _host, _port);
    }

    private void SendTcp(byte[] bytes)
    {
        if (_tcpClient is null || !_tcpClient.Connected)
        {
            _tcpClient?.Dispose();
            _tcpClient = new TcpClient();
            _tcpClient.Connect(_host, _port);
        }
        var stream = _tcpClient.GetStream();
        stream.Write(bytes, 0, bytes.Length);
        stream.WriteByte((byte)'\n');
        stream.Flush();
    }

    public override void Dispose()
    {
        base.Dispose();
        try { _tcpClient?.Dispose(); } catch { }
    }
}

/// <summary>POSTs each event as JSON to a SIEM/webhook endpoint.</summary>
public sealed class WebhookSink : AsyncSinkBase
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _url;

    public WebhookSink(string url) : base("Webhook") => _url = url;

    protected override void Send(ShieldEvent e)
    {
        using var content = new StringContent(Json.Event(e), Encoding.UTF8, "application/json");
        using var resp = Http.PostAsync(_url, content).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
    }
}

/// <summary>
/// Tamper-evident audit log. Each record embeds the SHA-256 of the previous
/// record, forming a hash chain; removing or altering any record breaks the chain,
/// which <see cref="Verify"/> detects.
/// </summary>
public sealed class AuditLogSink : IEventSink
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly object _gate = new();
    private readonly string _path;
    private string _prevHash;
    private long _seq;

    public AuditLogSink(string path)
    {
        _path = path;
        (_seq, _prevHash) = RecoverTail(path);
    }

    public void Emit(ShieldEvent e)
    {
        lock (_gate)
        {
            string canonical = Json.Event(e);
            string hash = Sha256Hex(_prevHash + canonical);
            var record = new AuditRecord
            {
                Seq = _seq,
                TimeUtc = DateTime.UtcNow,
                PrevHash = _prevHash,
                Hash = hash,
                Event = e
            };
            try
            {
                File.AppendAllText(_path, JsonSerializer.Serialize(record, Json.Compact) + Environment.NewLine);
                _prevHash = hash;
                _seq++;
            }
            catch { /* best effort */ }
        }
    }

    public void Dispose() { }

    /// <summary>Recomputes the chain and returns true only if every link is intact.</summary>
    public static bool Verify(string path, out string error)
    {
        error = "";
        try
        {
            if (!File.Exists(path)) { error = "file not found"; return false; }
            string prev = Genesis;
            long expectedSeq = 0;

            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var rec = JsonSerializer.Deserialize<AuditRecord>(line);
                if (rec is null) { error = $"unparsable record at seq {expectedSeq}"; return false; }
                if (rec.Seq != expectedSeq) { error = $"seq gap: expected {expectedSeq}, got {rec.Seq}"; return false; }
                if (rec.PrevHash != prev) { error = $"broken link at seq {rec.Seq}"; return false; }

                string canonical = Json.Event(rec.Event);
                if (Sha256Hex(rec.PrevHash + canonical) != rec.Hash)
                { error = $"tampered record at seq {rec.Seq}"; return false; }

                prev = rec.Hash;
                expectedSeq++;
            }
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    private static (long seq, string prevHash) RecoverTail(string path)
    {
        try
        {
            if (!File.Exists(path)) return (0, Genesis);
            AuditRecord? last = null;
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var rec = JsonSerializer.Deserialize<AuditRecord>(line);
                if (rec is not null) last = rec;
            }
            return last is null ? (0, Genesis) : (last.Seq + 1, last.Hash);
        }
        catch { return (0, Genesis); }
    }

    private static string Sha256Hex(string input)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash);
    }

    private sealed class AuditRecord
    {
        public long Seq { get; set; }
        public DateTime TimeUtc { get; set; }
        public string PrevHash { get; set; } = "";
        public string Hash { get; set; } = "";
        public ShieldEvent Event { get; set; } = new();
    }
}
