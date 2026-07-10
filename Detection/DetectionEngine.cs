using ProcessShield.Core;

namespace ProcessShield.Detection;

public sealed class EngineOptions
{
    public int WarnThreshold { get; init; } = 40;
    public int QuarantineThreshold { get; init; } = 70;
    public TimeSpan CorrelationWindow { get; init; } = TimeSpan.FromSeconds(30);
    public bool AutoKillOnQuarantine { get; init; } = false;
    public int TrustDiscount { get; init; } = 30;
}

public sealed class DetectionResult
{
    public required Verdict Verdict { get; init; }
    public required string Trigger { get; init; }
    public required ProfileSnapshot Snapshot { get; init; }
}

/// <summary>
/// Pure detection state machine. Every public method is invoked ONLY from the
/// single ShieldHost owner thread, so the profile store needs no locking. Ingest
/// returns zero or more verdicts (a single archive signal can implicate several
/// processes). Thresholds are hot-updatable via UpdateThresholds (also owner-thread).
/// </summary>
public sealed class DetectionEngine
{
    private int _warn;
    private int _quarantine;
    private int _scanAt;
    private TimeSpan _window;
    private int _trustDiscount;

    private readonly IMemoryScanner _memScanner;
    private readonly Func<int, bool> _isTrusted;

    private readonly Dictionary<int, ThreatProfile> _profiles = new();
    private DateTime _lastPrune = DateTime.UtcNow;

    public DetectionEngine(EngineOptions opt, IMemoryScanner memScanner, Func<int, bool> isTrusted)
    {
        _memScanner = memScanner;
        _isTrusted = isTrusted;
        Apply(opt.WarnThreshold, opt.QuarantineThreshold,
              (int)opt.CorrelationWindow.TotalSeconds, opt.TrustDiscount);
    }

    /// <summary>Hot-reload of detection posture. Owner thread only.</summary>
    public void UpdateThresholds(int warn, int quarantine, int windowSeconds, int trustDiscount)
        => Apply(warn, quarantine, windowSeconds, trustDiscount);

    private void Apply(int warn, int quarantine, int windowSeconds, int trustDiscount)
    {
        _warn = Math.Max(1, warn);
        _quarantine = Math.Max(_warn + 1, quarantine);
        _scanAt = Math.Max(20, _warn / 2);
        _window = TimeSpan.FromSeconds(windowSeconds > 0 ? windowSeconds : 30);
        _trustDiscount = Math.Max(0, trustDiscount);
    }

    public IReadOnlyList<DetectionResult> Ingest(Signal s)
    {
        var results = new List<DetectionResult>();
        MaybePrune();

        if (s.Kind == SignalKind.FileCreate && s.Pid == 0)
        {
            CorrelateUnattributedArchive(s, results);
            return results;
        }
        if (s.Pid <= 0) return results;

        var p = GetOrAdd(s.Pid);
        if (!string.IsNullOrEmpty(s.ProcessName)) p.ProcessName = s.ProcessName;
        if (!string.IsNullOrEmpty(s.ImagePath)) p.ImagePath = s.ImagePath;

        switch (s.Kind)
        {
            case SignalKind.ProcessStart:   RuleProcessStart(p, s); break;
            case SignalKind.ImageLoad:      RuleImageLoad(p, s);    break;
            case SignalKind.FileCreate:     RuleFileCreate(p, s);   break;
            case SignalKind.NetworkConnect: RuleNetwork(p, s);      break;
        }

        MaybeScanMemory(p);

        var r = Decide(p, s.Kind.ToString());
        if (r is not null) results.Add(r);
        return results;
    }

    public IReadOnlyList<ProfileSnapshot> Snapshot(bool onlyContained)
    {
        var list = new List<ProfileSnapshot>();
        foreach (var p in _profiles.Values)
        {
            if (onlyContained) { if (!p.Contained) continue; }
            else if (p.Score < _warn) continue;
            list.Add(ToSnapshot(p));
        }
        list.Sort((a, b) => b.Score.CompareTo(a.Score));
        return list;
    }

    public ProfileSnapshot? SnapshotOne(int pid)
        => _profiles.TryGetValue(pid, out var p) ? ToSnapshot(p) : null;

    public bool SetSuspendedByAnalyst(int pid, bool value)
    {
        if (!_profiles.TryGetValue(pid, out var p)) return false;
        p.SuspendedByAnalyst = value;
        return true;
    }

    public bool SetTerminated(int pid)
    {
        if (!_profiles.TryGetValue(pid, out var p)) return false;
        p.Terminated = true;
        p.SuspendedByAnalyst = false;
        return true;
    }

    // ------------------------------------------------------------------- rules

    private void RuleProcessStart(ThreatProfile p, Signal s)
    {
        string name = s.ProcessName.ToLowerInvariant();
        string cmd = s.CommandLine.ToLowerInvariant();
        bool childIsLolBin = IocDatabase.LolBins.Contains(name);

        string parentName = _profiles.TryGetValue(s.ParentPid, out var pp)
            ? pp.ProcessName.ToLowerInvariant() : "";
        if (childIsLolBin && IocDatabase.UnusualParents.Contains(parentName))
        {
            p.SuspiciousSpawnUtc = s.TimestampUtc;
            p.Add(45, $"Unusual parent/child: {parentName} -> {name}");
        }

        foreach (var ioc in IocDatabase.CommandLineIocs)
            if (cmd.Contains(ioc))
                p.Add(15, $"Command-line IOC '{ioc}'");
    }

    private void RuleImageLoad(ThreatProfile p, Signal s)
    {
        string file = (s.FilePath ?? "").ToLowerInvariant();
        foreach (var frag in IocDatabase.SuspiciousModuleFragments)
            if (file.Contains(frag))
                p.Add(50, $"Loaded remote-control/injection module '{frag}'");
    }

    private void RuleFileCreate(ThreatProfile p, Signal s)
    {
        string file = (s.FilePath ?? "").ToLowerInvariant();
        if (file.Length == 0) return;

        if (IocDatabase.SensitiveFileFragments.Any(file.Contains))
        {
            p.CredentialAccessUtc = s.TimestampUtc;
            p.Add(35, "Touched sensitive credential/secret store");
        }

        string ext = Path.GetExtension(file);
        bool isArchive = IocDatabase.ArchiveExtensions.Contains(ext);
        bool inStaging = IocDatabase.StagingDirFragments.Any(file.Contains);
        if (isArchive && inStaging)
        {
            p.ArchiveStagedUtc = s.TimestampUtc;
            p.StagedArchives.Add(file);
            p.Add(30, "Created archive in a staging directory");

            if (p.CredentialAccessUtc is { } c && s.TimestampUtc - c <= _window)
                p.Add(25, "Archive staged shortly after reading secrets");
        }
    }

    private void RuleNetwork(ThreatProfile p, Signal s)
    {
        if (!NetworkUtil.IsRoutableRemote(s.RemoteAddress)) return;

        if (p.ArchiveStagedUtc is { } t && s.TimestampUtc - t <= _window)
            p.Add(45, $"Outbound to {s.RemoteAddress}:{s.RemotePort} shortly after " +
                      "staging an archive (collect->exfil)");
        else if (p.Score >= _warn)
            p.Add(15, $"Outbound to {s.RemoteAddress}:{s.RemotePort} from a flagged process");
    }

    private void CorrelateUnattributedArchive(Signal s, List<DetectionResult> results)
    {
        var now = s.TimestampUtc;
        string file = (s.FilePath ?? "").ToLowerInvariant();

        foreach (var p in _profiles.Values)
        {
            if (p.Score <= 0 || p.Contained) continue;
            if (now - p.LastUpdatedUtc > _window) continue;

            p.ArchiveStagedUtc = now;
            p.StagedArchives.Add(file);
            p.Add(25, $"Archive '{Path.GetFileName(s.FilePath)}' staged near flagged activity");

            var r = Decide(p, "ArchiveCorrelation");
            if (r is not null) results.Add(r);
        }
    }

    private void MaybeScanMemory(ThreatProfile p)
    {
        if (p.MemoryScanned || p.Score < _scanAt) return;
        p.MemoryScanned = true;

        IReadOnlyList<string> hits;
        try { hits = _memScanner.Scan(p.Pid); }
        catch { return; }

        if (hits.Count > 0)
            p.Add(20 + 5 * Math.Min(hits.Count, 6),
                  "Memory IOC(s): " + string.Join(", ", hits));
    }

    private DetectionResult? Decide(ThreatProfile p, string trigger)
    {
        if (!p.SignatureChecked)
        {
            p.SignatureChecked = true;
            bool trusted;
            try { trusted = _isTrusted(p.Pid); } catch { trusted = false; }
            if (trusted)
            {
                p.Trusted = true;
                p.Score = Math.Max(0, p.Score - _trustDiscount);
                p.Reasons.Add($"[-{_trustDiscount}] Signed by allowlisted publisher");
            }
        }

        Verdict v = p.Score >= _quarantine ? Verdict.Quarantine
                  : p.Score >= _warn ? Verdict.Warn
                  : Verdict.Allow;

        if (v == Verdict.Allow) return null;
        if (v == Verdict.Quarantine && p.Contained) return null;

        if (v == Verdict.Quarantine) p.Contained = true;
        return new DetectionResult { Verdict = v, Trigger = trigger, Snapshot = ToSnapshot(p) };
    }

    private static ProfileSnapshot ToSnapshot(ThreatProfile p) => new()
    {
        Pid = p.Pid,
        ProcessName = p.ProcessName,
        ImagePath = p.ImagePath,
        Score = p.Score,
        Trusted = p.Trusted,
        Contained = p.Contained,
        SuspendedByAnalyst = p.SuspendedByAnalyst,
        Terminated = p.Terminated,
        Reasons = p.Reasons.ToArray(),
        StagedArchives = p.StagedArchives.ToArray(),
        FirstSeenUtc = p.FirstSeenUtc,
        LastUpdatedUtc = p.LastUpdatedUtc
    };

    private ThreatProfile GetOrAdd(int pid)
    {
        if (!_profiles.TryGetValue(pid, out var p))
        {
            p = new ThreatProfile(pid);
            _profiles[pid] = p;
        }
        return p;
    }

    private void MaybePrune()
    {
        var now = DateTime.UtcNow;
        if (now - _lastPrune < TimeSpan.FromMinutes(1)) return;
        _lastPrune = now;

        var cutoff = now - TimeSpan.FromMinutes(10);
        List<int>? dead = null;
        foreach (var kv in _profiles)
        {
            bool retain = kv.Value.Contained && !kv.Value.Terminated;
            if (retain) continue;
            if (kv.Value.LastUpdatedUtc >= cutoff) continue;
            (dead ??= new List<int>()).Add(kv.Key);
        }
        if (dead is null) return;
        foreach (var pid in dead) _profiles.Remove(pid);
    }
}
