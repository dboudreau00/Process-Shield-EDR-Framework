using System.Collections.Concurrent;
using System.Text;
using ProcessShield.Detection;
using ProcessShield.Monitoring;
using ProcessShield.Response;

namespace ProcessShield.Core;

/// <summary>
/// Single-owner (actor) orchestrator. Exactly ONE thread reads and mutates
/// detection state; monitors and the console feed the same queue. Slow containment
/// runs on a separate response worker. Detection posture is hot-reloadable via a
/// ConfigCommand routed through the same owner thread.
/// </summary>
public sealed class ShieldHost : IDisposable
{
    private abstract class Command { }

    private sealed class SignalCommand : Command
    {
        public required Signal Signal { get; init; }
    }

    private sealed class ListCommand : Command
    {
        public required bool OnlyContained { get; init; }
        public required TaskCompletionSource<IReadOnlyList<ProfileSnapshot>> Result { get; init; }
    }

    private enum ActionKind { Resume, Suspend, Kill, Info }

    private sealed class ActionCommand : Command
    {
        public required ActionKind Kind { get; init; }
        public required int Pid { get; init; }
        public required TaskCompletionSource<ActionResult> Result { get; init; }
    }

    private sealed class ConfigCommand : Command
    {
        public required int Warn { get; init; }
        public required int Quarantine { get; init; }
        public required int WindowSeconds { get; init; }
        public required int TrustDiscount { get; init; }
        public required bool AutoKill { get; init; }
    }

    // Follow-up commands posted BACK to the owner thread after off-thread work, so all
    // engine-state mutation stays single-threaded (no lock on the profile store).
    private sealed class KillDoneCommand : Command
    {
        public required int Pid { get; init; }
        public required TaskCompletionSource<ActionResult> Result { get; init; }
        public required ActionResult Outcome { get; init; }
    }

    private sealed class MemScanResultCommand : Command
    {
        public required int Pid { get; init; }
        public required IReadOnlyList<string> Hits { get; init; }
    }

    private readonly DetectionEngine _engine;
    private readonly ResponseManager _response;
    private readonly IMemoryScanner _scanner;
    private readonly Logger _log;

    // Telemetry (high-volume) and analyst/config control commands use SEPARATE queues so
    // a telemetry flood can never starve or delay an operator action. The owner thread
    // drains the control queue with priority over signals.
    private readonly BlockingCollection<Command> _signalQueue = new(boundedCapacity: 8192);
    private readonly BlockingCollection<Command> _controlQueue = new(boundedCapacity: 1024);
    private readonly BlockingCollection<Action> _responseQueue = new(boundedCapacity: 1024);

    private Thread? _ownerThread;
    private Thread? _responseThread;

    private EtwMonitor? _etw;
    private WmiProcessMonitor? _wmi;
    private FileActivityMonitor? _files;

    private volatile bool _autoKill;
    private long _signalsProcessed;
    private long _signalsDropped;
    private long _responsesRun;
    private long _responseErrors;
    private int _stopped;

    public string ActiveMonitors { get; private set; } = "none";

    public ShieldHost(bool autoKill, DetectionEngine engine, ResponseManager response,
        IMemoryScanner scanner, Logger log)
    {
        _autoKill = autoKill;
        _engine = engine;
        _response = response;
        _scanner = scanner;
        _log = log;
    }

    // ---------------------------------------------------------------- lifecycle

    public bool Start()
    {
        _ownerThread = new Thread(OwnerLoop) { IsBackground = true, Name = "Shield-Owner" };
        _ownerThread.Start();

        _responseThread = new Thread(ResponseLoop) { IsBackground = true, Name = "Shield-Response" };
        _responseThread.Start();

        var active = new List<string>();
        try
        {
            _etw = new EtwMonitor(EnqueueSignal, _log);
            _etw.Start();
            active.Add("ETW(process,image,file,network)");
        }
        catch (Exception ex)
        {
            _log.Error("ETW start failed; trying WMI fallback", ex);
            SafeDispose(ref _etw);
            try
            {
                _wmi = new WmiProcessMonitor(EnqueueSignal, _log);
                _wmi.Start();
                active.Add("WMI(process)");
            }
            catch (Exception ex2)
            {
                _log.Error("WMI start failed", ex2);
                SafeDispose(ref _wmi);
            }
        }

        try
        {
            _files = new FileActivityMonitor(EnqueueSignal, _log);
            _files.Start();
            active.Add("FileStaging");
        }
        catch (Exception ex)
        {
            _log.Error("file monitor start failed (continuing)", ex);
            SafeDispose(ref _files);
        }

        ActiveMonitors = active.Count > 0 ? string.Join(", ", active) : "none";
        return active.Count > 0;
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 1) return;

        SafeDispose(ref _etw);
        SafeDispose(ref _wmi);
        SafeDispose(ref _files);

        try { _signalQueue.CompleteAdding(); } catch { }
        try { _controlQueue.CompleteAdding(); } catch { }
        _ownerThread?.Join(TimeSpan.FromSeconds(5));

        try { _responseQueue.CompleteAdding(); } catch { }
        _responseThread?.Join(TimeSpan.FromSeconds(8));

        _log.Info($"shutdown complete. processed={Interlocked.Read(ref _signalsProcessed)} " +
                  $"dropped={Interlocked.Read(ref _signalsDropped)} " +
                  $"responses={Interlocked.Read(ref _responsesRun)} " +
                  $"responseErrors={Interlocked.Read(ref _responseErrors)}");
    }

    public void Dispose()
    {
        Stop();
        try { _signalQueue.Dispose(); } catch { }
        try { _controlQueue.Dispose(); } catch { }
        try { _responseQueue.Dispose(); } catch { }
    }

    // --------------------------------------------------------------- producers

    private void EnqueueSignal(Signal s)
    {
        try
        {
            if (!_signalQueue.TryAdd(new SignalCommand { Signal = s }))
                Interlocked.Increment(ref _signalsDropped);
        }
        catch (InvalidOperationException) { /* shutting down */ }
    }

    // ----------------------------------------------------- console-facing API

    public IReadOnlyList<ProfileSnapshot> ListProfiles(bool onlyContained)
    {
        var tcs = new TaskCompletionSource<IReadOnlyList<ProfileSnapshot>>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TryPost(new ListCommand { OnlyContained = onlyContained, Result = tcs }))
            return Array.Empty<ProfileSnapshot>();
        return Wait(tcs.Task, Array.Empty<ProfileSnapshot>());
    }

    public ActionResult Resume(int pid) => PostAction(ActionKind.Resume, pid);
    public ActionResult Suspend(int pid) => PostAction(ActionKind.Suspend, pid);
    public ActionResult Kill(int pid) => PostAction(ActionKind.Kill, pid);
    public ActionResult Info(int pid) => PostAction(ActionKind.Info, pid);

    /// <summary>Apply a hot-reloaded detection posture on the owner thread.</summary>
    public void ApplyDetectionConfig(int warn, int quarantine, int windowSeconds, int trustDiscount, bool autoKill)
    {
        TryPost(new ConfigCommand
        {
            Warn = warn,
            Quarantine = quarantine,
            WindowSeconds = windowSeconds,
            TrustDiscount = trustDiscount,
            AutoKill = autoKill
        });
    }

    public string Stats() =>
        $"processed={Interlocked.Read(ref _signalsProcessed)} " +
        $"dropped={Interlocked.Read(ref _signalsDropped)} " +
        $"queued={_signalQueue.Count} " +
        $"responsesRun={Interlocked.Read(ref _responsesRun)} " +
        $"responseErrors={Interlocked.Read(ref _responseErrors)} " +
        $"autoKill={_autoKill} monitors=[{ActiveMonitors}]";

    private ActionResult PostAction(ActionKind kind, int pid)
    {
        var tcs = new TaskCompletionSource<ActionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TryPost(new ActionCommand { Kind = kind, Pid = pid, Result = tcs }))
            return ActionResult.Fail("agent is shutting down");
        return Wait(tcs.Task, ActionResult.Fail("timed out waiting for the engine"));
    }

    private bool TryPost(Command cmd)
    {
        try { _controlQueue.Add(cmd); return true; }
        catch (InvalidOperationException) { return false; }
    }

    private static T Wait<T>(Task<T> task, T fallback)
    {
        try { return task.Wait(TimeSpan.FromSeconds(10)) ? task.Result : fallback; }
        catch { return fallback; }
    }

    // ------------------------------------------------------------ owner thread

    private void OwnerLoop()
    {
        var queues = new[] { _controlQueue, _signalQueue };
        try
        {
            while (true)
            {
                // Drain ALL pending control commands before touching a signal, so analyst
                // actions and config reloads are never delayed behind queued telemetry.
                while (_controlQueue.TryTake(out var ctrl))
                    DispatchSafe(ctrl);

                Command? cmd;
                int idx;
                try { idx = BlockingCollection<Command>.TakeFromAny(queues, out cmd); }
                catch (Exception) { break; }   // a queue was completed/disposed during shutdown
                if (idx < 0 || cmd is null) break;   // both queues completed and empty
                DispatchSafe(cmd);
            }
        }
        catch (Exception ex) { _log.Error("owner loop terminated", ex); }
    }

    private void DispatchSafe(Command cmd)
    {
        try { Dispatch(cmd); }
        catch (Exception ex) { _log.Error("owner dispatch", ex); FailCommand(cmd); }
    }

    private void Dispatch(Command cmd)
    {
        switch (cmd)
        {
            case SignalCommand sc:
                Interlocked.Increment(ref _signalsProcessed);
                foreach (var verdict in _engine.Ingest(sc.Signal))
                    OnVerdict(verdict);
                // Offload the (up to ~2s) memory scan to the response worker so it never
                // stalls the detection loop; hits fold back in via MemScanResultCommand.
                if (sc.Signal.Pid > 0 && _engine.TryClaimMemoryScan(sc.Signal.Pid))
                    ScheduleMemoryScan(sc.Signal.Pid);
                break;

            case ListCommand lc:
                lc.Result.TrySetResult(_engine.Snapshot(lc.OnlyContained));
                break;

            case ActionCommand ac:
                DispatchAction(ac);
                break;

            case KillDoneCommand kd:
                if (kd.Outcome.Ok) _engine.SetTerminated(kd.Pid);
                kd.Result.TrySetResult(kd.Outcome);
                break;

            case MemScanResultCommand mr:
                foreach (var verdict in _engine.ApplyMemoryHits(mr.Pid, mr.Hits))
                    OnVerdict(verdict);
                break;

            case ConfigCommand cc:
                _engine.UpdateThresholds(cc.Warn, cc.Quarantine, cc.WindowSeconds, cc.TrustDiscount);
                _autoKill = cc.AutoKill;
                _log.Info($"config applied: warn>={cc.Warn} quarantine>={cc.Quarantine} autoKill={cc.AutoKill}");
                break;
        }
    }

    // The blocking analyst kill (WaitForExit up to 3s) must not run on the detection
    // thread. Offload it to the response worker and complete the caller's result on the
    // owner thread via a KillDoneCommand, keeping all engine mutation single-threaded.
    private void DispatchAction(ActionCommand ac)
    {
        if (ac.Kind != ActionKind.Kill)
        {
            ac.Result.TrySetResult(ExecuteAction(ac.Kind, ac.Pid));
            return;
        }

        var tcs = ac.Result;
        int pid = ac.Pid;
        bool scheduled = EnqueueResponse(() =>
        {
            var r = ResponseManager.KillProcess(pid);
            TryPost(new KillDoneCommand { Pid = pid, Result = tcs, Outcome = r });
        });
        if (!scheduled)
            tcs.TrySetResult(ActionResult.Fail("response queue full; kill not scheduled"));
    }

    private void ScheduleMemoryScan(int pid)
    {
        EnqueueResponse(() =>
        {
            IReadOnlyList<string> hits;
            try { hits = _scanner.Scan(pid); }
            catch { return; }
            if (hits.Count > 0)
                TryPost(new MemScanResultCommand { Pid = pid, Hits = hits });
        });
    }

    private static void FailCommand(Command cmd)
    {
        switch (cmd)
        {
            case ListCommand lc: lc.Result.TrySetResult(Array.Empty<ProfileSnapshot>()); break;
            case ActionCommand ac: ac.Result.TrySetResult(ActionResult.Fail("engine error")); break;
            case KillDoneCommand kd: kd.Result.TrySetResult(ActionResult.Fail("engine error")); break;
        }
    }

    private void OnVerdict(DetectionResult verdict)
    {
        if (verdict.Verdict == Verdict.Warn)
        {
            _log.Warn(verdict);
            return;
        }

        _log.Quarantine(verdict);

        var suspend = ResponseManager.SuspendProcess(verdict.Snapshot.Pid);
        _engine.SetSuspendedByAnalyst(verdict.Snapshot.Pid, suspend.Ok);
        _log.Action(suspend.Ok
            ? $"pid {verdict.Snapshot.Pid} suspended"
            : $"pid {verdict.Snapshot.Pid} suspend failed: {suspend.Message}");

        var snap = verdict.Snapshot;
        bool alreadySuspended = suspend.Ok;
        bool autoKill = _autoKill;
        EnqueueResponse(() => _response.Contain(snap, alreadySuspended, autoKill));
    }

    private ActionResult ExecuteAction(ActionKind kind, int pid)
    {
        switch (kind)
        {
            case ActionKind.Info:
            {
                var snap = _engine.SnapshotOne(pid);
                return snap is null
                    ? ActionResult.Fail($"no tracked process with pid {pid}")
                    : ActionResult.Success(RenderInfo(snap));
            }
            case ActionKind.Resume:
            {
                var r = ResponseManager.ResumeProcess(pid);
                if (r.Ok) _engine.SetSuspendedByAnalyst(pid, false);
                return r;
            }
            case ActionKind.Suspend:
            {
                // NtSuspendProcess is COUNTED, but we model suspension as a boolean and a
                // single Resume issues one NtResumeProcess. A redundant suspend would then
                // need two resumes to thaw. Skip if this profile is already suspended so
                // "SuspendedByAnalyst==true" stays 1:1 with one outstanding OS suspend.
                var snap = _engine.SnapshotOne(pid);
                if (snap is not null && snap.SuspendedByAnalyst)
                    return ActionResult.Success($"pid {pid} already suspended");
                var r = ResponseManager.SuspendProcess(pid);
                if (r.Ok) _engine.SetSuspendedByAnalyst(pid, true);
                return r;
            }
            // ActionKind.Kill is handled asynchronously in DispatchAction (offloaded to
            // the response worker), so it never reaches here.
            default:
                return ActionResult.Fail("unknown action");
        }
    }

    private static string RenderInfo(ProfileSnapshot s)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"pid {s.Pid}  {s.ProcessName}  score={s.Score}");
        sb.AppendLine($"  trusted={s.Trusted} contained={s.Contained} " +
                      $"suspended={s.SuspendedByAnalyst} terminated={s.Terminated}");
        sb.AppendLine($"  image: {s.ImagePath}");
        if (s.StagedArchives.Count > 0)
            sb.AppendLine("  staged: " + string.Join(", ", s.StagedArchives));
        sb.AppendLine("  reasons:");
        foreach (var r in s.Reasons) sb.AppendLine("    " + r);
        return sb.ToString().TrimEnd();
    }

    // --------------------------------------------------------- response thread

    private bool EnqueueResponse(Action work)
    {
        try
        {
            if (_responseQueue.TryAdd(work)) return true;
            Interlocked.Increment(ref _responseErrors);
            _log.Error("response backlog", new InvalidOperationException("queue full; dropped a containment task"));
            return false;
        }
        catch (InvalidOperationException) { return false; /* shutting down */ }
    }

    private void ResponseLoop()
    {
        try
        {
            foreach (var work in _responseQueue.GetConsumingEnumerable())
            {
                try { work(); Interlocked.Increment(ref _responsesRun); }
                catch (Exception ex) { Interlocked.Increment(ref _responseErrors); _log.Error("response task", ex); }
            }
        }
        catch (Exception ex) { _log.Error("response loop terminated", ex); }
    }

    private static void SafeDispose<T>(ref T? disposable) where T : class, IDisposable
    {
        try { disposable?.Dispose(); } catch { }
        disposable = null;
    }
}
