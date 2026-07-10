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

    private readonly DetectionEngine _engine;
    private readonly ResponseManager _response;
    private readonly Logger _log;

    private readonly BlockingCollection<Command> _queue = new(boundedCapacity: 8192);
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

    public ShieldHost(bool autoKill, DetectionEngine engine, ResponseManager response, Logger log)
    {
        _autoKill = autoKill;
        _engine = engine;
        _response = response;
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

        try { _queue.CompleteAdding(); } catch { }
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
        try { _queue.Dispose(); } catch { }
        try { _responseQueue.Dispose(); } catch { }
    }

    // --------------------------------------------------------------- producers

    private void EnqueueSignal(Signal s)
    {
        try
        {
            if (!_queue.TryAdd(new SignalCommand { Signal = s }))
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
        $"queued={_queue.Count} " +
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
        try { _queue.Add(cmd); return true; }
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
        try
        {
            foreach (var cmd in _queue.GetConsumingEnumerable())
            {
                try { Dispatch(cmd); }
                catch (Exception ex) { _log.Error("owner dispatch", ex); FailCommand(cmd); }
            }
        }
        catch (Exception ex) { _log.Error("owner loop terminated", ex); }
    }

    private void Dispatch(Command cmd)
    {
        switch (cmd)
        {
            case SignalCommand sc:
                Interlocked.Increment(ref _signalsProcessed);
                foreach (var verdict in _engine.Ingest(sc.Signal))
                    OnVerdict(verdict);
                break;

            case ListCommand lc:
                lc.Result.TrySetResult(_engine.Snapshot(lc.OnlyContained));
                break;

            case ActionCommand ac:
                ac.Result.TrySetResult(ExecuteAction(ac.Kind, ac.Pid));
                break;

            case ConfigCommand cc:
                _engine.UpdateThresholds(cc.Warn, cc.Quarantine, cc.WindowSeconds, cc.TrustDiscount);
                _autoKill = cc.AutoKill;
                _log.Info($"config applied: warn>={cc.Warn} quarantine>={cc.Quarantine} autoKill={cc.AutoKill}");
                break;
        }
    }

    private static void FailCommand(Command cmd)
    {
        switch (cmd)
        {
            case ListCommand lc: lc.Result.TrySetResult(Array.Empty<ProfileSnapshot>()); break;
            case ActionCommand ac: ac.Result.TrySetResult(ActionResult.Fail("engine error")); break;
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
                var r = ResponseManager.SuspendProcess(pid);
                if (r.Ok) _engine.SetSuspendedByAnalyst(pid, true);
                return r;
            }
            case ActionKind.Kill:
            {
                var r = ResponseManager.KillProcess(pid);
                if (r.Ok) _engine.SetTerminated(pid);
                return r;
            }
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

    private void EnqueueResponse(Action work)
    {
        try
        {
            if (!_responseQueue.TryAdd(work))
            {
                Interlocked.Increment(ref _responseErrors);
                _log.Error("response backlog", new InvalidOperationException("queue full; dropped a containment task"));
            }
        }
        catch (InvalidOperationException) { /* shutting down */ }
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
