using ProcessShield.Core;

namespace ProcessShield.Monitoring;

/// <summary>
/// Watches common staging directories for archive creation. Complements ETW and
/// still works when ETW is unavailable. FileSystemWatcher cannot attribute the
/// writing process, so emitted signals carry Pid = 0 and the engine correlates
/// them by time against recently-flagged processes.
///
/// Hardening: skips missing/duplicate directories, guards each callback, handles
/// the watcher Error event (internal buffer overflow), and throws from Start only
/// if nothing at all could be watched (so the host can note the degraded state).
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly List<FileSystemWatcher> _watchers = new();

    public FileActivityMonitor(Action<Signal> emit, Logger log)
    {
        _emit = emit;
        _log = log;
    }

    public void Start()
    {
        foreach (var dir in CandidateDirectories())
        {
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = true
                };
                w.Created += OnChanged;
                w.Renamed += OnChanged;
                w.Error += OnError;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _log.Error($"watch '{dir}'", ex);
            }
        }

        if (_watchers.Count == 0)
            throw new InvalidOperationException("no staging directories could be watched");
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            var ext = Path.GetExtension(e.FullPath);
            bool isArchive = Array.Exists(
                IocDatabase.ArchiveExtensions,
                x => string.Equals(x, ext, StringComparison.OrdinalIgnoreCase));
            if (!isArchive) return;

            _emit(new Signal
            {
                Kind = SignalKind.FileCreate,
                Pid = 0,
                FilePath = e.FullPath,
                Detail = "archive-in-staging"
            });
        }
        catch (Exception ex)
        {
            _log.Error("file event", ex);
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
        => _log.Error("file watcher", e.GetException());

    private static IEnumerable<string> CandidateDirectories()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in Enumerate())
            if (!string.IsNullOrEmpty(d) && Directory.Exists(d) && seen.Add(d))
                yield return d;

        static IEnumerable<string> Enumerate()
        {
            yield return Path.GetTempPath();
            yield return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            yield return Environment.GetEnvironmentVariable("ProgramData") ?? "";
            yield return @"C:\Users\Public";
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }
}
