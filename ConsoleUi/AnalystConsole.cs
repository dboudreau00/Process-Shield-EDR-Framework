using ProcessShield.Core;

namespace ProcessShield.ConsoleUi;

/// <summary>
/// Interactive analyst REPL. Lists contained/flagged processes and resumes /
/// suspends / kills them by the number from the last listing. 'reload' re-reads
/// config; 'audit' verifies the tamper-evident log. Runs on the main thread.
/// </summary>
public sealed class AnalystConsole
{
    private readonly ShieldHost _host;
    private readonly Logger _log;
    private readonly Action? _reloadConfig;
    private readonly Func<string>? _verifyAudit;
    private List<int> _listing = new();

    public AnalystConsole(ShieldHost host, Logger log,
        Action? reloadConfig = null, Func<string>? verifyAudit = null)
    {
        _host = host;
        _log = log;
        _reloadConfig = reloadConfig;
        _verifyAudit = verifyAudit;
    }

    public void Run()
    {
        PrintHelp();
        while (true)
        {
            Console.Write("shield> ");
            string? line;
            try { line = Console.ReadLine(); }
            catch { break; }
            if (line is null) break;

            line = line.Trim();
            if (line.Length == 0) continue;

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string cmd = parts[0].ToLowerInvariant();
            string arg = parts.Length > 1 ? parts[1] : "";

            try
            {
                if (Handle(cmd, arg)) return;
            }
            catch (ConsoleInputException cie) { _log.Raw("  " + cie.Message); }
            catch (Exception ex) { _log.Error("console command", ex); }
        }
    }

    private bool Handle(string cmd, string arg)
    {
        switch (cmd)
        {
            case "help" or "?": PrintHelp(); return false;
            case "list" or "ls": RenderList(arg.Equals("all", StringComparison.OrdinalIgnoreCase)); return false;
            case "info": _log.Raw(_host.Info(ResolvePid(arg)).Message); return false;
            case "resume": Report(_host.Resume(ResolvePid(arg))); return false;
            case "suspend": Report(_host.Suspend(ResolvePid(arg))); return false;
            case "kill": KillWithConfirm(ResolvePid(arg)); return false;
            case "stats": _log.Raw("  " + _host.Stats()); return false;

            case "reload":
                if (_reloadConfig is null) { _log.Raw("  reload not available in this mode."); }
                else { _reloadConfig(); _log.Raw("  config reload requested."); }
                return false;

            case "audit":
                _log.Raw("  " + (_verifyAudit?.Invoke() ?? "audit verification not available."));
                return false;

            case "clear" or "cls": try { Console.Clear(); } catch { } return false;
            case "quit" or "exit" or "q": return true;
            default: _log.Raw($"  unknown command '{cmd}'. type 'help'."); return false;
        }
    }

    private void RenderList(bool showAll)
    {
        var snaps = _host.ListProfiles(onlyContained: !showAll);
        _listing = snaps.Select(s => s.Pid).ToList();
        if (_listing.Count == 0)
        {
            _log.Raw(showAll ? "  no flagged processes." : "  no contained processes.");
            return;
        }
        _log.Raw($"  {"#",-3} {"PID",-7} {"SCORE",-6} {"STATE",-20} NAME");
        for (int i = 0; i < snaps.Count; i++)
        {
            var s = snaps[i];
            string state = s.Terminated ? "terminated"
                         : s.SuspendedByAnalyst ? "suspended"
                         : s.Contained ? "contained" : "flagged";
            if (s.Trusted) state += "/trusted";
            _log.Raw($"  {i + 1,-3} {s.Pid,-7} {s.Score,-6} {state,-20} {s.ProcessName}");
        }
        _log.Raw("  (use: info N | resume N | suspend N | kill N)");
    }

    private void KillWithConfirm(int pid)
    {
        Console.Write($"  terminate pid {pid} and its child tree? type 'yes': ");
        string? confirm;
        try { confirm = Console.ReadLine(); } catch { confirm = null; }
        if (!string.Equals(confirm?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
        {
            _log.Raw("  cancelled.");
            return;
        }
        Report(_host.Kill(pid));
    }

    private int ResolvePid(string arg)
    {
        if (string.IsNullOrWhiteSpace(arg))
            throw new ConsoleInputException("missing number. run 'list', then e.g. 'kill 2'.");
        if (arg.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
        {
            if (int.TryParse(arg.AsSpan(4), out int rawPid) && rawPid > 0) return rawPid;
            throw new ConsoleInputException($"'{arg}' is not a valid pid.");
        }
        if (!int.TryParse(arg, out int index))
            throw new ConsoleInputException($"'{arg}' is not a number.");
        if (_listing.Count == 0)
            throw new ConsoleInputException("no listing yet. run 'list' first.");
        if (index < 1 || index > _listing.Count)
            throw new ConsoleInputException($"index {index} is out of range (1..{_listing.Count}).");
        return _listing[index - 1];
    }

    private void Report(ActionResult r) => _log.Raw("  " + (r.Ok ? r.Message : "error: " + r.Message));

    private void PrintHelp()
    {
        _log.Raw(
            "\n  ProcessShield analyst console\n" +
            "  ---------------------------------------------------------------\n" +
            "  list [all]   show contained (or all flagged) processes\n" +
            "  info N       full reason breakdown for entry N\n" +
            "  resume N     un-suspend entry N (release a false positive)\n" +
            "  suspend N    re-suspend entry N\n" +
            "  kill N       terminate entry N (asks for confirmation)\n" +
            "  stats        engine / queue counters\n" +
            "  reload       re-read shield.config.json\n" +
            "  audit        verify the tamper-evident audit log\n" +
            "  clear        clear the screen\n" +
            "  quit         stop the agent and exit\n" +
            "  (N is the number from the last 'list'; or use pid:1234)\n");
    }
}

internal sealed class ConsoleInputException : Exception
{
    public ConsoleInputException(string message) : base(message) { }
}
