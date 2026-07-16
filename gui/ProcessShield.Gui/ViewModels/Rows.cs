using ProcessShield.Core;
using ProcessShield.Telemetry;

namespace ProcessShield.Gui.ViewModels;

/// <summary>A single process in the threat table. Severity drives the row signal colour.</summary>
public sealed class ThreatRow : ViewModelBase
{
    public int Pid { get; }
    public string Name { get; private set; } = "";
    public int Score { get; private set; }
    public string State { get; private set; } = "";
    public string Severity { get; private set; } = "watch";   // safe | watch | threat
    public bool Trusted { get; private set; }
    public string Trust => Trusted ? "signed" : "\u2014";
    public string ImagePath { get; private set; } = "";
    public IReadOnlyList<string> Reasons { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> StagedArchives { get; private set; } = Array.Empty<string>();

    public ThreatRow(ProfileSnapshot s)
    {
        Pid = s.Pid;
        Update(s);
    }

    public void Update(ProfileSnapshot s)
    {
        Name = s.ProcessName;
        Score = s.Score;
        Trusted = s.Trusted;
        ImagePath = s.ImagePath;
        Reasons = s.Reasons;
        StagedArchives = s.StagedArchives;
        State = s.Terminated ? "Terminated"
              : s.SuspendedByAnalyst ? "Suspended"
              : s.Contained ? "Contained"
              : "Flagged";
        Severity = s.Terminated ? "safe"
                 : s.Contained ? "threat"
                 : s.Trusted ? "safe"
                 : s.Score >= 70 ? "threat"
                 : "watch";

        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Score));
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(Severity));
        OnPropertyChanged(nameof(Trusted));
        OnPropertyChanged(nameof(Trust));
        OnPropertyChanged(nameof(ImagePath));
        OnPropertyChanged(nameof(Reasons));
        OnPropertyChanged(nameof(StagedArchives));
    }
}

/// <summary>A line in the live event feed.</summary>
public sealed class EventRow
{
    public string Time { get; }
    public string Level { get; }       // QUARANTINE | WARN | ACTION | INFO
    public string Category { get; }
    public string Text { get; }

    public EventRow(ShieldEvent e)
    {
        Time = e.TimeUtc.ToLocalTime().ToString("HH:mm:ss");
        Level = e.Level;
        Category = e.Category;
        Text = e.Pid > 0
            ? $"pid {e.Pid} {e.Process} \u2014 {(string.IsNullOrEmpty(e.Trigger) ? e.Message : e.Trigger)}"
              + (e.Score > 0 ? $"  (score {e.Score})" : "")
            : e.Message;
    }
}
