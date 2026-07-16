using ProcessShield.Telemetry;

namespace ProcessShield.Gui.Services;

/// <summary>An IEventSink that hands each event to a callback (marshaled to the UI thread by the caller).</summary>
public sealed class UiEventSink : IEventSink
{
    private readonly Action<ShieldEvent> _onEvent;
    public UiEventSink(Action<ShieldEvent> onEvent) => _onEvent = onEvent;
    public void Emit(ShieldEvent e) { try { _onEvent(e); } catch { /* never break the pipeline */ } }
    public void Dispose() { }
}
