using System.Diagnostics;
using System.ServiceProcess;

namespace ClaudeVpnGuard;

public sealed class GuardService : ServiceBase
{
    public const string Name = "ClaudeVpnGuard";

    private const int DebounceMs = 500;
    private const int RetryMs = 5_000;
    private const int PollMs = 30_000;

    private readonly string _configPath;
    private readonly object _gate = new();
    private Reconciler? _reconciler;
    private Timer? _timer;
    private IDisposable? _watch;

    public GuardService(string configPath)
    {
        _configPath = configPath;
        ServiceName = Name;
        CanStop = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        // A ConfigException here fails the start and leaves installed filters untouched.
        var config = GuardConfig.Load(_configPath);

        _reconciler = new Reconciler(
            config,
            () => Adapters.FindLuid(config.AdapterName),
            File.Exists,
            Wfp.ReplaceFilters);

        _timer = new Timer(_ => Tick(), null, Timeout.Infinite, Timeout.Infinite);
        Tick();
        _watch = Adapters.Watch(() => _timer?.Change(DebounceMs, PollMs));
    }

    protected override void OnStop()
    {
        _watch?.Dispose();
        _watch = null;
        _timer?.Dispose();
        _timer = null;
    }

    private void Tick()
    {
        lock (_gate)
        {
            var timer = _timer;
            if (timer is null || _reconciler is null) return;

            try
            {
                var result = _reconciler.Run();
                if (result.Changed)
                {
                    var text = "Фильтры обновлены.";
                    if (result.Warnings.Count > 0)
                        text += Environment.NewLine + string.Join(Environment.NewLine, result.Warnings);
                    Log(text, result.Warnings.Count > 0 ? EventLogEntryType.Warning : EventLogEntryType.Information);
                }
                timer.Change(PollMs, PollMs);
            }
            catch (Exception e)
            {
                Log($"Не удалось обновить фильтры, повтор через {RetryMs / 1000} с: {e.Message}", EventLogEntryType.Error);
                timer.Change(RetryMs, PollMs);
            }
        }
    }

    private void Log(string message, EventLogEntryType type)
    {
        try
        {
            EventLog.WriteEntry(message, type);
        }
        catch
        {
            // Logging must never take the guard down.
        }
    }
}
