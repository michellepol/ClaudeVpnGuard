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
    private int _generation;
    private string? _lastError; // guarded by _gate

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

        // Subscribed before the first reconcile so an adapter event in between is not left to the poll:
        // the callback only bumps the generation and arms the timer, which Tick then notices.
        _watch = Adapters.Watch(OnAdapterChanged);
        Tick();
    }

    protected override void OnStop()
    {
        // Subscription first: no new adapter events. Then wait for a running Tick via _gate
        // so the timer is never disposed under it.
        _watch?.Dispose();
        _watch = null;
        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }

    // Runs on a native notification thread: cheap, no _gate, never disposes the subscription.
    private void OnAdapterChanged()
    {
        Interlocked.Increment(ref _generation);
        Arm(_timer, DebounceMs);
    }

    private static void Arm(Timer? timer, int dueMs)
    {
        try
        {
            timer?.Change(dueMs, PollMs);
        }
        catch (ObjectDisposedException)
        {
            // Service is stopping.
        }
    }

    private void Tick()
    {
        lock (_gate)
        {
            var timer = _timer;
            if (timer is null || _reconciler is null) return;

            var generation = Volatile.Read(ref _generation);
            var failed = false;
            try
            {
                var result = _reconciler.Run();
                if (_lastError is not null)
                {
                    _lastError = null;
                    Log("Обновление фильтров снова работает.", EventLogEntryType.Information);
                }
                if (result.Changed)
                {
                    var text = "Фильтры обновлены.";
                    if (result.Warnings.Count > 0)
                        text += Environment.NewLine + string.Join(Environment.NewLine, result.Warnings);
                    Log(text, result.Warnings.Count > 0 ? EventLogEntryType.Warning : EventLogEntryType.Information);
                }
            }
            catch (Exception e)
            {
                failed = true;

                // The retry repeats every few seconds; the log gets one entry per distinct failure.
                if (e.Message != _lastError)
                {
                    _lastError = e.Message;
                    Log($"Не удалось обновить фильтры, повтор каждые {RetryMs / 1000} с: {e.Message}", EventLogEntryType.Error);
                }
            }

            if (failed)
            {
                Arm(timer, RetryMs);
                return;
            }

            // An adapter event during Run() may not be reflected in it: re-arm with the debounce.
            // The re-check after arming closes the window between the check and the Change call.
            var changed = Volatile.Read(ref _generation) != generation;
            Arm(timer, changed ? DebounceMs : PollMs);
            if (!changed && Volatile.Read(ref _generation) != generation)
                Arm(timer, DebounceMs);
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
