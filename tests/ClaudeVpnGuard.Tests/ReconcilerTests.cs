namespace ClaudeVpnGuard.Tests;

public class ReconcilerTests
{
    private const string ClaudePath = @"C:\Users\ME\.local\bin\claude.exe";
    private static readonly GuardConfig Config = GuardConfig.Default(ClaudePath);

    private ulong? _luid = 100;
    private bool _appExists = true;
    private bool _failApply;
    private readonly List<IReadOnlyList<FilterSpec>> _applied = [];

    private Reconciler Create() => new(
        Config,
        () => _luid,
        _ => _appExists,
        specs =>
        {
            if (_failApply) throw new InvalidOperationException("WFP is down");
            _applied.Add(specs);
        });

    [Fact]
    public void First_run_applies()
    {
        var result = Create().Run();

        Assert.True(result.Changed);
        Assert.Single(_applied);
        Assert.Equal(10, _applied[0].Count);
    }

    [Fact]
    public void Unchanged_state_is_not_reapplied()
    {
        var reconciler = Create();
        reconciler.Run();

        var second = reconciler.Run();

        Assert.False(second.Changed);
        Assert.Single(_applied);
    }

    [Fact]
    public void Reapplies_when_adapter_luid_changes()
    {
        var reconciler = Create();
        reconciler.Run();

        _luid = 200;
        var result = reconciler.Run();

        Assert.True(result.Changed);
        Assert.Equal(2, _applied.Count);
        Assert.Contains(_applied[1], f => f.InterfaceLuid == 200);
        Assert.DoesNotContain(_applied[1], f => f.InterfaceLuid == 100);
    }

    [Fact]
    public void Reapplies_without_permits_when_adapter_disappears()
    {
        var reconciler = Create();
        reconciler.Run();

        _luid = null;
        reconciler.Run();

        Assert.DoesNotContain(_applied[1], f => f.InterfaceLuid is not null);
        Assert.Contains(_applied[1], f => f.Action == FilterAction.Block);
    }

    [Fact]
    public void Reapplies_when_app_file_reappears()
    {
        _appExists = false;
        var reconciler = Create();

        var first = reconciler.Run();
        Assert.Single(first.Warnings);
        Assert.DoesNotContain(_applied[0], f => f.AppPath is not null);
        Assert.Contains(_applied[0], f => f.Action == FilterAction.Block && f.Remote is not null);

        _appExists = true;
        var second = reconciler.Run();

        Assert.True(second.Changed);
        Assert.Empty(second.Warnings);
        Assert.Contains(_applied[1], f => f.AppPath == ClaudePath && f.Action == FilterAction.Block);
    }

    [Fact]
    public void Retries_after_apply_failure()
    {
        var reconciler = Create();

        _failApply = true;
        Assert.Throws<InvalidOperationException>(() => reconciler.Run());
        Assert.Empty(_applied);

        _failApply = false;
        var result = reconciler.Run();

        Assert.True(result.Changed);
        Assert.Single(_applied);
    }

    [Fact]
    public void Warnings_are_reported_even_when_nothing_changed()
    {
        _appExists = false;
        var reconciler = Create();
        reconciler.Run();

        var second = reconciler.Run();

        Assert.False(second.Changed);
        Assert.Single(second.Warnings);
    }
}
