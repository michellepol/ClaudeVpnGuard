namespace ClaudeVpnGuard;

public sealed record ReconcileResult(bool Changed, IReadOnlyList<string> Warnings);

public sealed class Reconciler(
    GuardConfig config,
    Func<ulong?> findLuid,
    Func<string, bool> appExists,
    Action<IReadOnlyList<FilterSpec>> apply)
{
    private IReadOnlyList<FilterSpec>? _applied;

    public ReconcileResult Run()
    {
        var policy = Policy.Build(config, findLuid(), appExists);

        if (_applied is not null && _applied.SequenceEqual(policy.Filters))
            return new ReconcileResult(false, policy.Warnings);

        // _applied is only updated after apply succeeds, so a failed run is retried next time.
        apply(policy.Filters);
        _applied = policy.Filters;
        return new ReconcileResult(true, policy.Warnings);
    }
}
