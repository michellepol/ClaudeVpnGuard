namespace ClaudeVpnGuard;

public enum FilterAction { Permit, Block }

public enum IpLayer { V4, V6 }

public sealed record FilterSpec(
    string Name,
    IpLayer Layer,
    FilterAction Action,
    byte Weight,
    Cidr? Remote,
    string? AppPath,
    ulong? InterfaceLuid,
    bool Loopback);

public sealed record PolicyResult(IReadOnlyList<FilterSpec> Filters, IReadOnlyList<string> Warnings);

public sealed record FilterDiff(IReadOnlyList<string> Missing, IReadOnlyList<string> Unexpected);

public static class Policy
{
    public const byte PermitWeight = 15;
    public const byte BlockWeight = 1;

    public static PolicyResult Build(GuardConfig config, ulong? adapterLuid, Func<string, bool> appExists)
    {
        var filters = new List<FilterSpec>();
        var warnings = new List<string>();

        foreach (var cidr in config.Ipv4Cidrs.Concat(config.Ipv6Cidrs))
        {
            var layer = cidr.IsIPv6 ? IpLayer.V6 : IpLayer.V4;
            filters.Add(Block($"block {cidr}", layer, cidr, null));
            if (adapterLuid is { } luid)
                filters.Add(Permit($"permit {cidr} via VPN", layer, cidr, null, luid, false));
        }

        foreach (var app in config.AppPaths)
        {
            // A missing file (auto-update by rename, wrong path) must not leave the application unblocked.
            if (!appExists(app))
                warnings.Add($"Файл приложения не найден, фильтры построены по пути из конфига: {app}");

            foreach (var layer in new[] { IpLayer.V4, IpLayer.V6 })
            {
                filters.Add(Block($"block {app} {layer}", layer, null, app));
                filters.Add(Permit($"permit {app} loopback {layer}", layer, null, app, null, true));
                if (adapterLuid is { } luid)
                    filters.Add(Permit($"permit {app} via VPN {layer}", layer, null, app, luid, false));
            }
        }

        return new PolicyResult(filters, warnings);
    }

    // Names are compared as multisets: a range listed twice in the config yields two filters
    // with the same name, which is neither missing nor unexpected when both are installed.
    public static FilterDiff Compare(IReadOnlyList<FilterSpec> expected, IEnumerable<string> installedNames)
    {
        var balance = new Dictionary<string, int>();
        foreach (var spec in expected)
            balance[spec.Name] = balance.GetValueOrDefault(spec.Name) + 1;
        foreach (var name in installedNames)
            balance[name] = balance.GetValueOrDefault(name) - 1;

        var missing = new List<string>();
        var unexpected = new List<string>();
        foreach (var (name, count) in balance)
        {
            for (var i = 0; i < count; i++) missing.Add(name);
            for (var i = 0; i > count; i--) unexpected.Add(name);
        }
        return new FilterDiff(missing, unexpected);
    }

    private static FilterSpec Block(string name, IpLayer layer, Cidr? remote, string? app) =>
        new($"ClaudeVpnGuard: {name}", layer, FilterAction.Block, BlockWeight, remote, app, null, false);

    private static FilterSpec Permit(
        string name, IpLayer layer, Cidr? remote, string? app, ulong? luid, bool loopback) =>
        new($"ClaudeVpnGuard: {name}", layer, FilterAction.Permit, PermitWeight, remote, app, luid, loopback);
}
