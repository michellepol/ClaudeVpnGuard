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
            if (!appExists(app))
            {
                warnings.Add($"Файл приложения не найден, фильтры для него пропущены: {app}");
                continue;
            }

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

    private static FilterSpec Block(string name, IpLayer layer, Cidr? remote, string? app) =>
        new($"ClaudeVpnGuard: {name}", layer, FilterAction.Block, BlockWeight, remote, app, null, false);

    private static FilterSpec Permit(
        string name, IpLayer layer, Cidr? remote, string? app, ulong? luid, bool loopback) =>
        new($"ClaudeVpnGuard: {name}", layer, FilterAction.Permit, PermitWeight, remote, app, luid, loopback);
}
