namespace ClaudeVpnGuard.Tests;

public class PolicyTests
{
    private const string ClaudePath = @"C:\Users\ME\.local\bin\claude.exe";
    private const ulong Luid = 0x35000000000000;

    private static readonly GuardConfig Config = GuardConfig.Default(ClaudePath);

    [Fact]
    public void With_adapter_builds_block_and_permit_filters()
    {
        var policy = Policy.Build(Config, Luid, _ => true);

        // 1 IPv4 CIDR: block + permit; 1 IPv6 CIDR: block + permit;
        // 1 app on 2 layers: block + loopback permit + adapter permit.
        Assert.Equal(10, policy.Filters.Count);
        Assert.Empty(policy.Warnings);
        Assert.Equal(4, policy.Filters.Count(f => f.Action == FilterAction.Block));
        Assert.Equal(4, policy.Filters.Count(f => f.InterfaceLuid == Luid));
        Assert.Equal(2, policy.Filters.Count(f => f.Loopback));
    }

    [Fact]
    public void Without_adapter_only_blocks_and_loopback_remain()
    {
        var policy = Policy.Build(Config, null, _ => true);

        Assert.Equal(6, policy.Filters.Count);
        Assert.DoesNotContain(policy.Filters, f => f.InterfaceLuid is not null);
        Assert.All(
            policy.Filters.Where(f => f.Action == FilterAction.Permit),
            f => Assert.True(f.Loopback));
        Assert.Equal(4, policy.Filters.Count(f => f.Action == FilterAction.Block));
    }

    [Fact]
    public void Weights_follow_action()
    {
        var policy = Policy.Build(Config, Luid, _ => true);

        Assert.All(policy.Filters, f =>
            Assert.Equal(f.Action == FilterAction.Permit ? Policy.PermitWeight : Policy.BlockWeight, f.Weight));
        Assert.True(Policy.PermitWeight > Policy.BlockWeight);
    }

    [Fact]
    public void Cidr_filters_live_on_their_own_layer()
    {
        var policy = Policy.Build(Config, Luid, _ => true);

        Assert.All(
            policy.Filters.Where(f => f.Remote is not null),
            f => Assert.Equal(f.Remote!.IsIPv6 ? IpLayer.V6 : IpLayer.V4, f.Layer));
    }

    [Fact]
    public void Every_adapter_permit_has_a_matching_block()
    {
        var policy = Policy.Build(Config, Luid, _ => true);

        Assert.All(
            policy.Filters.Where(f => f.InterfaceLuid is not null),
            permit => Assert.Contains(policy.Filters, block =>
                block.Action == FilterAction.Block
                && block.Layer == permit.Layer
                && block.Remote == permit.Remote
                && block.AppPath == permit.AppPath));
    }

    [Fact]
    public void Loopback_permit_never_applies_to_address_ranges()
    {
        var policy = Policy.Build(Config, Luid, _ => true);

        Assert.All(policy.Filters.Where(f => f.Loopback), f =>
        {
            Assert.Null(f.Remote);
            Assert.NotNull(f.AppPath);
        });
    }

    [Fact]
    public void Missing_app_is_still_blocked_and_reported_with_a_warning()
    {
        var policy = Policy.Build(Config, Luid, _ => false);

        Assert.Equal(Policy.Build(Config, Luid, _ => true).Filters, policy.Filters);
        Assert.Equal(2, policy.Filters.Count(f => f.AppPath == ClaudePath && f.Action == FilterAction.Block));
        var warning = Assert.Single(policy.Warnings);
        Assert.Contains(ClaudePath, warning);
    }

    [Fact]
    public void Missing_app_is_still_blocked_without_adapter()
    {
        var policy = Policy.Build(Config, null, _ => false);

        Assert.Equal(6, policy.Filters.Count);
        Assert.Equal(2, policy.Filters.Count(f => f.AppPath == ClaudePath && f.Action == FilterAction.Block));
        Assert.Single(policy.Warnings);
    }

    [Fact]
    public void Multiple_ranges_and_apps_each_get_filters()
    {
        var config = Config with
        {
            Ipv4Cidrs = [Cidr.Parse("160.79.104.0/21"), Cidr.Parse("192.0.2.0/24")],
            AppPaths = [ClaudePath, @"C:\Tools\other.exe"],
        };

        var policy = Policy.Build(config, Luid, _ => true);

        // 2 IPv4 + 1 IPv6 ranges, 2 filters each; 2 apps, 6 filters each.
        Assert.Equal(18, policy.Filters.Count);
        Assert.Equal(policy.Filters.Count, policy.Filters.Select(f => f.Name).Distinct().Count());
    }

    [Fact]
    public void Same_input_builds_equal_output()
    {
        Assert.Equal(
            Policy.Build(Config, Luid, _ => true).Filters,
            Policy.Build(Config, Luid, _ => true).Filters);
    }
}
