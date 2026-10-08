using System.Net;

namespace ClaudeVpnGuard.Tests;

public class ConfigTests
{
    private const string ClaudePath = @"C:\Users\ME\.local\bin\claude.exe";

    [Fact]
    public void Default_has_spec_values()
    {
        var c = GuardConfig.Default(ClaudePath);

        Assert.Equal("AmneziaVPN", c.AdapterName);
        Assert.Equal(new[] { Cidr.Parse("160.79.104.0/21") }, c.Ipv4Cidrs);
        Assert.Equal(new[] { Cidr.Parse("2607:6bc0::/48") }, c.Ipv6Cidrs);
        Assert.Equal(new[] { ClaudePath }, c.AppPaths);
        Assert.Contains("claude.ai", c.CheckDomains);
        Assert.Contains("api.anthropic.com", c.CheckDomains);
    }

    [Fact]
    public void Round_trips_through_json()
    {
        var original = GuardConfig.Default(ClaudePath);
        var parsed = GuardConfig.Parse(original.ToJson());

        Assert.Equal(original.AdapterName, parsed.AdapterName);
        Assert.Equal(original.Ipv4Cidrs, parsed.Ipv4Cidrs);
        Assert.Equal(original.Ipv6Cidrs, parsed.Ipv6Cidrs);
        Assert.Equal(original.AppPaths, parsed.AppPaths);
        Assert.Equal(original.CheckDomains, parsed.CheckDomains);
    }

    [Fact]
    public void Accepts_comments_and_trailing_commas()
    {
        var c = GuardConfig.Parse("""
            {
              // мой VPN
              "adapterName": "AmneziaVPN",
              "ipv4Cidrs": ["160.79.104.0/21",],
            }
            """);

        Assert.Single(c.Ipv4Cidrs);
        Assert.Empty(c.Ipv6Cidrs);
        Assert.Empty(c.AppPaths);
        Assert.Empty(c.CheckDomains);
    }

    [Fact]
    public void Accepts_keys_in_any_case()
    {
        var c = GuardConfig.Parse("""
            {
              "AdapterName": "AmneziaVPN",
              "IPV4CIDRS": ["160.79.104.0/21"],
              "ipv6cidrs": ["2607:6bc0::/48"],
              "APPPATHS": ["C:\\Tools\\claude.exe"],
              "checkdomains": ["claude.ai"]
            }
            """);

        Assert.Equal("AmneziaVPN", c.AdapterName);
        Assert.Equal(new[] { Cidr.Parse("160.79.104.0/21") }, c.Ipv4Cidrs);
        Assert.Equal(new[] { Cidr.Parse("2607:6bc0::/48") }, c.Ipv6Cidrs);
        Assert.Equal(new[] { @"C:\Tools\claude.exe" }, c.AppPaths);
        Assert.Equal(new[] { "claude.ai" }, c.CheckDomains);
    }

    [Theory]
    [InlineData("somethingElse")]
    [InlineData("ipv4Cidr")]
    public void Rejects_unknown_key_and_names_it(string key)
    {
        var json = $$"""
            {
              "adapterName": "AmneziaVPN",
              "{{key}}": ["160.79.104.0/21"],
              "appPaths": ["C:\\Tools\\claude.exe"]
            }
            """;

        var e = Assert.Throws<ConfigException>(() => GuardConfig.Parse(json));
        Assert.Contains(key, e.Message);
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("""{ "adapterName": 5, "ipv4Cidrs": ["160.79.104.0/21"] }""")]
    [InlineData("""{ "ipv4Cidrs": ["160.79.104.0/21"] }""")]
    [InlineData("""{ "adapterName": "  ", "ipv4Cidrs": ["160.79.104.0/21"] }""")]
    [InlineData("""{ "adapterName": "A", "ipv4Cidrs": ["160.79.104.0/40"] }""")]
    [InlineData("""{ "adapterName": "A", "ipv4Cidrs": ["2607:6bc0::/48"] }""")]
    [InlineData("""{ "adapterName": "A", "ipv6Cidrs": ["160.79.104.0/21"] }""")]
    [InlineData("""{ "adapterName": "A", "appPaths": ["claude.exe"] }""")]
    [InlineData("""{ "adapterName": "A", "ipv4Cidrs": [null] }""")]
    [InlineData("""{ "adapterName": "A" }""")]
    public void Rejects_invalid_config(string json)
    {
        Assert.Throws<ConfigException>(() => GuardConfig.Parse(json));
    }

    [Fact]
    public void Load_reports_missing_file()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");

        var e = Assert.Throws<ConfigException>(() => GuardConfig.Load(path));
        Assert.Contains(path, e.Message);
    }

    [Theory]
    [InlineData("160.79.104.10", true)]
    [InlineData("::ffff:160.79.104.10", true)]
    [InlineData("2607:6bc0::10", true)]
    [InlineData("35.190.46.17", false)]
    [InlineData("2001:db8::1", false)]
    public void Covers(string ip, bool expected)
    {
        Assert.Equal(expected, GuardConfig.Default(ClaudePath).Covers(IPAddress.Parse(ip)));
    }
}
