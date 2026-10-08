using System.Net;

namespace ClaudeVpnGuard.Tests;

public class CidrTests
{
    [Fact]
    public void Parses_ipv4()
    {
        var c = Cidr.Parse("160.79.104.0/21");

        Assert.False(c.IsIPv6);
        Assert.Equal(21, c.PrefixLength);
        Assert.Equal(0xA04F6800u, c.V4Address);
        Assert.Equal(0xFFFFF800u, c.V4Mask);
    }

    [Fact]
    public void Parses_ipv6()
    {
        var c = Cidr.Parse("2607:6bc0::/48");

        Assert.True(c.IsIPv6);
        Assert.Equal(48, c.PrefixLength);
        Assert.Equal(16, c.AddressBytes.Length);
        Assert.Equal(new byte[] { 0x26, 0x07, 0x6b, 0xc0 }, c.AddressBytes[..4]);
    }

    [Fact]
    public void Normalizes_host_bits()
    {
        Assert.Equal(Cidr.Parse("160.79.104.0/21"), Cidr.Parse("160.79.104.10/21"));
        Assert.Equal("160.79.104.0/21", Cidr.Parse("160.79.104.10/21").ToString());
    }

    [Theory]
    [InlineData("0.0.0.0/0", 0u)]
    [InlineData("1.2.3.4/32", 0xFFFFFFFFu)]
    [InlineData("10.0.0.0/8", 0xFF000000u)]
    public void Computes_mask_for_edge_prefixes(string text, uint mask)
    {
        Assert.Equal(mask, Cidr.Parse(text).V4Mask);
    }

    [Theory]
    [InlineData("")]
    [InlineData("160.79.104.0")]
    [InlineData("160.79.104.0/33")]
    [InlineData("2607:6bc0::/129")]
    [InlineData("160.79.104/21")]
    [InlineData("abc/8")]
    [InlineData("160.79.104.0/-1")]
    [InlineData("160.79.104.0/ 21")]
    [InlineData("160.79.104.0/21/3")]
    [InlineData("160.79.104.0/")]
    public void Rejects_invalid_input(string text)
    {
        Assert.Throws<FormatException>(() => Cidr.Parse(text));
    }

    [Theory]
    [InlineData("160.79.104.0/21", "160.79.104.10", true)]
    [InlineData("160.79.104.0/21", "160.79.111.255", true)]
    [InlineData("160.79.104.0/21", "160.79.112.0", false)]
    [InlineData("160.79.104.0/21", "::ffff:160.79.104.10", true)]
    [InlineData("160.79.104.0/21", "2607:6bc0::1", false)]
    [InlineData("2607:6bc0::/48", "2607:6bc0:0:1::10", true)]
    [InlineData("2607:6bc0::/48", "2607:6bc1::1", false)]
    [InlineData("2607:6bc0::/48", "160.79.104.10", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    public void Contains(string cidr, string ip, bool expected)
    {
        Assert.Equal(expected, Cidr.Parse(cidr).Contains(IPAddress.Parse(ip)));
    }
}
