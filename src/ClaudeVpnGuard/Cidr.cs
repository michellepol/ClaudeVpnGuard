using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ClaudeVpnGuard;

public sealed record Cidr
{
    private Cidr(IPAddress address, int prefixLength)
    {
        Address = address;
        PrefixLength = prefixLength;
    }

    public IPAddress Address { get; }
    public int PrefixLength { get; }

    public bool IsIPv6 => Address.AddressFamily == AddressFamily.InterNetworkV6;
    public byte[] AddressBytes => Address.GetAddressBytes();

    // Host byte order, as FWP_V4_ADDR_AND_MASK expects.
    public uint V4Address => IsIPv6
        ? throw new InvalidOperationException("Not an IPv4 range")
        : BinaryPrimitives.ReadUInt32BigEndian(AddressBytes);

    public uint V4Mask => PrefixLength == 0 ? 0u : uint.MaxValue << (32 - PrefixLength);

    public static Cidr Parse(string text)
    {
        var parts = text.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address))
            throw new FormatException($"Некорректный CIDR: '{text}'");

        var v6 = address.AddressFamily == AddressFamily.InterNetworkV6;

        // IPAddress.TryParse accepts shorthand like "160.79.104" and reads it as 160.79.0.104.
        if (!v6 && parts[0].Count(c => c == '.') != 3)
            throw new FormatException($"Некорректный IPv4-адрес в CIDR: '{text}'");

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
            || prefix > (v6 ? 128 : 32))
            throw new FormatException($"Некорректная длина префикса в CIDR: '{text}'");

        var bytes = address.GetAddressBytes();
        for (var bit = prefix; bit < bytes.Length * 8; bit++)
            bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));

        return new Cidr(new IPAddress(bytes), prefix);
    }

    public bool Contains(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != Address.AddressFamily) return false;

        var network = AddressBytes;
        var candidate = ip.GetAddressBytes();
        for (var bit = 0; bit < PrefixLength; bit++)
        {
            var mask = 0x80 >> (bit % 8);
            if (((network[bit / 8] ^ candidate[bit / 8]) & mask) != 0) return false;
        }
        return true;
    }

    public override string ToString() => $"{Address}/{PrefixLength}";
}
