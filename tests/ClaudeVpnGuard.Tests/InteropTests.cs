using System.Runtime.CompilerServices;

namespace ClaudeVpnGuard.Tests;

public class InteropTests
{
    [Fact]
    public void Native_struct_sizes_match_x64_headers()
    {
        Assert.Equal(8, IntPtr.Size);
        Assert.Equal(16, Unsafe.SizeOf<WfpNative.DisplayData>());
        Assert.Equal(16, Unsafe.SizeOf<WfpNative.ByteBlob>());
        Assert.Equal(16, Unsafe.SizeOf<WfpNative.Value>());
        Assert.Equal(40, Unsafe.SizeOf<WfpNative.Condition>());
        Assert.Equal(20, Unsafe.SizeOf<WfpNative.FilterActionData>());
        Assert.Equal(64, Unsafe.SizeOf<WfpNative.Provider>());
        Assert.Equal(72, Unsafe.SizeOf<WfpNative.SubLayer>());
        Assert.Equal(200, Unsafe.SizeOf<WfpNative.Filter>());
        Assert.Equal(8, Unsafe.SizeOf<WfpNative.V4AddrMask>());
        Assert.Equal(17, Unsafe.SizeOf<WfpNative.V6AddrMask>());
    }

    [Fact]
    public void FindLuid_returns_null_for_unknown_adapter()
    {
        Assert.Null(Adapters.FindLuid("no-such-adapter-7c1e"));
    }

    [Fact]
    public void FindLuid_finds_loopback()
    {
        Assert.NotNull(Adapters.FindLuid("Loopback Pseudo-Interface 1"));
    }

    [Fact]
    public void Watch_subscribes_and_unsubscribes()
    {
        using var subscription = Adapters.Watch(() => { });
        Assert.NotNull(subscription);
    }
}
