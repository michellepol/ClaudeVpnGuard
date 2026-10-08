using System.Runtime.InteropServices;

namespace ClaudeVpnGuard;

public static class Adapters
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void IpInterfaceChangeCallback(IntPtr context, IntPtr row, int notificationType);

    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);

    [DllImport("iphlpapi.dll")]
    private static extern uint NotifyIpInterfaceChange(
        ushort family,
        IpInterfaceChangeCallback callback,
        IntPtr context,
        [MarshalAs(UnmanagedType.U1)] bool initialNotification,
        out IntPtr handle);

    [DllImport("iphlpapi.dll")]
    private static extern uint CancelMibChangeNotify2(IntPtr handle);

    public static ulong? FindLuid(string alias) =>
        ConvertInterfaceAliasToLuid(alias, out var luid) == 0 ? luid : null;

    public static IDisposable Watch(Action onChange) => new Subscription(onChange);

    private sealed class Subscription : IDisposable
    {
        // Held in a field so the GC does not collect the delegate while native code can still call it.
        private readonly IpInterfaceChangeCallback _callback;
        private IntPtr _handle;

        public Subscription(Action onChange)
        {
            _callback = (_, _, _) =>
            {
                try
                {
                    onChange();
                }
                catch
                {
                    // An exception must not escape into the native notification thread.
                }
            };

            const ushort AfUnspec = 0;
            var error = NotifyIpInterfaceChange(AfUnspec, _callback, IntPtr.Zero, false, out _handle);
            if (error != 0)
                throw new InvalidOperationException($"NotifyIpInterfaceChange завершилась с ошибкой {error}");
        }

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            CancelMibChangeNotify2(_handle);
            _handle = IntPtr.Zero;
        }
    }
}
