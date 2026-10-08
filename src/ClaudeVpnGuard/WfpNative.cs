using System.Runtime.InteropServices;

namespace ClaudeVpnGuard;

// Layouts follow fwptypes.h / fwpmtypes.h for x64.
internal static unsafe class WfpNative
{
    private const string Dll = "fwpuclnt.dll";

    public const uint RpcAuthnWinNt = 10;

    public const uint FlagPersistent = 0x1; // same value for provider, sublayer and filter

    public const uint TypeUInt8 = 1;
    public const uint TypeUInt32 = 3;
    public const uint TypeUInt64 = 4;
    public const uint TypeByteBlob = 12;
    public const uint TypeV4AddrMask = 0x100;
    public const uint TypeV6AddrMask = 0x101;

    public const uint MatchEqual = 0;
    public const uint MatchFlagsAllSet = 6;

    public const uint ActionBlock = 0x1001;
    public const uint ActionPermit = 0x1002;

    public const uint ConditionFlagIsLoopback = 0x1;

    public const uint ErrorAlreadyExists = 0x80320009;
    public const uint ErrorFilterNotFound = 0x80320003;
    public const uint ErrorProviderNotFound = 0x80320005;
    public const uint ErrorSubLayerNotFound = 0x80320007;

    public static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    public static readonly Guid ConditionIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    public static readonly Guid ConditionIpLocalInterface = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    public static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");

    [StructLayout(LayoutKind.Sequential)]
    public struct DisplayData
    {
        public char* name;
        public char* description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ByteBlob
    {
        public uint size;
        public byte* data;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    public struct Value
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public byte uint8;
        [FieldOffset(8)] public uint uint32;
        [FieldOffset(8)] public void* ptr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Condition
    {
        public Guid fieldKey;
        public uint matchType;
        public Value value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FilterActionData
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Provider
    {
        public Guid providerKey;
        public DisplayData displayData;
        public uint flags;
        public ByteBlob providerData;
        public char* serviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SubLayer
    {
        public Guid subLayerKey;
        public DisplayData displayData;
        public uint flags;
        public Guid* providerKey;
        public ByteBlob providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Filter
    {
        public Guid filterKey;
        public DisplayData displayData;
        public uint flags;
        public Guid* providerKey;
        public ByteBlob providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public Value weight;
        public uint numFilterConditions;
        public Condition* filterCondition;
        public FilterActionData action;
        public ulong rawContext;        // union { UINT64 rawContext; GUID providerContextKey; }
        public ulong rawContextHigh;
        public Guid* reserved;
        public ulong filterId;
        public Value effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct V4AddrMask
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct V6AddrMask
    {
        public fixed byte addr[16];
        public byte prefixLength;
    }

    [DllImport(Dll)]
    public static extern uint FwpmEngineOpen0(
        char* serverName, uint authnService, void* authIdentity, void* session, IntPtr* engine);

    [DllImport(Dll)]
    public static extern uint FwpmEngineClose0(IntPtr engine);

    [DllImport(Dll)]
    public static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);

    [DllImport(Dll)]
    public static extern uint FwpmTransactionCommit0(IntPtr engine);

    [DllImport(Dll)]
    public static extern uint FwpmTransactionAbort0(IntPtr engine);

    [DllImport(Dll)]
    public static extern uint FwpmProviderAdd0(IntPtr engine, Provider* provider, void* sd);

    [DllImport(Dll)]
    public static extern uint FwpmProviderDeleteByKey0(IntPtr engine, Guid* key);

    [DllImport(Dll)]
    public static extern uint FwpmSubLayerAdd0(IntPtr engine, SubLayer* subLayer, void* sd);

    [DllImport(Dll)]
    public static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, Guid* key);

    [DllImport(Dll)]
    public static extern uint FwpmFilterAdd0(IntPtr engine, Filter* filter, void* sd, ulong* id);

    [DllImport(Dll)]
    public static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    [DllImport(Dll)]
    public static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, void* enumTemplate, IntPtr* enumHandle);

    [DllImport(Dll)]
    public static extern uint FwpmFilterEnum0(
        IntPtr engine, IntPtr enumHandle, uint requested, Filter*** entries, uint* returned);

    [DllImport(Dll)]
    public static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);

    [DllImport(Dll)]
    public static extern void FwpmFreeMemory0(void** p);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern uint FwpmGetAppIdFromFileName0(string fileName, ByteBlob** appId);
}
