using static ClaudeVpnGuard.WfpNative;

namespace ClaudeVpnGuard;

public sealed class WfpException(string operation, uint code)
    : Exception($"{operation} завершилась с ошибкой 0x{code:X8}")
{
    public uint Code { get; } = code;
}

public sealed record InstalledFilter(ulong Id, string Name, ulong? InterfaceLuid);

public static unsafe class Wfp
{
    public static readonly Guid ProviderKey = new("6f1d3c52-8a4e-4b7b-9c1e-2d5a7e90b3f4");
    public static readonly Guid SubLayerKey = new("b84a9e17-3c26-4f5d-a1b0-7e6c2d48f9a3");

    private const string DisplayName = "ClaudeVpnGuard";

    public static void ReplaceFilters(IReadOnlyList<FilterSpec> specs) => InTransaction(engine =>
    {
        EnsureProviderAndSubLayer(engine);
        foreach (var filter in List(engine))
            Check(FwpmFilterDeleteById0(engine, filter.Id), "FwpmFilterDeleteById0", ErrorFilterNotFound);
        foreach (var spec in specs)
            Add(engine, spec);
    });

    public static IReadOnlyList<InstalledFilter> ListFilters()
    {
        var engine = Open();
        try
        {
            return List(engine);
        }
        finally
        {
            FwpmEngineClose0(engine);
        }
    }

    public static void RemoveAll() => InTransaction(engine =>
    {
        foreach (var filter in List(engine))
            Check(FwpmFilterDeleteById0(engine, filter.Id), "FwpmFilterDeleteById0", ErrorFilterNotFound);

        var subLayerKey = SubLayerKey;
        Check(FwpmSubLayerDeleteByKey0(engine, &subLayerKey), "FwpmSubLayerDeleteByKey0", ErrorSubLayerNotFound);

        var providerKey = ProviderKey;
        Check(FwpmProviderDeleteByKey0(engine, &providerKey), "FwpmProviderDeleteByKey0", ErrorProviderNotFound);
    });

    private static IntPtr Open()
    {
        IntPtr engine;
        Check(FwpmEngineOpen0(null, RpcAuthnWinNt, null, null, &engine), "FwpmEngineOpen0");
        return engine;
    }

    private static void InTransaction(Action<IntPtr> body)
    {
        var engine = Open();
        try
        {
            Check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0");
            try
            {
                body(engine);
            }
            catch
            {
                FwpmTransactionAbort0(engine);
                throw;
            }
            Check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0");
        }
        finally
        {
            FwpmEngineClose0(engine);
        }
    }

    private static void EnsureProviderAndSubLayer(IntPtr engine)
    {
        var providerKey = ProviderKey;
        fixed (char* name = DisplayName)
        {
            var provider = new Provider
            {
                providerKey = providerKey,
                displayData = new DisplayData { name = name },
                flags = FlagPersistent,
            };
            Check(FwpmProviderAdd0(engine, &provider, null), "FwpmProviderAdd0", ErrorAlreadyExists);

            var subLayer = new SubLayer
            {
                subLayerKey = SubLayerKey,
                displayData = new DisplayData { name = name },
                flags = FlagPersistent,
                providerKey = &providerKey,
                weight = 0xFFFF,
            };
            Check(FwpmSubLayerAdd0(engine, &subLayer, null), "FwpmSubLayerAdd0", ErrorAlreadyExists);
        }
    }

    private static void Add(IntPtr engine, FilterSpec spec)
    {
        var conditions = stackalloc Condition[4];
        uint count = 0;

        var v4 = default(V4AddrMask);
        var v6 = default(V6AddrMask);
        ulong luid = 0;
        var appId = default(ByteBlob);

        // A managed copy, pinned until FwpmFilterAdd0 returns; never freed with FwpmFreeMemory0.
        var appIdBytes = spec.AppPath is { } appPath ? AppId.Resolve(appPath) : null;
        fixed (byte* appIdData = appIdBytes)
        {
            if (spec.Remote is { } cidr)
            {
                if (cidr.IsIPv6)
                {
                    var bytes = cidr.AddressBytes;
                    for (var i = 0; i < 16; i++) v6.addr[i] = bytes[i];
                    v6.prefixLength = (byte)cidr.PrefixLength;
                    conditions[count++] = new Condition
                    {
                        fieldKey = ConditionIpRemoteAddress,
                        matchType = MatchEqual,
                        value = new Value { type = TypeV6AddrMask, ptr = &v6 },
                    };
                }
                else
                {
                    v4.addr = cidr.V4Address;
                    v4.mask = cidr.V4Mask;
                    conditions[count++] = new Condition
                    {
                        fieldKey = ConditionIpRemoteAddress,
                        matchType = MatchEqual,
                        value = new Value { type = TypeV4AddrMask, ptr = &v4 },
                    };
                }
            }

            if (appIdBytes is not null)
            {
                appId = new ByteBlob { size = (uint)appIdBytes.Length, data = appIdData };
                conditions[count++] = new Condition
                {
                    fieldKey = ConditionAleAppId,
                    matchType = MatchEqual,
                    value = new Value { type = TypeByteBlob, ptr = &appId },
                };
            }

            if (spec.InterfaceLuid is { } interfaceLuid)
            {
                luid = interfaceLuid;
                conditions[count++] = new Condition
                {
                    fieldKey = ConditionIpLocalInterface,
                    matchType = MatchEqual,
                    value = new Value { type = TypeUInt64, ptr = &luid },
                };
            }

            if (spec.Loopback)
            {
                conditions[count++] = new Condition
                {
                    fieldKey = ConditionFlags,
                    matchType = MatchFlagsAllSet,
                    value = new Value { type = TypeUInt32, uint32 = ConditionFlagIsLoopback },
                };
            }

            var providerKey = ProviderKey;
            fixed (char* name = spec.Name)
            {
                var filter = new Filter
                {
                    displayData = new DisplayData { name = name },
                    flags = FlagPersistent,
                    providerKey = &providerKey,
                    layerKey = spec.Layer == IpLayer.V4 ? LayerAleAuthConnectV4 : LayerAleAuthConnectV6,
                    subLayerKey = SubLayerKey,
                    weight = new Value { type = TypeUInt8, uint8 = spec.Weight },
                    numFilterConditions = count,
                    filterCondition = conditions,
                    action = new FilterActionData
                    {
                        type = spec.Action == FilterAction.Permit ? ActionPermit : ActionBlock,
                    },
                };
                ulong id;
                Check(FwpmFilterAdd0(engine, &filter, null, &id), $"FwpmFilterAdd0 ({spec.Name})");
            }
        }
    }

    private static List<InstalledFilter> List(IntPtr engine)
    {
        const uint PageSize = 256;
        var result = new List<InstalledFilter>();

        IntPtr enumHandle;
        Check(FwpmFilterCreateEnumHandle0(engine, null, &enumHandle), "FwpmFilterCreateEnumHandle0");
        try
        {
            while (true)
            {
                Filter** entries = null;
                uint returned;
                Check(FwpmFilterEnum0(engine, enumHandle, PageSize, &entries, &returned), "FwpmFilterEnum0");
                try
                {
                    for (uint i = 0; i < returned; i++)
                    {
                        var filter = entries[i];
                        if (filter->subLayerKey != SubLayerKey) continue;

                        ulong? luid = null;
                        for (uint c = 0; c < filter->numFilterConditions; c++)
                        {
                            var condition = filter->filterCondition[c];
                            if (condition.fieldKey == ConditionIpLocalInterface && condition.value.ptr != null)
                                luid = *(ulong*)condition.value.ptr;
                        }

                        var name = filter->displayData.name != null ? new string(filter->displayData.name) : "";
                        result.Add(new InstalledFilter(filter->filterId, name, luid));
                    }
                }
                finally
                {
                    if (entries != null) FwpmFreeMemory0((void**)&entries);
                }
                if (returned < PageSize) break;
            }
        }
        finally
        {
            FwpmFilterDestroyEnumHandle0(engine, enumHandle);
        }
        return result;
    }

    private static void Check(uint code, string operation, params uint[] ignored)
    {
        if (code != 0 && Array.IndexOf(ignored, code) < 0)
            throw new WfpException(operation, code);
    }
}
