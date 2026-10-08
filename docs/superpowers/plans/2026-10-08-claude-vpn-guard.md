# ClaudeVpnGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Служба Windows, которая пропускает трафик к сетям Anthropic и весь трафик `claude.exe` только через адаптер AmneziaVPN, а на остальных интерфейсах блокирует.

**Architecture:** Один exe на .NET 9 (CLI + служба). Чистая функция `Policy` строит список фильтров из конфига и LUID адаптера; `Wfp` через P/Invoke к `fwpuclnt.dll` атомарно заменяет ими постоянные фильтры в собственном sublayer; служба повторяет это при изменении адаптеров. Block-фильтры стоят всегда, permit-фильтры привязаны к LUID адаптера, поэтому любой сбой ведёт к блокировке.

**Tech Stack:** C# / .NET 9 (`net9.0-windows`, x64), Windows Filtering Platform (`fwpuclnt.dll`), IP Helper (`iphlpapi.dll`), `System.ServiceProcess.ServiceController`, xUnit.

**Spec:** `docs/superpowers/specs/2026-10-08-claude-vpn-guard-design.md`

## Global Constraints

- Корень проекта: `C:\Users\ME\Development\Repositories\ClaudeVpnGuard`. Все команды — PowerShell из этого каталога.
- Только x64: раскладка структур WFP в `WfpNative` рассчитана на 64-битные указатели.
- Слои: только `FWPM_LAYER_ALE_AUTH_CONNECT_V4` и `_V6`. Веса: permit = 15, block = 1.
- Provider, sublayer и все фильтры — `PERSISTENT`.
- Диапазоны по умолчанию: `160.79.104.0/21`, `2607:6bc0::/48`. Адаптер по умолчанию: `AmneziaVPN`.
- Каталог установки: `C:\Program Files\ClaudeVpnGuard`; имя службы: `ClaudeVpnGuard`; учётная запись `LocalSystem`.
- Коды возврата CLI: 0 — успех, 1 — ошибка (в том числе нет прав администратора), 2 — `status` с предупреждениями.
- Сообщения пользователю — на русском; идентификаторы — на английском.
- Любой отказ должен оставлять block-фильтры на месте (fail-closed).
- Каждый коммит заканчивается строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Задачи 1–5 не требуют прав администратора. Задачи 6–7 включают шаги в терминале с правами администратора.

## Review Focus

1. **`claude.exe` временно отсутствует (автообновление) в момент reconcile** — фильтры по IP остаются, фильтры по приложению возвращаются при следующем проходе сами. Тест: `ReconcilerTests.Reapplies_when_app_file_reappears` (задача 5).
2. **Ошибка WFP во время применения** — старые фильтры остаются, следующий проход повторяет попытку, а не считает набор применённым. Тест: `ReconcilerTests.Retries_after_apply_failure` (задача 5).
3. **`config.json` отредактирован руками: комментарии, запятая в конце, лишние поля, пропущенное поле, не тот тип** — понятная `ConfigException`, а не падение. Тесты: `ConfigTests` (задача 2).
4. **CIDR с ненулевыми битами хоста (`160.79.104.10/21`) и сокращённая запись (`160.79.104/21`)** — первое нормализуется, второе отвергается. Тесты: `CidrTests` (задача 1).
5. **Домен резолвится в IPv4-mapped IPv6 (`::ffff:160.79.104.10`)** — `status` считает адрес покрытым, без ложного предупреждения. Тест: `CidrTests.Contains` и `ConfigTests.Covers` (задачи 1, 2).

## File Structure

```
ClaudeVpnGuard.sln
.gitignore
src/ClaudeVpnGuard/
  ClaudeVpnGuard.csproj
  Cidr.cs          — разбор CIDR, проверка вхождения адреса
  Config.cs        — GuardConfig, ConfigException, чтение/запись JSON
  Policy.cs        — FilterSpec и Policy.Build (чистая логика правил)
  WfpNative.cs     — структуры и DllImport для fwpuclnt.dll
  Wfp.cs           — ReplaceFilters / ListFilters / RemoveAll
  Adapters.cs      — LUID по имени адаптера, подписка на изменения
  Reconciler.cs    — «построить политику и применить, если изменилась»
  GuardService.cs  — служба Windows
  Installer.cs     — команды install / uninstall / status
  Program.cs       — разбор аргументов
tests/ClaudeVpnGuard.Tests/
  ClaudeVpnGuard.Tests.csproj
  CidrTests.cs, ConfigTests.cs, PolicyTests.cs,
  InteropTests.cs, ReconcilerTests.cs
```

---

### Task 1: Каркас решения и `Cidr`

**Files:**
- Create: `ClaudeVpnGuard.sln`, `.gitignore`, `src/ClaudeVpnGuard/ClaudeVpnGuard.csproj`, `src/ClaudeVpnGuard/Program.cs`, `src/ClaudeVpnGuard/Cidr.cs`
- Create: `tests/ClaudeVpnGuard.Tests/ClaudeVpnGuard.Tests.csproj`
- Test: `tests/ClaudeVpnGuard.Tests/CidrTests.cs`

**Interfaces:**
- Consumes: ничего.
- Produces:
  - `Cidr.Parse(string) : Cidr` — бросает `FormatException`.
  - `Cidr.Address : IPAddress` (сетевой адрес, биты хоста обнулены), `Cidr.PrefixLength : int`, `Cidr.IsIPv6 : bool`.
  - `Cidr.AddressBytes : byte[]`, `Cidr.V4Address : uint` и `Cidr.V4Mask : uint` (порядок байт хоста).
  - `Cidr.Contains(IPAddress) : bool`.
  - `Cidr` — record с равенством по значению.

- [ ] **Step 1: Создать решение и проекты**

```powershell
dotnet new sln -n ClaudeVpnGuard
dotnet new console -n ClaudeVpnGuard -o src/ClaudeVpnGuard -f net9.0
dotnet new xunit -n ClaudeVpnGuard.Tests -o tests/ClaudeVpnGuard.Tests -f net9.0
dotnet sln add src/ClaudeVpnGuard tests/ClaudeVpnGuard.Tests
dotnet add tests/ClaudeVpnGuard.Tests reference src/ClaudeVpnGuard
Remove-Item tests/ClaudeVpnGuard.Tests/UnitTest1.cs
```

- [ ] **Step 2: Заменить `src/ClaudeVpnGuard/ClaudeVpnGuard.csproj`**

`RuntimeIdentifier` и `SelfContained` сюда не добавлять: self-contained exe нельзя
подключить к тестовому проекту (ошибка NETSDK1151). Они задаются при публикации.

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0-windows</TargetFramework>
    <PlatformTarget>x64</PlatformTarget>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <InvariantGlobalization>true</InvariantGlobalization>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="System.ServiceProcess.ServiceController" Version="9.0.0" />
  </ItemGroup>

  <ItemGroup>
    <InternalsVisibleTo Include="ClaudeVpnGuard.Tests" />
  </ItemGroup>

</Project>
```

- [ ] **Step 3: Поправить тестовый проект и добавить `.gitignore`**

В `tests/ClaudeVpnGuard.Tests/ClaudeVpnGuard.Tests.csproj` заменить
`<TargetFramework>net9.0</TargetFramework>` на
`<TargetFramework>net9.0-windows</TargetFramework>` и добавить в ту же
`PropertyGroup` строку `<PlatformTarget>x64</PlatformTarget>`.

`.gitignore`:

```
bin/
obj/
publish/
*.user
.vs/
```

- [ ] **Step 4: Написать падающие тесты `tests/ClaudeVpnGuard.Tests/CidrTests.cs`**

```csharp
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
```

- [ ] **Step 5: Убедиться, что тесты не компилируются**

Run: `dotnet test`
Expected: ошибка сборки `CS0103: The name 'Cidr' does not exist`.

- [ ] **Step 6: Написать `src/ClaudeVpnGuard/Cidr.cs`**

```csharp
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
```

- [ ] **Step 7: Заменить `src/ClaudeVpnGuard/Program.cs` временной заглушкой**

```csharp
Console.Error.WriteLine("ClaudeVpnGuard: команды появятся в следующих задачах.");
return 1;
```

- [ ] **Step 8: Прогнать тесты**

Run: `dotnet test`
Expected: все тесты `CidrTests` проходят, 0 упавших.

- [ ] **Step 9: Commit**

```powershell
git add -A
git commit -m "feat: scaffold solution and add Cidr" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `Config`

**Files:**
- Create: `src/ClaudeVpnGuard/Config.cs`
- Test: `tests/ClaudeVpnGuard.Tests/ConfigTests.cs`

**Interfaces:**
- Consumes: `Cidr.Parse(string)`, `Cidr.IsIPv6`, `Cidr.Contains(IPAddress)`, `Cidr.ToString()`.
- Produces:
  - `sealed class ConfigException : Exception`.
  - `sealed record GuardConfig(string AdapterName, IReadOnlyList<Cidr> Ipv4Cidrs, IReadOnlyList<Cidr> Ipv6Cidrs, IReadOnlyList<string> AppPaths, IReadOnlyList<string> CheckDomains)`.
  - `GuardConfig.Default(string claudeExePath) : GuardConfig`.
  - `GuardConfig.Parse(string json) : GuardConfig` — бросает `ConfigException`.
  - `GuardConfig.Load(string path) : GuardConfig` — бросает `ConfigException`.
  - `GuardConfig.ToJson() : string`.
  - `GuardConfig.Covers(IPAddress) : bool` — адрес входит хотя бы в один диапазон.

- [ ] **Step 1: Написать падающие тесты `tests/ClaudeVpnGuard.Tests/ConfigTests.cs`**

```csharp
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
    public void Accepts_comments_trailing_commas_and_unknown_fields()
    {
        var c = GuardConfig.Parse("""
            {
              // мой VPN
              "adapterName": "AmneziaVPN",
              "ipv4Cidrs": ["160.79.104.0/21",],
              "somethingElse": 42,
            }
            """);

        Assert.Single(c.Ipv4Cidrs);
        Assert.Empty(c.Ipv6Cidrs);
        Assert.Empty(c.AppPaths);
        Assert.Empty(c.CheckDomains);
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
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `dotnet test --filter "FullyQualifiedName~ConfigTests"`
Expected: ошибка сборки `CS0103: The name 'GuardConfig' does not exist`.

- [ ] **Step 3: Написать `src/ClaudeVpnGuard/Config.cs`**

```csharp
using System.Net;
using System.Text.Json;

namespace ClaudeVpnGuard;

public sealed class ConfigException(string message) : Exception(message);

internal sealed class ConfigDto
{
    public string? AdapterName { get; set; }
    public List<string?>? Ipv4Cidrs { get; set; }
    public List<string?>? Ipv6Cidrs { get; set; }
    public List<string?>? AppPaths { get; set; }
    public List<string?>? CheckDomains { get; set; }
}

public sealed record GuardConfig(
    string AdapterName,
    IReadOnlyList<Cidr> Ipv4Cidrs,
    IReadOnlyList<Cidr> Ipv6Cidrs,
    IReadOnlyList<string> AppPaths,
    IReadOnlyList<string> CheckDomains)
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
    };

    public static GuardConfig Default(string claudeExePath) => new(
        "AmneziaVPN",
        [Cidr.Parse("160.79.104.0/21")],
        [Cidr.Parse("2607:6bc0::/48")],
        [claudeExePath],
        [
            "api.anthropic.com", "claude.ai", "claude.com",
            "platform.claude.com", "console.anthropic.com", "mcp-proxy.anthropic.com",
        ]);

    public static GuardConfig Load(string path)
    {
        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new ConfigException($"Не удалось прочитать конфиг {path}: {e.Message}");
        }
        return Parse(json);
    }

    public static GuardConfig Parse(string json)
    {
        ConfigDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<ConfigDto>(json, Options);
        }
        catch (JsonException e)
        {
            throw new ConfigException($"Ошибка JSON в конфиге: {e.Message}");
        }
        if (dto is null) throw new ConfigException("Конфиг пуст");

        if (string.IsNullOrWhiteSpace(dto.AdapterName))
            throw new ConfigException("adapterName не задан");

        var v4 = ParseCidrs(dto.Ipv4Cidrs, "ipv4Cidrs", wantV6: false);
        var v6 = ParseCidrs(dto.Ipv6Cidrs, "ipv6Cidrs", wantV6: true);
        var apps = Strings(dto.AppPaths, "appPaths");
        var domains = Strings(dto.CheckDomains, "checkDomains");

        foreach (var app in apps)
            if (!Path.IsPathFullyQualified(app))
                throw new ConfigException($"appPaths: путь должен быть абсолютным: '{app}'");

        if (v4.Count + v6.Count + apps.Count == 0)
            throw new ConfigException("Нечего блокировать: ipv4Cidrs, ipv6Cidrs и appPaths пусты");

        return new GuardConfig(dto.AdapterName, v4, v6, apps, domains);
    }

    public string ToJson() => JsonSerializer.Serialize(new ConfigDto
    {
        AdapterName = AdapterName,
        Ipv4Cidrs = [.. Ipv4Cidrs.Select(c => c.ToString())],
        Ipv6Cidrs = [.. Ipv6Cidrs.Select(c => c.ToString())],
        AppPaths = [.. AppPaths],
        CheckDomains = [.. CheckDomains],
    }, Options);

    public bool Covers(IPAddress ip) =>
        Ipv4Cidrs.Any(c => c.Contains(ip)) || Ipv6Cidrs.Any(c => c.Contains(ip));

    private static List<string> Strings(List<string?>? values, string field)
    {
        var result = new List<string>();
        foreach (var value in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ConfigException($"{field}: пустое значение");
            result.Add(value);
        }
        return result;
    }

    private static List<Cidr> ParseCidrs(List<string?>? values, string field, bool wantV6)
    {
        var result = new List<Cidr>();
        foreach (var text in Strings(values, field))
        {
            Cidr cidr;
            try
            {
                cidr = Cidr.Parse(text);
            }
            catch (FormatException e)
            {
                throw new ConfigException($"{field}: {e.Message}");
            }
            if (cidr.IsIPv6 != wantV6)
                throw new ConfigException($"{field}: '{text}' — диапазон не того семейства адресов");
            result.Add(cidr);
        }
        return result;
    }
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `dotnet test`
Expected: все тесты `CidrTests` и `ConfigTests` проходят.

- [ ] **Step 5: Commit**

```powershell
git add -A
git commit -m "feat: add GuardConfig" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `Policy`

**Files:**
- Create: `src/ClaudeVpnGuard/Policy.cs`
- Test: `tests/ClaudeVpnGuard.Tests/PolicyTests.cs`

**Interfaces:**
- Consumes: `GuardConfig` (`Ipv4Cidrs`, `Ipv6Cidrs`, `AppPaths`), `Cidr`.
- Produces:
  - `enum FilterAction { Permit, Block }`, `enum IpLayer { V4, V6 }`.
  - `sealed record FilterSpec(string Name, IpLayer Layer, FilterAction Action, byte Weight, Cidr? Remote, string? AppPath, ulong? InterfaceLuid, bool Loopback)`.
  - `sealed record PolicyResult(IReadOnlyList<FilterSpec> Filters, IReadOnlyList<string> Warnings)`.
  - `Policy.PermitWeight = 15`, `Policy.BlockWeight = 1`.
  - `Policy.Build(GuardConfig config, ulong? adapterLuid, Func<string, bool> appExists) : PolicyResult`.

- [ ] **Step 1: Написать падающие тесты `tests/ClaudeVpnGuard.Tests/PolicyTests.cs`**

```csharp
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
    public void Missing_app_is_skipped_with_warning_but_ranges_stay_blocked()
    {
        var policy = Policy.Build(Config, Luid, _ => false);

        Assert.DoesNotContain(policy.Filters, f => f.AppPath is not null);
        Assert.Equal(4, policy.Filters.Count);
        var warning = Assert.Single(policy.Warnings);
        Assert.Contains(ClaudePath, warning);
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
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `dotnet test --filter "FullyQualifiedName~PolicyTests"`
Expected: ошибка сборки `CS0103: The name 'Policy' does not exist`.

- [ ] **Step 3: Написать `src/ClaudeVpnGuard/Policy.cs`**

```csharp
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
```

- [ ] **Step 4: Прогнать тесты**

Run: `dotnet test`
Expected: все тесты проходят.

- [ ] **Step 5: Commit**

```powershell
git add -A
git commit -m "feat: add Policy" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Interop — `WfpNative`, `Wfp`, `Adapters`

Эта задача — единственная, где ошибка не ловится юнит-тестами целиком: вызовы WFP
требуют прав администратора. Юнит-тесты фиксируют раскладку структур и поиск
адаптера; сами вызовы проверяются в задаче 7. Неверный GUID слоя или условия не
пройдёт молча: `FwpmFilterAdd0` вернёт `FWP_E_LAYER_NOT_FOUND` (0x80320004) или
`FWP_E_CONDITION_NOT_FOUND` (0x80320002).

**Files:**
- Create: `src/ClaudeVpnGuard/WfpNative.cs`, `src/ClaudeVpnGuard/Wfp.cs`, `src/ClaudeVpnGuard/Adapters.cs`
- Test: `tests/ClaudeVpnGuard.Tests/InteropTests.cs`

**Interfaces:**
- Consumes: `FilterSpec`, `FilterAction`, `IpLayer`, `Cidr` (`IsIPv6`, `AddressBytes`, `V4Address`, `V4Mask`, `PrefixLength`).
- Produces:
  - `sealed class WfpException : Exception` со свойством `uint Code`.
  - `sealed record InstalledFilter(ulong Id, string Name, ulong? InterfaceLuid)`.
  - `Wfp.ReplaceFilters(IReadOnlyList<FilterSpec> specs) : void` — в одной транзакции создаёт provider и sublayer, удаляет наши фильтры и добавляет новые; при ошибке откатывает и бросает `WfpException`.
  - `Wfp.ListFilters() : IReadOnlyList<InstalledFilter>` — только фильтры нашего sublayer.
  - `Wfp.RemoveAll() : void` — удаляет фильтры, sublayer и provider.
  - `Adapters.FindLuid(string alias) : ulong?`.
  - `Adapters.Watch(Action onChange) : IDisposable`.

- [ ] **Step 1: Написать падающие тесты `tests/ClaudeVpnGuard.Tests/InteropTests.cs`**

Размеры — из `fwptypes.h`/`fwpmtypes.h` для x64. Тест с loopback-адаптером
рассчитан на английское имя интерфейса, как на целевой машине.

```csharp
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
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `dotnet test --filter "FullyQualifiedName~InteropTests"`
Expected: ошибка сборки `CS0103: The name 'WfpNative' does not exist`.

- [ ] **Step 3: Написать `src/ClaudeVpnGuard/WfpNative.cs`**

```csharp
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
```

- [ ] **Step 4: Написать `src/ClaudeVpnGuard/Wfp.cs`**

```csharp
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
        ByteBlob* appId = null;

        try
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

            if (spec.AppPath is { } appPath)
            {
                Check(FwpmGetAppIdFromFileName0(appPath, &appId), "FwpmGetAppIdFromFileName0");
                conditions[count++] = new Condition
                {
                    fieldKey = ConditionAleAppId,
                    matchType = MatchEqual,
                    value = new Value { type = TypeByteBlob, ptr = appId },
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
        finally
        {
            if (appId != null) FwpmFreeMemory0((void**)&appId);
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
```

- [ ] **Step 5: Написать `src/ClaudeVpnGuard/Adapters.cs`**

```csharp
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
```

- [ ] **Step 6: Прогнать тесты**

Run: `dotnet test`
Expected: все тесты проходят, включая `InteropTests`. Если упал
`Native_struct_sizes_match_x64_headers` — раскладка структуры неверна; править
структуру в `WfpNative.cs`, а не ожидаемое число в тесте.

- [ ] **Step 7: Commit**

```powershell
git add -A
git commit -m "feat: add WFP and IP Helper interop" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: `Reconciler` и `GuardService`

**Files:**
- Create: `src/ClaudeVpnGuard/Reconciler.cs`, `src/ClaudeVpnGuard/GuardService.cs`
- Test: `tests/ClaudeVpnGuard.Tests/ReconcilerTests.cs`

**Interfaces:**
- Consumes:
  - `Policy.Build(GuardConfig, ulong?, Func<string, bool>) : PolicyResult`
  - `GuardConfig.Load(string) : GuardConfig`, `ConfigException`
  - `Wfp.ReplaceFilters(IReadOnlyList<FilterSpec>)`
  - `Adapters.FindLuid(string) : ulong?`, `Adapters.Watch(Action) : IDisposable`
- Produces:
  - `sealed record ReconcileResult(bool Changed, IReadOnlyList<string> Warnings)`.
  - `sealed class Reconciler(GuardConfig config, Func<ulong?> findLuid, Func<string, bool> appExists, Action<IReadOnlyList<FilterSpec>> apply)` с методом `Run() : ReconcileResult`.
  - `sealed class GuardService : ServiceBase` с конструктором `GuardService(string configPath)` и константой `GuardService.Name = "ClaudeVpnGuard"`.

- [ ] **Step 1: Написать падающие тесты `tests/ClaudeVpnGuard.Tests/ReconcilerTests.cs`**

```csharp
namespace ClaudeVpnGuard.Tests;

public class ReconcilerTests
{
    private const string ClaudePath = @"C:\Users\ME\.local\bin\claude.exe";
    private static readonly GuardConfig Config = GuardConfig.Default(ClaudePath);

    private ulong? _luid = 100;
    private bool _appExists = true;
    private bool _failApply;
    private readonly List<IReadOnlyList<FilterSpec>> _applied = [];

    private Reconciler Create() => new(
        Config,
        () => _luid,
        _ => _appExists,
        specs =>
        {
            if (_failApply) throw new InvalidOperationException("WFP is down");
            _applied.Add(specs);
        });

    [Fact]
    public void First_run_applies()
    {
        var result = Create().Run();

        Assert.True(result.Changed);
        Assert.Single(_applied);
        Assert.Equal(10, _applied[0].Count);
    }

    [Fact]
    public void Unchanged_state_is_not_reapplied()
    {
        var reconciler = Create();
        reconciler.Run();

        var second = reconciler.Run();

        Assert.False(second.Changed);
        Assert.Single(_applied);
    }

    [Fact]
    public void Reapplies_when_adapter_luid_changes()
    {
        var reconciler = Create();
        reconciler.Run();

        _luid = 200;
        var result = reconciler.Run();

        Assert.True(result.Changed);
        Assert.Equal(2, _applied.Count);
        Assert.Contains(_applied[1], f => f.InterfaceLuid == 200);
        Assert.DoesNotContain(_applied[1], f => f.InterfaceLuid == 100);
    }

    [Fact]
    public void Reapplies_without_permits_when_adapter_disappears()
    {
        var reconciler = Create();
        reconciler.Run();

        _luid = null;
        reconciler.Run();

        Assert.DoesNotContain(_applied[1], f => f.InterfaceLuid is not null);
        Assert.Contains(_applied[1], f => f.Action == FilterAction.Block);
    }

    [Fact]
    public void Reapplies_when_app_file_reappears()
    {
        _appExists = false;
        var reconciler = Create();

        var first = reconciler.Run();
        Assert.Single(first.Warnings);
        Assert.DoesNotContain(_applied[0], f => f.AppPath is not null);
        Assert.Contains(_applied[0], f => f.Action == FilterAction.Block && f.Remote is not null);

        _appExists = true;
        var second = reconciler.Run();

        Assert.True(second.Changed);
        Assert.Empty(second.Warnings);
        Assert.Contains(_applied[1], f => f.AppPath == ClaudePath && f.Action == FilterAction.Block);
    }

    [Fact]
    public void Retries_after_apply_failure()
    {
        var reconciler = Create();

        _failApply = true;
        Assert.Throws<InvalidOperationException>(() => reconciler.Run());
        Assert.Empty(_applied);

        _failApply = false;
        var result = reconciler.Run();

        Assert.True(result.Changed);
        Assert.Single(_applied);
    }

    [Fact]
    public void Warnings_are_reported_even_when_nothing_changed()
    {
        _appExists = false;
        var reconciler = Create();
        reconciler.Run();

        var second = reconciler.Run();

        Assert.False(second.Changed);
        Assert.Single(second.Warnings);
    }
}
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `dotnet test --filter "FullyQualifiedName~ReconcilerTests"`
Expected: ошибка сборки `CS0246: The type or namespace name 'Reconciler' could not be found`.

- [ ] **Step 3: Написать `src/ClaudeVpnGuard/Reconciler.cs`**

```csharp
namespace ClaudeVpnGuard;

public sealed record ReconcileResult(bool Changed, IReadOnlyList<string> Warnings);

public sealed class Reconciler(
    GuardConfig config,
    Func<ulong?> findLuid,
    Func<string, bool> appExists,
    Action<IReadOnlyList<FilterSpec>> apply)
{
    private IReadOnlyList<FilterSpec>? _applied;

    public ReconcileResult Run()
    {
        var policy = Policy.Build(config, findLuid(), appExists);

        if (_applied is not null && _applied.SequenceEqual(policy.Filters))
            return new ReconcileResult(false, policy.Warnings);

        // _applied is only updated after apply succeeds, so a failed run is retried next time.
        apply(policy.Filters);
        _applied = policy.Filters;
        return new ReconcileResult(true, policy.Warnings);
    }
}
```

- [ ] **Step 4: Прогнать тесты**

Run: `dotnet test`
Expected: все тесты проходят.

- [ ] **Step 5: Написать `src/ClaudeVpnGuard/GuardService.cs`**

Служба не имеет собственной логики правил: таймер и уведомления об адаптерах
лишь вызывают `Reconciler.Run()`. Таймер каждые 30 секунд страхует от пропущенных
уведомлений и возвращает фильтры приложения после автообновления `claude.exe`.

```csharp
using System.Diagnostics;
using System.ServiceProcess;

namespace ClaudeVpnGuard;

public sealed class GuardService : ServiceBase
{
    public const string Name = "ClaudeVpnGuard";

    private const int DebounceMs = 500;
    private const int RetryMs = 5_000;
    private const int PollMs = 30_000;

    private readonly string _configPath;
    private readonly object _gate = new();
    private Reconciler? _reconciler;
    private Timer? _timer;
    private IDisposable? _watch;

    public GuardService(string configPath)
    {
        _configPath = configPath;
        ServiceName = Name;
        CanStop = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        // A ConfigException here fails the start and leaves installed filters untouched.
        var config = GuardConfig.Load(_configPath);

        _reconciler = new Reconciler(
            config,
            () => Adapters.FindLuid(config.AdapterName),
            File.Exists,
            Wfp.ReplaceFilters);

        _timer = new Timer(_ => Tick(), null, Timeout.Infinite, Timeout.Infinite);
        Tick();
        _watch = Adapters.Watch(() => _timer?.Change(DebounceMs, PollMs));
    }

    protected override void OnStop()
    {
        _watch?.Dispose();
        _watch = null;
        _timer?.Dispose();
        _timer = null;
    }

    private void Tick()
    {
        lock (_gate)
        {
            var timer = _timer;
            if (timer is null || _reconciler is null) return;

            try
            {
                var result = _reconciler.Run();
                if (result.Changed)
                {
                    var text = "Фильтры обновлены.";
                    if (result.Warnings.Count > 0)
                        text += Environment.NewLine + string.Join(Environment.NewLine, result.Warnings);
                    Log(text, result.Warnings.Count > 0 ? EventLogEntryType.Warning : EventLogEntryType.Information);
                }
                timer.Change(PollMs, PollMs);
            }
            catch (Exception e)
            {
                Log($"Не удалось обновить фильтры, повтор через {RetryMs / 1000} с: {e.Message}", EventLogEntryType.Error);
                timer.Change(RetryMs, PollMs);
            }
        }
    }

    private void Log(string message, EventLogEntryType type)
    {
        try
        {
            EventLog.WriteEntry(message, type);
        }
        catch
        {
            // Logging must never take the guard down.
        }
    }
}
```

- [ ] **Step 6: Собрать и прогнать тесты**

Run: `dotnet build` затем `dotnet test`
Expected: сборка без ошибок, все тесты проходят.

- [ ] **Step 7: Commit**

```powershell
git add -A
git commit -m "feat: add Reconciler and GuardService" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: CLI — `install`, `uninstall`, `status` — и публикация

**Files:**
- Create: `src/ClaudeVpnGuard/Installer.cs`
- Modify: `src/ClaudeVpnGuard/Program.cs` (заменить заглушку целиком)

**Interfaces:**
- Consumes:
  - `GuardConfig.Default(string)`, `GuardConfig.Load(string)`, `GuardConfig.ToJson()`, `GuardConfig.Covers(IPAddress)`, `ConfigException`
  - `Policy.Build(...) : PolicyResult`
  - `Wfp.ReplaceFilters(...)`, `Wfp.ListFilters() : IReadOnlyList<InstalledFilter>`, `Wfp.RemoveAll()`, `WfpException`
  - `Adapters.FindLuid(string) : ulong?`
  - `GuardService(string configPath)`, `GuardService.Name`
- Produces:
  - `Installer.InstallDir`, `Installer.ExePath`, `Installer.ConfigPath` (строки).
  - `Installer.Install() : int`, `Installer.Uninstall() : int`, `Installer.Status() : int` — коды возврата из Global Constraints.
  - Командная строка: `ClaudeVpnGuard install | uninstall | status | service`.

- [ ] **Step 1: Написать `src/ClaudeVpnGuard/Installer.cs`**

```csharp
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.ServiceProcess;

namespace ClaudeVpnGuard;

public static class Installer
{
    public static readonly string InstallDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClaudeVpnGuard");

    public static readonly string ExePath = Path.Combine(InstallDir, "ClaudeVpnGuard.exe");
    public static readonly string ConfigPath = Path.Combine(InstallDir, "config.json");

    public static int Install()
    {
        if (!RequireAdmin()) return 1;

        Directory.CreateDirectory(InstallDir);
        StopService();
        if (!CopySelf()) return 1;

        if (!File.Exists(ConfigPath))
        {
            var claudePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe");
            File.WriteAllText(ConfigPath, GuardConfig.Default(claudePath).ToJson());
            Console.WriteLine($"Создан конфиг: {ConfigPath}");
            Console.WriteLine($"  Путь к Claude Code: {claudePath}");
        }

        GuardConfig config;
        try
        {
            config = GuardConfig.Load(ConfigPath);
        }
        catch (ConfigException e)
        {
            Console.Error.WriteLine(e.Message);
            return 1;
        }

        var luid = Adapters.FindLuid(config.AdapterName);
        var policy = Policy.Build(config, luid, File.Exists);
        try
        {
            Wfp.ReplaceFilters(policy.Filters);
        }
        catch (WfpException e)
        {
            Console.Error.WriteLine($"Не удалось установить фильтры: {e.Message}");
            return 1;
        }

        Console.WriteLine($"Установлено фильтров: {policy.Filters.Count}");
        foreach (var warning in policy.Warnings) Console.WriteLine($"Предупреждение: {warning}");
        if (luid is null)
            Console.WriteLine($"Адаптер '{config.AdapterName}' не найден: Claude заблокирован, пока VPN не включён.");

        var binPath = $"\"{ExePath}\" service";
        var registered = ServiceExists()
            ? Sc("config", GuardService.Name, "binPath=", binPath, "start=", "auto")
            : Sc("create", GuardService.Name, "binPath=", binPath, "start=", "auto",
                "obj=", "LocalSystem", "DisplayName=", "Claude VPN Guard");
        if (registered != 0)
        {
            Console.Error.WriteLine($"Не удалось зарегистрировать службу (sc.exe вернул {registered}).");
            return 1;
        }

        Sc("description", GuardService.Name, "Пропускает трафик Claude только через VPN.");
        Sc("failure", GuardService.Name, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000");

        var started = Sc("start", GuardService.Name);
        if (started != 0)
        {
            Console.Error.WriteLine($"Фильтры установлены, но служба не запустилась (sc.exe вернул {started}).");
            return 1;
        }

        Console.WriteLine("Служба ClaudeVpnGuard установлена и запущена.");
        return 0;
    }

    public static int Uninstall()
    {
        if (!RequireAdmin()) return 1;

        if (ServiceExists())
        {
            StopService();
            var deleted = Sc("delete", GuardService.Name);
            if (deleted != 0)
            {
                Console.Error.WriteLine($"Не удалось удалить службу (sc.exe вернул {deleted}).");
                return 1;
            }
        }

        try
        {
            Wfp.RemoveAll();
        }
        catch (WfpException e)
        {
            Console.Error.WriteLine($"Не удалось удалить фильтры: {e.Message}");
            return 1;
        }

        Console.WriteLine("Служба и фильтры удалены. Файлы остались в " + InstallDir);
        return 0;
    }

    public static int Status()
    {
        var warnings = 0;
        void Warn(string message)
        {
            warnings++;
            Console.WriteLine($"  ! {message}");
        }

        Console.WriteLine("Служба:");
        if (!ServiceExists())
        {
            Warn("не установлена");
        }
        else
        {
            using var service = new ServiceController(GuardService.Name);
            Console.WriteLine($"  состояние: {service.Status}");
            if (service.Status != ServiceControllerStatus.Running) Warn("служба не запущена");
        }

        GuardConfig? config = null;
        Console.WriteLine("Конфиг:");
        try
        {
            config = GuardConfig.Load(ConfigPath);
            Console.WriteLine($"  {ConfigPath}");
        }
        catch (ConfigException e)
        {
            Warn(e.Message);
        }

        var luid = config is null ? null : Adapters.FindLuid(config.AdapterName);
        if (config is not null)
        {
            Console.WriteLine("Адаптер:");
            Console.WriteLine(luid is null
                ? $"  '{config.AdapterName}' не найден — VPN выключен, Claude заблокирован"
                : $"  '{config.AdapterName}', LUID 0x{luid:X}");
        }

        Console.WriteLine("Фильтры:");
        try
        {
            var filters = Wfp.ListFilters();
            Console.WriteLine($"  установлено: {filters.Count}");
            if (filters.Count == 0) Warn("фильтров нет — защита не действует");

            var stale = filters.Count(f => f.InterfaceLuid is not null && f.InterfaceLuid != luid);
            if (stale > 0)
                Warn($"разрешающих фильтров с устаревшим LUID: {stale} — Claude заблокирован, пока служба их не обновит");

            if (luid is not null && filters.Count > 0 && filters.All(f => f.InterfaceLuid is null))
                Warn("адаптер найден, но разрешающих фильтров нет — Claude заблокирован, пока служба их не добавит");
        }
        catch (WfpException e)
        {
            Warn($"не удалось прочитать фильтры ({e.Message}); запустите от имени администратора");
        }

        if (config is not null && config.CheckDomains.Count > 0)
        {
            Console.WriteLine("Домены:");
            foreach (var domain in config.CheckDomains)
            {
                IPAddress[] addresses;
                try
                {
                    addresses = Dns.GetHostAddresses(domain);
                }
                catch (SocketException)
                {
                    Warn($"{domain} не резолвится");
                    continue;
                }

                var outside = addresses.Where(a => !config.Covers(a)).ToList();
                if (outside.Count == 0)
                    Console.WriteLine($"  {domain}: в диапазонах конфига");
                else
                    Warn($"{domain}: адреса вне диапазонов конфига: {string.Join(", ", outside)}");
            }
        }

        Console.WriteLine(warnings == 0 ? "Всё в порядке." : $"Предупреждений: {warnings}");
        return warnings == 0 ? 0 : 2;
    }

    private static bool RequireAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return true;

        Console.Error.WriteLine("Нужны права администратора: запустите терминал от имени администратора.");
        return false;
    }

    private static bool ServiceExists() =>
        ServiceController.GetServices().Any(s => s.ServiceName == GuardService.Name);

    private static void StopService()
    {
        if (!ServiceExists()) return;

        using var service = new ServiceController(GuardService.Name);
        if (service.Status == ServiceControllerStatus.Stopped) return;

        try
        {
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
        }
        catch (Exception e) when (e is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine($"Не удалось остановить службу: {e.Message}");
        }
    }

    private static bool CopySelf()
    {
        var self = Path.GetFullPath(Environment.ProcessPath!);
        if (string.Equals(self, ExePath, StringComparison.OrdinalIgnoreCase)) return true;

        // The service process can hold the file for a moment after it reports Stopped.
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Copy(self, ExePath, overwrite: true);
                return true;
            }
            catch (IOException) when (attempt < 10)
            {
                Thread.Sleep(500);
            }
            catch (IOException e)
            {
                Console.Error.WriteLine($"Не удалось скопировать {self} в {ExePath}: {e.Message}");
                return false;
            }
        }
    }

    private static int Sc(params string[] args)
    {
        var info = new ProcessStartInfo("sc.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args) info.ArgumentList.Add(arg);

        using var process = Process.Start(info)!;
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        return process.ExitCode;
    }
}
```

- [ ] **Step 2: Заменить `src/ClaudeVpnGuard/Program.cs`**

```csharp
using System.ServiceProcess;
using System.Text;
using ClaudeVpnGuard;

if (args.Length == 1 && args[0] == "service")
{
    ServiceBase.Run(new GuardService(Installer.ConfigPath));
    return 0;
}

Console.OutputEncoding = Encoding.UTF8;

switch (args.Length == 1 ? args[0] : "")
{
    case "install":
        return Installer.Install();
    case "uninstall":
        return Installer.Uninstall();
    case "status":
        return Installer.Status();
    default:
        Console.Error.WriteLine("""
            Использование: ClaudeVpnGuard <команда>

              install    установить фильтры и службу (нужны права администратора)
              uninstall  удалить службу и фильтры (нужны права администратора)
              status     показать состояние защиты
            """);
        return 1;
}
```

- [ ] **Step 3: Собрать и прогнать тесты**

Run: `dotnet build` затем `dotnet test`
Expected: сборка без ошибок и без предупреждений CA1416, все тесты проходят.

- [ ] **Step 4: Опубликовать одним файлом**

```powershell
dotnet publish src/ClaudeVpnGuard -c Release -r win-x64 --self-contained `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
Get-ChildItem publish | Select-Object Name, Length
```

Expected: в `publish` лежит `ClaudeVpnGuard.exe` (десятки мегабайт) и, возможно,
`.pdb`; других `.dll` нет.

- [ ] **Step 5: Проверить CLI без прав администратора**

Запускать в обычном (не повышенном) терминале:

```powershell
.\publish\ClaudeVpnGuard.exe; "exit=$LASTEXITCODE"
.\publish\ClaudeVpnGuard.exe install; "exit=$LASTEXITCODE"
.\publish\ClaudeVpnGuard.exe status; "exit=$LASTEXITCODE"
```

Expected:
1. Текст «Использование: …», `exit=1`.
2. «Нужны права администратора…», `exit=1`, каталог `C:\Program Files\ClaudeVpnGuard` не создан.
3. Русский текст читается (не кракозябры); «Служба: не установлена», предупреждение
   о конфиге, `exit=2`.

Если терминал уже повышен, пункт 2 пропустить — он выполнится в задаче 7.

- [ ] **Step 6: Commit**

```powershell
git add -A
git commit -m "feat: add install, uninstall and status commands" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Живая проверка на машине

Здесь нет нового кода — только проверка и исправление найденного. Все шаги с
`install`/`uninstall` выполняются в терминале **от имени администратора**. Если
сессия исполнителя не повышена, эти команды запускает пользователь, а исполнитель
читает их вывод.

**Аварийный выход.** Если после `install` Claude Code потерял сеть при включённом
VPN, пользователь запускает в терминале администратора:

```powershell
& "C:\Program Files\ClaudeVpnGuard\ClaudeVpnGuard.exe" uninstall
```

**Files:**
- Modify: любые файлы из задач 1–6, если проверка выявит ошибку (с тестом, который её воспроизводит, где это возможно без прав администратора).

**Interfaces:**
- Consumes: `publish\ClaudeVpnGuard.exe` из задачи 6.
- Produces: установленная и проверенная защита.

- [ ] **Step 1: Снять базовую картину до установки (VPN включён)**

```powershell
$eth = (Get-NetIPAddress -InterfaceAlias 'Ethernet 4' -AddressFamily IPv4).IPAddress
$ex  = (Resolve-DnsName example.com -Type A | Where-Object IPAddress | Select-Object -First 1).IPAddress
"eth=$eth example=$ex"
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth --resolve "example.com:443:$ex" https://example.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --resolve "example.com:443:$ex" https://example.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth https://api.anthropic.com
```

Expected: первые две команды печатают `200`. Третья печатает HTTP-код (например
`404`) — то есть без защиты Anthropic доступен мимо VPN.

Если первая команда не соединяется уже сейчас, значит физический интерфейс
закрыт чем-то ещё (например, kill switch самой Amnezia). Тогда шаги 3 и 5 не
могут отличить нашу блокировку от чужой: остановиться и сообщить пользователю.

- [ ] **Step 2: Пробная установка на безопасной цели**

Сначала проверяем механику на адресе `example.com`, а не на Anthropic: если
permit по LUID работает неправильно, сломается только `example.com`, а не
сессия Claude Code.

В терминале администратора (переменная `$ex` — из шага 1):

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\ClaudeVpnGuard' | Out-Null
@"
{
  "adapterName": "AmneziaVPN",
  "ipv4Cidrs": ["$ex/32"],
  "ipv6Cidrs": [],
  "appPaths": [],
  "checkDomains": []
}
"@ | Set-Content -Encoding utf8 'C:\Program Files\ClaudeVpnGuard\config.json'
C:\Users\ME\Development\Repositories\ClaudeVpnGuard\publish\ClaudeVpnGuard.exe install; "exit=$LASTEXITCODE"
& 'C:\Program Files\ClaudeVpnGuard\ClaudeVpnGuard.exe' status; "exit=$LASTEXITCODE"
```

Expected: `install` печатает «Установлено фильтров: 2» и «Служба ClaudeVpnGuard
установлена и запущена.», `exit=0`. `status`: служба `Running`, адаптер найден
с LUID, «установлено: 2», `exit=0`.

- [ ] **Step 3: Проверить блокировку и разрешение на безопасной цели**

```powershell
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth --resolve "example.com:443:$ex" https://example.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --resolve "example.com:443:$ex" https://example.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth https://api.anthropic.com
```

Expected:
1. Ошибка соединения (`curl: (7) …`), код `000` — блокировка на `Ethernet 4` работает.
2. `200` — permit через AmneziaVPN работает.
3. HTTP-код, как в шаге 1 — посторонний трафик не задет.

Если пункт 2 даёт ошибку — permit по LUID не срабатывает. Выполнить `uninstall`,
найти причину (навык superpowers:systematic-debugging), исправить и повторить с шага 2.

- [ ] **Step 4: Перейти на настоящий конфиг**

В терминале администратора:

```powershell
Remove-Item 'C:\Program Files\ClaudeVpnGuard\config.json'
C:\Users\ME\Development\Repositories\ClaudeVpnGuard\publish\ClaudeVpnGuard.exe install; "exit=$LASTEXITCODE"
& 'C:\Program Files\ClaudeVpnGuard\ClaudeVpnGuard.exe' status; "exit=$LASTEXITCODE"
Get-Content 'C:\Program Files\ClaudeVpnGuard\config.json'
```

Expected: повторный `install` проходит при работающей службе (останавливает её
и перезаписывает exe), печатает «Создан конфиг», путь
`C:\Users\ME\.local\bin\claude.exe`, «Установлено фильтров: 10», `exit=0`.
`status`: все домены «в диапазонах конфига», «Всё в порядке.», `exit=0`.

Если путь к `claude.exe` в конфиге другой (терминал администратора запущен от
другой учётной записи), исправить `appPaths` в `config.json` и выполнить
`Restart-Service ClaudeVpnGuard`.

- [ ] **Step 5: Проверить настоящую защиту при включённом VPN**

```powershell
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth https://api.anthropic.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth https://claude.ai
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" https://api.anthropic.com
curl.exe -sS -m 10 -o NUL -w "%{http_code}`n" --interface $eth --resolve "example.com:443:$ex" https://example.com
```

Expected:
1. и 2. — ошибка соединения, код `000`.
3. HTTP-код (например `404`) — через VPN доступно.
4. `200` — пробный фильтр из шага 2 убран, посторонний трафик свободен.

Claude Code в этой сессии продолжает отвечать.

- [ ] **Step 6: Проверить состояние после перезапуска службы**

В терминале администратора:

```powershell
Restart-Service ClaudeVpnGuard
& 'C:\Program Files\ClaudeVpnGuard\ClaudeVpnGuard.exe' status; "exit=$LASTEXITCODE"
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'ClaudeVpnGuard' } -MaxEvents 5 |
  Select-Object TimeCreated, LevelDisplayName, Message | Format-List
```

Expected: `exit=0`; в журнале есть «Фильтры обновлены.» и нет записей уровня Error.

- [ ] **Step 7: Проверка отключением VPN — выполняет пользователь**

Этот шаг обрывает сессию Claude Code, поэтому исполнитель передаёт его
пользователю как инструкцию и на этом завершает работу:

1. Отключить AmneziaVPN. Claude Code перестаёт отвечать, `claude.ai` в браузере
   не открывается, остальные сайты открываются.
2. `& 'C:\Program Files\ClaudeVpnGuard\ClaudeVpnGuard.exe' status` — адаптер
   «не найден — VPN выключен, Claude заблокирован».
3. Включить AmneziaVPN. Через пару секунд Claude Code и `claude.ai` снова работают
   без перезапуска службы.
4. Перезагрузить компьютер с выключенным VPN — Claude без сети до включения VPN.
5. При желании убрать защиту: `ClaudeVpnGuard.exe uninstall` в терминале
   администратора — всё работает как до установки.

- [ ] **Step 8: Commit исправлений, если они были**

```powershell
git status --short
git add -A
git commit -m "fix: address issues found in live verification" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Если изменений нет, коммит не делать.
