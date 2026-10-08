using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

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
        // A misspelled key must fail loudly: silently ignoring it would install less protection.
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
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
