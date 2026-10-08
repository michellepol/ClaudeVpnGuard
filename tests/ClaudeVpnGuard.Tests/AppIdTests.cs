using System.Text;

namespace ClaudeVpnGuard.Tests;

public class AppIdTests
{
    public static TheoryData<string> ExistingFiles() => new()
    {
        Environment.ProcessPath!,
        Path.Combine(Environment.SystemDirectory, "curl.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
        typeof(AppIdTests).Assembly.Location,
    };

    // The format is not documented, so it is pinned to what the real API returns.
    [Theory]
    [MemberData(nameof(ExistingFiles))]
    public void Computed_id_equals_the_api_id_byte_for_byte(string path)
    {
        var fromApi = AppId.FromFile(path);

        Assert.NotNull(fromApi);
        Assert.Equal(Convert.ToHexString(fromApi), Convert.ToHexString(AppId.FromPath(path)));
    }

    [Fact]
    public void Computed_id_equals_the_api_id_for_a_non_ascii_mixed_case_path()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ClaudeVpnGuard Тест ЁЖ " + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "Прога Ünï.EXE");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllBytes(path, []);

            var fromApi = AppId.FromFile(path);

            Assert.NotNull(fromApi);
            Assert.Equal(Convert.ToHexString(fromApi), Convert.ToHexString(AppId.FromPath(path)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    // The API lower-cases A–Z only. Checked for every character .NET considers upper-case,
    // so a path with Cyrillic or accented letters gets the same ID with and without the file.
    [Fact]
    public void Computed_id_equals_the_api_id_for_every_cased_character()
    {
        var cased = Enumerable.Range(0x21, 0xFFFE - 0x21)
            .Select(code => (char)code)
            .Where(c => !char.IsSurrogate(c) && !"\"*/:<>?\\|".Contains(c) && char.ToLowerInvariant(c) != c)
            .ToArray();
        Assert.True(cased.Length > 1000);

        var directory = Path.Combine(Path.GetTempPath(), "ClaudeVpnGuard " + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            foreach (var chunk in cased.Chunk(100))
            {
                var path = Path.Combine(directory, "a" + new string(chunk) + "z");
                File.WriteAllBytes(path, []);

                var fromApi = AppId.FromFile(path);

                Assert.NotNull(fromApi);
                Assert.Equal(Convert.ToHexString(fromApi), Convert.ToHexString(AppId.FromPath(path)));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Id_is_the_lower_cased_device_path_with_terminator()
    {
        var path = Path.Combine(Environment.SystemDirectory, "curl.exe");

        var text = Encoding.Unicode.GetString(AppId.FromPath(path));

        Assert.StartsWith(@"\device\harddiskvolume", text);
        Assert.EndsWith(path[2..].ToLowerInvariant() + "\0", text);
        Assert.Equal(text.ToLowerInvariant(), text);
    }

    [Fact]
    public void Computed_id_does_not_need_the_file()
    {
        var existing = Path.Combine(Environment.SystemDirectory, "curl.exe");
        var missing = Path.Combine(Environment.SystemDirectory, "no-such-file-7c1e.exe");
        Assert.False(File.Exists(missing));

        var expected = Encoding.Unicode.GetString(AppId.FromPath(existing))
            .Replace("curl.exe", "no-such-file-7c1e.exe");

        Assert.Null(AppId.FromFile(missing));
        Assert.Equal(expected, Encoding.Unicode.GetString(AppId.FromPath(missing)));
        Assert.Equal(AppId.FromPath(missing), AppId.Resolve(missing));
    }

    [Fact]
    public void Resolve_prefers_the_api_for_an_existing_file()
    {
        var path = Path.Combine(Environment.SystemDirectory, "curl.exe");

        Assert.Equal(AppId.FromFile(path), AppId.Resolve(path));
    }

    [Fact]
    public void Path_is_normalized_before_use()
    {
        var plain = Path.Combine(Environment.SystemDirectory, "curl.exe");
        var dotted = Path.Combine(Environment.SystemDirectory, "drivers", "..", "curl.exe").Replace('\\', '/');

        Assert.Equal(AppId.FromPath(plain), AppId.FromPath(dotted));
    }

    [Theory]
    [InlineData(@"\\server\share\claude.exe")]
    [InlineData(@"\\?\C:\Tools\claude.exe")]
    [InlineData(@"claude.exe")]
    [InlineData(@"C:claude.exe")]
    [InlineData(@"\Tools\claude.exe")]
    public void Rejects_paths_without_a_drive(string path)
    {
        var e = Assert.Throws<AppIdException>(() => AppId.FromPath(path));
        Assert.Contains(path, e.Message);
    }

    [Fact]
    public void Rejects_a_drive_that_does_not_exist()
    {
        var used = Environment.GetLogicalDrives().Select(d => char.ToUpperInvariant(d[0])).ToHashSet();
        var free = "ZYXWVUTSRQPONMLKJIHGFED".First(letter => !used.Contains(letter));
        var path = $@"{free}:\Tools\claude.exe";

        var e = Assert.Throws<AppIdException>(() => AppId.FromPath(path));
        Assert.Contains(path, e.Message);
    }
}
