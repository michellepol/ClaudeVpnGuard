using System.Runtime.InteropServices;
using System.Text;
using static ClaudeVpnGuard.WfpNative;

namespace ClaudeVpnGuard;

public sealed class AppIdException(string message) : Exception(message);

// A WFP application ID is the file's NT device path with A–Z lower-cased, as a null-terminated
// UTF-16LE string: "\device\harddiskvolume4\users\me\.local\bin\claude.exe\0".
internal static unsafe class AppId
{
    private const string VolumePrefix = @"\Device\HarddiskVolume";
    private const int ErrorInsufficientBuffer = 122;

    // DWORD QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax) — fileapi.h
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string deviceName, char* targetPath, uint max);

    // The API resolves links and junctions but needs the file to exist; the computed ID keeps
    // an application blocked while its file is missing (auto-update by rename, wrong path).
    public static byte[] Resolve(string path) => FromFile(path) ?? FromPath(path);

    public static byte[]? FromFile(string path)
    {
        ByteBlob* blob = null;
        if (FwpmGetAppIdFromFileName0(path, &blob) != 0 || blob == null) return null;

        try
        {
            return new ReadOnlySpan<byte>(blob->data, checked((int)blob->size)).ToArray();
        }
        finally
        {
            FwpmFreeMemory0((void**)&blob);
        }
    }

    public static byte[] FromPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path[1] != ':')
            throw new AppIdException($"Не удалось построить app ID: нужен полный путь с буквой диска, а не '{path}'");

        var full = Path.GetFullPath(path);
        var device = QueryDevice(full[..2], path);

        // FwpmGetAppIdFromFileName0 lower-cases A–Z only and leaves every other character as it is
        // (pinned by AppIdTests); a full Unicode lower-casing would not match non-ASCII paths.
        var text = (device + full[2..] + "\0").ToCharArray();
        for (var i = 0; i < text.Length; i++)
            if (text[i] is >= 'A' and <= 'Z') text[i] = (char)(text[i] | 0x20);
        return Encoding.Unicode.GetBytes(text);
    }

    private static string QueryDevice(string drive, string path)
    {
        for (var size = 512; ; size *= 2)
        {
            var buffer = new char[size];
            uint length;
            int error;
            fixed (char* target = buffer)
            {
                length = QueryDosDeviceW(drive, target, (uint)size);
                error = Marshal.GetLastPInvokeError();
            }

            if (length == 0 && error == ErrorInsufficientBuffer && size < 32768) continue;
            if (length == 0)
                throw new AppIdException(
                    $"Не удалось построить app ID для '{path}': диск {drive} не найден (ошибка {error})");

            // The result is a list of null-terminated strings; the first one is the current mapping.
            var device = new string(buffer, 0, Array.IndexOf(buffer, '\0'));
            if (!device.StartsWith(VolumePrefix, StringComparison.OrdinalIgnoreCase))
                throw new AppIdException(
                    $"Не удалось построить app ID для '{path}': диск {drive} — не локальный том ({device})");
            return device;
        }
    }
}
