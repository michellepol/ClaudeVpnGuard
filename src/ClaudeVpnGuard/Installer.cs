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

    private const int ServiceAlreadyRunning = 1056; // ERROR_SERVICE_ALREADY_RUNNING

    public static int Install()
    {
        if (!RequireAdmin()) return 1;

        GuardConfig config;
        ulong? luid;
        PolicyResult policy;
        bool wasRunning;
        try
        {
            Directory.CreateDirectory(InstallDir);

            if (!File.Exists(ConfigPath))
            {
                var claudePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe");
                File.WriteAllText(ConfigPath, GuardConfig.Default(claudePath).ToJson());
                Console.WriteLine($"Создан конфиг: {ConfigPath}");
                Console.WriteLine($"  Путь к Claude Code: {claudePath}");
            }

            try
            {
                config = GuardConfig.Load(ConfigPath);
            }
            catch (ConfigException e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }

            luid = Adapters.FindLuid(config.AdapterName);
            policy = Policy.Build(config, luid, File.Exists);
            wasRunning = ServiceIsActive();
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Установка не выполнена ({e.Message}); служба и фильтры не изменены.");
            return 1;
        }

        // Everything that can fail without needing the service stopped is done; only now stop it.
        var filtersInstalled = false;
        try
        {
            if (!StopService())
            {
                Console.Error.WriteLine("Не удалось остановить службу, поэтому exe не заменён. Фильтры не изменены.");
                return 1;
            }

            if (!CopySelf()) return FailAfterStop(wasRunning);

            try
            {
                Wfp.ReplaceFilters(policy.Filters);
            }
            catch (Exception e) when (e is WfpException or AppIdException)
            {
                Console.Error.WriteLine($"Не удалось установить фильтры: {e.Message}");
                return FailAfterStop(wasRunning);
            }

            filtersInstalled = true;
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
                Console.Error.WriteLine(
                    $"Фильтры установлены и остаются на месте, но не удалось зарегистрировать службу (sc.exe вернул {registered}).");
                return FailAfterStop(wasRunning);
            }

            Sc("description", GuardService.Name, "Пропускает трафик Claude только через VPN.");
            var failureConfigured = Sc("failure", GuardService.Name,
                "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000");
            if (failureConfigured != 0)
                Console.Error.WriteLine(
                    $"Не удалось настроить автоматический перезапуск службы (sc.exe вернул {failureConfigured}).");

            var started = Sc("start", GuardService.Name);
            if (started != 0)
            {
                Console.Error.WriteLine($"Фильтры установлены, но служба не запустилась (sc.exe вернул {started}).");
                return 1;
            }

            if (!WaitForRunning())
            {
                Console.Error.WriteLine("Фильтры установлены, но служба не перешла в состояние Running.");
                return 1;
            }

            if (failureConfigured != 0) return 1;

            Console.WriteLine("Служба ClaudeVpnGuard установлена и запущена.");
            return 0;
        }
        catch (Exception e)
        {
            // Nothing above removes filters: whichever set was installed last stays in force.
            Console.Error.WriteLine(filtersInstalled
                ? $"Установка прервана ({e.Message}); новые фильтры установлены и остаются на месте."
                : $"Установка прервана ({e.Message}); прежние фильтры не изменены.");
            return FailAfterStop(wasRunning);
        }
    }

    public static int Uninstall()
    {
        if (!RequireAdmin()) return 1;

        try
        {
            if (ServiceExists())
            {
                if (!StopService())
                {
                    Console.Error.WriteLine(
                        "Не удалось остановить службу: она продолжила бы восстанавливать фильтры. Служба и фильтры не тронуты.");
                    return 1;
                }

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
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(
                $"Удаление прервано ({e.Message}); фильтры остались на месте, служба могла остановиться. Повторите uninstall.");
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

        if (config is not null)
        {
            foreach (var app in config.AppPaths.Where(p => !File.Exists(p)))
                Warn($"{app}: файл не найден — фильтры построены по пути из конфига, проверьте путь");
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

    private static bool ServiceIsActive()
    {
        if (!ServiceExists()) return false;

        using var service = new ServiceController(GuardService.Name);
        return service.Status != ServiceControllerStatus.Stopped;
    }

    // True when the service does not exist or is really stopped afterwards.
    private static bool StopService()
    {
        if (!ServiceExists()) return true;

        using var service = new ServiceController(GuardService.Name);
        if (service.Status == ServiceControllerStatus.Stopped) return true;

        try
        {
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
        }
        catch (Exception e) when (e is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine($"Не удалось остановить службу: {e.Message}");
        }

        service.Refresh();
        return service.Status == ServiceControllerStatus.Stopped;
    }

    private static bool WaitForRunning()
    {
        using var service = new ServiceController(GuardService.Name);
        try
        {
            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
        }
        catch (Exception e) when (e is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
        }

        service.Refresh();
        return service.Status == ServiceControllerStatus.Running;
    }

    // Best effort: put the previously running service back so its filters do not go stale.
    private static int FailAfterStop(bool wasRunning)
    {
        if (!wasRunning) return 1;

        try
        {
            // "Already running" is the wanted outcome when the stop itself is what failed.
            if (Sc("start", GuardService.Name) is 0 or ServiceAlreadyRunning) return 1;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Не удалось запустить sc.exe: {e.Message}");
        }

        Console.Error.WriteLine("Прежняя служба не перезапущена: запустите её вручную или повторите install.");
        return 1;
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
            catch (Exception e) when (e is (IOException or UnauthorizedAccessException) && attempt < 10)
            {
                Thread.Sleep(500);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Не удалось скопировать {self} в {ExePath}: {e.Message}");
                return false;
            }
        }
    }

    private static int Sc(params string[] args)
    {
        // Full path: a bare name would also be searched for next to our own, user-writable, exe.
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"))
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
