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
              status     показать состояние защиты (проверка фильтров работает
                         только в терминале администратора)
            """);
        return 1;
}
