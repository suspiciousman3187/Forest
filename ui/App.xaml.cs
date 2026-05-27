using System.Windows;
using System.Windows.Threading;

namespace Forest.UI;

public partial class App : Application
{
    private static void Dump(string where, Exception ex)
    {
        Forest.DiagLog.Crash(where, ex);
        MessageBox.Show($"Startup error ({where}):\n\n{ex.Message}\n\n"
            + $"Details written to:\n{Forest.DiagLog.Dir}", "Forest",
            MessageBoxButton.OK, MessageBoxImage.Error);
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, a) =>
        {
            Program.T("AppDomain.UnhandledException: " + a.ExceptionObject);
            Dump("AppDomain", (a.ExceptionObject as Exception)
                 ?? new Exception(a.ExceptionObject?.ToString() ?? "unknown"));
        };
        DispatcherUnhandledException += (_, a) =>
        {
            Program.T("Dispatcher.UnhandledException: " + a.Exception);
            Dump("Dispatcher", a.Exception); a.Handled = true;
        };
        Exit += (_, a) =>
        {
            Program.T($"App.Exit code={a.ApplicationExitCode}");
            try { Forest.PolProxy.Stop(); } catch { }
        };
        SessionEnding += (_, a) =>
        {
            Program.T("App.SessionEnding " + a.ReasonSessionEnding);
            try { Forest.PolProxy.Stop(); } catch { }
        };

        Program.T("App.OnStartup: enter");

        Forest.PolProxy.Log = m => Program.T(m);
        try { Forest.PolProxy.CleanHosts(); } catch { }

        base.OnStartup(e);
        try
        {
            Program.T("App.OnStartup: creating WebHostWindow");
            var w = new WebHostWindow();
            Program.T("App.OnStartup: WebHostWindow constructed, Show()");
            w.Show();
            Program.T("App.OnStartup: WebHostWindow shown OK");
        }
        catch (Exception ex)
        {
            Program.T("App.OnStartup: EXCEPTION " + ex);
            Dump("MainWindow ctor", ex);
            Shutdown(1);
        }
    }
}
