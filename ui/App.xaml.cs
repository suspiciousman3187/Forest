using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Forest.UI;

public partial class App : Application
{
    private static readonly string CrashLog =
        Path.Combine(Path.GetTempPath(), "forest_crash.txt");

    private static void Dump(string where, Exception ex)
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"[{DateTime.Now:u}] {where}");
            for (Exception? e = ex; e != null; e = e.InnerException)
                sb.AppendLine($"{e.GetType().FullName}: {e.Message}\n{e.StackTrace}");
            File.WriteAllText(CrashLog, sb.ToString());
        }
        catch {  }
        MessageBox.Show($"Startup error ({where}):\n\n{ex.Message}\n\n"
            + $"Details written to:\n{CrashLog}", "Forest",
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
        try
        {
            var cfg = Forest.Config.Load();
            if (cfg.UsePolProxy) Forest.PolProxy.Start(cfg);
        }
        catch (Exception ex) { Program.T("PolProxy start failed: " + ex.Message); }

        base.OnStartup(e);
        try
        {
            Program.T("App.OnStartup: creating MainWindow");
            var w = new MainWindow();
            Program.T("App.OnStartup: MainWindow constructed, Show()");
            w.Show();
            Program.T("App.OnStartup: MainWindow shown OK");
        }
        catch (Exception ex)
        {
            Program.T("App.OnStartup: EXCEPTION " + ex);
            Dump("MainWindow ctor", ex);
            Shutdown(1);
        }
    }
}
