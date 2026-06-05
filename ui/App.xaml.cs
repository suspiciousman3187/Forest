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
            // Parse command-line: --launch "ProfileName" (or comma-separated)
            // and --quit-when-loaded enable splash + auto-quit mode for this
            // session. Equivalents in config: LaunchMode = "Splash" plus
            // SelectedAccounts populated, plus AutoQuitWhenAllLoaded.
            string[]? cliLaunch = null;
            bool cliQuitWhenLoaded = false;
            for (int i = 0; i < e.Args.Length; ++i)
            {
                var a = e.Args[i];
                if ((a == "--launch" || a == "/launch") && i + 1 < e.Args.Length)
                    cliLaunch = e.Args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                else if (a == "--quit-when-loaded" || a == "/quit-when-loaded")
                    cliQuitWhenLoaded = true;
            }

            var cfg = Forest.Config.Load();
            bool configSplash = string.Equals(cfg.LaunchMode, "Splash", StringComparison.OrdinalIgnoreCase);

            string[]? autoLaunchProfiles = cliLaunch
                ?? (cfg.LaunchSelectedOnStartup && cfg.SelectedAccounts.Count > 0
                    ? cfg.SelectedAccounts.ToArray()
                    : null);

            bool useSplash = autoLaunchProfiles is { Length: > 0 }
                          && (cliLaunch != null ? cliQuitWhenLoaded : configSplash);
            bool autoQuit = useSplash;

            Program.T($"App.OnStartup: creating WebHostWindow (autoLaunch={(autoLaunchProfiles is null ? "(none)" : string.Join(",", autoLaunchProfiles))}, splash={useSplash}, autoQuit={autoQuit})");
            var w = new WebHostWindow();
            if (useSplash) w.SetSplashMode(true);
            w.Show();
            Program.T("App.OnStartup: WebHostWindow shown OK");

            if (autoLaunchProfiles is { Length: > 0 })
            {
                w.OnBridgeReady += bridge =>
                {
                    if (bridge.AreAllRunning(autoLaunchProfiles))
                    {
                        if (useSplash) w.SetSplashMode(false);
                        return;
                    }
                    if (useSplash) bridge.ArmSplash(autoLaunchProfiles, autoQuit);
                    bridge.LaunchProgrammatic(autoLaunchProfiles);
                };
            }
        }
        catch (Exception ex)
        {
            Program.T("App.OnStartup: EXCEPTION " + ex);
            Dump("MainWindow ctor", ex);
            Shutdown(1);
        }
    }
}
