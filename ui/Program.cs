using System.IO;
using System.Windows;

namespace Forest.UI;

internal static class Program
{
    internal static readonly string Trace =
        Path.Combine(Path.GetTempPath(), "forest_trace.txt");

    internal static void T(string s)
    {
        try { File.AppendAllText(Trace,
            $"[{DateTime.Now:HH:mm:ss.fff}] {s}\r\n"); } catch { }
    }

    [STAThread]
    public static void Main()
    {
        var log = Path.Combine(Path.GetTempPath(), "forest_crash.txt");
        try { File.WriteAllText(Trace,
            $"[{DateTime.Now:HH:mm:ss.fff}] Main: ENTER  base={AppContext.BaseDirectory}\r\n"); }
        catch { }
        try
        {

            Directory.SetCurrentDirectory(AppContext.BaseDirectory);
            T("Main: CWD set, creating App");

            var app = new App();
            app.InitializeComponent();
            T("Main: App.InitializeComponent OK, calling Run()");
            app.Run();
            T("Main: Run() returned -> normal exit");
        }
        catch (Exception ex)
        {
            T("Main: EXCEPTION " + ex.GetType().Name + ": " + ex.Message);
            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"[{DateTime.Now:u}] fatal in Main");
                sb.AppendLine($"CWD={Directory.GetCurrentDirectory()}");
                sb.AppendLine($"Base={AppContext.BaseDirectory}");
                for (Exception? e = ex; e != null; e = e.InnerException)
                    sb.AppendLine($"{e.GetType().FullName}: {e.Message}\n{e.StackTrace}");
                File.WriteAllText(log, sb.ToString());
            }
            catch {  }
            try
            {
                MessageBox.Show($"Forest failed to start:\n\n{ex.Message}"
                    + $"\n\nFull details:\n{log}", "Forest startup error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch {  }
            Environment.Exit(1);
        }
    }
}
