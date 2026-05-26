using System.IO;
using System.Windows;

namespace Forest.UI;

internal static class Program
{
    internal static void T(string s) => Forest.DiagLog.Log(s);

    [STAThread]
    public static void Main()
    {
        T($"Main: ENTER  base={AppContext.BaseDirectory}");
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
            Forest.DiagLog.Crash("Main", ex);
            try
            {
                MessageBox.Show($"Forest failed to start:\n\n{ex.Message}"
                    + $"\n\nFull details:\n{Forest.DiagLog.Dir}", "Forest startup error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch {  }
            Environment.Exit(1);
        }
    }
}
