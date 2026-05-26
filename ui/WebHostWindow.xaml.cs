using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Forest;

namespace Forest.UI;

public partial class WebHostWindow : Window
{
    private const string Host = "forest.app";
    private WebBridge? _bridge;

    public WebHostWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var userData = Path.Combine(AppData.Dir, "WebView2");
            Directory.CreateDirectory(userData);
            var env = await CoreWebView2Environment.CreateAsync(null, userData);
            await Web.EnsureCoreWebView2Async(env);

            var core = Web.CoreWebView2;
            var webuiDir = Path.Combine(AppContext.BaseDirectory, "webui");
            core.SetVirtualHostNameToFolderMapping(Host, webuiDir, CoreWebView2HostResourceAccessKind.Allow);

            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;

            core.NewWindowRequested += (_, a) =>
            {
                a.Handled = true;
                try { Process.Start(new ProcessStartInfo(a.Uri) { UseShellExecute = true }); } catch { }
            };

            _bridge = new WebBridge(core, this);

            core.Navigate($"https://{Host}/index.html");
            Program.T("WebHostWindow: navigated to webui");
        }
        catch (Exception ex)
        {
            Program.T("WebHostWindow.OnLoaded EX: " + ex);
            DiagLog.Crash("WebHostWindow", ex);
            MessageBox.Show(
                "Forest's UI failed to load (WebView2 Runtime may be missing).\n\n"
                + ex.Message + "\n\nDetails written to:\n" + DiagLog.Dir,
                "Forest", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
