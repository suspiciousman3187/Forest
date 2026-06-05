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

    // Fires once after the WebView2 + WebBridge are fully constructed, so
    // callers (App.xaml.cs splash startup path) can interact with the bridge.
    public event Action<WebBridge>? OnBridgeReady;

    // Remember the "normal" window chrome so we can restore it after a splash
    // session ends (user hits STOP / launch fails / user terminates).
    private double _normalWidth;
    private double _normalHeight;
    private double _normalMinWidth;
    private double _normalMinHeight;
    private ResizeMode _normalResizeMode;
    private WindowStyle _normalWindowStyle;
    private WindowStartupLocation _normalStartLoc;
    private bool _splashState;

    public bool IsSplashMode => _splashState;

    public WebHostWindow()
    {
        InitializeComponent();
        // Snapshot the XAML-set defaults so we can return to them later.
        _normalWidth = Width; _normalHeight = Height;
        _normalMinWidth = MinWidth; _normalMinHeight = MinHeight;
        _normalResizeMode = ResizeMode; _normalWindowStyle = WindowStyle;
        _normalStartLoc = WindowStartupLocation;
        Loaded += OnLoaded;
    }

    // Toggle between the full app window and the small minimalist splash.
    // The WebView2 + bridge stay the same instance throughout — only the
    // host window's chrome/size changes. The React side decides which
    // component to render based on the splash.armed bridge state.
    public void SetSplashMode(bool on)
    {
        if (on == _splashState) return;
        if (on)
        {
            _normalWidth = Width; _normalHeight = Height;
            ResizeMode = ResizeMode.NoResize;
            MinWidth = 0; MinHeight = 0;
            Width = 480; Height = 440;
            Left = (SystemParameters.PrimaryScreenWidth - Width) / 2;
            Top  = (SystemParameters.PrimaryScreenHeight - Height) / 2;
        }
        else
        {
            ResizeMode = _normalResizeMode;
            MinWidth = _normalMinWidth; MinHeight = _normalMinHeight;
            Width = _normalWidth; Height = _normalHeight;
            Left = (SystemParameters.PrimaryScreenWidth - Width) / 2;
            Top  = (SystemParameters.PrimaryScreenHeight - Height) / 2;
        }
        _splashState = on;
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

            try { OnBridgeReady?.Invoke(_bridge); } catch (Exception bx) {
                Program.T("OnBridgeReady handler threw: " + bx);
            }
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
