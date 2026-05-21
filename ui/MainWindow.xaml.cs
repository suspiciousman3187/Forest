using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using MahApps.Metro.Controls;
using Microsoft.Win32;
using Forest;

namespace Forest.UI;

public sealed class StatusColorConverter : IValueConverter
{

    private static readonly string[] Flow =
    {
        "LAUNCH WINDOWER", "LAUNCH POL", "SELECT ACCOUNT",
        "INPUT PASSWORD", "LOGGING IN", "LAUNCHING GAME",
    };

    private static readonly (byte r, byte g, byte b) Dull  = (0x36, 0x47, 0x3D);
    private static readonly (byte r, byte g, byte b) Vivid = (0x22, 0xC5, 0x5E);

    public object Convert(object? value, Type targetType, object? parameter,
                          CultureInfo culture)
    {
        var s = (value?.ToString() ?? "").ToUpperInvariant();
        if (s.StartsWith("DONE") || s.StartsWith("RUNNING"))
            return new SolidColorBrush(Color.FromRgb(Vivid.r, Vivid.g, Vivid.b));

        if (s.StartsWith("WRONG SE PASSWORD") || s.StartsWith("WRONG_SE_PASSWORD"))
            return new SolidColorBrush(Color.FromRgb(0xE0, 0x8B, 0x1F));

        if (s.StartsWith("LOGIN STUCK") || s.StartsWith("POST_CONNECT_STUCK"))
            return new SolidColorBrush(Color.FromRgb(0xEB, 0xC8, 0x2A));
        if (s.StartsWith("FAILED") || s.StartsWith("ERR") ||
            s.Contains("TIMEOUT") || s.StartsWith("TERMINATED"))
            return new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
        if (s is "" or "—" or "-" or "PENDING" or "INACTIVE" || s.StartsWith("QUEUED"))
            return new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80));

        if (s == "LAUNCH ASHITA") s = "LAUNCH WINDOWER";
        int i = Array.IndexOf(Flow, s);
        if (i < 0)
            return (Application.Current?.TryFindResource("MahApps.Brushes.Accent")
                    as Brush) ?? new SolidColorBrush(Color.FromRgb(0x3F, 0xA8, 0x46));

        double t = (i + 1) / (double)(Flow.Length + 1);
        double e = Math.Pow(t, 1.8);
        byte Lerp(byte a, byte b) => (byte)Math.Round(a + (b - a) * e);
        return new SolidColorBrush(Color.FromRgb(
            Lerp(Dull.r, Vivid.r), Lerp(Dull.g, Vivid.g), Lerp(Dull.b, Vivid.b)));
    }
    public object ConvertBack(object? value, Type targetType, object? parameter,
                              CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class StatusRunningConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        (value?.ToString() ?? "").Trim()
            .Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

public sealed class HasPidConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        int.TryParse(value?.ToString(), out var pid) && pid > 0;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

public sealed class CanTerminateStatusConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        var s = (value?.ToString() ?? "").Trim().ToUpperInvariant();
        if (s.Length == 0 || s is "-" or "—") return false;
        return s != "INACTIVE" && s != "TERMINATED";
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

public sealed class NotCheckedToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

public sealed class LauncherToIconConverter : IValueConverter
{
    private static readonly System.Windows.Media.Imaging.BitmapImage Ashita =
        Load("ashita.ico");
    private static readonly System.Windows.Media.Imaging.BitmapImage Windower =
        Load("iconWindower.png");

    private static System.Windows.Media.Imaging.BitmapImage Load(string file)
    {
        var b = new System.Windows.Media.Imaging.BitmapImage();
        b.BeginInit();
        b.UriSource = new Uri($"pack://application:,,,/Assets/{file}");
        b.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
        b.EndInit();
        b.Freeze();
        return b;
    }

    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        string.Equals(value?.ToString(), "Ashita",
            StringComparison.OrdinalIgnoreCase) ? Ashita : Windower;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

public partial class MainWindow : MetroWindow
{
    public sealed class AccountRow : INotifyPropertyChanged
    {
        public string Profile { get; set; } = "";
        public string Windower { get; set; } = "";
        public string Slot { get; set; } = "";

        public string Launcher { get; set; } = "Windower";
        private bool _selected;
        public bool Selected { get => _selected; set { _selected = value; OnPropertyChanged(); } }

        private bool _dragging;
        public bool Dragging { get => _dragging; set { _dragging = value; OnPropertyChanged(); } }
        private string _pid = "-", _status = "INACTIVE";
        public string Pid    { get => _pid;    set { _pid = value; OnPropertyChanged(); } }

        public DateTime? TerminatedAt { get; private set; }
        public string Status
        {
            get => _status;
            set
            {
                _status = value;
                TerminatedAt = (value == "TERMINATED" ||
                                value == "WRONG SE PASSWORD" ||
                                value == "LOGIN STUCK")
                                ? DateTime.UtcNow : null;
                OnPropertyChanged();
            }
        }
        public event PropertyChangedEventHandler? PropertyChanged;
        void OnPropertyChanged([CallerMemberName] string? n = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    private readonly ObservableCollection<AccountRow> _rows = new();
    private readonly Dictionary<string, LaunchService.Handle> _handles = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Dictionary<int, DateTime> _proxyServed = new();
    private readonly Dictionary<int, DateTime> _doneSince = new();

    private readonly HashSet<string> _noAuto =
        new(StringComparer.OrdinalIgnoreCase);

    private bool _launching;

    private static readonly HashSet<string> InFlightStates =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "QUEUED", "LAUNCH WINDOWER", "LAUNCH ASHITA", "LAUNCH POL",
            "SELECT ACCOUNT", "INPUT PASSWORD", "LOGGING IN", "LAUNCHING GAME",
        };

    private bool IsInFlight(AccountRow r) =>
        _handles.ContainsKey(r.Profile) || InFlightStates.Contains(r.Status);

    private static readonly HashSet<string> RelaunchableStates =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "INACTIVE", "FAILED", "TERMINATED", "TIMEOUT", "ERR",
        };

    private bool IsLaunchable(AccountRow r) =>
        !IsInFlight(r) && RelaunchableStates.Contains(r.Status);

    private bool HasPid(AccountRow r) =>
        _handles.ContainsKey(r.Profile) ||
        (int.TryParse(r.Pid, out var p) && p > 0);

    private static bool CanTerminate(AccountRow r)
    {
        var s = (r.Status ?? "").Trim().ToUpperInvariant();
        if (s.Length == 0 || s is "-" or "—") return false;
        return s != "INACTIVE" && s != "TERMINATED";
    }

    private readonly HashSet<string> _cancelled =
        new(StringComparer.OrdinalIgnoreCase);

    public MainWindow()
    {
        Program.T("MainWindow.ctor: InitializeComponent");
        InitializeComponent();
        Program.T("MainWindow.ctor: InitializeComponent OK");
        Grid.ItemsSource = _rows;
        _timer.Tick += PollStatuses;
        _timer.Start();
        PolProxy.FastServed += OnFastServed;
        Loaded += (_, _) =>
        {
            Program.T("MainWindow.Loaded: enter");
            try { RefreshGrid(); ReattachRunning(); LoadSettings();
                  UpdateStatusBar();
                  UpdateProxyBadge(); MaybeStartupLaunch();
                  Program.T("MainWindow.Loaded: OK"); }
            catch (Exception ex) { Program.T("MainWindow.Loaded EX: " + ex); }
        };
    }

    private void UpdateProxyBadge()
    {
        bool on = PolProxy.Running;
        ProxyDot.Fill = new SolidColorBrush(on
            ? Color.FromRgb(0x22, 0xC5, 0x5E) : Color.FromRgb(0x6B, 0x72, 0x80));
        ProxyStatus.Text = on ? "POL Proxy: RUNNING" : "POL Proxy: OFF";
    }

    private void OnTab(object s, RoutedEventArgs e)
    {
        if (PanelAccounts == null) return;
        bool acc = TabAccounts.IsChecked == true;
        PanelAccounts.Visibility = acc ? Visibility.Visible : Visibility.Collapsed;
        PanelSettings.Visibility = acc ? Visibility.Collapsed : Visibility.Visible;
    }

    private bool _restoringSel;

    private void RefreshGrid()
    {
        var sel = (Grid.SelectedItem as AccountRow)?.Profile;
        var cfg = Config.Load();

        var ticked = new HashSet<string>(
            cfg.SelectedAccounts, StringComparer.OrdinalIgnoreCase);
        var defLauncher = cfg.DefaultLauncher;

        var orderIx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < cfg.AccountOrder.Count; i++)
            orderIx.TryAdd(cfg.AccountOrder[i], i);
        var ordered = CredentialStore.Load().Accounts()
            .Select((a, idx) => (a,
                key: orderIx.TryGetValue(a.Name, out var ix) ? ix : int.MaxValue,
                idx))
            .OrderBy(t => t.key).ThenBy(t => t.idx)
            .Select(t => t.a)
            .ToList();

        _restoringSel = true;
        _rows.Clear();
        foreach (var a in ordered)
        {
            _handles.TryGetValue(a.Name, out var h);
            var row = new AccountRow
            {
                Profile  = a.Name,
                Windower = a.WindowerProfile ?? "—",
                Slot     = a.PolSlot == 0 ? "—" : a.PolSlot.ToString(),
                Launcher = Config.NormalizeLauncher(a.Launcher ?? defLauncher),
                Pid      = h is null ? "-" : h.Pid.ToString(),
                Selected = ticked.Contains(a.Name),
            };
            row.PropertyChanged += OnRowChanged;
            _rows.Add(row);
        }
        _restoringSel = false;
        if (sel != null)
            Grid.SelectedItem = _rows.FirstOrDefault(r => r.Profile == sel);

        SaveOrder(cfg.AccountOrder);
        UpdateActionButtons();
    }

    private Point _dragStart;
    private AccountRow? _dragRow;
    private bool _dragging;

    private static AccountRow? RowFromVisual(DependencyObject? d)
    {
        while (d != null && d is not System.Windows.Controls.DataGridRow)
            d = VisualTreeHelper.GetParent(d);
        return (d as System.Windows.Controls.DataGridRow)?.Item as AccountRow;
    }

    private AccountRow? RowAt(double y)
    {
        AccountRow? first = null, last = null;
        foreach (var r in _rows)
        {
            if (Grid.ItemContainerGenerator.ContainerFromItem(r)
                is not System.Windows.Controls.DataGridRow dgr) continue;
            var top = dgr.TranslatePoint(new Point(0, 0), Grid).Y;
            var bot = top + dgr.ActualHeight;
            first ??= r;
            last = r;
            if (y >= top && y <= bot) return r;
        }
        if (first != null && y < 0) return first;
        return last;
    }

    private void OnGridDragStart(object s,
        System.Windows.Input.MouseButtonEventArgs e)
    {
        _dragStart = e.GetPosition(Grid);
        _dragRow = RowFromVisual(e.OriginalSource as DependencyObject);
        _dragging = false;
    }

    private void OnGridDragMove(object s, System.Windows.Input.MouseEventArgs e)
    {
        if (_dragRow == null ||
            e.LeftButton != System.Windows.Input.MouseButtonState.Pressed)
            return;

        var p = e.GetPosition(Grid);

        if (!_dragging)
        {

            if (Math.Abs(p.X - _dragStart.X) < SystemParameters.MinimumHorizontalDragDistance &&
                Math.Abs(p.Y - _dragStart.Y) < SystemParameters.MinimumVerticalDragDistance)
                return;
            _dragging = true;
            _dragRow.Dragging = true;
            System.Windows.Input.Mouse.Capture(Grid);
        }

        var over = RowAt(p.Y);
        if (over != null && !ReferenceEquals(over, _dragRow))
        {
            int from = _rows.IndexOf(_dragRow), to = _rows.IndexOf(over);
            if (from >= 0 && to >= 0 && from != to) _rows.Move(from, to);
        }
    }

    private void OnGridDragEnd(object s,
        System.Windows.Input.MouseButtonEventArgs e) => EndDrag();

    private void OnGridDragCancel(object s, RoutedEventArgs e) => EndDrag();

    private void EndDrag()
    {
        bool wasDragging = _dragging;
        if (_dragRow != null) _dragRow.Dragging = false;
        if (System.Windows.Input.Mouse.Captured == Grid)
            System.Windows.Input.Mouse.Capture(null);
        _dragging = false;
        _dragRow = null;
        if (wasDragging) SaveOrder();
    }

    private void SaveOrder(List<string>? known = null)
    {
        try
        {
            var now = _rows.Select(r => r.Profile).ToList();
            if (known != null && known.SequenceEqual(now,
                    StringComparer.OrdinalIgnoreCase))
                return;
            var c = Config.Load();
            c.AccountOrder = now;
            c.Save();
        }
        catch (Exception ex) { Program.T("SaveOrder EX: " + ex); }
    }

    private void OnRowChanged(object? s, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AccountRow.Selected) && !_restoringSel)
            SaveSelection();
        if (e.PropertyName is nameof(AccountRow.Selected)
                           or nameof(AccountRow.Status)
                           or nameof(AccountRow.Pid))
            UpdateActionButtons();
    }

    private void UpdateActionButtons()
    {
        if (LaunchBtn == null || TerminateBtn == null) return;
        var sel = _rows.Where(r => r.Selected).ToList();

        int launchN    = sel.Count(IsLaunchable);
        int terminateN = sel.Count(CanTerminate);

        LaunchBtn.IsEnabled    = !_launching && launchN > 0;
        TerminateBtn.IsEnabled = terminateN > 0;

        LaunchBtn.Content    = launchN    >= 2 ? $"LAUNCH ({launchN})"
                                               : "LAUNCH";
        TerminateBtn.Content = terminateN >= 2 ? $"TERMINATE ({terminateN})"
                                               : "TERMINATE";
    }

    private void SaveSelection()
    {
        try
        {
            var c = Config.Load();
            c.SelectedAccounts = _rows.Where(r => r.Selected)
                                      .Select(r => r.Profile).ToList();
            c.Save();
        }
        catch (Exception ex) { Program.T("SaveSelection EX: " + ex); }
    }

    private void OnSelectAll(object s, RoutedEventArgs e)
    {
        if (s is System.Windows.Controls.CheckBox cb)
            foreach (var r in _rows) r.Selected = cb.IsChecked == true;
    }

    private AccountRow? Row(string p) => _rows.FirstOrDefault(r => r.Profile == p);

    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void UpdateStatusBar(string? extra = null)
    {
        if (!string.IsNullOrEmpty(extra)) Program.T("ui: " + extra);
    }
    private void Log(string s) => Program.T("ui: " + s);

    private void OnAdd(object s, RoutedEventArgs e)
    {
        if (new AccountWindow { Owner = this }.ShowDialog() == true) RefreshGrid();
    }

    private static AccountRow? MenuRow(object s) =>
        (s as FrameworkElement)?.DataContext as AccountRow;

    private void OnEditRow(object s, RoutedEventArgs e)
    {
        if (MenuRow(s) is AccountRow r) EditAccount(r);
    }
    private void OnRemoveRow(object s, RoutedEventArgs e)
    {
        if (MenuRow(s) is AccountRow r) RemoveAccount(r);
    }
    private void OnTerminateRow(object s, RoutedEventArgs e)
    {
        if (MenuRow(s) is not AccountRow r) return;
        if (!CanTerminate(r)) return;

        var msg = "The following processes will be closed.\n\n" + FormatTarget(r);
        if (!ConfirmWindow.Ask(this, msg, confirmText: "Terminate",
                danger: true, header: "TERMINATE ACCOUNT"))
            return;
        KillRow(r, quiet: false);
    }

    private int ResolvePid(AccountRow r)
    {
        if (_handles.TryGetValue(r.Profile, out var h) && h.Pid > 0) return h.Pid;
        return int.TryParse(r.Pid, out var p) ? p : 0;
    }

    private string FormatTarget(AccountRow r)
    {
        int pid = ResolvePid(r);
        if (pid > 0)
            return $"   •  {r.Profile}   (pid {pid})";
        if (LaunchService.InFlightWaitinjects.ContainsKey(r.Profile))
            return $"   •  {r.Profile}   (launching)";
        return $"   •  {r.Profile}";
    }

    private void EditAccount(AccountRow r)
    {
        if (new AccountWindow(r.Profile) { Owner = this }.ShowDialog() == true)
        {

            _wrongPwFailCount.Remove(r.Profile);
            RefreshGrid();
        }
    }
    private void RemoveAccount(AccountRow r)
    {
        if (!ConfirmWindow.Ask(this,
                $"Remove the account “{r.Profile}”? This deletes its "
                + "stored credentials and cannot be undone.",
                confirmText: "Remove", danger: true, header: "REMOVE ACCOUNT"))
            return;
        CredentialStore.Load().Remove(r.Profile);
        _handles.Remove(r.Profile);
        RefreshGrid();
    }

    private void OnKillRow(object s, RoutedEventArgs e)
    {
        if (s is FrameworkElement fe && fe.DataContext is AccountRow row)
            KillRow(row, quiet: false);
    }

    private void OnTerminateSelected(object s, RoutedEventArgs e)
    {
        var sel = _rows.Where(r => r.Selected).ToList();
        if (sel.Count == 0)
        { ConfirmWindow.Info(this, "Tick the checkbox on one or more accounts first."); return; }

        var targets = sel.Where(CanTerminate).ToList();
        if (targets.Count == 0)
        {
            ConfirmWindow.Info(this, "None of the selected accounts are in a "
                + "terminable state (INACTIVE and TERMINATED rows have nothing "
                + "to close).");
            return;
        }

        var lines = string.Join("\n", targets.Select(FormatTarget));
        var msg = "The following processes will be closed.\n\n" + lines;
        var btn = targets.Count == 1 ? "Terminate" : $"Terminate {targets.Count}";

        if (!ConfirmWindow.Ask(this, msg, confirmText: btn, danger: true,
                header: targets.Count == 1 ? "TERMINATE ACCOUNT"
                                           : "TERMINATE ACCOUNTS"))
            return;

        int killed = targets.Count(r => KillRow(r, quiet: true));
        UpdateStatusBar($"Terminated {killed} of {targets.Count}.");
    }

    private bool KillRow(AccountRow row, bool quiet)
    {
        int polPid = ResolvePid(row);
        bool haveInFlight =
            LaunchService.InFlightWaitinjects.TryGetValue(row.Profile, out int wiPid);

        if (polPid <= 0 && !haveInFlight)
        {
            if (string.Equals(row.Status, "QUEUED",
                              StringComparison.OrdinalIgnoreCase))
            {
                _cancelled.Add(row.Profile);
                row.Pid = "-";
                row.Status = "INACTIVE";
                UpdateStatusBar($"Cancelled queued launch for {row.Profile}.");
                return true;
            }
            return false;
        }

        bool killedSomething = false;

        if (haveInFlight && wiPid > 0)
        {
            _cancelled.Add(row.Profile);
            try
            {
                var wi = Process.GetProcessById(wiPid);
                if (wi.ProcessName.Equals("waitinject",
                                          StringComparison.OrdinalIgnoreCase))
                {
                    wi.Kill();
                    wi.WaitForExit(2000);
                    killedSomething = true;
                    UpdateStatusBar(
                        $"Cancelled in-flight launch for {row.Profile}.");
                }
            }
            catch (ArgumentException) {  }
            catch (Exception ex)
            {
                if (!quiet)
                    ConfirmWindow.Info(this,
                        $"Could not cancel in-flight launch (pid {wiPid}): "
                        + ex.Message, header: "TERMINATE FAILED");
            }
            LaunchService.InFlightWaitinjects.TryRemove(row.Profile, out _);
        }

        if (polPid > 0)
        {
            try
            {
                var proc = Process.GetProcessById(polPid);
                if (!proc.ProcessName.Equals("pol",
                                             StringComparison.OrdinalIgnoreCase))
                {
                    if (!quiet)
                        ConfirmWindow.Info(this,
                            $"PID {polPid} is not pol.exe (it's "
                            + $"“{proc.ProcessName}”) — not terminating, to "
                            + "protect your other processes.",
                            header: "NOT TERMINATED");

                }
                else
                {
                    proc.Kill();
                    proc.WaitForExit(3000);
                    killedSomething = true;
                    UpdateStatusBar(
                        $"Terminated {row.Profile} (pid {polPid}).");
                }
            }
            catch (ArgumentException)
            {

                killedSomething = true;
                UpdateStatusBar($"{row.Profile} (pid {polPid}) already gone.");
            }
            catch (Exception ex)
            {
                if (!quiet)
                    ConfirmWindow.Info(this,
                        $"Could not terminate PID {polPid}: {ex.Message}",
                        header: "TERMINATE FAILED");
                if (!killedSomething) return false;
            }
        }

        if (!killedSomething) return false;

        _handles.Remove(row.Profile);
        _noAuto.Remove(row.Profile);
        row.Pid = "-";
        row.Status = "TERMINATED";
        return true;
    }

    private static readonly string[] MarkerPrefixes =
        { "status", "slot", "cred", "totp", "nohide" };

    private static int? MarkerPid(string fileName)
    {
        int us = fileName.IndexOf('_');
        int dot = fileName.LastIndexOf('.');
        if (us <= 0 || dot <= us + 1) return null;
        if (Array.IndexOf(MarkerPrefixes, fileName.Substring(0, us)) < 0) return null;
        return int.TryParse(fileName.Substring(us + 1, dot - us - 1), out var p)
            ? p : null;
    }

    private static void DeleteMarkers(string dir, int pid)
    {
        foreach (var pre in MarkerPrefixes)
            foreach (var ext in new[] { "txt", "bin" })
                try
                {
                    var f = Path.Combine(dir, $"{pre}_{pid}.{ext}");
                    if (File.Exists(f)) File.Delete(f);
                }
                catch {  }
    }

    private void ReattachRunning()
    {
        var dir = Config.Load().TreesDir;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;

        var bySlot = new Dictionary<int, string>();
        foreach (var a in CredentialStore.Load().Accounts())
            if (a.PolSlot > 0) bySlot[a.PolSlot] = a.Name;

        int n = 0;
        try
        {
            foreach (var path in Directory.EnumerateFiles(dir, "status_*.txt"))
            {
                if (MarkerPid(Path.GetFileName(path)) is not { } pid) continue;
                try
                {
                    if (!Process.GetProcessById(pid).ProcessName
                            .Equals("pol", StringComparison.OrdinalIgnoreCase))
                        continue;
                }
                catch { continue; }

                int slot = 0;
                try
                {
                    var sp = Path.Combine(dir, $"slot_{pid}.txt");
                    if (File.Exists(sp) &&
                        int.TryParse(File.ReadAllText(sp).Trim(), out var sv))
                        slot = sv;
                }
                catch { }
                if (slot <= 0 || !bySlot.TryGetValue(slot, out var profile))
                    continue;
                if (_handles.ContainsKey(profile)) continue;

                _handles[profile] = new LaunchService.Handle(
                    profile, pid, Path.Combine(dir, $"status_{pid}.txt"));

                _noAuto.Add(profile);
                if (Row(profile) is { } r)
                { r.Pid = pid.ToString(); r.Status = "RUNNING"; }
                n++;
            }
        }
        catch (Exception ex) { Program.T("ReattachRunning EX: " + ex); }

        if (n > 0)
        {
            Program.T($"reattached {n} still-running client(s) from a "
                + "previous session");
            UpdateActionButtons();
        }
    }

    private void OnCleanStalePol(object s, RoutedEventArgs e)
    {
        var dir = Config.Load().TreesDir;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            ConfirmWindow.Info(this, "Trees directory is not set or doesn't "
                + "exist (Settings → Trees Directory).", header: "STALE CLEANUP");
            return;
        }

        var pids = new HashSet<int>();
        try
        {
            foreach (var path in Directory.EnumerateFiles(dir))
                if (MarkerPid(Path.GetFileName(path)) is { } p) pids.Add(p);
        }
        catch (Exception ex)
        {
            ConfirmWindow.Info(this, "Could not scan Trees directory: "
                + ex.Message, header: "STALE CLEANUP");
            return;
        }

        var keep = new HashSet<int>(_rows.Where(r => r.Status == "RUNNING")
            .Select(r => int.TryParse(r.Pid, out var p) ? p : -1));

        var kill = new List<int>();
        int pruned = 0;
        foreach (var pid in pids)
        {
            bool alivePol = false;
            try
            {
                alivePol = Process.GetProcessById(pid).ProcessName
                    .Equals("pol", StringComparison.OrdinalIgnoreCase);
            }
            catch { alivePol = false; }

            if (!alivePol) { DeleteMarkers(dir, pid); pruned++; continue; }
            if (keep.Contains(pid)) continue;
            kill.Add(pid);
        }

        if (kill.Count == 0)
        {
            ConfirmWindow.Info(this, pruned > 0
                ? $"No stale Forest pol.exe running. Cleaned up {pruned} "
                  + "orphaned marker file set(s)."
                : "No stale Forest pol.exe processes found.",
                header: "STALE CLEANUP");
            return;
        }

        string Desc(int pid)
        {
            var prof = _handles.FirstOrDefault(kv => kv.Value.Pid == pid).Key;
            return prof != null ? $"PID {pid}  ({prof})" : $"PID {pid}";
        }
        var listing = string.Join("\n",
            kill.OrderBy(x => x).Select(Desc));

        if (!ConfirmWindow.Ask(this,
                $"Kill these {kill.Count} Forest-launched pol.exe process(es)?"
                + "\n\n" + listing + "\n\nEach has a Forest marker file and is "
                + "not a currently-RUNNING account. Your hand-run characters "
                + "are not listed and will not be touched.",
                confirmText: $"Kill {kill.Count}", danger: true,
                header: "CLEAN UP STALE POL"))
            return;

        int killed = 0;
        foreach (var pid in kill)
        {
            try
            {
                var pr = Process.GetProcessById(pid);
                if (!pr.ProcessName.Equals("pol",
                        StringComparison.OrdinalIgnoreCase))
                    continue;
                pr.Kill(); pr.WaitForExit(3000); killed++;
                DeleteMarkers(dir, pid);
                var prof = _handles.FirstOrDefault(kv => kv.Value.Pid == pid).Key;
                if (prof != null) { _handles.Remove(prof); _noAuto.Remove(prof); }
                foreach (var r in _rows)
                    if (int.TryParse(r.Pid, out var rp) && rp == pid)
                    { r.Pid = "-"; r.Status = "TERMINATED"; }
            }
            catch {  }
        }

        ConfirmWindow.Info(this,
            $"Terminated {killed} of {kill.Count} stale Forest pol.exe."
            + (pruned > 0 ? $"  Pruned {pruned} orphaned marker set(s)." : ""),
            header: "STALE CLEANUP");
    }

    private bool _loadingSettings;

    private void LoadSettings()
    {
        _loadingSettings = true;
        try
        {
            var c = Config.Load();
            WinExeBox.Text  = c.WindowerExe ?? "";
            AshitaExeBox.Text = c.AshitaExe ?? "";
            DefaultLauncherBox.SelectedIndex =
                Config.NormalizeLauncher(c.DefaultLauncher) == "Ashita" ? 1 : 0;
            TreesBox.Text  = c.TreesDir ?? "";
            TimeoutBox.Text = c.LoginTimeoutSeconds.ToString();
            HideWndBox.IsChecked = c.HidePolWindow;
            NoAutoLoginBox.IsChecked = c.DisableAutoLogin;
            PolProxyBox.IsChecked = c.UsePolProxy;
            StartupLaunchBox.IsChecked = c.LaunchSelectedOnStartup;

            DelayBox.SelectedIndex = c.FastSequential ? 1 : 0;
        }
        finally { _loadingSettings = false; }
    }

    private void OnSettingChanged(object s, RoutedEventArgs e) => ApplySettings();
    private void OnSettingTextChanged(object s,
        System.Windows.Controls.TextChangedEventArgs e) => ApplySettings();
    private void OnSettingSelectionChanged(object s,
        System.Windows.Controls.SelectionChangedEventArgs e) => ApplySettings();

    private void ApplySettings()
    {
        if (_loadingSettings) return;
        var c = Config.Load();
        c.WindowerExe  = string.IsNullOrWhiteSpace(WinExeBox.Text) ? null : WinExeBox.Text.Trim();
        c.AshitaExe    = string.IsNullOrWhiteSpace(AshitaExeBox.Text) ? null : AshitaExeBox.Text.Trim();
        c.DefaultLauncher = DefaultLauncherBox.SelectedIndex == 1 ? "Ashita" : "Windower";
        c.TreesDir     = string.IsNullOrWhiteSpace(TreesBox.Text) ? null : TreesBox.Text.Trim();
        if (int.TryParse(TimeoutBox.Text.Trim(), out var to) && to > 0)
            c.LoginTimeoutSeconds = to;
        c.HidePolWindow = HideWndBox.IsChecked == true;
        c.DisableAutoLogin = NoAutoLoginBox.IsChecked == true;
        c.UsePolProxy = PolProxyBox.IsChecked == true;
        c.LaunchSelectedOnStartup = StartupLaunchBox.IsChecked == true;

        c.ParallelLaunch = false;
        c.FastSequential = DelayBox.SelectedIndex == 1;
        c.Save();
        UpdateProxyBadge();
        UpdateStatusBar("Settings applied.");
    }

    private void OnPolProxyToggled(object s, RoutedEventArgs e)
    {
        if (_loadingSettings) return;
        ApplySettings();
        bool wantProxy = PolProxyBox.IsChecked == true;
        try
        {
            if (wantProxy && !PolProxy.Running) PolProxy.Start(Config.Load());
            else if (!wantProxy && PolProxy.Running) PolProxy.Stop();
        }
        catch (Exception ex)
        {
            ConfirmWindow.Info(this, "POL Proxy could not start (run Forest as "
                + "administrator so it can edit the hosts file):\n\n" + ex.Message,
                header: "POL PROXY");
            _loadingSettings = true;
            PolProxyBox.IsChecked = PolProxy.Running;
            _loadingSettings = false;
        }
        UpdateProxyBadge();
    }
    private void BrowseExe(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Windower (*.exe)|*.exe|All|*.*" };
        if (Directory.Exists(Path.GetDirectoryName(WinExeBox.Text)))
            d.InitialDirectory = Path.GetDirectoryName(WinExeBox.Text);
        if (d.ShowDialog() == true) WinExeBox.Text = d.FileName;
    }
    private void BrowseAshita(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "ashita-cli (*.exe)|*.exe|All|*.*" };
        if (Directory.Exists(Path.GetDirectoryName(AshitaExeBox.Text)))
            d.InitialDirectory = Path.GetDirectoryName(AshitaExeBox.Text);
        if (d.ShowDialog() == true) AshitaExeBox.Text = d.FileName;
    }
    private void BrowseDir(object s, RoutedEventArgs e)
    {
        var d = new OpenFolderDialog();
        if (Directory.Exists(TreesBox.Text)) d.InitialDirectory = TreesBox.Text;
        if (d.ShowDialog() == true) TreesBox.Text = d.FolderName;
    }

    private void OnOpenGitHub(object s, RoutedEventArgs e) =>
        OpenUrl("https://github.com/suspiciousman3187");

    private void OnOpenKofi(object s, RoutedEventArgs e) =>
        OpenUrl("https://ko-fi.com/lesserevil");

    private void OnNav(object s, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        OpenUrl(e.Uri.AbsoluteUri);
        e.Handled = true;
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ConfirmWindow.Info(this, "Could not open the link: " + ex.Message,
                header: "LINK");
        }
    }

    private LaunchService? MakeService()
    {
        try { return new LaunchService(Config.Load(), CredentialStore.Load()); }
        catch (Exception ex)
        {
            ConfirmWindow.Info(this, ex.Message, header: "CONFIGURATION");
            return null;
        }
    }

    private void OnLaunchSelected(object s, RoutedEventArgs e)
    {
        var p = _rows.Where(r => r.Selected).Select(r => r.Profile).ToList();
        if (p.Count == 0)
        { ConfirmWindow.Info(this, "Tick the checkbox on one or more accounts first."); return; }
        LaunchMany(p);
    }

    private void MaybeStartupLaunch()
    {
        if (!Config.Load().LaunchSelectedOnStartup) return;
        var p = _rows.Where(r => r.Selected).Select(r => r.Profile).ToList();
        if (p.Count == 0) return;
        Program.T($"startup auto-launch: {p.Count} account(s)");
        Dispatcher.BeginInvoke(new Action(() => LaunchMany(p)),
            System.Windows.Threading.DispatcherPriority.Background);
    }

    private void LaunchMany(List<string> profiles)
    {

        if (_launching)
        {
            ConfirmWindow.Info(this, "A launch is already in progress. Wait "
                + "for it to finish before launching more accounts.");
            return;
        }

        var launch  = profiles.Where(p => Row(p) is { } r && IsLaunchable(r))
                              .ToList();
        var skipped = profiles.Except(launch, StringComparer.OrdinalIgnoreCase)
                              .ToList();
        if (launch.Count == 0)
        {
            ConfirmWindow.Info(this, "None of the selected accounts are idle "
                + "and ready to launch — they may already be running or still "
                + "logging in.");
            return;
        }

        var svc = MakeService();
        if (svc is null) return;
        if (!IsElevated() && !ConfirmWindow.Ask(this,
                "Forest is not running as administrator, so injection will "
                + "fail. Launch anyway?", confirmText: "Launch anyway",
                header: "NOT ELEVATED"))
            return;

        if (skipped.Count > 0)
            Log($"launch: skipped {skipped.Count} not-launchable "
                + $"({string.Join(", ", skipped)})");

        var confirmed = new List<string>();
        foreach (var p in launch)
        {
            int fails = _wrongPwFailCount.TryGetValue(p, out var n) ? n : 0;
            if (fails == 0) { confirmed.Add(p); continue; }
            int remaining = Math.Max(0, 4 - fails);

            string status = remaining > 0
                ? $"Square Enix will lock the account after {remaining} more "
                  + $"consecutive failure" + (remaining == 1 ? "" : "s")
                  + " (~15–30 minute cooldown).\n\n"
                : "Square Enix has likely locked the account already "
                  + "(~15–30 min cooldown).\n\n";

            bool go = ConfirmWindow.Ask(this,
                $"Account “{p}” has had {fails} wrong-SE-password "
                + $"failure" + (fails == 1 ? "" : "s") + " this session "
                + "without a successful login or credential update.\n\n"
                + status
                + "Are you sure the SE password in Forest is correct?",
                confirmText: "Yes, launch", danger: true,
                header: "CONFIRM SE PASSWORD");

            if (go) confirmed.Add(p);
            else Log($"launch: user cancelled '{p}' after wrong-pw guard "
                     + $"(fails={fails}, remaining={remaining})");
        }
        if (confirmed.Count == 0) {
            Log("launch: all selected profiles cancelled by wrong-pw guard");
            return;
        }
        launch = confirmed;

        profiles = launch;
        _launching = true;
        UpdateActionButtons();

        foreach (var p in profiles)
            if (Row(p) is { } r) { r.Status = "QUEUED"; r.Pid = "-"; }

        foreach (var p in profiles) {
            _wrongPwShown.Remove(p);
            _stuckShown.Remove(p);
            _stagnationShown.Remove(p);
            _stagnTrack.Remove(p);
        }

        void LaunchOne(string p)
        {
            string curSt = (string)Dispatcher.Invoke(
                () => Row(p)?.Status ?? "");
            if (!string.Equals(curSt, "QUEUED",
                               StringComparison.OrdinalIgnoreCase))
            {
                Log($"'{p}' skipped (status '{curSt}', no longer QUEUED)");
                return;
            }
            try
            {
                string first = "LAUNCH WINDOWER";
                try
                {
                    var lc = Config.Load();
                    var lk = Config.NormalizeLauncher(
                        CredentialStore.Load().GetAccount(p).Launcher
                        ?? lc.DefaultLauncher);
                    first = lk == "Ashita" ? "LAUNCH ASHITA" : "LAUNCH WINDOWER";
                }
                catch {  }
                Dispatcher.Invoke(() => { if (Row(p) is { } r) r.Status = first; });
                var h = svc.Launch(p, Log);
                _handles[p] = h;
                var c = Config.Load();
                bool noAuto = c.DisableAutoLogin && !c.HidePolWindow;
                if (noAuto) _noAuto.Add(p); else _noAuto.Remove(p);
                Dispatcher.Invoke(() =>
                {
                    if (Row(p) is { } r)
                    {
                        r.Pid = h.Pid.ToString();

                        r.Status = noAuto ? "RUNNING" : "LAUNCH POL";
                    }
                });
            }
            catch (Exception ex)
            {

                bool cancelled = _cancelled.Remove(p);
                if (!cancelled)
                    Dispatcher.Invoke(() => { if (Row(p) is { } r) r.Status = "FAILED"; });
                Log("'" + p + "' launch " + (cancelled ? "cancelled" : "failed")
                    + ": " + ex.Message);
            }
        }

        Task.Run(() =>
        {
            try
            {
                var cfg = Config.Load();
                if (cfg.ParallelLaunch)
                {
                    bool IsAshita(string p)
                    {
                        try
                        {
                            return Config.NormalizeLauncher(
                                CredentialStore.Load().GetAccount(p).Launcher
                                ?? cfg.DefaultLauncher) == "Ashita";
                        }
                        catch { return false; }
                    }
                    var ashita   = profiles.Where(IsAshita).ToList();
                    var windower = profiles.Where(p => !IsAshita(p)).ToList();

                    foreach (var p in ashita) LaunchOne(p);

                    if (windower.Count > 0)
                        Task.WaitAll(windower
                            .Select(p => Task.Run(() => LaunchOne(p))).ToArray());
                }
                else
                {
                    string St(string prof) => (string)Dispatcher.Invoke(
                        () => Row(prof)?.Status ?? "");
                    bool fast = cfg.FastSequential;
                    for (int i = 0; i < profiles.Count; i++)
                    {
                        LaunchOne(profiles[i]);
                        if (i >= profiles.Count - 1) break;
                        var deadline = DateTime.UtcNow.AddSeconds(
                            cfg.LoginTimeoutSeconds + 30);
                        while (DateTime.UtcNow < deadline)
                        {
                            var st = St(profiles[i]);
                            if (st is "RUNNING" or "FAILED" or "TERMINATED"
                                   or "TIMEOUT" or "ERR" or "INACTIVE") break;
                            if (fast && string.Equals(st, "LOGGING IN",
                                    StringComparison.OrdinalIgnoreCase)) break;
                            Thread.Sleep(500);
                        }
                    }
                }
            }
            finally
            {

                Dispatcher.Invoke(() => { _launching = false; UpdateActionButtons(); });
            }
        });
    }

    private static string Friendly(string raw, string msg)
    {
        var m = (msg ?? "").Trim().ToUpperInvariant();
        var r = raw.Trim().ToUpperInvariant();
        if (r == "FAILED" && m.Contains("WRONG_SE_PASSWORD"))
            return "WRONG SE PASSWORD";
        if (r == "FAILED" && m.Contains("POST_CONNECT_STUCK"))
            return "LOGIN STUCK";
        return r switch
        {
            "INJECTED"                => "LAUNCH POL",
            "MEMBERLIST" or "LOGIN"   => "SELECT ACCOUNT",
            "PASSWORD"  or "SOFTKBD"  => "INPUT PASSWORD",
            "CONNECT"                 => "LOGGING IN",
            "DONE"                    => "RUNNING",
            "FAILED"                  => "FAILED",
            _                         => "",
        };
    }

    private static bool PolAlive(int pid)
    {
        try
        {
            var pr = Process.GetProcessById(pid);
            return !pr.HasExited &&
                   pr.ProcessName.Equals("pol", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private void OnFastServed(int pid) =>
        Dispatcher.Invoke(() => _proxyServed[pid] = DateTime.UtcNow);

    private const double TerminatedBadgeSeconds = 8;

    private readonly HashSet<string> _wrongPwShown =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _wrongPwFailCount =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _stuckShown =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, (string status, DateTime since)>
        _stagnTrack = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _stagnationShown =
        new(StringComparer.OrdinalIgnoreCase);
    private const double StagnationSeconds = 90;

    private void ShowWrongPwDialogOnce(string profile)
    {
        if (!_wrongPwShown.Add(profile)) return;

        int fails = _wrongPwFailCount.TryGetValue(profile, out var n) ? n + 1 : 1;
        _wrongPwFailCount[profile] = fails;
        int remaining = Math.Max(0, 4 - fails);

        Dispatcher.BeginInvoke(new Action(() =>
        {
            string status = remaining > 0
                ? $"This is failure #{fails}/4 for this account. "
                    + $"Square Enix will lock the account for ~15–30 minutes "
                    + $"after {remaining} more consecutive failure"
                    + (remaining == 1 ? "" : "s") + "."
                : $"This is failure #{fails}/4 — Square Enix has likely "
                    + "locked the account now (~15–30 min cooldown).";

            bool openEdit = ConfirmWindow.Ask(this,
                $"PlayOnline rejected the Square Enix credentials for "
                + $"“{profile}” (POL-5311).\n\n"
                + status + "\n\n"
                + "Open Edit Account now to re-enter the SE password "
                + "(or one-time password)?",
                confirmText: "Edit Account", header: "WRONG SE PASSWORD");

            if (openEdit)
            {
                var row = Row(profile);
                if (row != null) EditAccount(row);
            }
        }));
    }

    private void ShowLoginStuckDialogOnce(string profile)
    {
        if (!_stuckShown.Add(profile)) return;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            ConfirmWindow.Info(this,
                $"PlayOnline didn't transition to the game after auth for "
                + $"“{profile}”.\n\n"
                + "POL appears to have hit an error other than wrong-SE-"
                + "password (e.g. network issue, server maintenance, wrong "
                + "one-time password, account suspension). Forest doesn't "
                + "decode those specific codes yet — Forest force-closed "
                + "the stuck pol.exe to keep things tidy.\n\n"
                + "Try launching again. If it keeps happening, log in once "
                + "manually (uncheck “Hide PlayOnline Window During Login” "
                + "in Settings) to see the exact error code POL is showing.",
                header: "LOGIN STUCK");
        }));
    }

    private void ShowStagnationWarningOnce(string profile, string stuckAt)
    {
        if (!_stagnationShown.Add(profile)) return;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            bool kill = ConfirmWindow.Ask(this,
                $"Account “{profile}” has been stuck at status "
                + $"“{stuckAt}” for over {(int)StagnationSeconds} seconds "
                + "without any change.\n\n"
                + "This usually means the helper inside its pol.exe stopped "
                + "reporting progress (rare — most likely a helper-thread "
                + "issue or a status-file write failure).\n\n"
                + "Terminate this account's pol.exe now?",
                confirmText: "Terminate", danger: true,
                header: "LOGIN STAGNATION");
            if (kill && Row(profile) is { } r) KillRow(r, quiet: false);
        }));
    }

    private void PollStatuses(object? s, EventArgs e)
    {
        UpdateProxyBadge();

        foreach (var r in _rows)
            if (r.Status == "TERMINATED" && r.TerminatedAt is { } t &&
                (DateTime.UtcNow - t).TotalSeconds > TerminatedBadgeSeconds)
                r.Status = "INACTIVE";

        const double WrongPwBadgeSeconds = 60;
        foreach (var r in _rows)
            if (r.Status == "WRONG SE PASSWORD" && r.TerminatedAt is { } tw &&
                (DateTime.UtcNow - tw).TotalSeconds > WrongPwBadgeSeconds)
                r.Status = "INACTIVE";

        const double LoginStuckBadgeSeconds = 60;
        foreach (var r in _rows)
            if (r.Status == "LOGIN STUCK" && r.TerminatedAt is { } tls &&
                (DateTime.UtcNow - tls).TotalSeconds > LoginStuckBadgeSeconds)
                r.Status = "INACTIVE";

        if (_handles.Count == 0) return;
        Config cfg; LaunchService svc;
        try { cfg = Config.Load(); svc = new LaunchService(cfg, CredentialStore.Load()); }
        catch { return; }

        foreach (var (profile, h) in _handles.ToList())
        {
            var r = Row(profile);
            var (state, msg, _) = svc.ReadStatus(h);

            bool wrongPw = state.Equals("FAILED", StringComparison.OrdinalIgnoreCase)
                && msg.IndexOf("WRONG_SE_PASSWORD",
                               StringComparison.OrdinalIgnoreCase) >= 0;
            bool stuckPost = state.Equals("FAILED", StringComparison.OrdinalIgnoreCase)
                && msg.IndexOf("POST_CONNECT_STUCK",
                               StringComparison.OrdinalIgnoreCase) >= 0;

            if (!PolAlive(h.Pid))
            {
                if (r != null) {
                    if (wrongPw) {
                        r.Status = "WRONG SE PASSWORD";
                        ShowWrongPwDialogOnce(profile);
                    } else if (stuckPost) {
                        r.Status = "LOGIN STUCK";
                        ShowLoginStuckDialogOnce(profile);
                    } else {
                        r.Status = "TERMINATED";
                    }
                    r.Pid = "-";
                }
                _handles.Remove(profile);
                _noAuto.Remove(profile);
                _proxyServed.Remove(h.Pid);
                _doneSince.Remove(h.Pid);
                continue;
            }
            if (r == null) continue;

            if (wrongPw)
            {

                r.Status = "WRONG SE PASSWORD";
                ShowWrongPwDialogOnce(profile);
                continue;
            }
            if (stuckPost)
            {
                r.Status = "LOGIN STUCK";
                ShowLoginStuckDialogOnce(profile);
                continue;
            }

            if (_noAuto.Contains(profile)) { r.Status = "RUNNING"; continue; }

            var f = Friendly(state, msg);

            if (cfg.UsePolProxy)
            {

                if (_proxyServed.TryGetValue(h.Pid, out var t))
                {
                    r.Status = (DateTime.UtcNow - t).TotalSeconds < 3
                               ? "LAUNCHING GAME" : "RUNNING";
                    continue;
                }

                if (f == "RUNNING")
                {
                    if (!_doneSince.ContainsKey(h.Pid))
                        _doneSince[h.Pid] = DateTime.UtcNow;
                    r.Status = (DateTime.UtcNow - _doneSince[h.Pid]).TotalSeconds > 90
                               ? "RUNNING" : "LOGGING IN";
                    continue;
                }
            }

            if (f.Length > 0) r.Status = f;
        }

        foreach (var r in _rows)
            if (r.Status == "RUNNING")
                _wrongPwFailCount.Remove(r.Profile);

        var staticBuckets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RUNNING", "INACTIVE", "TERMINATED", "FAILED",
            "WRONG SE PASSWORD", "LOGIN STUCK",
            "QUEUED",
            "", "-", "—", "PENDING",
        };
        foreach (var r in _rows)
        {
            if (string.IsNullOrEmpty(r.Profile)) continue;
            if (staticBuckets.Contains(r.Status))
            {
                _stagnTrack.Remove(r.Profile);
                _stagnationShown.Remove(r.Profile);
                continue;
            }
            if (!_stagnTrack.TryGetValue(r.Profile, out var t) ||
                t.status != r.Status)
            {
                _stagnTrack[r.Profile] = (r.Status, DateTime.UtcNow);
                continue;
            }
            if ((DateTime.UtcNow - t.since).TotalSeconds > StagnationSeconds)
            {
                ShowStagnationWarningOnce(r.Profile, r.Status);
            }
        }
    }
}
