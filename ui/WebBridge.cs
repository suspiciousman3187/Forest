using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;
using Forest;

namespace Forest.UI;

public sealed class WebBridge
{
    private readonly CoreWebView2 _core;
    private readonly Window _window;
    private readonly System.Windows.Threading.Dispatcher _ui;
    private readonly System.Windows.Threading.DispatcherTimer _timer =
        new() { Interval = TimeSpan.FromSeconds(1) };

    private sealed class Stat { public int Pid; public string Status = "INACTIVE"; public DateTime? TermAt; }

    private readonly Dictionary<string, Stat> _state = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, LaunchService.Handle> _handles = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _noAuto = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _cancelled = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, DateTime> _proxyServed = new();
    private readonly Dictionary<int, DateTime> _doneSince = new();
    private readonly Dictionary<string, int> _wrongPwFailCount = new(StringComparer.OrdinalIgnoreCase);
    private bool _launching;

    private static readonly HashSet<string> InFlightStates = new(StringComparer.OrdinalIgnoreCase)
    {
        "QUEUED", "LAUNCH WINDOWER", "LAUNCH ASHITA", "LAUNCH POL",
        "SELECT ACCOUNT", "INPUT PASSWORD", "LOGGING IN", "LAUNCHING GAME",
    };
    private static readonly HashSet<string> Relaunchable = new(StringComparer.OrdinalIgnoreCase)
    {
        "INACTIVE", "FAILED", "TERMINATED", "TIMEOUT", "ERR",
        "WRONG SE PASSWORD", "LOGIN STUCK",
    };

    private const double TerminatedBadgeSeconds = 8;
    private const double WrongPwBadgeSeconds = 60;
    private const double LoginStuckBadgeSeconds = 60;

    public WebBridge(CoreWebView2 core, Window window)
    {
        _core = core;
        _window = window;
        _ui = window.Dispatcher;

        _core.WebMessageReceived += OnMessage;
        PolProxy.FastServed += OnFastServed;
        _window.Closed += (_, _) => { try { PolProxy.FastServed -= OnFastServed; } catch { } _timer.Stop(); };

        SeedState();
        ReattachRunning();

        _timer.Tick += (_, _) => Poll();
        _timer.Start();
    }

    private void OnFastServed(int pid) =>
        _ui.BeginInvoke(new Action(() => { _proxyServed[pid] = DateTime.UtcNow; DiagLog.Debug($"proxy fast-served pid {pid}"); }));

    // ── request dispatch ──────────────────────────────────────────────────────
    private void OnMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string raw;
        try { raw = e.TryGetWebMessageAsString(); }
        catch { return; }
        if (string.IsNullOrEmpty(raw)) return;

        int id = 0;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            if (root.GetProperty("kind").GetString() != "req") return;
            id = root.GetProperty("id").GetInt32();
            var method = root.GetProperty("method").GetString() ?? "";
            var p = root.TryGetProperty("params", out var pv) ? pv : default;
            Dispatch(id, method, p);
        }
        catch (Exception ex)
        {
            if (id != 0) Reply(id, false, null, ex.Message);
            DiagLog.Log("WebBridge dispatch error: " + ex.Message);
        }
    }

    private void Dispatch(int id, string method, JsonElement p)
    {
        switch (method)
        {
            case "config.get": Reply(id, true, ConfigDto(Config.Load()), null); break;
            case "config.set": ApplyConfigPatch(p); Reply(id, true, null, null); break;

            case "accounts.list": Reply(id, true, ListAccounts(), null); break;
            case "accounts.save": SaveAccount(p); Reply(id, true, null, null); break;
            case "accounts.remove":
                CredentialStore.Load().Remove(p.GetProperty("profile").GetString() ?? "");
                Reply(id, true, null, null); break;
            case "accounts.reorder":
            {
                var c = Config.Load();
                c.AccountOrder = p.GetProperty("order").EnumerateArray().Select(x => x.GetString()!).ToList();
                c.Save();
                Reply(id, true, null, null); break;
            }

            case "status.all": Reply(id, true, Snapshot(), null); break;
            case "launch": Launch(p.GetProperty("profiles").EnumerateArray().Select(x => x.GetString()!).ToArray()); Reply(id, true, null, null); break;
            case "terminate": Terminate(p.GetProperty("profiles").EnumerateArray().Select(x => x.GetString()!).ToArray()); Reply(id, true, null, null); break;

            case "browse": Reply(id, true, Browse(p), null); break;
            case "diagnostics.export": Reply(id, true, ExportDiag(), null); break;
            case "logs.open": OpenLogs(); Reply(id, true, null, null); break;
            case "polproxy.status": Reply(id, true, PolProxy.Running, null); break;
            case "cleanup.scan": Reply(id, true, ScanStale(), null); break;
            case "cleanup.kill": KillStale(p.GetProperty("pids").EnumerateArray().Select(x => x.GetInt32()).ToArray()); Reply(id, true, null, null); break;
            case "open.external": OpenExternal(p.GetProperty("url").GetString() ?? ""); Reply(id, true, null, null); break;

            case "window.minimize": _window.WindowState = WindowState.Minimized; Reply(id, true, null, null); break;
            case "window.maximize":
                _window.WindowState = _window.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
                Reply(id, true, null, null); break;
            case "window.close": _window.Close(); Reply(id, true, null, null); break;
            case "window.alwaysOnTop": _window.Topmost = p.GetProperty("on").GetBoolean(); Reply(id, true, null, null); break;
            case "window.drag": Reply(id, true, null, null); BeginDrag(); break;

            default: Reply(id, false, null, "unknown method: " + method); break;
        }
    }

    private void Reply(int id, bool ok, object? result, string? error) =>
        _core.PostWebMessageAsJson(JsonSerializer.Serialize(new { kind = "res", id, ok, result, error }));

    private void Emit(string evt, object data) =>
        _core.PostWebMessageAsJson(JsonSerializer.Serialize(new { kind = "evt", @event = evt, data }));

    // ── config ────────────────────────────────────────────────────────────────
    private static object ConfigDto(Config c) => new
    {
        windowerExe = c.WindowerExe ?? "",
        ashitaExe = c.AshitaExe ?? "",
        treesDir = c.TreesDir ?? "",
        defaultLauncher = Config.NormalizeLauncher(c.DefaultLauncher),
        windowerArgs = c.WindowerArgs,
        ashitaArgs = c.AshitaArgs,
        staggerSeconds = c.StaggerSeconds,
        fastSequential = c.FastSequential,
        loginTimeoutSeconds = c.LoginTimeoutSeconds,
        hidePolWindow = c.HidePolWindow,
        disableAutoLogin = c.DisableAutoLogin,
        usePolProxy = c.UsePolProxy,
        polProxyUpstream = c.PolProxyUpstream ?? "",
        launchSelectedOnStartup = c.LaunchSelectedOnStartup,
        autoLoginCharacter = c.AutoLoginCharacter,
        autoLoginSettleSeconds = c.AutoLoginSettleSeconds,
        autoLoginSendInputFallback = c.AutoLoginSendInputFallback,
        debugLogging = c.DebugLogging,
        selectedAccounts = c.SelectedAccounts,
        accountOrder = c.AccountOrder,
    };

    private void ApplyConfigPatch(JsonElement p)
    {
        var c = Config.Load();
        static string? E(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

        foreach (var prop in p.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "windowerExe": c.WindowerExe = E(prop.Value.GetString()); break;
                case "ashitaExe": c.AshitaExe = E(prop.Value.GetString()); break;
                case "treesDir": c.TreesDir = E(prop.Value.GetString()); break;
                case "defaultLauncher": c.DefaultLauncher = Config.NormalizeLauncher(prop.Value.GetString()); break;
                case "windowerArgs": c.WindowerArgs = prop.Value.GetString() ?? c.WindowerArgs; break;
                case "ashitaArgs": c.AshitaArgs = prop.Value.GetString() ?? c.AshitaArgs; break;
                case "staggerSeconds": c.StaggerSeconds = prop.Value.GetInt32(); break;
                case "fastSequential": c.FastSequential = prop.Value.GetBoolean(); break;
                case "loginTimeoutSeconds": c.LoginTimeoutSeconds = prop.Value.GetInt32(); break;
                case "hidePolWindow": c.HidePolWindow = prop.Value.GetBoolean(); break;
                case "disableAutoLogin": c.DisableAutoLogin = prop.Value.GetBoolean(); break;
                case "usePolProxy": c.UsePolProxy = prop.Value.GetBoolean(); break;
                case "polProxyUpstream": c.PolProxyUpstream = E(prop.Value.GetString()); break;
                case "launchSelectedOnStartup": c.LaunchSelectedOnStartup = prop.Value.GetBoolean(); break;
                case "autoLoginCharacter": c.AutoLoginCharacter = prop.Value.GetBoolean(); break;
                case "autoLoginSettleSeconds": c.AutoLoginSettleSeconds = prop.Value.GetInt32(); break;
                case "autoLoginSendInputFallback": c.AutoLoginSendInputFallback = prop.Value.GetBoolean(); break;
                case "debugLogging": c.DebugLogging = prop.Value.GetBoolean(); break;
                case "selectedAccounts": c.SelectedAccounts = prop.Value.EnumerateArray().Select(x => x.GetString()!).ToList(); break;
                case "accountOrder": c.AccountOrder = prop.Value.EnumerateArray().Select(x => x.GetString()!).ToList(); break;
            }
        }
        c.ParallelLaunch = false;
        c.Save();
        DiagLog.Verbose = c.DebugLogging;
    }

    // ── accounts ────────────────────────────────────────────────────────────────
    private static object[] ListAccounts()
    {
        var store = CredentialStore.Load();
        var cfg = Config.Load();
        var orderIx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < cfg.AccountOrder.Count; i++) orderIx.TryAdd(cfg.AccountOrder[i], i);

        return store.Accounts()
            .Select((a, idx) => (a, key: orderIx.TryGetValue(a.Name, out var ix) ? ix : int.MaxValue, idx))
            .OrderBy(t => t.key).ThenBy(t => t.idx)
            .Select(t => (object)new
            {
                profile = t.a.Name,
                windower = t.a.WindowerProfile ?? "",
                polSlot = t.a.PolSlot,
                ingameSlot = t.a.IngameSlot,
                launcher = string.Equals(t.a.Launcher, "Ashita", StringComparison.OrdinalIgnoreCase) ? "Ashita"
                         : string.Equals(t.a.Launcher, "Windower", StringComparison.OrdinalIgnoreCase) ? "Windower"
                         : "Default",
                launchArgs = t.a.LaunchArgs ?? "",
                hasTotp = store.HasTotp(t.a.Name),
            })
            .ToArray();
    }

    private static void SaveAccount(JsonElement p)
    {
        string Get(string k) => p.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        int GetInt(string k) => p.TryGetProperty(k, out var v) && v.TryGetInt32(out var n) ? n : 0;

        var profile = Get("profile").Trim();
        var original = p.TryGetProperty("originalProfile", out var ov) && ov.ValueKind == JsonValueKind.String ? ov.GetString() : null;
        var windower = string.IsNullOrWhiteSpace(Get("windower")) ? null : Get("windower").Trim();
        var args = string.IsNullOrWhiteSpace(Get("launchArgs")) ? null : Get("launchArgs").Trim();
        var pw = Get("password");
        var totp = string.IsNullOrWhiteSpace(Get("totpSecret")) ? null : Get("totpSecret").Trim();
        int slot = GetInt("polSlot");
        int ingame = GetInt("ingameSlot");
        var launcherRaw = Get("launcher");
        string? launcher = string.Equals(launcherRaw, "Ashita", StringComparison.OrdinalIgnoreCase) ? "Ashita"
                         : string.Equals(launcherRaw, "Windower", StringComparison.OrdinalIgnoreCase) ? "Windower"
                         : null;

        if (string.IsNullOrWhiteSpace(profile)) throw new InvalidOperationException("Account name is required.");

        var store = CredentialStore.Load();
        bool editing = !string.IsNullOrEmpty(original);
        bool renaming = editing && !profile.Equals(original, StringComparison.OrdinalIgnoreCase);

        if (!editing && store.Accounts().Count >= 20)
            throw new InvalidOperationException("Account limit reached (20). Remove an account before adding another.");

        if (renaming && !store.Rename(original!, profile))
            throw new InvalidOperationException($"Could not rename to \"{profile}\" (name already in use).");

        if (!editing)
        {
            if (string.IsNullOrEmpty(pw)) throw new InvalidOperationException("SE password is required for a new account.");
            store.Set(profile, pw, totp, windower, slot, args, launcher, ingame);
        }
        else if (!string.IsNullOrEmpty(pw))
            store.Set(profile, pw, totp, windower, slot, args, launcher, ingame);
        else
            store.SetMeta(profile, windower, slot, args, launcher, ingame);

        if (editing && totp != null) store.SetTotp(profile, totp);
    }

    // ── status ────────────────────────────────────────────────────────────────
    private void SeedState()
    {
        foreach (var a in CredentialStore.Load().Accounts())
            if (!_state.ContainsKey(a.Name)) _state[a.Name] = new Stat();
    }

    private Stat StatOf(string profile)
    {
        if (!_state.TryGetValue(profile, out var s)) { s = new Stat(); _state[profile] = s; }
        return s;
    }

    private object[] Snapshot() =>
        _state.Select(kv => (object)new { profile = kv.Key, pid = kv.Value.Pid, status = kv.Value.Status }).ToArray();

    private void EmitStatus() => Emit("status", Snapshot());

    private void Set(string profile, string status, int pid)
    {
        var s = StatOf(profile);
        s.Status = status;
        s.Pid = pid;
        s.TermAt = status is "TERMINATED" or "WRONG SE PASSWORD" or "LOGIN STUCK" ? DateTime.UtcNow : null;
    }

    private void Poll()
    {
        foreach (var s in _state.Values)
        {
            if (s.TermAt is not { } t) continue;
            double age = (DateTime.UtcNow - t).TotalSeconds;
            if ((s.Status == "TERMINATED" && age > TerminatedBadgeSeconds) ||
                (s.Status == "WRONG SE PASSWORD" && age > WrongPwBadgeSeconds) ||
                (s.Status == "LOGIN STUCK" && age > LoginStuckBadgeSeconds))
            { s.Status = "INACTIVE"; s.Pid = 0; s.TermAt = null; }
        }

        if (_handles.IsEmpty) { EmitStatus(); return; }
        Config cfg; LaunchService svc;
        try { cfg = Config.Load(); svc = new LaunchService(cfg, CredentialStore.Load()); }
        catch { EmitStatus(); return; }

        foreach (var (profile, h) in _handles.ToArray())
        {
            var (state, msg, _) = svc.ReadStatus(h);
            bool wrongPw = state.Equals("FAILED", StringComparison.OrdinalIgnoreCase) && msg.Contains("WRONG_SE_PASSWORD", StringComparison.OrdinalIgnoreCase);
            bool stuckPost = state.Equals("FAILED", StringComparison.OrdinalIgnoreCase) && msg.Contains("POST_CONNECT_STUCK", StringComparison.OrdinalIgnoreCase);

            if (!PolAlive(h.Pid))
            {
                Set(profile, wrongPw ? "WRONG SE PASSWORD" : stuckPost ? "LOGIN STUCK" : "TERMINATED", 0);
                _handles.TryRemove(profile, out _);
                _noAuto.TryRemove(profile, out _);
                _proxyServed.Remove(h.Pid);
                _doneSince.Remove(h.Pid);
                continue;
            }
            if (wrongPw) { Set(profile, "WRONG SE PASSWORD", h.Pid); continue; }
            if (stuckPost) { Set(profile, "LOGIN STUCK", h.Pid); continue; }
            if (_noAuto.ContainsKey(profile)) { Set(profile, "RUNNING", h.Pid); continue; }

            var f = Friendly(state, msg);
            if (f.Length > 0) Set(profile, f, h.Pid);
        }

        foreach (var kv in _state)
            if (kv.Value.Status == "RUNNING") _wrongPwFailCount.Remove(kv.Key);

        EmitStatus();
    }

    private static string Friendly(string raw, string msg)
    {
        var m = (msg ?? "").Trim().ToUpperInvariant();
        var r = raw.Trim().ToUpperInvariant();
        if (r == "FAILED" && m.Contains("WRONG_SE_PASSWORD")) return "WRONG SE PASSWORD";
        if (r == "FAILED" && m.Contains("POST_CONNECT_STUCK")) return "LOGIN STUCK";
        return r switch
        {
            "INJECTED" => "LAUNCH POL",
            "MEMBERLIST" or "LOGIN" => "SELECT ACCOUNT",
            "PASSWORD" or "SOFTKBD" => "INPUT PASSWORD",
            "CONNECT" => "LOGGING IN",
            "DONE" => "RUNNING",
            "FAILED" => "FAILED",
            _ => "",
        };
    }

    private static bool PolAlive(int pid)
    {
        try { var p = Process.GetProcessById(pid); return !p.HasExited && p.ProcessName.Equals("pol", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    // ── launch / terminate ──────────────────────────────────────────────────────
    private bool IsInFlight(string p) => _handles.ContainsKey(p) || InFlightStates.Contains(StatOf(p).Status);
    private bool IsLaunchable(string p) => !IsInFlight(p) && Relaunchable.Contains(StatOf(p).Status);

    private void Launch(string[] profiles)
    {
        if (_launching) return;
        var launch = profiles.Where(IsLaunchable).ToList();
        if (launch.Count == 0) return;

        LaunchService svc;
        try { svc = new LaunchService(Config.Load(), CredentialStore.Load()); }
        catch (Exception ex) { Emit("notice", new { level = "error", title = "CONFIGURATION", message = ex.Message }); return; }

        _launching = true;
        foreach (var p in launch) { _cancelled.TryRemove(p, out _); Set(p, "QUEUED", 0); }
        EmitStatus();

        void LaunchOne(string p)
        {
            if (!string.Equals(_ui.Invoke(() => StatOf(p).Status), "QUEUED", StringComparison.OrdinalIgnoreCase)) return;
            try
            {
                string first = "LAUNCH WINDOWER";
                try
                {
                    var lc = Config.Load();
                    var lk = Config.NormalizeLauncher(CredentialStore.Load().GetAccount(p).Launcher ?? lc.DefaultLauncher);
                    first = lk == "Ashita" ? "LAUNCH ASHITA" : "LAUNCH WINDOWER";
                }
                catch { }
                _ui.Invoke(() => { Set(p, first, 0); EmitStatus(); });

                var h = svc.Launch(p, DiagLog.Log);
                _handles[p] = h;
                var c = Config.Load();
                bool noAuto = c.DisableAutoLogin && !c.HidePolWindow;
                if (noAuto) _noAuto[p] = 1; else _noAuto.TryRemove(p, out _);
                _ui.Invoke(() => { _proxyServed.Remove(h.Pid); _doneSince.Remove(h.Pid); Set(p, noAuto ? "RUNNING" : "LAUNCH POL", h.Pid); EmitStatus(); });
            }
            catch (Exception ex)
            {
                bool cancelled = _cancelled.TryRemove(p, out _);
                if (!cancelled) _ui.Invoke(() => { Set(p, "FAILED", 0); EmitStatus(); });
                DiagLog.Log($"'{p}' launch {(cancelled ? "cancelled" : "failed")}: {ex.Message}");
            }
        }

        Task.Run(() =>
        {
            try
            {
                var cfg = Config.Load();
                bool fast = cfg.FastSequential;
                bool noAuto = cfg.DisableAutoLogin && !cfg.HidePolWindow;
                for (int i = 0; i < launch.Count; i++)
                {
                    LaunchOne(launch[i]);
                    if (i >= launch.Count - 1) break;
                    if (noAuto)
                    {
                        // No login to gate on; just stagger so we don't open every POL at once.
                        Thread.Sleep(TimeSpan.FromSeconds(Math.Max(1, cfg.StaggerSeconds)));
                        continue;
                    }
                    var deadline = DateTime.UtcNow.AddSeconds(cfg.LoginTimeoutSeconds + 30);
                    while (DateTime.UtcNow < deadline)
                    {
                        var st = _ui.Invoke(() => StatOf(launch[i]).Status);
                        if (st is "RUNNING" or "FAILED" or "TERMINATED" or "TIMEOUT" or "ERR" or "INACTIVE") break;
                        if (fast && string.Equals(st, "LOGGING IN", StringComparison.OrdinalIgnoreCase)) break;
                        Thread.Sleep(500);
                    }
                }
            }
            finally { _ui.Invoke(() => { _launching = false; EmitStatus(); }); }
        });
    }

    private void Terminate(string[] profiles)
    {
        bool any = false;
        foreach (var p in profiles) any |= KillRow(p);
        if (any) EmitStatus();
    }

    private bool KillRow(string profile)
    {
        int polPid = _handles.TryGetValue(profile, out var h) && h.Pid > 0 ? h.Pid : StatOf(profile).Pid;
        bool haveInFlight = LaunchService.InFlightWaitinjects.TryGetValue(profile, out int wiPid);

        if (polPid <= 0 && !haveInFlight)
        {
            if (string.Equals(StatOf(profile).Status, "QUEUED", StringComparison.OrdinalIgnoreCase))
            { _cancelled[profile] = 1; Set(profile, "INACTIVE", 0); return true; }
            return false;
        }

        bool killed = false;

        if (haveInFlight && wiPid > 0)
        {
            _cancelled[profile] = 1;
            try
            {
                var wi = Process.GetProcessById(wiPid);
                if (wi.ProcessName.Equals("waitinject", StringComparison.OrdinalIgnoreCase))
                { wi.Kill(); wi.WaitForExit(2000); killed = true; }
            }
            catch { }
            LaunchService.InFlightWaitinjects.TryRemove(profile, out _);
        }

        if (polPid > 0)
        {
            try
            {
                var proc = Process.GetProcessById(polPid);
                if (proc.ProcessName.Equals("pol", StringComparison.OrdinalIgnoreCase))
                { proc.Kill(); proc.WaitForExit(3000); killed = true; }
            }
            catch (ArgumentException) { killed = true; }
            catch (Exception ex) { DiagLog.Log($"terminate pid {polPid} failed: {ex.Message}"); if (!killed) return false; }
        }

        if (!killed) return false;
        _handles.TryRemove(profile, out _);
        _noAuto.TryRemove(profile, out _);
        if (polPid > 0) { _proxyServed.Remove(polPid); _doneSince.Remove(polPid); }
        Set(profile, "TERMINATED", 0);
        return true;
    }

    // ── reattach / stale cleanup ────────────────────────────────────────────────
    private static readonly string[] MarkerPrefixes = { "status", "slot", "cred", "totp", "nohide" };

    private static int? MarkerPid(string fileName)
    {
        int us = fileName.IndexOf('_');
        int dot = fileName.LastIndexOf('.');
        if (us <= 0 || dot <= us + 1) return null;
        if (Array.IndexOf(MarkerPrefixes, fileName.Substring(0, us)) < 0) return null;
        return int.TryParse(fileName.Substring(us + 1, dot - us - 1), out var p) ? p : null;
    }

    private static void DeleteMarkers(string dir, int pid)
    {
        foreach (var pre in MarkerPrefixes)
            foreach (var ext in new[] { "txt", "bin" })
                try { var f = Path.Combine(dir, $"{pre}_{pid}.{ext}"); if (File.Exists(f)) File.Delete(f); } catch { }
    }

    private void ReattachRunning()
    {
        var dir = Config.Load().TreesDir;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;

        var bySlot = new Dictionary<int, string>();
        foreach (var a in CredentialStore.Load().Accounts())
            if (a.PolSlot > 0) bySlot[a.PolSlot] = a.Name;

        try
        {
            foreach (var path in Directory.EnumerateFiles(dir, "status_*.txt"))
            {
                if (MarkerPid(Path.GetFileName(path)) is not { } pid) continue;
                if (!PolAlive(pid)) continue;

                int slot = 0;
                try
                {
                    var sp = Path.Combine(dir, $"slot_{pid}.txt");
                    if (File.Exists(sp) && int.TryParse(File.ReadAllText(sp).Trim(), out var sv)) slot = sv;
                }
                catch { }
                if (slot <= 0 || !bySlot.TryGetValue(slot, out var profile)) continue;
                if (_handles.ContainsKey(profile)) continue;

                _handles[profile] = new LaunchService.Handle(profile, pid, Path.Combine(dir, $"status_{pid}.txt"));
                _noAuto[profile] = 1;
                Set(profile, "RUNNING", pid);
            }
        }
        catch (Exception ex) { DiagLog.Log("ReattachRunning error: " + ex.Message); }
    }

    private object[] ScanStale()
    {
        var dir = Config.Load().TreesDir;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return Array.Empty<object>();

        var pids = new HashSet<int>();
        try { foreach (var path in Directory.EnumerateFiles(dir)) if (MarkerPid(Path.GetFileName(path)) is { } p) pids.Add(p); }
        catch { return Array.Empty<object>(); }

        var running = new HashSet<int>(_handles.Values.Select(h => h.Pid));
        var result = new List<object>();
        foreach (var pid in pids)
        {
            if (!PolAlive(pid)) { DeleteMarkers(dir, pid); continue; }
            if (running.Contains(pid)) continue;
            int slot = 0;
            try { var sp = Path.Combine(dir, $"slot_{pid}.txt"); if (File.Exists(sp) && int.TryParse(File.ReadAllText(sp).Trim(), out var sv)) slot = sv; } catch { }
            var profile = _handles.FirstOrDefault(kv => kv.Value.Pid == pid).Key ?? "";
            result.Add(new { pid, profile, slot });
        }
        return result.ToArray();
    }

    private void KillStale(int[] pids)
    {
        var dir = Config.Load().TreesDir;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
        foreach (var pid in pids)
        {
            try
            {
                var pr = Process.GetProcessById(pid);
                if (!pr.ProcessName.Equals("pol", StringComparison.OrdinalIgnoreCase)) continue;
                pr.Kill(); pr.WaitForExit(3000);
                DeleteMarkers(dir, pid);
                var prof = _handles.FirstOrDefault(kv => kv.Value.Pid == pid).Key;
                if (prof != null) { _handles.TryRemove(prof, out _); _noAuto.TryRemove(prof, out _); Set(prof, "TERMINATED", 0); }
            }
            catch { }
        }
        EmitStatus();
    }

    // ── misc ────────────────────────────────────────────────────────────────────
    private string Browse(JsonElement p)
    {
        var kind = p.TryGetProperty("kind", out var k) ? k.GetString() : "file";
        var filter = p.TryGetProperty("filter", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null;
        if (kind == "dir")
        {
            var d = new OpenFolderDialog();
            return d.ShowDialog(_window) == true ? d.FolderName : "";
        }
        var fd = new OpenFileDialog
        {
            Filter = filter == "exe" ? "Programs (*.exe)|*.exe|All files (*.*)|*.*" : "All files (*.*)|*.*",
        };
        return fd.ShowDialog(_window) == true ? fd.FileName : "";
    }

    private static string ExportDiag()
    {
        var zip = DiagLog.ExportZip(Config.Load());
        try { Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = $"/select,\"{zip}\"" }); } catch { }
        return zip;
    }

    private static void OpenLogs()
    {
        try { Directory.CreateDirectory(DiagLog.Dir); Process.Start(new ProcessStartInfo { FileName = DiagLog.Dir, UseShellExecute = true }); }
        catch (Exception ex) { DiagLog.Log("OpenLogs failed: " + ex.Message); }
    }

    private static void OpenExternal(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { DiagLog.Log("OpenExternal failed: " + ex.Message); }
    }

    // Frameless drag: WebView2 ignores -webkit-app-region and DragMove() throws when
    // called from an async web message, so hand off to the native caption move loop.
    private const int WM_NCLBUTTONDOWN = 0xA1;
    private const int HTCAPTION = 0x2;
    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    private void BeginDrag()
    {
        try
        {
            if (_window.WindowState == WindowState.Maximized) return;
            var hwnd = new WindowInteropHelper(_window).Handle;
            if (hwnd == IntPtr.Zero) return;
            ReleaseCapture();
            SendMessage(hwnd, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero);
        }
        catch (Exception ex) { DiagLog.Log("BeginDrag failed: " + ex.Message); }
    }
}
