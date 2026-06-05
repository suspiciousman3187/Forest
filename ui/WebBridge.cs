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

    // ── Splash / auto-quit state ─────────────────────────────────────────────
    // _splashArmed: React renders the splash component instead of the full UI
    // _autoQuitArmed: when all watched profiles reach IN_GAME, exit Forest
    // _autoQuitWatching: which profiles to watch (the ones launched in this
    //   splash session); empty set = no autoquit pending
    // _inGameSeen: per-profile flag set when IN_GAME status is observed
    private bool _splashArmed;
    private bool _autoQuitArmed;
    private readonly HashSet<string> _autoQuitWatching = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _inGameSeen = new(StringComparer.OrdinalIgnoreCase);
    private DateTime? _autoQuitFireAt;
    private const double AutoQuitSettleSeconds = 5;

    private static readonly HashSet<string> InFlightStates = new(StringComparer.OrdinalIgnoreCase)
    {
        "QUEUED", "LAUNCH WINDOWER", "LAUNCH ASHITA", "LAUNCH POL",
        "SELECT ACCOUNT", "INPUT PASSWORD", "LOGGING IN", "LAUNCHING GAME",
    };
    private static readonly HashSet<string> Relaunchable = new(StringComparer.OrdinalIgnoreCase)
    {
        "INACTIVE", "FAILED", "TERMINATED", "TIMEOUT", "ERR",
        "WRONG SE PASSWORD", "LOGIN STUCK", "DISCONNECTED",
    };

    private const double TerminatedBadgeSeconds = 8;
    private const double WrongPwBadgeSeconds = 60;
    private const double LoginStuckBadgeSeconds = 60;
    private const double InGameTimeoutSeconds = 90;

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
            case "accounts.save": SaveAccount(p); Reply(id, true, null, null); EmitStatus(); break;
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

            case "splash.armed": Reply(id, true, new { armed = _splashArmed, watching = _autoQuitWatching.ToArray() }, null); break;
            case "splash.exit": SplashExit(p); Reply(id, true, null, null); break;
            case "splash.retry": SplashRetry(); Reply(id, true, null, null); break;

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
        waitForFFXiRegistryReadBetweenLaunches = c.WaitForFFXiRegistryReadBetweenLaunches,
        waitForFFXiRegistryReadTimeoutSeconds = c.WaitForFFXiRegistryReadTimeoutSeconds,
        overrideFFXiResolution = c.OverrideFFXiResolution,
        launchMode = c.LaunchMode ?? "Full",
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
                case "waitForFFXiRegistryReadBetweenLaunches": c.WaitForFFXiRegistryReadBetweenLaunches = prop.Value.GetBoolean(); break;
                case "waitForFFXiRegistryReadTimeoutSeconds": c.WaitForFFXiRegistryReadTimeoutSeconds = prop.Value.GetInt32(); break;
                case "overrideFFXiResolution": c.OverrideFFXiResolution = prop.Value.GetBoolean(); break;
                case "launchMode":
                {
                    var s = prop.Value.GetString();
                    c.LaunchMode = string.Equals(s, "Splash", StringComparison.OrdinalIgnoreCase) ? "Splash" : "Full";
                    break;
                }
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

    private void SaveAccount(JsonElement p)
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

        // Bug fix: when renaming, migrate the old name to the new name in every
        // place keyed by profile name so (a) display order is preserved, (b) the
        // selection checkbox carries over, and (c) running-instance state isn't
        // lost (running pol.exe -> INACTIVE was caused by _handles/_state keying
        // by profile name, not pid).
        if (renaming) MigrateProfileKey(original!, profile);
    }

    private void MigrateProfileKey(string oldName, string newName)
    {
        // Config-side lists: replace old name with new name in-place (preserves
        // the account's position in the displayed list).
        var c = Config.Load();
        bool cfgChanged = false;
        for (int i = 0; i < c.AccountOrder.Count; i++)
        {
            if (string.Equals(c.AccountOrder[i], oldName, StringComparison.OrdinalIgnoreCase))
            { c.AccountOrder[i] = newName; cfgChanged = true; }
        }
        for (int i = 0; i < c.SelectedAccounts.Count; i++)
        {
            if (string.Equals(c.SelectedAccounts[i], oldName, StringComparison.OrdinalIgnoreCase))
            { c.SelectedAccounts[i] = newName; cfgChanged = true; }
        }
        if (cfgChanged) c.Save();

        // Runtime per-profile state dicts: move the entry from old key to new
        // key so a running instance's pid/status/handle stay associated with
        // the renamed account.
        if (_state.TryGetValue(oldName, out var st))
        {
            _state.Remove(oldName);
            _state[newName] = st;
        }
        if (_handles.TryRemove(oldName, out var h))
            _handles[newName] = h;
        if (_noAuto.TryRemove(oldName, out var na))
            _noAuto[newName] = na;
        if (_cancelled.TryRemove(oldName, out var cn))
            _cancelled[newName] = cn;

        DiagLog.Log($"account renamed: '{oldName}' -> '{newName}' " +
                    $"(order/selection/state migrated)");
    }

    // ── status ────────────────────────────────────────────────────────────────
    private void SeedState()
    {
        var accountNames = new HashSet<string>(
            CredentialStore.Load().Accounts().Select(a => a.Name),
            StringComparer.OrdinalIgnoreCase);

        foreach (var name in accountNames)
            if (!_state.ContainsKey(name)) _state[name] = new Stat();

        try
        {
            var c = Config.Load();
            int removedOrder = c.AccountOrder.RemoveAll(n => !accountNames.Contains(n));
            int removedSel   = c.SelectedAccounts.RemoveAll(n => !accountNames.Contains(n));
            if (removedOrder > 0 || removedSel > 0)
            {
                c.Save();
                DiagLog.Log($"SeedState: pruned {removedOrder} stale AccountOrder + {removedSel} stale SelectedAccounts entries");
            }
        }
        catch (Exception ex) { DiagLog.Log("SeedState prune failed: " + ex.Message); }
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

            // Splash auto-quit: when Trees.dll writes IN_GAME for a watched
            // profile, mark it as ready. Once every watched profile has been
            // seen IN_GAME, start the settle countdown.
            if (_autoQuitArmed && _autoQuitWatching.Contains(profile) &&
                state.Equals("IN_GAME", StringComparison.OrdinalIgnoreCase))
            {
                _inGameSeen.Add(profile);
            }

            var f = Friendly(state, msg);
            if (f.Length > 0)
            {
                // Once RUNNING, only terminal-bad states can move us off it.
                var currentStatus = StatOf(profile).Status;
                bool isRunningDowngrade =
                    string.Equals(currentStatus, "RUNNING", StringComparison.OrdinalIgnoreCase)
                    && (f == "LAUNCHING GAME" || f == "LAUNCH POL"
                        || f == "SELECT ACCOUNT" || f == "INPUT PASSWORD"
                        || f == "LOGGING IN");
                if (!isRunningDowngrade) Set(profile, f, h.Pid);
            }

            if (state.Equals("DONE", StringComparison.OrdinalIgnoreCase))
            {
                if (!_doneSince.ContainsKey(h.Pid))
                    _doneSince[h.Pid] = DateTime.UtcNow;
                else if ((DateTime.UtcNow - _doneSince[h.Pid]).TotalSeconds > InGameTimeoutSeconds)
                {
                    DiagLog.Log($"[{profile}] DONE→IN_GAME timeout after {InGameTimeoutSeconds}s; terminating stuck client");
                    _doneSince.Remove(h.Pid);
                    KillRow(profile);
                    Set(profile, "TIMEOUT", 0);
                    continue;
                }
            }
            else if (state.Equals("IN_GAME", StringComparison.OrdinalIgnoreCase))
            {
                _doneSince.Remove(h.Pid);
            }
        }

        foreach (var kv in _state)
            if (kv.Value.Status == "RUNNING") _wrongPwFailCount.Remove(kv.Key);

        if (_autoQuitArmed)
        {
            foreach (var watched in _autoQuitWatching)
            {
                if (_state.TryGetValue(watched, out var st) &&
                    (st.Status is "FAILED" or "WRONG SE PASSWORD" or "LOGIN STUCK" or "TIMEOUT" or "TERMINATED" or "DISCONNECTED"))
                {
                    DiagLog.Log($"autoquit: disarming (splash kept open) because '{watched}' is {st.Status}");
                    _autoQuitArmed = false;
                    _autoQuitFireAt = null;
                    Emit("inGame", new { allInGame = false });
                    break;
                }
            }
        }

        // If all watched have hit IN_GAME, arm the settle countdown.
        if (_autoQuitArmed && _autoQuitFireAt is null &&
            _autoQuitWatching.Count > 0 &&
            _autoQuitWatching.SetEquals(_inGameSeen))
        {
            _autoQuitFireAt = DateTime.UtcNow.AddSeconds(AutoQuitSettleSeconds);
            DiagLog.Log($"autoquit: all {_autoQuitWatching.Count} watched profile(s) IN_GAME; " +
                        $"firing shutdown in {AutoQuitSettleSeconds}s");
            Emit("inGame", new { allInGame = true, watching = _autoQuitWatching.ToArray() });
        }

        // Fire the actual shutdown when the settle elapses.
        if (_autoQuitArmed && _autoQuitFireAt is { } fireAt && DateTime.UtcNow >= fireAt)
        {
            _autoQuitArmed = false;
            DiagLog.Log("autoquit: settle elapsed; shutting down Forest");
            _ui.BeginInvoke(new Action(() => Application.Current.Shutdown()));
        }

        EmitStatus();
    }

    // ── Splash mode + auto-quit control ──────────────────────────────────────
    // Called by App.xaml.cs at startup when the user has armed single-character
    // splash mode (config or command-line). Also callable from the React UI
    // via a future bridge method if we add a "launch into splash" button.
    public void ArmSplash(string[] profiles, bool withAutoQuit)
    {
        _splashArmed = true;
        _autoQuitArmed = withAutoQuit;
        _autoQuitWatching.Clear();
        foreach (var p in profiles)
            if (!string.IsNullOrWhiteSpace(p)) _autoQuitWatching.Add(p);
        _inGameSeen.Clear();
        _autoQuitFireAt = null;
        _ui.BeginInvoke(new Action(() =>
        {
            if (_window is WebHostWindow whw) whw.SetSplashMode(true);
        }));
        Emit("splashChanged", new { armed = true, watching = _autoQuitWatching.ToArray() });
        DiagLog.Log($"splash armed: watching {string.Join(",", _autoQuitWatching)} " +
                    $"(autoQuit={withAutoQuit})");
    }

    private void SplashExit(JsonElement p)
    {
        string reason = p.ValueKind == JsonValueKind.Object &&
                        p.TryGetProperty("reason", out var rv)
                        ? rv.GetString() ?? "user-stop" : "user-stop";

        // STOP kills in-flight launches; RUNNING profiles are left in-game.
        if (reason == "user-stop")
        {
            var inFlight = new List<string>();
            foreach (var watched in _autoQuitWatching)
            {
                if (_state.TryGetValue(watched, out var st) &&
                    !string.Equals(st.Status, "RUNNING", StringComparison.OrdinalIgnoreCase))
                {
                    inFlight.Add(watched);
                }
            }
            if (inFlight.Count > 0)
            {
                DiagLog.Log($"splash stop: terminating in-flight launches: {string.Join(",", inFlight)}");
                foreach (var prof in inFlight) KillRow(prof);
                EmitStatus();
            }
        }

        SplashExitInternal(reason);
    }

    private void SplashRetry()
    {
        if (!_splashArmed || _autoQuitWatching.Count == 0) return;

        var toRetry = new List<string>();
        foreach (var watched in _autoQuitWatching)
        {
            if (!_state.TryGetValue(watched, out var st)) continue;
            if (string.Equals(st.Status, "RUNNING", StringComparison.OrdinalIgnoreCase)) continue;
            if (InFlightStates.Contains(st.Status)) continue;
            if (_handles.ContainsKey(watched)) continue;
            toRetry.Add(watched);
            _inGameSeen.Remove(watched);
        }
        if (toRetry.Count == 0) return;

        _autoQuitArmed = true;
        _autoQuitFireAt = null;
        DiagLog.Log($"splash retry: re-launching {string.Join(",", toRetry)}");
        Launch(toRetry.ToArray());
    }

    private void SplashExitInternal(string reason)
    {
        if (!_splashArmed && !_autoQuitArmed) return;
        _splashArmed = false;
        _autoQuitArmed = false;
        _autoQuitFireAt = null;
        _autoQuitWatching.Clear();
        _inGameSeen.Clear();
        _ui.BeginInvoke(new Action(() =>
        {
            if (_window is WebHostWindow whw) whw.SetSplashMode(false);
        }));
        Emit("splashChanged", new { armed = false });
        Emit("inGame", new { allInGame = false });
        DiagLog.Log($"splash exit: reason={reason}");
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
            "DONE" => "LAUNCHING GAME",
            "IN_GAME" => "RUNNING",
            "DISCONNECTED" => "DISCONNECTED",
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

    // Programmatic entry for App.xaml.cs's splash startup path. Just a
    // public wrapper around the internal Launch — same flow as if the user
    // clicked Launch from the UI.
    public void LaunchProgrammatic(string[] profiles) => Launch(profiles);

    public bool AreAllRunning(string[] profiles)
    {
        if (profiles == null || profiles.Length == 0) return false;
        foreach (var p in profiles)
        {
            var s = StatOf(p);
            if (!string.Equals(s.Status, "RUNNING", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(s.Status, "DONE", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

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

                    // FFXi bg-res clobber barrier (opt-in, Windower-only). The
                    // next Windower launch will write its profile's bg-res
                    // values directly into HKLM\...\FinalFantasyXI\0001-0004;
                    // if launch[i]'s pol.exe hasn't yet read its own values
                    // by then, it gets the next profile's values and renders
                    // at the wrong res. Wait for Trees.dll's kernel-level
                    // NtQueryValueKey hook to fire CONFIG_READ first.
                    // Skipped for Ashita launches (Ashita doesn't write these
                    // FFXi registry keys, so there's no clobber to defend
                    // against).
                    if (cfg.WaitForFFXiRegistryReadBetweenLaunches &&
                        _handles.TryGetValue(launch[i], out var crHandle))
                    {
                        string launcherKind = "Windower";
                        try
                        {
                            launcherKind = Config.NormalizeLauncher(
                                CredentialStore.Load().GetAccount(launch[i]).Launcher
                                ?? cfg.DefaultLauncher);
                        }
                        catch { }
                        if (launcherKind == "Ashita")
                        {
                            DiagLog.Log($"[{launch[i]}] FFXi bg-res barrier SKIPPED (Ashita launcher)");
                        }
                        else
                        {
                            DiagLog.Log($"[{launch[i]}] FFXi bg-res barrier armed " +
                                        $"(timeout {cfg.WaitForFFXiRegistryReadTimeoutSeconds}s)");
                            var crState = svc.WaitForConfigRead(crHandle,
                                (s, m) => DiagLog.Log($"  [{launch[i]}] {s}: {m}"));
                            DiagLog.Log($"[{launch[i]}] FFXi bg-res barrier resolved: {crState}");
                        }
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
        string dir;
        try { dir = Config.Load().ResolveTreesDir(); }
        catch { return; }
        if (!Directory.Exists(dir)) return;

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
        string dir;
        try { dir = Config.Load().ResolveTreesDir(); }
        catch { return Array.Empty<object>(); }
        if (!Directory.Exists(dir)) return Array.Empty<object>();

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
        string dir;
        try { dir = Config.Load().ResolveTreesDir(); }
        catch { return; }
        if (!Directory.Exists(dir)) return;
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
