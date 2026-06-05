using System.Collections.Concurrent;
using System.Diagnostics;

namespace Forest;

public sealed class LaunchService
{

    public static ConcurrentDictionary<string, int> InFlightWaitinjects { get; }
        = new(StringComparer.OrdinalIgnoreCase);

    private readonly Config _cfg;
    private readonly CredentialStore _store;
    private readonly string _treesDir, _treesDll, _waitInject;

    public LaunchService(Config cfg, CredentialStore store)
    {
        _cfg = cfg; _store = store;

        _treesDir   = cfg.ResolveTreesDir();
        _treesDll   = Path.Combine(_treesDir, "Trees.dll");
        _waitInject = Path.Combine(_treesDir, "waitinject.exe");
    }

    public sealed record Handle(string Profile, int Pid, string StatusFile);

    public (string state, string msg, string time) ReadStatus(Handle h)
    {
        try
        {
            if (!File.Exists(h.StatusFile)) return ("PENDING", "", "");
            var parts = File.ReadAllText(h.StatusFile).Trim().Split('|');
            return (parts.ElementAtOrDefault(0) ?? "?",
                    parts.ElementAtOrDefault(1) ?? "",
                    parts.ElementAtOrDefault(2) ?? "");
        }
        catch { return ("PENDING", "", ""); }
    }

    public static bool IsTerminal(string state) =>
        state is "DONE" or "FAILED";

    public Handle Launch(string profile, Action<string>? log = null)
    {
        var uiLog = log ?? (_ => { });
        log = m => { DiagLog.Debug(m); uiLog(m); };

        try
        {
            var dbgMarker = Path.Combine(_treesDir, "forest_debug.txt");
            if (_cfg.DebugLogging) File.WriteAllText(dbgMarker, "1");
            else if (File.Exists(dbgMarker)) File.Delete(dbgMarker);

            var siMarker = Path.Combine(_treesDir, "forest_sendinput.txt");
            if (_cfg.AutoLoginSendInputFallback) File.WriteAllText(siMarker, "1");
            else if (File.Exists(siMarker)) File.Delete(siMarker);

            var flMarker = Path.Combine(_treesDir, "forest_fastlogin.txt");
            if (_cfg.UsePolProxy) File.WriteAllText(flMarker, "1");
            else if (File.Exists(flMarker)) File.Delete(flMarker);
        }
        catch {  }

        var acct = _store.GetAccount(profile);
        if (string.IsNullOrWhiteSpace(acct.WindowerProfile))
            throw new InvalidOperationException(
                $"'{profile}' has no Windower profile. Edit it in the account dialog.");

        bool noAuto = _cfg.DisableAutoLogin && !_cfg.HidePolWindow;

        if (!noAuto && acct.PolSlot <= 0)
            throw new InvalidOperationException(
                $"'{profile}' has no POL slot. Edit it in the account dialog.");

        var kind = Config.NormalizeLauncher(acct.Launcher ?? _cfg.DefaultLauncher);
        var (launcherExe, launcherArgs) = _cfg.ResolveLauncher(kind);

        var marker = (_cfg.ParallelLaunch && kind != "Ashita")
            ? "F" + Guid.NewGuid().ToString("N") : null;

        var credSrc = Path.Combine(_treesDir, $"cred_src_{profile}.bin");
        var totpSrc = Path.Combine(_treesDir, $"totp_src_{profile}.bin");
        bool haveTotp = false;
        if (!noAuto)
        {
            _store.ExportEncryptedPassword(profile, credSrc);

            haveTotp = _store.ExportEncryptedTotp(profile, totpSrc);
        }

        var psi = new ProcessStartInfo(_waitInject)
        {
            WorkingDirectory = _treesDir,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(_treesDll);
        psi.ArgumentList.Add(noAuto ? "0" : acct.PolSlot.ToString());
        psi.ArgumentList.Add(noAuto ? "" : credSrc);
        psi.ArgumentList.Add(_cfg.HidePolWindow ? "hide" : "nohide");
        psi.ArgumentList.Add(marker ?? "");
        psi.ArgumentList.Add(noAuto ? "nologin" : "");
        psi.ArgumentList.Add(!noAuto && haveTotp ? totpSrc : "");
        psi.ArgumentList.Add(_cfg.AutoLoginCharacter ? "autoenter" : "noautoenter");
        psi.ArgumentList.Add(acct.IngameSlot.ToString());
        psi.ArgumentList.Add((_cfg.AutoLoginSettleSeconds * 1000).ToString());

        var wi = Process.Start(psi)
                 ?? throw new InvalidOperationException("waitinject failed to start.");

        InFlightWaitinjects[profile] = wi.Id;

        int pid = 0; bool injectOk = false;

        try
        {
            var pump = new Thread(() =>
            {
                try
                {
                    string? line;
                    while ((line = wi.StandardOutput.ReadLine()) != null)
                    {
                        log($"[waitinject] {line}");
                        if (line.StartsWith("READY"))
                            LaunchGame(launcherExe, launcherArgs, kind,
                                       acct.WindowerProfile!, acct.LaunchArgs,
                                       marker, log);
                        else if (line.StartsWith("CAPTURED_PID="))
                        {
                            int.TryParse(line.AsSpan("CAPTURED_PID=".Length), out pid);
                            // BG-RES OVERRIDE: snapshot the FFXi registry RIGHT
                            // NOW (Windower just wrote this profile's values)
                            // and persist them as a per-pid sidecar that
                            // Trees.dll reads. Later Windower launches will
                            // clobber the registry; Trees.dll's hook then
                            // returns OUR snapshot to FFXi instead of whatever
                            // the (potentially-clobbered) registry holds.
                            if (_cfg.OverrideFFXiResolution &&
                                pid > 0 && kind != "Ashita")
                            {
                                try { WriteBgResSidecar(pid, log); }
                                catch (Exception ex)
                                { log($"bgres sidecar write failed: {ex.Message}"); }
                            }
                        }
                        else if (line.StartsWith("INJECT_OK"))   injectOk = true;
                        else if (line.StartsWith("INJECT_FAIL")) injectOk = false;
                    }
                }
                catch (Exception ex)
                {
                    log($"launch pump error: {ex.Message}");
                }
            }) { IsBackground = true };
            pump.Start();

            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < TimeSpan.FromMinutes(5) && !wi.HasExited)
                Thread.Sleep(200);
            pump.Join(2000);
            try { File.Delete(credSrc); } catch {  }
            try { File.Delete(totpSrc); } catch {  }

            if (pid == 0)
                throw new InvalidOperationException(
                    "waitinject did not capture a new pol.exe (timeout, "
                    + "or the launch was cancelled).");
            if (!injectOk)
                log($"WARNING: inject reported failure for pid {pid} "
                    + "(orchestrator must run elevated). Check trees.log.");

            return new Handle(profile, pid,
                Path.Combine(_treesDir, $"status_{pid}.txt"));
        }
        finally
        {
            InFlightWaitinjects.TryRemove(profile, out _);
        }
    }

    // Read the current FFXi-side resolution registry values that Windower just
    // wrote (HKLM\SOFTWARE\WOW6432Node\PlayOnlineUS\SquareEnix\FinalFantasyXI)
    // and persist them as bgres_<pid>.txt next to Trees.dll. Trees.dll's
    // BgResSidecarLoaderThread picks this up async and uses it to override
    // future reads inside pol.exe — so concurrent Windower launches can
    // clobber the registry freely without affecting this pol.exe's render.
    //
    // The keys we capture (DWORD values): 0001, 0002, 0003, 0004, 0037, 0038
    //   0001/0002 = window width/height
    //   0003/0004 = render width/height (background resolution)
    //   0037/0038 = menu/UI resolution
    private void WriteBgResSidecar(int pid, Action<string> log)
    {
        using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
            Microsoft.Win32.RegistryHive.LocalMachine,
            Microsoft.Win32.RegistryView.Registry32);
        using var ffxi = key.OpenSubKey(@"SOFTWARE\PlayOnlineUS\SquareEnix\FinalFantasyXI");
        if (ffxi == null)
        {
            log($"bgres sidecar: HKLM\\...\\FinalFantasyXI not present, skipping");
            return;
        }
        var lines = new List<string>();
        foreach (var name in new[] { "0001", "0002", "0003", "0004", "0037", "0038" })
        {
            var v = ffxi.GetValue(name);
            if (v is int iv) lines.Add($"{name}={(uint)iv}");
            else if (v is long lv) lines.Add($"{name}={(uint)lv}");
        }
        if (lines.Count == 0)
        {
            log($"bgres sidecar: no DWORD values found under FinalFantasyXI key");
            return;
        }
        var path = Path.Combine(_treesDir, $"bgres_{pid}.txt");
        File.WriteAllLines(path, lines);
        log($"bgres sidecar written: {path} ({lines.Count} keys)");
    }

    private void LaunchGame(string exe, string defaultTemplate, string kind,
                            string profile, string? customArgs, string? marker,
                            Action<string> log)
    {
        var template = string.IsNullOrWhiteSpace(customArgs)
            ? defaultTemplate : customArgs!;
        var rawArgs = template.Replace("{profile}", profile);

        // Use long form --hide. Short -h collides with Windower's `h|height=`
        // parser inside GetProfile and would swallow the next arg as its value.
        if (string.Equals(kind, "Windower", StringComparison.OrdinalIgnoreCase)
            && !HasWindowerHideFlag(rawArgs))
        {
            rawArgs = "--hide " + rawArgs;
        }

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = rawArgs,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        if (marker != null)
        {
            psi.UseShellExecute = false;
            psi.EnvironmentVariables["FOREST_TAG"] = marker;
        }
        else
        {
            psi.UseShellExecute = true;
        }
        Process.Start(psi);
        log($"launched [{kind}]: \"{exe}\" {rawArgs}"
            + (marker != null ? $"  [tag {marker}]" : ""));
    }

    private static bool HasWindowerHideFlag(string args)
    {
        foreach (var t in args.Split(new[] { ' ', '\t' },
                                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (t.Equals("-h", StringComparison.OrdinalIgnoreCase)
                || t.Equals("--hide", StringComparison.OrdinalIgnoreCase)
                || t.Equals("-q", StringComparison.OrdinalIgnoreCase)
                || t.Equals("--quit", StringComparison.OrdinalIgnoreCase)
                || t.Equals("-u", StringComparison.OrdinalIgnoreCase)
                || t.Equals("--update", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public string WaitForLogin(Handle h, Action<string, string>? onState = null)
    {
        var sw = Stopwatch.StartNew();
        string last = "";
        var limit = TimeSpan.FromSeconds(_cfg.LoginTimeoutSeconds);
        while (sw.Elapsed < limit)
        {
            var (state, msg, _) = ReadStatus(h);
            if (state != last) { onState?.Invoke(state, msg); last = state; }
            if (IsTerminal(state)) return state;
            Thread.Sleep(400);
        }
        return "TIMEOUT";
    }

    // Waits until the launched instance has performed its first FFXi-pathed
    // registry read (CONFIG_READ status), or terminates, or times out. Used
    // as a serial-launch barrier so a later Windower invocation cannot
    // clobber HKLM\...\FinalFantasyXI\0001-0004 before this instance has
    // consumed its own values.
    public string WaitForConfigRead(Handle h, Action<string, string>? onState = null)
    {
        var sw = Stopwatch.StartNew();
        string last = "";
        var limit = TimeSpan.FromSeconds(
            _cfg.WaitForFFXiRegistryReadTimeoutSeconds > 0
                ? _cfg.WaitForFFXiRegistryReadTimeoutSeconds
                : 120);
        while (sw.Elapsed < limit)
        {
            var (state, msg, _) = ReadStatus(h);
            if (state != last) { onState?.Invoke(state, msg); last = state; }
            if (state == "CONFIG_READ" || IsTerminal(state)) return state;
            Thread.Sleep(400);
        }
        return "TIMEOUT";
    }

    public IReadOnlyList<Handle> LaunchAll(IEnumerable<string> profiles,
                                           Action<string>? log = null)
    {
        log ??= Console.WriteLine;
        var handles = new List<Handle>();
        var list = profiles.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            var p = list[i];
            log($"=== [{i + 1}/{list.Count}] launching '{p}' ===");
            Handle? launchedHandle = null;
            try
            {
                launchedHandle = Launch(p, log);
                handles.Add(launchedHandle);
            }
            catch (Exception ex) { log($"'{p}' launch FAILED: {ex.Message}"); }

            if (i >= list.Count - 1) continue;

            if (_cfg.WaitForFFXiRegistryReadBetweenLaunches && launchedHandle != null)
            {
                log($"waiting for '{p}' to consume its FFXi registry values " +
                    $"(prevents bg-res clobber on next launch; timeout " +
                    $"{_cfg.WaitForFFXiRegistryReadTimeoutSeconds}s)...");
                var st = WaitForConfigRead(launchedHandle,
                    (s, m) => log($"  [{p}] {s}: {m}"));
                log($"'{p}' barrier resolved: {st}");
                // If CONFIG_READ fired but stagger is still desired (e.g. for
                // POL viewer settling), respect a non-zero StaggerSeconds too.
                if (_cfg.StaggerSeconds > 0)
                {
                    log($"(additional stagger {_cfg.StaggerSeconds}s)");
                    Thread.Sleep(TimeSpan.FromSeconds(_cfg.StaggerSeconds));
                }
            }
            else
            {
                log($"(stagger {_cfg.StaggerSeconds}s)");
                Thread.Sleep(TimeSpan.FromSeconds(_cfg.StaggerSeconds));
            }
        }
        return handles;
    }
}
