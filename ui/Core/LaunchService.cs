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
        log ??= _ => { };
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
                            int.TryParse(line.AsSpan("CAPTURED_PID=".Length), out pid);
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
            while (sw.Elapsed < TimeSpan.FromMinutes(5) &&
                   (pid == 0 || !wi.HasExited))
            {
                if (pid != 0 && wi.HasExited) break;
                Thread.Sleep(200);
            }
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

    private void LaunchGame(string exe, string defaultTemplate, string kind,
                            string profile, string? customArgs, string? marker,
                            Action<string> log)
    {
        var template = string.IsNullOrWhiteSpace(customArgs)
            ? defaultTemplate : customArgs!;
        var rawArgs = template.Replace("{profile}", profile);
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
            try { handles.Add(Launch(p, log)); }
            catch (Exception ex) { log($"'{p}' launch FAILED: {ex.Message}"); }
            if (i < list.Count - 1)
            {
                log($"(stagger {_cfg.StaggerSeconds}s)");
                Thread.Sleep(TimeSpan.FromSeconds(_cfg.StaggerSeconds));
            }
        }
        return handles;
    }
}
