using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Forest;

internal static class DiagLog
{
    public static readonly string Dir = Path.Combine(AppData.Dir, "logs");

    public static readonly string SessionFile =
        Path.Combine(Dir, $"forest-{DateTime.Now:yyyyMMdd-HHmmss}.log");

    public static bool Verbose;

    public static string AppVersion =>
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName().Version?.ToString() ?? "?";

    static DiagLog()
    {
        try
        {
            Directory.CreateDirectory(Dir);
            Prune();
            File.AppendAllText(SessionFile,
                $"[{DateTime.Now:HH:mm:ss.fff}] === Forest session start (v{AppVersion}) ===\r\n");
        }
        catch {  }
    }

    public static void Log(string s)   => Write("   ", s);
    public static void Debug(string s) { if (Verbose) Write("dbg", s); }

    private static void Write(string lvl, string s)
    {
        try
        {
            File.AppendAllText(SessionFile,
                $"[{DateTime.Now:HH:mm:ss.fff}] {lvl} {s}\r\n");
        }
        catch {  }
    }

    public static void Crash(string where, Exception ex)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"[{DateTime.Now:u}] CRASH @ {where}");
            for (Exception? e = ex; e != null; e = e.InnerException)
                sb.AppendLine($"{e.GetType().FullName}: {e.Message}\n{e.StackTrace}");
            File.AppendAllText(SessionFile, sb.ToString());
            File.WriteAllText(Path.Combine(Dir, "last-crash.txt"), sb.ToString());
        }
        catch {  }
    }

    private static void Prune()
    {
        try
        {
            var files = new DirectoryInfo(Dir).GetFiles("forest-*.log");
            if (files.Length <= 12) return;
            Array.Sort(files, (a, b) => b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc));
            for (int i = 12; i < files.Length; i++)
                try { files[i].Delete(); } catch {  }
        }
        catch {  }
    }

    public static string ExportZip(Config cfg)
    {
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var zipPath = Path.Combine(desktop, $"Forest-Diagnostics-{stamp}.zip");
        var staging = Path.Combine(Path.GetTempPath(), "ForestDiag-" + stamp);
        Directory.CreateDirectory(staging);
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Forest Diagnostics   {DateTime.Now:u}");
            sb.AppendLine($"Forest version  : {AppVersion}");
            sb.AppendLine($"OS              : {Environment.OSVersion}  ({(Environment.Is64BitOperatingSystem ? "x64" : "x86")})");
            sb.AppendLine($".NET            : {Environment.Version}");
            sb.AppendLine($"AppData         : {AppData.Dir}");
            string resolvedTreesDir;
            try { resolvedTreesDir = cfg.ResolveTreesDir(); }
            catch (Exception ex) { resolvedTreesDir = $"(unresolved: {ex.Message})"; }
            sb.AppendLine($"TreesDir (config): {cfg.TreesDir ?? "(none, using embedded)"}");
            sb.AppendLine($"TreesDir (resolved): {resolvedTreesDir}");
            sb.AppendLine($"DefaultLauncher : {cfg.DefaultLauncher}");
            sb.AppendLine($"WindowerExe     : {cfg.WindowerExe}  (exists={File.Exists(cfg.WindowerExe ?? "")})");
            sb.AppendLine($"AshitaExe       : {cfg.AshitaExe}  (exists={File.Exists(cfg.AshitaExe ?? "")})");
            sb.AppendLine($"HidePolWindow   : {cfg.HidePolWindow}");
            sb.AppendLine($"DisableAutoLogin: {cfg.DisableAutoLogin}");
            sb.AppendLine($"AutoLoginChar   : {cfg.AutoLoginCharacter}");
            sb.AppendLine($"DebugLogging    : {cfg.DebugLogging}");
            sb.AppendLine($"Accounts        : {cfg.AccountOrder.Count}");
            File.WriteAllText(Path.Combine(staging, "diag.txt"), sb.ToString());

            var logsOut = Path.Combine(staging, "logs");
            Directory.CreateDirectory(logsOut);
            try
            {
                foreach (var f in Directory.GetFiles(Dir))
                    File.Copy(f, Path.Combine(logsOut, Path.GetFileName(f)), true);
            }
            catch {  }

            try
            {
                var tl = Path.Combine(resolvedTreesDir, "trees.log");
                if (File.Exists(tl))
                    File.Copy(tl, Path.Combine(staging, "trees.log"), true);
            }
            catch {  }

            try
            {
                var cfgPath = Path.Combine(AppData.Dir, "config.json");
                if (File.Exists(cfgPath))
                    File.Copy(cfgPath, Path.Combine(staging, "config.json"), true);
            }
            catch {  }

            ScrubStaging(staging, cfg);

            if (File.Exists(zipPath)) File.Delete(zipPath);
            ZipFile.CreateFromDirectory(staging, zipPath);
            return zipPath;
        }
        finally
        {
            try { Directory.Delete(staging, true); } catch {  }
        }
    }

    private static void ScrubStaging(string staging, Config cfg)
    {
        var names = cfg.AccountOrder.Concat(cfg.SelectedAccounts)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct().OrderByDescending(n => n.Length).ToList();
        var map = new Dictionary<string, string>();
        for (int i = 0; i < names.Count; i++) map[names[i]] = $"ACCOUNT_{i + 1}";
        string user = Environment.UserName;

        foreach (var file in Directory.GetFiles(staging, "*", SearchOption.AllDirectories))
        {
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext != ".log" && ext != ".json" && ext != ".txt") continue;
            try { File.WriteAllText(file, Redact(File.ReadAllText(file), user, map)); }
            catch {  }
        }
    }

    private static string Redact(string s, string user, Dictionary<string, string> map)
    {
        if (!string.IsNullOrWhiteSpace(user))
            s = Regex.Replace(s, Regex.Escape(user), "USER", RegexOptions.IgnoreCase);

        // context patterns catch any name (incl. deleted accounts no longer in config)
        s = Regex.Replace(s, "-p=\"[^\"]*\"", "-p=\"PROFILE\"");
        s = Regex.Replace(s, @"Terminated .+? \(pid", "Terminated ACCOUNT (pid");
        s = Regex.Replace(s, @"launching '[^']*'", "launching 'ACCOUNT'");
        s = Regex.Replace(s, @"'[^']*' launch", "'ACCOUNT' launch");

        // current account names anywhere else (whole-word, longest first)
        foreach (var kv in map)
            s = Regex.Replace(s, $@"(?<![A-Za-z0-9_]){Regex.Escape(kv.Key)}(?![A-Za-z0-9_])", kv.Value);
        return s;
    }
}
