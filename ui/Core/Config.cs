using System.Text.Json;

namespace Forest;

public sealed class Config
{
    public string? WindowerExe { get; set; }

    public string? AshitaExe   { get; set; }
    public string? TreesDir    { get; set; }

    public string DefaultLauncher { get; set; } = "Windower";

    public string WindowerArgs { get; set; } = "-p=\"{profile}\"";

    public string AshitaArgs { get; set; } = "{profile}";

    public int StaggerSeconds  { get; set; } = 8;

    public bool ParallelLaunch { get; set; } = false;

    public bool FastSequential { get; set; } = true;

    public int LoginTimeoutSeconds { get; set; } = 120;

    public bool HidePolWindow { get; set; } = true;

    public bool DisableAutoLogin { get; set; } = false;

    public bool UsePolProxy { get; set; } = true;

    public string? PolProxyUpstream { get; set; } = "202.67.54.55";

    public bool LaunchSelectedOnStartup { get; set; } = false;

    public bool AutoLoginCharacter { get; set; } = true;

    public int AutoLoginSettleSeconds { get; set; } = 5;

    public bool AutoLoginSendInputFallback { get; set; } = false;

    public bool WaitForFFXiRegistryReadBetweenLaunches { get; set; } = false;

    public int WaitForFFXiRegistryReadTimeoutSeconds { get; set; } = 120;

    public bool OverrideFFXiResolution { get; set; } = true;

    // "Full" (default) renders the normal main UI on startup. "Splash" boots
    // into the minimalist auto-launch window if LaunchSelectedOnStartup is on
    // and SelectedAccounts has entries. Command-line --launch overrides.
    public string LaunchMode { get; set; } = "Full";

    public bool DebugLogging { get; set; } = false;

    public List<string> SelectedAccounts { get; set; } = new();

    public List<string> AccountOrder { get; set; } = new();

    // Schema version for one-time migrations. Bump when adding a migration in
    // Load(). Existing configs without this field deserialize as 0.
    public int ConfigVersion { get; set; } = 0;

    private static readonly string Path_ =
        System.IO.Path.Combine(AppData.Dir, "config.json");

    public static Config Load()
    {
        bool fileExists = File.Exists(Path_);
        Config c = fileExists
            ? JsonSerializer.Deserialize<Config>(File.ReadAllText(Path_)) ?? new()
            : new();

        if (string.IsNullOrWhiteSpace(c.TreesDir))
        {
            string[] guesses = {
                System.IO.Path.Combine(AppContext.BaseDirectory, "trees"),
                System.IO.Path.Combine(AppContext.BaseDirectory,
                    "..", "..", "..", "..", "trees"),
            };
            foreach (var g in guesses)
                if (Directory.Exists(g))
                {
                    c.TreesDir = System.IO.Path.GetFullPath(g);
                    break;
                }
        }

        // One-time migrations. ConfigVersion is the source of truth for what's
        // already been applied. Each migration is idempotent within its guard.
        bool migrated = false;

        // v1: turn the FFXi resolution override ON for everyone upgrading from
        // a pre-1.3.1 config (where it defaulted off). The fix is opt-in only
        // by way of needing the registry-snapshot+inline-hook pipeline to fire;
        // it's a no-op for Ashita launches and for users who don't multi-box,
        // so flipping it on by default is safe and matches the new install
        // default.
        if (c.ConfigVersion < 1)
        {
            c.OverrideFFXiResolution = true;
            // The two MULTI-BOX SAFETY toggles are mutually exclusive in the
            // UI; turning Recommended on requires Legacy to be off. v1.3.0
            // users who had Legacy on get migrated to the (better) Recommended
            // fix.
            c.WaitForFFXiRegistryReadBetweenLaunches = false;
            c.ConfigVersion = 1;
            migrated = true;
        }

        if (migrated) c.Save();
        return c;
    }

    public void Save()
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
        File.WriteAllText(Path_,
            JsonSerializer.Serialize(this,
                new JsonSerializerOptions { WriteIndented = true }));
    }

    public static string NormalizeLauncher(string? kind) =>
        string.Equals(kind, "Ashita", StringComparison.OrdinalIgnoreCase)
            ? "Ashita" : "Windower";

    public string ResolveTreesDir()
    {
        // TreesDir is a dev override; production uses NativeAssets.
        if (!string.IsNullOrWhiteSpace(TreesDir))
        {
            var diskTrees = System.IO.Path.Combine(TreesDir, "Trees.dll");
            var diskWait  = System.IO.Path.Combine(TreesDir, "waitinject.exe");
            if (File.Exists(diskTrees) && File.Exists(diskWait))
            {
                var treesVer = System.Diagnostics.FileVersionInfo.GetVersionInfo(diskTrees).FileVersion;
                var ownVer   = typeof(Config).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";
                if (TreesVersionsMatch(treesVer, ownVer))
                    return TreesDir!;
            }
        }
        return NativeAssets.RuntimeDir();
    }

    private static bool TreesVersionsMatch(string? treesVer, string ownVer)
    {
        if (string.IsNullOrEmpty(treesVer)) return false;
        if (!Version.TryParse(treesVer, out var vt) || !Version.TryParse(ownVer, out var vo)) return false;
        return vt.Major == vo.Major && vt.Minor == vo.Minor && vt.Build == vo.Build;
    }

    public (string exe, string argsTemplate) ResolveLauncher(string? kind)
    {
        if (NormalizeLauncher(kind) == "Ashita")
        {
            if (string.IsNullOrWhiteSpace(AshitaExe) || !File.Exists(AshitaExe))
                throw new InvalidOperationException(
                    "Ashita launcher (ashita-cli.exe) path not set/invalid. "
                    + "Set it in Settings.");
            return (AshitaExe!, AshitaArgs);
        }
        if (string.IsNullOrWhiteSpace(WindowerExe) || !File.Exists(WindowerExe))
            throw new InvalidOperationException(
                "Windower.exe path not set/invalid. Set it in Settings.");
        return (WindowerExe!, WindowerArgs);
    }
}
