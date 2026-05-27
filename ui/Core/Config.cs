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

    public bool UsePolProxy { get; set; } = false;

    public string? PolProxyUpstream { get; set; } = "202.67.54.55";

    public bool LaunchSelectedOnStartup { get; set; } = false;

    public bool AutoLoginCharacter { get; set; } = true;

    public int AutoLoginSettleSeconds { get; set; } = 5;

    public bool AutoLoginSendInputFallback { get; set; } = false;

    public bool DebugLogging { get; set; } = false;

    public List<string> SelectedAccounts { get; set; } = new();

    public List<string> AccountOrder { get; set; } = new();

    private static readonly string Path_ =
        System.IO.Path.Combine(AppData.Dir, "config.json");

    public static Config Load()
    {
        Config c = File.Exists(Path_)
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
        if (string.IsNullOrWhiteSpace(TreesDir) ||
            !File.Exists(System.IO.Path.Combine(TreesDir, "Trees.dll")) ||
            !File.Exists(System.IO.Path.Combine(TreesDir, "waitinject.exe")))
            throw new InvalidOperationException(
                "TreesDir not set/invalid (needs Trees.dll + waitinject.exe). "
                + "Set it in Settings.");
        return TreesDir!;
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
