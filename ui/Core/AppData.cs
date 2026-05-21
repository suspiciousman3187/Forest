namespace Forest;

internal static class AppData
{
    public static readonly string Dir = Init();

    private static string Init()
    {
        var roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);
        var dir = Path.Combine(roaming, "Forest");
        Directory.CreateDirectory(dir);

        try
        {
            var legacy = Path.Combine(roaming, "POLAutoLogin");
            if (Directory.Exists(legacy))
                foreach (var name in new[] { "creds.dat", "config.json" })
                {
                    var src = Path.Combine(legacy, name);
                    var dst = Path.Combine(dir, name);
                    if (File.Exists(src) && !File.Exists(dst))
                        File.Copy(src, dst);
                }
        }
        catch {  }

        return dir;
    }
}
