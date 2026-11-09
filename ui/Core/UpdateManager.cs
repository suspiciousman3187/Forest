using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Forest;

public sealed class UpdateManager
{
    // This fork ships its own builds; upstream releases would replace the
    // name-based POL login fix with upstream's binaries.
    public const string ManifestUrl =
        "https://github.com/AJHemmings/Forest/releases/latest/download/manifest.json";

    private static UpdateManager? _instance;
    public static UpdateManager Instance => _instance ??= new UpdateManager();

    private readonly object _sync = new();

    public sealed class ManifestEntry
    {
        [JsonPropertyName("version")] public string? Version { get; set; }
        [JsonPropertyName("url")]     public string? Url { get; set; }
        [JsonPropertyName("sha256")]  public string? Sha256 { get; set; }
        [JsonPropertyName("notes")]   public string? Notes { get; set; }
    }

    public sealed class Manifest
    {
        [JsonPropertyName("desktop")] public ManifestEntry? Desktop { get; set; }
    }

    public sealed class ChannelState
    {
        public string  Kind { get; set; } = "idle";
        public string? Version { get; set; }
        public string? Notes { get; set; }
        public string? Url { get; set; }
        public long    Downloaded { get; set; }
        public long?   Total { get; set; }
        public string? Message { get; set; }
    }

    public sealed class StateSnapshot
    {
        public ChannelState Desktop { get; set; } = new();
        public string  CurrentVersion { get; set; } = "0.0.0";
        public bool    CheckOnStartup { get; set; }
        public string? LastCheckIso { get; set; }
    }

    private ChannelState _desktop = new();
    private DateTime?    _lastCheck;

    public event Action? StateChanged;
    private void Bump()
    {
        var h = StateChanged;
        if (h != null) try { h(); } catch { }
    }

    public StateSnapshot Snapshot()
    {
        lock (_sync)
        {
            return new StateSnapshot
            {
                Desktop        = Clone(_desktop),
                CurrentVersion = GetCurrentVersion(),
                CheckOnStartup = Config.Load().CheckUpdatesOnStartup,
                LastCheckIso   = _lastCheck?.ToUniversalTime().ToString("o"),
            };
        }
    }

    private static ChannelState Clone(ChannelState s) => new()
    {
        Kind = s.Kind, Version = s.Version, Notes = s.Notes, Url = s.Url,
        Downloaded = s.Downloaded, Total = s.Total, Message = s.Message,
    };

    public static string GetCurrentVersion()
    {
        try
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            if (v == null) return "0.0.0";
            return $"{v.Major}.{v.Minor}.{v.Build}";
        }
        catch { return "0.0.0"; }
    }

    public static bool IsNewer(string? latest, string? installed)
    {
        if (string.IsNullOrEmpty(installed)) return !string.IsNullOrEmpty(latest);
        if (string.IsNullOrEmpty(latest)) return false;
        int[] a = latest!.Split('.').Select(s => int.TryParse(s, out var n) ? n : 0).ToArray();
        int[] b = installed!.Split('.').Select(s => int.TryParse(s, out var n) ? n : 0).ToArray();
        int len = Math.Max(a.Length, b.Length);
        for (int i = 0; i < len; i++)
        {
            int x = i < a.Length ? a[i] : 0;
            int y = i < b.Length ? b[i] : 0;
            if (x > y) return true;
            if (x < y) return false;
        }
        return false;
    }

    public async Task CheckAsync(bool respectSkip)
    {
        lock (_sync)
        {
            if (_desktop.Kind is "checking" or "downloading" or "installing") return;
            _desktop = new ChannelState { Kind = "checking" };
        }
        Bump();

        Manifest? manifest;
        try
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            client.DefaultRequestHeaders.Add("User-Agent", "Forest-Updater");
            string body = await client.GetStringAsync(ManifestUrl).ConfigureAwait(false);
            manifest = JsonSerializer.Deserialize<Manifest>(body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (manifest == null) throw new InvalidOperationException("manifest deserialized to null");
        }
        catch (Exception ex)
        {
            lock (_sync) _desktop = new ChannelState { Kind = "error", Message = "Failed to fetch manifest: " + ex.Message };
            DiagLog.Log("UpdateManager check failed: " + ex.Message);
            Bump();
            return;
        }

        lock (_sync) _lastCheck = DateTime.UtcNow;
        string current = GetCurrentVersion();
        var cfg = Config.Load();

        lock (_sync)
        {
            if (manifest.Desktop != null && IsNewer(manifest.Desktop.Version, current))
            {
                if (respectSkip && string.Equals(manifest.Desktop.Version, cfg.SkippedUpdateVersion, StringComparison.OrdinalIgnoreCase))
                    _desktop = new ChannelState { Kind = "none" };
                else
                {
                    _desktop = new ChannelState
                    {
                        Kind    = "available",
                        Version = manifest.Desktop.Version,
                        Notes   = manifest.Desktop.Notes,
                        Url     = manifest.Desktop.Url,
                    };
                    DiagLog.Log($"UpdateManager: v{manifest.Desktop.Version} available (current v{current})");
                }
            }
            else _desktop = new ChannelState { Kind = "none" };
        }
        Bump();
    }

    public async Task InstallAsync()
    {
        ManifestEntry target;
        lock (_sync)
        {
            if (_desktop.Kind != "available") return;
            target = new ManifestEntry { Version = _desktop.Version, Url = _desktop.Url };
            _desktop = new ChannelState { Kind = "downloading", Version = target.Version, Downloaded = 0, Total = null };
        }
        Bump();

        string zipPath;
        try
        {
            zipPath = await DownloadWithProgress(target.Url!, (downloaded, total) =>
            {
                lock (_sync)
                {
                    if (_desktop.Kind == "downloading")
                    {
                        _desktop.Downloaded = downloaded;
                        _desktop.Total = total;
                    }
                }
                Bump();
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            lock (_sync) _desktop = new ChannelState { Kind = "error", Message = "Download failed: " + ex.Message };
            DiagLog.Log("UpdateManager download failed: " + ex.Message);
            Bump();
            return;
        }

        lock (_sync) _desktop = new ChannelState { Kind = "installing", Version = target.Version };
        Bump();

        try
        {
            DesktopUpdater.StageAndLaunch(zipPath, target.Version!);
            lock (_sync) _desktop = new ChannelState { Kind = "installed", Version = target.Version };
            Bump();
        }
        catch (Exception ex)
        {
            lock (_sync) _desktop = new ChannelState { Kind = "error", Message = "Install failed: " + ex.Message };
            DiagLog.Log("UpdateManager install failed: " + ex.Message);
            Bump();
        }
    }

    public void Skip(string version)
    {
        var c = Config.Load();
        c.SkippedUpdateVersion = version;
        c.Save();
        lock (_sync) _desktop = new ChannelState { Kind = "idle" };
        Bump();
    }

    public void Dismiss()
    {
        lock (_sync)
        {
            if (_desktop.Kind is "available" or "none" or "error")
                _desktop = new ChannelState { Kind = "idle" };
        }
        Bump();
    }

    private async Task<string> DownloadWithProgress(string url, Action<long, long?>? onProgress)
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Forest", "updates");
        Directory.CreateDirectory(dir);
        string name = SafeName(url) ?? ("update-" + Guid.NewGuid().ToString("N") + ".zip");
        string path = Path.Combine(dir, name);

        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.Add("User-Agent", "Forest-Updater");
        using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        long? total = resp.Content.Headers.ContentLength;
        using var src = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var dst = File.Create(path);
        byte[] buf = new byte[81920];
        long downloaded = 0;
        int n;
        while ((n = await src.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
        {
            await dst.WriteAsync(buf, 0, n).ConfigureAwait(false);
            downloaded += n;
            onProgress?.Invoke(downloaded, total);
        }
        return path;
    }

    private static string? SafeName(string url)
    {
        try
        {
            var u = new Uri(url);
            string n = Path.GetFileName(u.LocalPath);
            return string.IsNullOrEmpty(n) ? null : n;
        }
        catch { return null; }
    }

    public static string Sha256Hex(string path)
    {
        using var sha = SHA256.Create();
        using var fs  = File.OpenRead(path);
        byte[] hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
