using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Forest;

public sealed class CredentialStore
{

    public sealed record Entry(
        string EncPassword,
        string? EncTotpSecret,
        string? WindowerProfile = null,
        int PolSlot = 0,
        string? LaunchArgs = null,
        string? Launcher = null);

    public sealed record Account(
        string Name, string? WindowerProfile, int PolSlot, string? LaunchArgs,
        string? Launcher);

    private static readonly string StorePath =
        Path.Combine(AppData.Dir, "creds.dat");

    private readonly Dictionary<string, Entry> _entries;

    private CredentialStore(Dictionary<string, Entry> entries) => _entries = entries;

    public static CredentialStore Load()
    {
        if (!File.Exists(StorePath))
            return new CredentialStore(new(StringComparer.OrdinalIgnoreCase));

        var json = File.ReadAllText(StorePath);
        var map = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json)
                  ?? new();
        return new CredentialStore(new(map, StringComparer.OrdinalIgnoreCase));
    }

    public IReadOnlyCollection<string> Profiles => _entries.Keys;

    public void Set(string profile, string password, string? totpSecret,
                    string? windowerProfile = null, int polSlot = 0,
                    string? launchArgs = null, string? launcher = null)
    {

        _entries.TryGetValue(profile, out var prev);
        _entries[profile] = new Entry(
            Protect(password),
            string.IsNullOrWhiteSpace(totpSecret) ? null : Protect(totpSecret),
            windowerProfile ?? prev?.WindowerProfile,
            polSlot != 0 ? polSlot : (prev?.PolSlot ?? 0),
            launchArgs ?? prev?.LaunchArgs,
            launcher ?? prev?.Launcher);
        Save();
    }

    public void SetMeta(string profile, string? windowerProfile, int polSlot,
                        string? launchArgs = null, string? launcher = null)
    {
        var e = Require(profile);
        _entries[profile] = e with
        {
            WindowerProfile = windowerProfile ?? e.WindowerProfile,
            PolSlot = polSlot != 0 ? polSlot : e.PolSlot,
            LaunchArgs = launchArgs ?? e.LaunchArgs,
            Launcher = launcher ?? e.Launcher,
        };
        Save();
    }

    public IReadOnlyList<Account> Accounts() =>
        _entries.Select(kv => new Account(
            kv.Key, kv.Value.WindowerProfile, kv.Value.PolSlot,
            kv.Value.LaunchArgs, kv.Value.Launcher)).ToList();

    public Account GetAccount(string profile)
    {
        var e = Require(profile);
        return new Account(profile, e.WindowerProfile, e.PolSlot, e.LaunchArgs,
                           e.Launcher);
    }

    public bool Remove(string profile)
    {
        var removed = _entries.Remove(profile);
        if (removed) Save();
        return removed;
    }

    public bool Rename(string oldName, string newName)
    {
        if (string.Equals(oldName, newName, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!_entries.TryGetValue(oldName, out var e)) return false;
        if (_entries.ContainsKey(newName)) return false;
        _entries.Remove(oldName);
        _entries[newName] = e;
        Save();
        return true;
    }

    public string GetPassword(string profile) =>
        Unprotect(Require(profile).EncPassword);

    public string? GetTotpSecret(string profile)
    {
        var e = Require(profile);
        return e.EncTotpSecret is null ? null : Unprotect(e.EncTotpSecret);
    }

    public void ExportEncryptedPassword(string profile, string path)
    {
        var b64 = Require(profile).EncPassword;
        File.WriteAllBytes(path, Convert.FromBase64String(b64));
    }

    public bool ExportEncryptedTotp(string profile, string path)
    {
        var b64 = Require(profile).EncTotpSecret;
        if (string.IsNullOrEmpty(b64)) return false;
        File.WriteAllBytes(path, Convert.FromBase64String(b64));
        return true;
    }

    private Entry Require(string profile) =>
        _entries.TryGetValue(profile, out var e)
            ? e
            : throw new KeyNotFoundException($"No credentials stored for profile '{profile}'.");

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);
        File.WriteAllText(StorePath,
            JsonSerializer.Serialize(_entries,
                new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string Protect(string plain)
    {
        var bytes = Encoding.UTF8.GetBytes(plain);
        return Convert.ToBase64String(CryptProtect(bytes, encrypt: true));
    }

    private static string Unprotect(string b64)
    {
        var bytes = CryptProtect(Convert.FromBase64String(b64), encrypt: false);
        return Encoding.UTF8.GetString(bytes);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pIn, string? szDescription, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pIn, IntPtr ppszDescription, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pOut);

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    private static byte[] CryptProtect(byte[] input, bool encrypt)
    {
        var inBlob = new DATA_BLOB();
        var outBlob = new DATA_BLOB();
        inBlob.pbData = Marshal.AllocHGlobal(input.Length);
        try
        {
            Marshal.Copy(input, 0, inBlob.pbData, input.Length);
            inBlob.cbData = input.Length;

            bool ok = encrypt
                ? CryptProtectData(ref inBlob, "Forest", IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob);

            if (!ok)
                throw new InvalidOperationException(
                    $"DPAPI {(encrypt ? "encrypt" : "decrypt")} failed (Win32 {Marshal.GetLastWin32Error()}).");

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            Marshal.FreeHGlobal(outBlob.pbData);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(inBlob.pbData);
        }
    }
}
