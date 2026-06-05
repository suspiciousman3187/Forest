using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Forest;

public static class NativeAssets
{
    private static string? _dir;
    private static readonly object _lock = new();

    public static string RuntimeDir()
    {
        if (_dir != null) return _dir;
        lock (_lock)
        {
            if (_dir != null) return _dir;

            var treesBytes = ReadResource("Trees.dll");
            var waitBytes  = ReadResource("waitinject.exe");

            var combined = new byte[treesBytes.Length + waitBytes.Length];
            Buffer.BlockCopy(treesBytes, 0, combined, 0, treesBytes.Length);
            Buffer.BlockCopy(waitBytes,  0, combined, treesBytes.Length, waitBytes.Length);
            var sha = Convert.ToHexString(SHA256.HashData(combined)).Substring(0, 12);

            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Forest", "bin", sha);
            Directory.CreateDirectory(root);

            WriteIfMissingOrDifferent(Path.Combine(root, "Trees.dll"),      treesBytes);
            WriteIfMissingOrDifferent(Path.Combine(root, "waitinject.exe"), waitBytes);

            _dir = root;
            return _dir;
        }
    }

    public static string TreesDllPath()    => Path.Combine(RuntimeDir(), "Trees.dll");
    public static string WaitInjectPath()  => Path.Combine(RuntimeDir(), "waitinject.exe");

    private static byte[] ReadResource(string name)
    {
        var asm = typeof(NativeAssets).Assembly;
        using var s = asm.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded resource '{name}' missing from Forest.exe.");
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    private const int ERROR_SHARING_VIOLATION = 0x20;
    private const int ERROR_LOCK_VIOLATION    = 0x21;

    private static void WriteIfMissingOrDifferent(string path, byte[] bytes)
    {
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length == bytes.Length) return;
        }
        catch (Exception ex)
        {
            DiagLog.Log($"NativeAssets: size check failed for {path}: {ex.Message}");
        }

        try
        {
            File.WriteAllBytes(path, bytes);
        }
        catch (IOException ex) when ((ex.HResult & 0xFFFF) is ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION)
        {
            DiagLog.Log($"NativeAssets: skipped write of {path} (locked by another process)");
        }
        catch (Exception ex)
        {
            DiagLog.Log($"NativeAssets: WRITE FAILED for {path}: {ex.GetType().Name}: {ex.Message}");
            throw new InvalidOperationException(
                $"Forest could not extract its embedded Trees.dll/waitinject.exe to '{path}'. " +
                "Check disk space, folder permissions, antivirus quarantine, or AppLocker policy.",
                ex);
        }
    }
}
