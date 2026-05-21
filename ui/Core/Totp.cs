using System.Security.Cryptography;

namespace Forest;

public static class Totp
{
    public static string Generate(string base32Secret, DateTimeOffset? when = null)
    {
        byte[] key = Base32Decode(base32Secret);
        long counter = (when ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30;

        Span<byte> msg = stackalloc byte[8];
        for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xFF); counter >>= 8; }

        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(key, msg, hash);

        int offset = hash[19] & 0x0F;
        int bin = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                |  (hash[offset + 3] & 0xFF);

        return (bin % 1_000_000).ToString("D6");
    }

    public static int SecondsRemaining(DateTimeOffset? when = null) =>
        30 - (int)((when ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() % 30);

    private static byte[] Base32Decode(string s)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        s = s.Trim().TrimEnd('=').Replace(" ", "").ToUpperInvariant();

        int bits = 0, value = 0;
        var output = new List<byte>(s.Length * 5 / 8);
        foreach (char c in s)
        {
            int idx = alphabet.IndexOf(c);
            if (idx < 0) throw new FormatException($"Invalid base32 character '{c}'.");
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
