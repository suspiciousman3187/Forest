using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Forest;

public static class PolProxy
{
    private const int    Port      = 51304;
    private const string PolHost   = "wh000.pol.com";
    private const string Sentinel  = "# Forest POL-Proxy (auto-managed)";
    private const string FastPml   =
        "<pml><head><meta http-equiv=\"Content-Type\" " +
        "content=\"text/x-playonline-pml;charset=UTF-8\"><title>Fast</title>" +
        "</head><body><timer name=\"fast\" href=\"gameto:1\" enable=\"1\" " +
        "delay=\"0\"></body></pml>";

    private static readonly string HostsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "drivers", "etc", "hosts");

    private static TcpListener? _listener;
    private static CancellationTokenSource? _cts;
    private static string _upstream = "202.67.54.55";
    private static readonly object _gate = new();
    public static bool Running { get; private set; }
    public static Action<string>? Log;

    public static event Action<int>? FastServed;

    private static void L(string s) => Log?.Invoke("[polproxy] " + s);

    public static void CleanHosts()
    {
        try
        {
            if (!File.Exists(HostsPath)) return;
            var lines = File.ReadAllLines(HostsPath);
            var kept = lines.Where(l => !l.Contains(Sentinel)).ToArray();
            if (kept.Length != lines.Length)
            {
                File.WriteAllLines(HostsPath, kept);
                L("cleaned stale hosts entries");
            }
        }
        catch (Exception ex) { L("CleanHosts failed: " + ex.Message); }
    }

    private static void AddHosts()
    {
        CleanHosts();
        var entry = $"127.0.0.1\t{PolHost}\t{Sentinel}";
        var text = File.Exists(HostsPath) ? File.ReadAllText(HostsPath) : "";
        if (!text.EndsWith("\n") && text.Length > 0) text += Environment.NewLine;
        File.AppendAllText(HostsPath, entry + Environment.NewLine);
        L($"hosts: {PolHost} -> 127.0.0.1");
    }

    public static void Start(Config cfg)
    {
        lock (_gate)
        {
            if (Running) return;

            CleanHosts();
            _upstream = ResolveUpstream(cfg);

            try { AddHosts(); }
            catch (Exception ex)
            {
                L("hosts edit FAILED (need admin): " + ex.Message);
                throw new InvalidOperationException(
                    "Could not edit the hosts file (admin required): "
                    + ex.Message);
            }

            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _listener.Start();
            Running = true;
            L($"listening on 127.0.0.1:{Port}, upstream {_upstream}");
            _ = AcceptLoop(_listener, _cts.Token);
        }
    }

    public static void Stop()
    {
        lock (_gate)
        {
            if (!Running) { CleanHosts(); return; }
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            _listener = null; _cts = null;
            Running = false;
            CleanHosts();
            L("stopped + hosts restored");
        }
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    private static extern bool DnsFlushResolverCache();

    private static string ResolveUpstream(Config cfg)
    {
        try { DnsFlushResolverCache(); } catch { }
        try
        {
            var ip = Dns.GetHostAddresses(PolHost)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork
                                  && !IPAddress.IsLoopback(a));
            if (ip != null) { L($"resolved {PolHost} -> {ip} (region upstream)"); return ip.ToString(); }
            L($"{PolHost} resolved to loopback/none; using fallback upstream.");
        }
        catch (Exception ex) { L($"resolve {PolHost} failed: {ex.Message}"); }

        var fb = string.IsNullOrWhiteSpace(cfg.PolProxyUpstream) ? "202.67.54.55" : cfg.PolProxyUpstream!.Trim();
        L($"fallback upstream {fb}");
        return fb;
    }

    private static async Task AcceptLoop(TcpListener l, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await l.AcceptTcpClientAsync(ct); }
            catch { break; }
            _ = Task.Run(() => Handle(c), ct);
        }
    }

    private static async Task Handle(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var cs = client.GetStream();

                var head = await ReadHead(cs);
                if (head.Length == 0) return;
                var reqText = Encoding.ASCII.GetString(head);
                var firstLine = reqText.Split('\n')[0].Trim();
                var parts = firstLine.Split(' ');
                string path = parts.Length >= 2 ? parts[1] : "/";

                byte[] upstream = await Upstream(reqText);
                var upHead = upstream.Length > 0
                    ? Encoding.ASCII.GetString(upstream, 0, Math.Min(upstream.Length, 48)).Split('\n')[0].Trim()
                    : "(empty)";
                L($"req: {firstLine} | upstream {_upstream} -> {upstream.Length}B [{upHead}]");

                if (PathOf(path) == "/pml/main/index.pml")
                {
                    await WriteSwapped(cs, upstream);
                    await cs.FlushAsync();

                    if (client.Client.RemoteEndPoint is IPEndPoint ep)
                    {
                        int pid = GetTcpOwnerPid(ep.Port);
                        if (pid > 0)
                        {
                            L($"fast page served to pol.exe pid {pid}");
                            try { FastServed?.Invoke(pid); } catch { }
                        }
                    }
                }
                else
                {
                    await cs.WriteAsync(upstream);
                    await cs.FlushAsync();
                }
            }
            catch (Exception ex) { L("conn error: " + ex.Message); }
        }
    }

    private static string PathOf(string p)
    {
        int q = p.IndexOf('?');
        return q >= 0 ? p[..q] : p;
    }

    private static async Task<byte[]> ReadHead(NetworkStream s)
    {
        var buf = new List<byte>(1024);
        var one = new byte[1];
        int idle = 0;
        while (buf.Count < 16384)
        {
            int n;
            try { n = await s.ReadAsync(one.AsMemory(0, 1)); }
            catch { break; }
            if (n == 0) break;
            buf.Add(one[0]);
            int c = buf.Count;
            if (c >= 4 && buf[c-4]==13 && buf[c-3]==10 &&
                buf[c-2]==13 && buf[c-1]==10) break;
            if (++idle > 65535) break;
        }
        return buf.ToArray();
    }

    private static async Task<byte[]> Upstream(string reqText)
    {

        var lines = reqText.Replace("\r\n", "\n").Split('\n').ToList();
        lines.RemoveAll(x => x.StartsWith("Connection:",
            StringComparison.OrdinalIgnoreCase) ||
            x.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase));

        int blank = lines.FindIndex(string.IsNullOrEmpty);
        if (blank < 0) blank = lines.Count;
        lines.Insert(blank, "Connection: close");
        var outReq = string.Join("\r\n", lines.Where(x => x.Length > 0))
                     + "\r\n\r\n";

        using var up = new TcpClient();
        await up.ConnectAsync(IPAddress.Parse(_upstream), Port);
        using var us = up.GetStream();
        await us.WriteAsync(Encoding.ASCII.GetBytes(outReq));
        await us.FlushAsync();

        using var ms = new MemoryStream();
        var b = new byte[8192];
        while (true)
        {
            int n;
            try { n = await us.ReadAsync(b); } catch { break; }
            if (n <= 0) break;
            ms.Write(b, 0, n);
        }
        return ms.ToArray();
    }

    private static async Task WriteSwapped(NetworkStream cs, byte[] upstream)
    {
        int sep = IndexOfCrlfCrlf(upstream);
        string headers = sep >= 0
            ? Encoding.ASCII.GetString(upstream, 0, sep)
            : "HTTP/1.1 200 OK";
        var body = Encoding.UTF8.GetBytes(FastPml);

        var hl = headers.Replace("\r\n", "\n").Split('\n')
            .Where(h => !h.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)
                     && !h.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase)
                     && !h.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase))
            .ToList();
        hl.Add($"Content-Length: {body.Length}");
        hl.Add("Connection: close");
        var outHead = string.Join("\r\n", hl) + "\r\n\r\n";

        await cs.WriteAsync(Encoding.ASCII.GetBytes(outHead));
        await cs.WriteAsync(body);
        L("served fast index.pml (skip POL loading)");
    }

    private static int IndexOfCrlfCrlf(byte[] d)
    {
        for (int i = 0; i + 3 < d.Length; i++)
            if (d[i]==13 && d[i+1]==10 && d[i+2]==13 && d[i+3]==10) return i;
        return -1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTable, ref int size,
        bool order, int af, int tableClass, int reserved);

    private static int GetTcpOwnerPid(int polLocalPort)
    {
        const int AF_INET = 2, TCP_TABLE_OWNER_PID_ALL = 5;
        try
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, false, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0) != 0) return 0;
                int n = Marshal.ReadInt32(buf);
                IntPtr row = buf + 4;
                int rs = Marshal.SizeOf<MibTcpRowOwnerPid>();
                for (int i = 0; i < n; i++)
                {
                    var r = Marshal.PtrToStructure<MibTcpRowOwnerPid>(row);
                    int lp = ((int)(r.localPort & 0xff) << 8) |
                             (int)((r.localPort >> 8) & 0xff);
                    int rp = ((int)(r.remotePort & 0xff) << 8) |
                             (int)((r.remotePort >> 8) & 0xff);
                    if (lp == polLocalPort && rp == Port)
                        return (int)r.owningPid;
                    row += rs;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch (Exception ex) { L("GetTcpOwnerPid failed: " + ex.Message); }
        return 0;
    }
}
