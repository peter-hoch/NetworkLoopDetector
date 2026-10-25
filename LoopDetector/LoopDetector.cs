// =====================================================================================
//  Tests every connected (Up) Ethernet/Wi-Fi interface for Layer-2 loops.
//
//  Run:
//    Windows (admin, Npcap installed):   dotnet run LoopDetector.cs
//    Linux   (root, libpcap installed):  sudo -E env "PATH=$PATH" dotnet run LoopDetector.cs
//
//  Options:
//    --frames <n>      test frames per interface        (default 3)
//    --baseline <sec>  broadcast measurement window      (default 3)
//    --wait <sec>      time to wait for echoes           (default 2)
//    --threshold <n>   broadcast pkts/s = storm          (default 1000)
//
//  Exit code: 0 = no loop, 1 = loop / storm detected, 2 = error
// =====================================================================================

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;

static class Program
{
    static async Task<int> Main(string[] args)
    {
        var opt = Options.Parse(args);

        if (!Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("Must run as Administrator (Windows) or root (Linux) for raw capture/send.");
            return 2;
        }

        // Map MAC -> NetworkInterface for all interfaces that are Up and not loopback/tunnel
        var upNics = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                     && n.GetPhysicalAddress().GetAddressBytes().Length == 6)
            .GroupBy(n => n.GetPhysicalAddress().ToString())
            .ToDictionary(g => g.Key, g => g.First());

        LibPcapLiveDeviceList devices;
        try
        {
            devices = LibPcapLiveDeviceList.Instance;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Cannot enumerate capture devices (Npcap/libpcap installed?): {ex.Message}");
            return 2;
        }

        var targets = devices
            .Where(d => d.MacAddress is not null && upNics.ContainsKey(d.MacAddress.ToString()))
            .GroupBy(d => d.MacAddress.ToString())
            .Select(g => g.First())
            .ToList();

        if (targets.Count == 0)
        {
            Console.WriteLine("No connected Ethernet/Wi-Fi interfaces found.");
            return 0;
        }

        Console.WriteLine($"Testing {targets.Count} interface(s): {opt.Frames} frame(s), " +
                          $"{opt.Baseline.TotalSeconds}s baseline, {opt.Wait.TotalSeconds}s echo wait ...\n");

        var results = await Task.WhenAll(targets.Select(d =>
            Task.Run(() => LoopTester.Test(d, upNics[d.MacAddress.ToString()].Name, opt))));

        Console.WriteLine($"{"Interface",-28} {"MAC",-17} {"Sent",4} {"Seen",5} {"MaxCopies",9} {"Bcast/s",9}  Result");
        Console.WriteLine(new string('-', 100));
        foreach (var r in results)
        {
            Console.WriteLine($"{Trunc(r.Name, 28),-28} {r.Mac,-17} {r.Sent,4} {r.Seen,5} {r.MaxCopies,9} " +
                              $"{r.BroadcastsPerSec,9:F0}  {r.Verdict}{(r.Error is null ? "" : " - " + r.Error)}");
        }

        bool loop = results.Any(r => r.IsLoop);
        Console.WriteLine();
        Console.WriteLine(loop ? "==> LOOP / BROADCAST STORM DETECTED" : "==> No loop detected");
        return loop ? 1 : results.Any(r => r.Error is not null) ? 2 : 0;
    }

    static string Trunc(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}

// -------------------------------------------------------------------------------------

sealed record Options(int Frames, TimeSpan Baseline, TimeSpan Wait, double StormThreshold)
{
    public static Options Parse(string[] a)
    {
        string? Get(string k) { int i = Array.IndexOf(a, k); return i >= 0 && i + 1 < a.Length ? a[i + 1] : null; }
        return new Options(
            int.TryParse(Get("--frames"), out var f) ? f : 3,
            TimeSpan.FromSeconds(double.TryParse(Get("--baseline"), out var b) ? b : 3),
            TimeSpan.FromSeconds(double.TryParse(Get("--wait"), out var w) ? w : 2),
            double.TryParse(Get("--threshold"), out var t) ? t : 1000);
    }
}

sealed record LoopResult(string Name, string Mac, int Sent, int Seen, int MaxCopies,
                         double BroadcastsPerSec, string Verdict, bool IsLoop, string? Error = null);

static class LoopTester
{
    // IEEE 802 "Local Experimental Ethertype 1" – safe for test traffic
    const ushort TestEtherType = 0x88B5;
    static readonly byte[] Broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    public static LoopResult Test(LibPcapLiveDevice dev, string name, Options opt)
    {
        string mac = string.Join(":", dev.MacAddress.GetAddressBytes().Select(b => b.ToString("X2")));
        byte[] srcMac = dev.MacAddress.GetAddressBytes();
        byte[] marker = Guid.NewGuid().ToByteArray();          // unique per interface and run
        var copies = new ConcurrentDictionary<int, int>();      // seq -> times seen
        long broadcasts = 0;

        void OnArrival(object sender, PacketCapture e)
        {
            ReadOnlySpan<byte> d = e.Data;
            if (d.Length < 14) return;

            if (d[..6].SequenceEqual(Broadcast))
                Interlocked.Increment(ref broadcasts);

            ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(12, 2));
            if (etherType == TestEtherType && d.Length >= 34 && d.Slice(14, 16).SequenceEqual(marker))
            {
                int seq = BinaryPrimitives.ReadInt32BigEndian(d.Slice(30, 4));
                copies.AddOrUpdate(seq, 1, (_, c) => c + 1);
            }
        }

        try
        {
            dev.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 100 });
            dev.Filter = "ether broadcast";                     // kernel filter: only broadcasts
            dev.OnPacketArrival += OnArrival;
            dev.StartCapture();

            // 1) Baseline: broadcast rate before we send anything
            Thread.Sleep(opt.Baseline);
            double bps = Interlocked.Read(ref broadcasts) / opt.Baseline.TotalSeconds;

            // 2) Send uniquely marked broadcast frames
            for (int seq = 0; seq < opt.Frames; seq++)
            {
                dev.SendPacket(BuildFrame(srcMac, marker, seq));
                Thread.Sleep(200);
            }

            // 3) Wait for echoes
            Thread.Sleep(opt.Wait);
            dev.StopCapture();
            dev.OnPacketArrival -= OnArrival;

            int seen = copies.Count;
            int maxCopies = copies.IsEmpty ? 0 : copies.Values.Max();

            // The sending NIC normally captures its own outgoing frame once.
            // Every additional copy came back from the network => loop.
            if (maxCopies > 1)
                return new(name, mac, opt.Frames, seen, maxCopies, bps,
                           $"LOOP DETECTED (frame returned {maxCopies - 1}x)", true);

            if (bps > opt.StormThreshold)
                return new(name, mac, opt.Frames, seen, maxCopies, bps,
                           "BROADCAST STORM (possible loop)", true);

            return new(name, mac, opt.Frames, seen, maxCopies, bps, "OK", false);
        }
        catch (Exception ex)
        {
            return new(name, mac, 0, 0, 0, 0, "ERROR", false, ex.Message);
        }
        finally
        {
            try { dev.Close(); } catch { /* ignore */ }
        }
    }

    static byte[] BuildFrame(byte[] srcMac, byte[] marker, int seq)
    {
        var f = new byte[60];                                   // min. Ethernet frame without FCS
        Broadcast.CopyTo(f, 0);                                 // dst
        srcMac.CopyTo(f, 6);                                    // src
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(12), TestEtherType);
        marker.CopyTo(f, 14);                                   // 16-byte marker
        BinaryPrimitives.WriteInt32BigEndian(f.AsSpan(30), seq);// sequence number
        return f;                                               // rest = zero padding
    }
}
