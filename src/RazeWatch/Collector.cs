using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;

namespace RazeWatch;

public sealed class Collector
{
    public event Action<string>? Progress;
    Evidence? evidence;
    public string? OutputRoot => evidence?.Root;
    public bool Partial { get; private set; }
    public void Mark(string text) => evidence?.Write("timeline.jsonl", new { Utc = DateTimeOffset.UtcNow, Kind = "user-mark", Text = text.Length > 2000 ? text[..2000] : text });
    public async Task<string> Run(Options o, CancellationToken userStop)
    {
        var root = o.Output ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RazeWatch", "collections", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
        using var e = new Evidence(root, o.MaxMiB); evidence = e;
        ResourceLimits.Activate(e);
        using var observation = CancellationTokenSource.CreateLinkedTokenSource(userStop);
        using var inventoryStop = CancellationTokenSource.CreateLinkedTokenSource(userStop);
        using var processes = new Processes(e);
        using var icmp = new Icmp(e);
        var created = DateTimeOffset.UtcNow; var watch = new Stopwatch(); bool packetOwned = false; bool partial = false;
        Evidence.ExternalBudget? packetBudget = null;
        DateTimeOffset? observationStart = null, observationEnd = null; string reason = "duration-complete";
        long polls = 0, errors = 0; double maxGap = 0, cpuSeconds = 0; long peakWorkingSet = 0;
        Task inventory = Task.CompletedTask, network = Task.CompletedTask, snapshots = Task.CompletedTask, synthetic = Task.CompletedTask, pulses = Task.CompletedTask;
        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        e.Save("capabilities.json", new { SchemaVersion = 1, Version = "0.3.0", Os = Environment.OSVersion.VersionString, Architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(), Admin = admin, CollectorPid = Environment.ProcessId, CollectorBirthUtc = Process.GetCurrentProcess().StartTime.ToUniversalTime(), Utc = created, TimeZone = TimeZoneInfo.Local.Id,
            PowerShell = File.Exists(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell/v1.0/powershell.exe")), Network = "IPHelper IPv4+IPv6 TCP/UDP snapshots; remote UDP unavailable; ICMP via WFP Security events (audit required)", Process = "WMI start/stop requested; actual status in collection-log", Privacy = "No packet payload, credentials/cookies/keys/dumps. Event text and commandlines may incidentally contain sensitive data. No upload." });
        try
        {
            Progress?.Invoke("Yetenek kontrolü; canlı sensörler başlatılıyor…");
            processes.Start();
            icmp.Start();
            observationStart = DateTimeOffset.UtcNow; watch.Start();
            network = Task.Run(async () => {
                double previous = watch.Elapsed.TotalSeconds;
                while (!observation.IsCancellationRequested)
                {
                    double now = watch.Elapsed.TotalSeconds; maxGap = Math.Max(maxGap, now - previous); previous = now;
                    foreach (var af in new[] { 2, 23 }) foreach (bool tcp in new[] { true, false })
                    {
                        var at = DateTimeOffset.UtcNow;
                        try { var rows = Network.Snapshot(af, tcp); foreach (var row in rows) e.Write("flows.jsonl", row); e.Write("network-health.jsonl", new { Utc = at, EndUtc = DateTimeOffset.UtcNow, Family = af, Protocol = tcp ? "TCP" : "UDP", Records = rows.Count, Status = rows.Count == 0 ? "success-empty" : "success" }); }
                        catch (Exception ex) { errors++; e.Write("network-health.jsonl", new { Utc = at, Family = af, Protocol = tcp ? "TCP" : "UDP", Status = "error", Error = ex.Message }); }
                    }
                    polls++;
                    try { await Task.Delay(1000, observation.Token); } catch (OperationCanceledException) { break; }
                }
            });
            snapshots = Task.Run(async () => {
                processes.Snapshot("baseline");
                while (!observation.IsCancellationRequested)
                {
                    try { await Task.Delay(10000, observation.Token); } catch (OperationCanceledException) { break; }
                    if (!observation.IsCancellationRequested) processes.Snapshot("periodic");
                }
            });
            if (!o.NoPacket && admin && File.Exists(Path.Combine(Environment.SystemDirectory, "pktmon.exe")))
            {
                int packetMiB=(int)Math.Min(32,e.DataRemaining/(4*1024*1024));
                packetBudget=packetMiB>=1?e.ReserveExternal("packet-metadata.etl",packetMiB*1024L*1024+128*1024):null;
                if(packetBudget!=null) {
                // PktMon start is atomic and fails if another session exists. Stop only after our successful start.
                var p = await Commands.Run(e, "pktmon-start", Path.Combine(Environment.SystemDirectory, "pktmon.exe"), new[] { "start", "--capture", "--comp", "nics", "--flags", "0x023", "--file-name", e.FilePath("packet-metadata.etl"), "--file-size", packetMiB.ToString(), "--log-mode", "circular" }, 15, userStop);
                packetOwned = p.ExitCode == 0 && p.Status == "success";
                e.Status(new Health("packet-mode", p.StartUtc, p.EndUtc, packetOwned ? "active" : "degraded", p.ExitCode, 0, "Flags 0x023: internal errors + summary/counters + component registration; no raw packet event. 32 MiB circular ETL may overwrite earlier metadata. Existing PktMon filters may constrain counters; see filter listing. Not parsed into flows."));
                if (packetOwned) await Commands.Run(e, "pktmon-filters", Path.Combine(Environment.SystemDirectory, "pktmon.exe"), new[] { "filter", "list" }, 10, userStop);
                } else e.Status(new Health("packet-mode",created,DateTimeOffset.UtcNow,"degraded",null,0,"Insufficient reserved ETL budget; endpoint sensor remains active."));
            }
            else e.Status(new Health("packet-mode", created, DateTimeOffset.UtcNow, "degraded", null, 0, o.NoPacket ? "Disabled by CLI; no ETL." : "Requires existing pktmon and administrator. No elevation or driver installation performed."));
            inventory = Inventory.Collect(e, "baseline", inventoryStop.Token);
            pulses = Task.Run(async () => {
                int i = 0;
                while (!observation.IsCancellationRequested)
                {
                    try { await Task.Delay(60000, observation.Token); } catch (OperationCanceledException) { break; }
                    await Inventory.Collect(e, "pulse-" + (++i).ToString("D2"), observation.Token, false, new[] { "network" });
                }
            });
            if (o.Synthetic) synthetic = Synthetic(e, observation.Token);
            var self = Process.GetCurrentProcess(); var cpuStart = self.TotalProcessorTime;
            while (watch.Elapsed.TotalSeconds < o.Seconds && !userStop.IsCancellationRequested)
            {
                self.Refresh(); peakWorkingSet = Math.Max(peakWorkingSet, self.WorkingSet64); cpuSeconds = (self.TotalProcessorTime - cpuStart).TotalSeconds;
                long bytes = Directory.EnumerateFiles(e.Root).Sum(p => new FileInfo(p).Length);
                if (e.Limited || bytes > (long)o.MaxMiB * 1024 * 1024 || self.WorkingSet64 > 768L * 1024 * 1024)
                { reason = "resource-limit"; partial = true; inventoryStop.Cancel(); break; }
                Progress?.Invoke($"Gözlem: {Math.Max(0, o.Seconds - (int)watch.Elapsed.TotalSeconds)} sn kaldı. " + (watch.Elapsed.TotalSeconds < 120 ? "İlk 2 dakika boşta bırakabilirsiniz." : "Normal uygulamalarınızı kullanıp işlemleri işaretleyebilirsiniz."));
                try { await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(500, Math.Max(1, (o.Seconds - watch.Elapsed.TotalSeconds) * 1000))), userStop); }
                catch (OperationCanceledException) { break; }
            }
            if (userStop.IsCancellationRequested) { partial = true; reason = "user-cancelled"; }
        }
        catch (Exception ex) { partial = true; reason = "collector-error"; e.Status(new Health("collector", created, DateTimeOffset.UtcNow, "error", ex.HResult, 0, ex.Message)); }
        finally
        {
            observationEnd = DateTimeOffset.UtcNow; watch.Stop(); observation.Cancel();
            Progress?.Invoke("Canlı sensörler durduruluyor; kısmi veriler korunuyor…");
            try { await Task.WhenAll(network, snapshots, synthetic, pulses); } catch (Exception ex) { e.Status(new Health("sensor-shutdown", created, DateTimeOffset.UtcNow, "error", ex.HResult, 0, ex.Message)); partial = true; }
            await processes.Stop();
            icmp.Dispose();
            if (packetOwned)
            {
                await Commands.Run(e, "pktmon-counters", Path.Combine(Environment.SystemDirectory, "pktmon.exe"), new[] { "counters" }, 10, CancellationToken.None);
                var stop = await Commands.Run(e, "pktmon-stop", Path.Combine(Environment.SystemDirectory, "pktmon.exe"), new[] { "stop" }, 15, CancellationToken.None);
                if (stop.ExitCode != 0) {
                    await Commands.Run(e,"pktmon-stop-status",Path.Combine(Environment.SystemDirectory,"pktmon.exe"),new[]{"status"},10,CancellationToken.None);
                    var retry=await Commands.Run(e,"pktmon-stop-retry",Path.Combine(Environment.SystemDirectory,"pktmon.exe"),new[]{"stop"},15,CancellationToken.None);
                    partial=true;reason=retry.ExitCode==0?"pktmon-stop-required-retry":"pktmon-stop-failed-manual-action-required";
                }
                bool valid = File.Exists(e.FilePath("packet-metadata.etl")) && new FileInfo(e.FilePath("packet-metadata.etl")).Length > 0;
                e.Status(new Health("packet-artifact", created, DateTimeOffset.UtcNow, valid ? "collected-not-parsed" : "missing-artifact", stop.ExitCode, 0, "ETL existence/size validated only; packet metadata has no process attribution. Counter/drop text retained verbatim."));
            }
            if (partial) inventoryStop.Cancel();
            packetBudget?.Dispose();
            try { await inventory; } catch (Exception ex) { partial = true; e.Status(new Health("inventory-unhandled", created, DateTimeOffset.UtcNow, "error", ex.HResult, 0, ex.Message)); }
        }
        e.Status(new Health("network-sensor", observationStart ?? created, observationEnd.Value, errors == 0 ? "stopped" : "degraded", 0, polls, $"Polls={polls}; errors={errors}; maximum start-to-start gap={maxGap:F3}s; nominal interval=1s; short connections can be missed."));
        if (!partial)
        {
            Progress?.Invoke("Bitiş envanteri ve geçmiş olaylar toplanıyor…");
            processes.Snapshot("final");
            using var finalDeadline=CancellationTokenSource.CreateLinkedTokenSource(userStop);finalDeadline.CancelAfter(TimeSpan.FromMinutes(3));
            await Inventory.Collect(e, "final", finalDeadline.Token, false);
            await Task.Run(() => Events.Collect(e, o, finalDeadline.Token));
            e.CloseStreams();
            await Task.Run(() => Files.Collect(e, finalDeadline.Token));
            if(finalDeadline.IsCancellationRequested){partial=true;reason=userStop.IsCancellationRequested?"user-cancelled":"finalization-timeout";}
        }
        if (userStop.IsCancellationRequested) { partial = true; reason = "user-cancelled"; }
        e.Status(new Health("historical-artifacts", created, DateTimeOffset.UtcNow, "scope-gap", null, 0, "Prefetch/Amcache/SRUM/LNK/Jump Lists: bounded metadata only, no raw acquisition/parser. No locked-file bypass, VSS, hive mount, disk/RAM acquisition."));
        Progress?.Invoke("Offline analiz, rapor ve SHA256 manifest hazırlanıyor…");
        var sessionData = new { SchemaVersion = 1, CreatedUtc = created, ObservationStartUtc = observationStart, ObservationEndUtc = observationEnd, MeasuredObservationSeconds = watch.Elapsed.TotalSeconds, RequestedSeconds = o.Seconds,
            Partial = partial || e.Limited, EndReason = reason, FinalizedUtc = DateTimeOffset.UtcNow, TimeZone = TimeZoneInfo.Local.Id, CollectorPid = Environment.ProcessId, Options = o, NetworkPolls = polls, NetworkErrors = errors, MaximumNetworkGapSeconds = maxGap, PeakCollectorWorkingSetBytes = peakWorkingSet, CollectorCpuSeconds = cpuSeconds, ResourceScope = "Native job: 1 GiB collector+children, 25% CPU when active; child 256 MiB (PktMon stop 768 MiB). WMI service excluded. All managed files share byte budget; control reserve up to 8 MiB. ETL and EVTX reserve bounded external space. See job-limits health." };
        var session=System.Text.Json.JsonSerializer.SerializeToNode(sessionData)!.AsObject();
        session["CoverageStatus"]=e.Health.Any(h=>new[]{"error","timeout","truncated","partial","degraded","scope-gap","unavailable","access-denied","channel-disabled","parse-error"}.Contains(h.Status))?"degraded":"available-with-documented-sensor-limitations";
        session["AnalysisStatus"]="complete";
        Partial = partial || e.Limited;
        try { Analysis.Report(e, o, session); }
        catch (Exception ex)
        {
            Partial = true; session["Partial"]=true;session["AnalysisStatus"]="failed";session["EndReason"]="analysis-failed";
            e.Status(new Health("analysis", created, DateTimeOffset.UtcNow, "parse-error", ex.HResult, 0, ex.Message));
            e.Save("session.json", session);
            e.SaveText("report.html", "<!doctype html><meta charset=utf-8><title>RazeWatch kısmi rapor</title><h1>Analiz tamamlanamadı</h1><p>Ham kanıtlar ve manifest korunmuştur. collection-log.jsonl dosyasını inceleyin.</p><pre>" + Analysis.Html(ex.Message) + "</pre>");
        }
        e.Manifest(); evidence = null;
        Progress?.Invoke("Rapor hazır: " + root); return root;
    }
    public static async Task Synthetic(Evidence e, CancellationToken ct)
    {
        try
        {
            await Task.Delay(2000, ct);
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            try
            {
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                using var client = new TcpClient(); var accept = listener.AcceptTcpClientAsync(ct);
                await client.ConnectAsync(IPAddress.Loopback, port, ct); using var server = await accept;
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                using var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe")) { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { "/d", "/c", "exit", "0" } });
                e.Write("synthetic-expected.jsonl", new { Utc = DateTimeOffset.UtcNow, ChildPid = child?.Id, ParentPid = Environment.ProcessId, TcpPort = port, UdpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port, Address = "127.0.0.1", HoldSeconds = 6, Kind = "authorized-controlled-localhost" });
                if (child != null) await child.WaitForExitAsync(ct);
                await Task.Delay(6000, ct);
            }
            finally { listener.Stop(); }
        }
        catch (OperationCanceledException) { }
    }
}
