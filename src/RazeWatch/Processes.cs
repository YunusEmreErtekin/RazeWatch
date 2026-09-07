using System.Management;
using System.Security.Principal;
using System.Threading.Channels;

namespace RazeWatch;

public sealed class Processes : IDisposable
{
    readonly Evidence e;
    readonly List<ManagementEventWatcher> watchers = new();
    readonly Channel<Proc> queue = Channel.CreateBounded<Proc>(new BoundedChannelOptions(512) { FullMode = BoundedChannelFullMode.Wait });
    long starts, stops, queueDrops;
    bool closing;
    readonly DateTimeOffset begin = DateTimeOffset.UtcNow;
    Task? worker;
    readonly CancellationTokenSource enrichStop = new();
    public Processes(Evidence evidence) => e = evidence;
    public void Start()
    {
        worker = Task.Run(async () => {
            await foreach (var item in queue.Reader.ReadAllAsync())
            {
                if(enrichStop.IsCancellationRequested) {Interlocked.Increment(ref queueDrops);continue;}
                try
                {
                    foreach (var p in Query(item.Pid,enrichStop.Token))
                    {
                        if (p.StartUtc > item.Utc.AddMilliseconds(100) || p.StartUtc < item.Utc.AddSeconds(-2)) continue;
                        e.Write("processes.jsonl", p with { Kind = "metadata", Utc = item.Utc, Source = "WMI-enrichment", Detail = "Identity checked against event time; hash collected later." });
                    }
                }
                catch (Exception ex) { e.Write("sensor-errors.jsonl", new { Utc = DateTimeOffset.UtcNow, Module = "process-enrichment", Pid = item.Pid, Error = ex.Message }); }
            }
        });
        foreach (string kind in new[] { "Start", "Stop" })
        {
            var at = DateTimeOffset.UtcNow;
            try
            {
                var w = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_Process" + kind + "Trace"));
                w.EventArrived += (_, a) => {
                    try
                    {
                        var p = a.NewEvent;
                        var utc = DateTimeOffset.FromFileTime(Convert.ToInt64(p["TIME_CREATED"]));
                        string? sid = p["Sid"] is byte[] bytes ? new SecurityIdentifier(bytes, 0).Value : null;
                        var rec = new Proc(kind.ToLowerInvariant(), utc, Convert.ToInt32(p["ProcessID"]), Convert.ToInt32(p["ParentProcessID"]), p["ProcessName"]?.ToString(), null, null, null, sid, "Win32_Process" + kind + "Trace", "Event-based; path/commandline may be unavailable for exited processes.");
                        e.Write("processes.jsonl", rec);
                        if (kind == "Start") { Interlocked.Increment(ref starts); if (!queue.Writer.TryWrite(rec)) Interlocked.Increment(ref queueDrops); }
                        else Interlocked.Increment(ref stops);
                    }
                    catch (Exception ex) { e.Write("sensor-errors.jsonl", new { Utc = DateTimeOffset.UtcNow, Module = "process-event", Error = ex.Message }); }
                };
                w.Stopped += (_, a) => { if (!closing) e.Status(new Health("process-" + kind, at, DateTimeOffset.UtcNow, "sensor-stopped", (int)a.Status, 0, "Unexpected WMI stop; observation gap begins here.")); };
                w.Start(); watchers.Add(w);
                e.Status(new Health("process-" + kind, at, DateTimeOffset.UtcNow, "active", 0, 0, "WMI event source; provider drop count not exposed. Complete delivery cannot be proven."));
            }
            catch (Exception ex) { e.Status(new Health("process-" + kind, at, DateTimeOffset.UtcNow, ex is UnauthorizedAccessException ? "access-denied" : "unavailable", ex.HResult, 0, ex.Message + "; 10-second snapshots remain incomplete fallback.")); }
        }
    }
    public static List<Proc> Query(int? pid = null,CancellationToken ct=default)
    {
        var result = new List<Proc>();
        var deadline=DateTimeOffset.UtcNow.AddSeconds(8);
        var opts = new System.Management.EnumerationOptions { ReturnImmediately = false, Timeout = TimeSpan.FromSeconds(5) };
        using var search = new ManagementObjectSearcher(new ManagementScope("root\\cimv2"), new ObjectQuery("SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate,CommandLine FROM Win32_Process" + (pid.HasValue ? " WHERE ProcessId=" + pid.Value : "")), opts);
        using var items = search.Get();
        foreach (ManagementObject p in items)
        {
            using (p)
            {
                ct.ThrowIfCancellationRequested();if(DateTimeOffset.UtcNow>deadline)throw new TimeoutException("Process snapshot exceeded 8 s; incomplete snapshot discarded.");
                DateTimeOffset? birth = p["CreationDate"] is string s ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(s)).ToUniversalTime() : null;
                string? sid = null; string detail = "";
                try { using var owner = p.InvokeMethod("GetOwnerSid", null, new InvokeMethodOptions { Timeout = TimeSpan.FromSeconds(1) }); sid = owner?["Sid"]?.ToString(); }
                catch (Exception ex) { detail = "Owner unavailable: " + ex.GetType().Name; }
                result.Add(new Proc("snapshot", DateTimeOffset.UtcNow, Convert.ToInt32(p["ProcessId"]), Convert.ToInt32(p["ParentProcessId"]), p["Name"]?.ToString(), p["ExecutablePath"]?.ToString(), birth, p["CommandLine"]?.ToString(), sid, "Win32_Process-snapshot", detail));
            }
        }
        return result;
    }
    public void Snapshot(string phase)
    {
        var at = DateTimeOffset.UtcNow;
        try { var rows = Query(); foreach (var row in rows) e.Write("processes.jsonl", row); e.Status(new Health("process-snapshot-" + phase, at, DateTimeOffset.UtcNow, rows.Count == 0 ? "success-empty" : "success", 0, rows.Count, "Point-in-time; cannot establish all short-lived processes.")); }
        catch (Exception ex) { e.Status(new Health("process-snapshot-" + phase, at, DateTimeOffset.UtcNow, "error", ex.HResult, 0, ex.Message)); }
    }
    public async Task Stop()
    {
        closing = true;
        enrichStop.Cancel();
        foreach (var w in watchers) { try { w.Stop(); } catch { } w.Dispose(); } watchers.Clear();
        queue.Writer.TryComplete();
        if (worker != null) await worker;
        e.Status(new Health("process-health", begin, DateTimeOffset.UtcNow, queueDrops > 0 ? "degraded" : "stopped", 0, starts + stops, $"Starts={starts}; Stops={stops}; EnrichmentQueueDrops={queueDrops}; provider drops unknown."));
    }
    public void Dispose() { foreach (var w in watchers) w.Dispose(); }
}
