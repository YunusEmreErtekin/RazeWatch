using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace RazeWatch;

public static class Events
{
    public static readonly string[] Channels = {
        "Security", "System", "Application", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational",
        "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-DNS-Client/Operational" };
    public static bool Important(string provider, string channel, int id) =>
        channel == "Security" && provider == "Microsoft-Windows-Security-Auditing" && new[] { 4624,4625,4648,4672,4688,4697,4698,4702,4720,4732,4719,5156,5157 }.Contains(id) ||
        channel == "Security" && provider == "Microsoft-Windows-Eventlog" && id == 1102 ||
        channel == "System" && (provider == "Service Control Manager" && id == 7045 || provider == "Microsoft-Windows-Eventlog" && id == 104) ||
        (channel == "Microsoft-Windows-PowerShell/Operational" && provider == "Microsoft-Windows-PowerShell" || channel == "PowerShellCore/Operational" && provider == "PowerShellCore") && new[] {4103,4104}.Contains(id) ||
        channel == "Microsoft-Windows-Sysmon/Operational" && provider == "Microsoft-Windows-Sysmon" && new[] {1,3,22}.Contains(id);
    public static void Collect(Evidence e, Options options, CancellationToken ct)
    {
        var from = DateTimeOffset.UtcNow.AddHours(-options.HistoryHours); var to = DateTimeOffset.UtcNow;
        string range = $"*[System[TimeCreated[@SystemTime >= '{from.UtcDateTime:O}' and @SystemTime <= '{to.UtcDateTime:O}']]]";
        foreach (var channel in Channels)
        {
            if (ct.IsCancellationRequested || e.Limited) break;
            var at = DateTimeOffset.UtcNow; long count = 0; string status = "success-empty", detail = ""; long? min = null, max = null;
            var exportIds = new List<(long Id,int XmlBytes)>();
            var name = "events-" + Array.IndexOf(Channels, channel).ToString("D2");
            try
            {
                using var config = new EventLogConfiguration(channel);
                var info = EventLogSession.GlobalSession.GetLogInformation(channel, PathType.LogName);
                using var oldestReader = new EventLogReader(new EventLogQuery(channel, PathType.LogName) { ReverseDirection = false });
                using var oldest = oldestReader.ReadEvent(TimeSpan.FromSeconds(2));
                e.Write("event-coverage.jsonl", new { Channel = channel, Enabled = config.IsEnabled, RequestedFromUtc = from, RequestedToUtc = to, OldestAvailableUtc = oldest?.TimeCreated?.ToUniversalTime(), LogRecords = info.RecordCount, LogBytes = info.FileSize, Limit = options.EventLimit, AuditPolicy = "See audit-policy; empty query is not evidence that auditing is enabled.", CoversRequestedStart = oldest?.TimeCreated?.ToUniversalTime() <= from.UtcDateTime });
                using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName, range) { ReverseDirection = true });
                while (!ct.IsCancellationRequested && !e.Limited)
                {
                    using var ev = reader.ReadEvent(TimeSpan.FromSeconds(2)); if (ev == null) break;
                    if (count >= options.EventLimit) { status = "truncated"; break; }
                    var xml = ev.ToXml();
                    if (xml.Length > 512 * 1024) { status = "truncated"; detail = "Oversized event skipped; EVTX coverage may include it."; continue; }
                    var doc = XElement.Parse(xml); XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                    var fields = doc.Descendants(ns + "Data").Select(x => new { Name = (string?)x.Attribute("Name"), Value = x.Value }).ToArray();
                    e.Write(name + ".jsonl", new { Utc = ev.TimeCreated?.ToUniversalTime(), Channel = channel, Provider = ev.ProviderName, Id = ev.Id, RecordId = ev.RecordId, ProcessId = ev.ProcessId, UserSid = ev.UserId?.Value, Important = Important(ev.ProviderName ?? "", channel, ev.Id), Fields = fields, Xml = xml });
                    if(ev.RecordId.HasValue)exportIds.Add((ev.RecordId.Value,System.Text.Encoding.UTF8.GetByteCount(xml)));
                    min = !min.HasValue ? ev.RecordId : Math.Min(min.Value, ev.RecordId ?? min.Value); max ??= ev.RecordId; count++;
                    if (DateTimeOffset.UtcNow - at > TimeSpan.FromSeconds(20)) { status = "timeout"; break; }
                }
                if (status == "success-empty" && count > 0) status = "success";
                if (!config.IsEnabled) { detail += " Channel disabled; retained history can still exist."; if(count == 0) status = "channel-disabled"; }
                if (oldest?.TimeCreated?.ToUniversalTime() > from.UtcDateTime) detail += " Retained log does not cover requested start.";
                if (min.HasValue && max.HasValue)
                {
                    // Export exactly the bounded record interval. Never clear, enable, or reconfigure logs.
                    try
                    {
                        long ceiling=Math.Min(12L*1024*1024,e.DataRemaining/Math.Max(1,Channels.Length-Array.IndexOf(Channels,channel)));
                        long reserved=1024*1024;var chosen=new List<long>();
                        foreach(var rec in exportIds) {if(chosen.Count>0 && rec.Id!=chosen[^1]-1)break;long cost=Math.Max(65536,rec.XmlBytes*8L);if(reserved+cost>ceiling)break;reserved+=cost;chosen.Add(rec.Id);}
                        if(chosen.Count==0)throw new IOException("EVTX budget unavailable; structured records retained.");
                        using var budget=e.ReserveExternal(name+".evtx",reserved)??throw new IOException("EVTX reservation unavailable");
                        // Export a verified contiguous selection: two predicates avoid Windows XPath complexity limits.
                        string query=$"*[System[EventRecordID >= {chosen.Min()} and EventRecordID <= {chosen.Max()}]]";
                        var exported=Commands.Run(e,name+"-export",Path.Combine(Environment.SystemDirectory,"wevtutil.exe"),new[]{"epl",channel,e.FilePath(name+".evtx"),"/q:"+query},20,ct).GetAwaiter().GetResult();
                        if(exported.ExitCode!=0 || exported.Status is "timeout" or "cancelled")throw new IOException("EVTX command failed; inspect export stdout/stderr and exit code.");
                        using var verify = new EventLogReader(e.FilePath(name + ".evtx"), PathType.FilePath);
                        var actual=new HashSet<long>();
                        while(true){using var entry=verify.ReadEvent(TimeSpan.FromSeconds(2));if(entry==null)break;if(entry.RecordId.HasValue)actual.Add(entry.RecordId.Value);}
                        if(!actual.SetEquals(chosen))throw new IOException("EVTX record IDs differ from requested selection (log rotation/clear possible).");
                        e.Status(new Health(name + "-evtx", at, DateTimeOffset.UtcNow, chosen.Count==count?"success":"truncated", 0, actual.Count, $"EVTX exact record IDs verified. Structured={count}; exported={actual.Count}; reservedBytes={reserved}. Selection limited by output budget."));
                    }
                    catch (Exception ex) { e.Status(new Health(name + "-evtx", at, DateTimeOffset.UtcNow, "unavailable", ex.HResult, 0, ex.Message)); }
                }
            }
            catch (UnauthorizedAccessException ex) { status = "access-denied"; detail = ex.Message; }
            catch (EventLogNotFoundException ex) { status = "unavailable"; detail = ex.Message; }
            catch (Exception ex) { status = "error"; detail = ex.Message; }
            e.Status(new Health(name, at, DateTimeOffset.UtcNow, status, null, count, channel + "; " + detail));
        }
    }
}
