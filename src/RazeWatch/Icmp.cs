using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace RazeWatch;

public record IcmpEvent(DateTimeOffset Utc, long RecordId, int EventId, string Protocol,
    int? Pid, string Application, string Direction, string SourceAddress, string DestinationAddress,
    string Decision, string Source);

// WFP authorization events are not individual packets or proof of a successful reply.
public sealed class Icmp : IDisposable
{
    readonly Evidence evidence;
    readonly object gate = new();
    EventLogWatcher? watcher;
    bool stopped;
    long count, errors;
    readonly DateTimeOffset started = DateTimeOffset.UtcNow;
    public Icmp(Evidence evidence) => this.evidence = evidence;
    public static IcmpEvent? Parse(string xml, string source)
    {
        var doc = XElement.Parse(xml); XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var system = doc.Element(ns + "System");
        if ((string?)system?.Element(ns + "Provider")?.Attribute("Name") != "Microsoft-Windows-Security-Auditing" ||
            (string?)system?.Element(ns + "Channel") != "Security") return null;
        if (!int.TryParse((string?)system.Element(ns + "EventID"), out int id) || id is not (5156 or 5157)) return null;
        var fields = doc.Element(ns + "EventData")?.Elements(ns + "Data")
            .GroupBy(x => (string?)x.Attribute("Name") ?? "").ToDictionary(x => x.Key, x => x.Last().Value) ?? new();
        string F(string name) => fields.GetValueOrDefault(name, "");
        if (F("Protocol") is not ("1" or "58")) return null;
        if (!DateTimeOffset.TryParse((string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time) ||
            !long.TryParse((string?)system.Element(ns + "EventRecordID"), out long record) ||
            !IPAddress.TryParse(F("SourceAddress"), out _) || !IPAddress.TryParse(F("DestAddress"), out _))
            throw new FormatException("Incomplete ICMP WFP event; time, record ID and valid addresses are required.");
        string pidText = F("ProcessID"); if (pidText.Length == 0) pidText = F("ProcessId");
        bool hex = pidText.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        int? pid = uint.TryParse(hex ? pidText[2..] : pidText, hex ? NumberStyles.HexNumber : NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var number) && number <= int.MaxValue ? (int)number : null;
        return new(time.ToUniversalTime(), record, id, F("Protocol") == "1" ? "ICMPv4" : "ICMPv6", pid,
            F("Application"), F("Direction") switch { "%%14592" => "Inbound", "%%14593" => "Outbound", var other => other },
            F("SourceAddress"), F("DestAddress"), id == 5156 ? "Allowed" : "Blocked", source);
    }
    public void Start()
    {
        try {
            uint flags = AuditPolicy.FilteringConnectionFlags();
            evidence.Save("icmp-audit-status.json", new { Utc = DateTimeOffset.UtcNow, Subcategory = AuditPolicy.FilteringConnectionGuid, RawFlags = flags, SuccessEnabled = (flags & 1) != 0, FailureEnabled = (flags & 2) != 0, PolicyModified = false });
            evidence.Status(new Health("icmp-audit", started, DateTimeOffset.UtcNow, (flags & 3) == 3 ? "success" : "degraded", null, 0,
                $"Success={(flags & 1) != 0}; Failure={(flags & 2) != 0}. Missing auditing cannot be recovered retrospectively. System policy only; per-user overrides or later policy changes may differ."));
        } catch (Exception ex) { evidence.Status(new Health("icmp-audit", started, DateTimeOffset.UtcNow, "unavailable", ex.HResult, 0, ex.Message)); }
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=5156 or EventID=5157)]] and *[EventData[Data[@Name='Protocol']='1' or Data[@Name='Protocol']='58']]");
            watcher = new EventLogWatcher(query, null, false);
            watcher.EventRecordWritten += Receive; watcher.Enabled = true;
            evidence.Status(new Health("icmp-live", started, DateTimeOffset.UtcNow, "active", 0, 0,
                "Security WFP subscription active; requires Filtering Platform Connection auditing. Subscription alone does not prove event coverage. No audit policy changed."));
        }
        catch (Exception ex) { errors++; evidence.Status(new Health("icmp-live", started, DateTimeOffset.UtcNow, "unavailable", ex.HResult, 0, ex.Message)); }
    }
    void Receive(object? sender, EventRecordWrittenEventArgs args)
    {
        using var record = args.EventRecord;
        lock (gate)
        {
            if (stopped) return;
            try
            {
                if (args.EventException != null) throw args.EventException;
                if (record == null) return;
                string xml = record.ToXml();
                var row = Parse(xml, "live-wfp");
                if (row != null && evidence.Write("icmp-live.jsonl", row))
                {
                    count++;
                    evidence.Write("icmp-raw.jsonl", new { row.Utc, row.RecordId, Xml = xml });
                }
            }
            catch (Exception ex) { errors++; if (errors <= 10) evidence.Status(new Health("icmp-live", started, DateTimeOffset.UtcNow, "error", ex.HResult, count, ex.Message)); }
        }
    }
    public void Dispose()
    {
        lock (gate) { if (stopped) return; stopped = true; }
        watcher?.Dispose();
        evidence.Status(new Health("icmp-live", started, DateTimeOffset.UtcNow, errors > 0 ? "degraded" : "stopped", null, count,
            $"Errors={errors}. Zero records does not establish absence of ICMP; audit policy, filters and observation window affect coverage."));
    }
    public static bool Matches(IcmpEvent row, string text) => text.Split(new[] { ',', ';', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Any(s => IPAddress.TryParse(s, out var ip) && (ip.Equals(IPAddress.Parse(row.SourceAddress)) || ip.Equals(IPAddress.Parse(row.DestinationAddress))));
    public static string Report(Evidence e, Options opts, List<Finding> findings)
    {
        var rows = Analysis.Read<IcmpEvent>(e.FilePath("icmp-live.jsonl"));
        foreach (var file in Directory.EnumerateFiles(e.Root, "events-*.jsonl"))
            foreach (var line in File.ReadLines(file))
            {
                try { using var doc = JsonDocument.Parse(line); if (doc.RootElement.TryGetProperty("Xml", out var xml)) { var row = Parse(xml.GetString()!, "historical-wfp"); if (row != null) rows.Add(row); } }
                catch (Exception ex) when (ex is FormatException or System.Xml.XmlException or JsonException)
                { e.Status(new Health("icmp-parser", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "parse-error", null, 0, Path.GetFileName(file) + ": " + ex.Message)); }
            }
        rows = rows.DistinctBy(r => (r.Utc, r.RecordId, r.EventId, r.Protocol, r.Pid, r.Application, r.SourceAddress, r.DestinationAddress, r.Direction)).OrderBy(r => r.Utc).ToList();
        e.Save("icmp-events.json", rows);
        using (var csv = e.OpenText("icmp-events.csv", bom: true))
        {
            csv.WriteLine("utc,protocol,event_id,record_id,pid,application,direction,source_address,destination_address,decision,ioc_match,source");
            foreach (var r in rows) csv.WriteLine(string.Join(",", new[] { r.Utc.ToString("O"), r.Protocol, r.EventId.ToString(), r.RecordId.ToString(), r.Pid?.ToString(), r.Application, r.Direction, r.SourceAddress, r.DestinationAddress, r.Decision, Matches(r, opts.Ioc).ToString(), r.Source }.Select(Analysis.Csv)));
        }
        var sb = new StringBuilder("<h2>ICMP — uygulama ve hedef</h2><p>Windows WFP izin/engel olaylarıdır; paket sayısı, ping aralığı veya başarılı yanıt kanıtı değildir. Uygulama/PID olay kaydından gelir; mevcut PID ile geçmiş süreç eşleştirilmez. Ham kayıtlar icmp-raw.jsonl ve events-*.jsonl içindedir.</p>");
        foreach (var health in e.Health.Where(h => h.Module == "icmp-audit" || h.Module == "icmp-live" && h.Status is "unavailable" or "error" or "degraded"))
            sb.Append("<div class=warn>" + Analysis.Html(health.Module + ": " + health.Status + " — " + health.Detail) + "</div>");
        sb.Append("<p><a href='icmp-events.csv'>ICMP CSV</a> · <a href='icmp-events.json'>ICMP JSON</a></p>");
        if (rows.Count == 0) sb.Append("<div class=warn>ICMP kaydı yok. Bu sonuç trafik olmadığı anlamına gelmez. Yönetici erişimini, Filtering Platform Connection başarı/başarısızlık denetimini ve gözlem süresini kontrol edin.</div>");
        sb.Append("<table><tr><th>UTC / kayıt<th>Uygulama / PID<th>Kaynak → hedef<th>Yön / karar<th>IOC eşleşmesi</tr>");
        foreach (var r in rows.OrderByDescending(r => Matches(r, opts.Ioc)).ThenBy(r => r.Utc).Take(500))
            sb.Append("<tr><td>" + Analysis.Html(r.Utc.ToString("O") + " / " + r.RecordId) + "<td>" + Analysis.Html(r.Application) + " / " + r.Pid + "<td>" + Analysis.Html(r.SourceAddress + " → " + r.DestinationAddress) + "<td>" + Analysis.Html(r.Direction + " / " + r.Decision) + "<td>" + (Matches(r, opts.Ioc) ? "Evet — inceleyin" : "Hayır") + "</tr>");
        foreach (var group in rows.Where(r => Matches(r, opts.Ioc)).GroupBy(r => new { r.Application, r.Pid, r.SourceAddress, r.DestinationAddress, r.Direction, r.Decision }))
            findings.Add(new Finding("icmp-ioc", "priority-review", $"WFP: {group.Key.Application}, PID={group.Key.Pid}, {group.Key.SourceAddress} -> {group.Key.DestinationAddress}, {group.Key.Direction}, {group.Key.Decision}; {group.Count()} authorization records. Not a C2 verdict or packet count.", "icmp-events.csv"));
        sb.Append($"</table><p>{rows.Count} kayıt; HTML ilk 500 kaydı IOC eşleşmeleri önde olacak şekilde gösterir. Tam liste CSV/JSON içindedir.</p>");
        return sb.ToString();
    }
}
