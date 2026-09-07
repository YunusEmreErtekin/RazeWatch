using System.Net;
using System.Text;
using System.Text.Json;

namespace RazeWatch;

public record Identity(string Id, int Pid, int? ParentPid, DateTimeOffset Birth, DateTimeOffset? End, string? Name, string? Path, string Source, bool ExactBirth);
public record Finding(string Rule, string Severity, string Reason, string Evidence, string? Identity = null);
public static class Analysis
{
    public static string Html(string? text) => WebUtility.HtmlEncode(text ?? "");
    public static string Csv(string? text)
    {
        text ??= "";
        if (text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@') || text.StartsWith('\t') || text.StartsWith('\r') || text.StartsWith('\n')) text = "'" + text;
        return "\"" + text.Replace("\"", "\"\"") + "\"";
    }
    public static List<T> Read<T>(string path)
    {
        var rows = new List<T>(); if (!File.Exists(path)) return rows;
        foreach (var line in File.ReadLines(path)) { var row = JsonSerializer.Deserialize<T>(line); if (row != null) rows.Add(row); }
        return rows;
    }
    public static List<Identity> Identities(List<Proc> raw)
    {
        var result=new List<Identity>();
        foreach(var group in raw.GroupBy(p=>p.Pid)) {
            var starts=group.Where(p=>p.Kind=="start").OrderBy(p=>p.Utc).ToList();
            var metadata=group.Where(p=>p.StartUtc.HasValue).ToList();
            var exact=metadata.Select(p=>p.StartUtc!.Value).Distinct().OrderBy(x=>x).ToList();
            var candidates=exact.Select(b=>(Birth:b,Row:metadata.First(p=>p.StartUtc==b),Exact:true)).ToList();
            foreach(var ev in starts) {
                bool linked=metadata.Any(p=>p.Kind=="metadata" && p.Utc==ev.Utc);
                var nearby=exact.Where(b=>Math.Abs((b-ev.Utc).TotalMilliseconds)<=100).ToList();
                bool competing=starts.Any(x=>x!=ev && Math.Abs((x.Utc-ev.Utc).TotalMilliseconds)<=200);
                if(!linked && !(nearby.Count==1 && !competing)) candidates.Add((ev.Utc,ev,false));
            }
            foreach(var item in candidates.OrderBy(x=>x.Birth)) {
                var next=exact.Where(x=>x>item.Birth).Select(x=>(DateTimeOffset?)x).FirstOrDefault();
                // An unmatched approximate event must not truncate an exact lifetime.
                var stop=group.Where(p=>p.Kind=="stop" && p.Utc>=item.Birth).OrderBy(p=>p.Utc).Select(p=>(DateTimeOffset?)p.Utc).FirstOrDefault();
                var end=stop.HasValue && (!next.HasValue || stop<next)?stop:next;
                result.Add(new Identity($"{group.Key}@{item.Birth:O}",group.Key,item.Row.ParentPid,item.Birth,end,item.Row.Name,item.Row.Path,item.Exact?"creation-time":"event-time",item.Exact));
            }
        }
        return result;
    }
    public static HashSet<string> CollectorIdentities(List<Identity> ids,IEnumerable<(int Pid,DateTimeOffset Birth)> roots)
    {
        var marked=new HashSet<string>();
        foreach(var root in roots) {var match=ids.Where(p=>p.Pid==root.Pid && Math.Abs((p.Birth-root.Birth).TotalMilliseconds)<1).ToList();if(match.Count==1)marked.Add(match[0].Id);}
        bool changed;
        do {changed=false;foreach(var child in ids.Where(p=>!marked.Contains(p.Id))){var parents=ids.Where(p=>p.Pid==child.ParentPid && p.Birth<=child.Birth && (!p.End.HasValue||p.End>child.Birth)).ToList();if(parents.Count==1 && marked.Contains(parents[0].Id)){marked.Add(child.Id);changed=true;}}}while(changed);
        return marked;
    }
    public sealed class Episodes
    {
        readonly Dictionary<string,(DateTimeOffset Last,int Count)> state=new();
        public void Observe(string key,DateTimeOffset utc) {var prev=state.GetValueOrDefault(key);state[key]=(utc,prev.Count==0?1:prev.Count+((utc-prev.Last).TotalSeconds>=3?1:0));}
        public IEnumerable<(string Key,int Count)> Results=>state.Select(x=>(x.Key,x.Value.Count));
    }
    public static List<Identity> Candidates(Flow f, List<Identity> ids) => ids.Where(p => p.Pid == f.Pid && p.Birth <= f.EndUtc && (!p.End.HasValue || p.End >= f.Utc)).ToList();
    public static string Confidence(Flow f, List<Identity> candidates) => candidates.Count != 1 ? candidates.Count == 0 ? "unresolved" : "ambiguous" : candidates[0].Birth <= f.Utc && (!candidates[0].End.HasValue || candidates[0].End > f.EndUtc) ? "consistent-owner-pid" : "boundary-ambiguous";
    public static void Report(Evidence e, Options opts, object session)
    {
        e.CloseStreams();
        var raw = Read<Proc>(e.FilePath("processes.jsonl")); var ids = Identities(raw);
        var findings = new List<Finding>();
        var roots=Read<JsonElement>(e.FilePath("collector-children.jsonl")).Where(x=>x.TryGetProperty("BirthUtc",out _)).Select(x=>(x.GetProperty("Pid").GetInt32(),x.GetProperty("BirthUtc").GetDateTimeOffset())).ToList();
        if(File.Exists(e.FilePath("capabilities.json"))) {using var cap=JsonDocument.Parse(File.ReadAllText(e.FilePath("capabilities.json")));if(cap.RootElement.TryGetProperty("CollectorBirthUtc",out var birth))roots.Add((cap.RootElement.GetProperty("CollectorPid").GetInt32(),birth.GetDateTimeOffset()));}
        var children=CollectorIdentities(ids,roots);var episodes=new Episodes();
        using var csv = e.OpenText("flows.csv",bom:true);
        csv.WriteLine("utc,protocol,pid,local_address,local_port,remote_address,remote_port,state,identity,confidence,collector_identity_observed");
        var destinations = new Dictionary<string, HashSet<string>>(); var ports = new Dictionary<string, HashSet<int>>();
        var flowCount = 0; var unresolved = 0;
        foreach (var f in StreamFlows(e.FilePath("flows.jsonl")))
        {
            var candidates = Candidates(f, ids); string confidence = Confidence(f, candidates);
            string id = candidates.Count == 1 ? candidates[0].Id : string.Join(";", candidates.Select(p => p.Id));
            csv.WriteLine(string.Join(",", new[] { f.Utc.ToString("O"), f.Protocol, f.Pid.ToString(), f.LocalAddress, f.LocalPort.ToString(), f.RemoteAddress, f.RemotePort?.ToString(), f.State, id, confidence, (candidates.Count==1 && children.Contains(candidates[0].Id)).ToString() }.Select(Csv)));
            flowCount++; if (confidence != "consistent-owner-pid") unresolved++;
            if (confidence == "consistent-owner-pid" && f.Protocol == "TCP" && f.RemoteAddress is not (null or "0.0.0.0" or "::") && f.RemotePort > 0)
            {
                if (!destinations.ContainsKey(id)) { destinations[id] = new(); ports[id] = new(); }
                if(f.State=="5")episodes.Observe(id+"|"+f.RemoteAddress+"|"+f.RemotePort,f.Utc);
                destinations[id].Add(f.RemoteAddress); ports[id].Add(f.RemotePort.Value);
                if (Iocs(opts.Ioc).Contains(f.RemoteAddress, StringComparer.OrdinalIgnoreCase)) findings.Add(new Finding("ioc-ip", "review", "Observed TCP remote endpoint exactly matches supplied IP; no C2 verdict.", "flows.csv", id));
            }
        }
        csv.Dispose();
        foreach(var ep in episodes.Results.Where(x=>x.Count>=5))findings.Add(new Finding("repeated-observed-endpoint","review",$"{ep.Count} observed ESTABLISHED episodes to same remote endpoint, threshold 5; at least 3 seconds between observations starts a new episode. Poll gaps can cause false separation; not proof of reconnect or periodicity.","flows.csv",ep.Key));
        e.Save("collector-identities.json",children);
        e.Save("endpoint-episodes.json",episodes.Results.Select(x=>new {x.Key,x.Count}));
        foreach (var (id, targets) in destinations)
        {
            if (targets.Count >= 20 || ports[id].Count >= 10) findings.Add(new Finding("many-endpoints", "review", $"Observed distinct remote IPs={targets.Count} (threshold 20), ports={ports[id].Count} (threshold 10). Snapshot coverage; not a scanning verdict.", "flows.csv", id));
            var child = ids.First(x => x.Id == id);
            if (new[] { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe" }.Contains(child.Name?.ToLowerInvariant()))
            {
                var parents = ids.Where(p => p.Pid == child.ParentPid && p.Birth <= child.Birth && (!p.End.HasValue || p.End > child.Birth)).ToList();
                if (parents.Count == 1 && new[] { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe" }.Contains(parents[0].Name?.ToLowerInvariant()))
                    findings.Add(new Finding("office-script-network", "review", "Single lifetime-compatible Office parent, script child and observed TCP endpoint. Investigate business context; parent linkage uses sampled PID/lifetime evidence.", "processes.jsonl", id));
            }
        }
        var diff = new List<object>();
        foreach (string module in new[] { "network", "hosts", "system", "persistence", "registry", "security", "firewall" })
        {
            var before = InventoryRows(e.FilePath("baseline-" + module + ".jsonl")); var after = InventoryRows(e.FilePath("final-" + module + ".jsonl"));
            var beforeKinds = before.Select(x => x.Kind).ToHashSet(); var afterKinds = after.Select(x => x.Kind).ToHashSet();
            foreach (var kind in beforeKinds.Union(afterKinds))
            {
                bool comparable = ModuleSuccess(e, "baseline-" + module + "/" + kind) && ModuleSuccess(e, "final-" + module + "/" + kind);
                var b = before.Where(x => x.Kind == kind).Select(x => x.Data).ToHashSet(); var a = after.Where(x => x.Kind == kind).Select(x => x.Data).ToHashSet();
                var added = a.Except(b).ToArray(); var removed = b.Except(a).ToArray();
                if (added.Length + removed.Length > 0)
                {
                    diff.Add(new { Module = module, Kind = kind, Comparable = comparable, Added = added, Removed = removed });
                    if (comparable && (module is "persistence" or "registry" or "firewall" || kind is "services" or "defender-exclusions")) findings.Add(new Finding("inventory-change", "review", $"{kind}: {added.Length} new/changed, {removed.Length} removed/changed records. Threshold 1; inventory intervals differ and changes are not automatically malicious.", "inventory-diff.json"));
                }
            }
        }
        foreach (var file in Directory.EnumerateFiles(e.Root, "events-*.jsonl"))
        {
            foreach (var ev in Read<JsonElement>(file))
            {
                if(ev.TryGetProperty("Fields",out var fields))foreach(var field in fields.EnumerateArray()) {
                    string value=field.GetProperty("Value").GetString()??"";
                    var tokens=value.Split(new[]{',',';',' ','='},StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Select(v=>v.TrimEnd('.'));
                    if(tokens.Any(v=>Iocs(opts.Ioc).Contains(v,StringComparer.OrdinalIgnoreCase)))findings.Add(new Finding("historical-ioc-field","priority-review",$"Exact IOC token in structured field of {ev.GetProperty("Provider")} / {ev.GetProperty("Channel")} / {ev.GetProperty("Id")} record {ev.GetProperty("RecordId")}; provider evidence, not a maliciousness verdict.",Path.GetFileName(file)));
                }
                if (ev.TryGetProperty("Important", out var important) && important.GetBoolean())
                {
                    bool near = DateTimeOffset.TryParse(opts.Incident, out var incident) && ev.GetProperty("Utc").TryGetDateTimeOffset(out var time) && Math.Abs((time - incident).TotalMinutes) <= 15;
                    findings.Add(new Finding(near ? "incident-near-event" : "historical-event", near ? "priority-review" : "context", $"{ev.GetProperty("Provider").GetString()} / {ev.GetProperty("Channel").GetString()} / {ev.GetProperty("Id")} record {ev.GetProperty("RecordId")}; threshold incident ±15 min. Event context required.", Path.GetFileName(file)));
                }
            }
        }
        foreach (var row in Read<JsonElement>(e.FilePath("file-metadata.jsonl")))
            if (row.TryGetProperty("Sha256", out var hash) && Iocs(opts.Ioc).Contains(hash.GetString(), StringComparer.OrdinalIgnoreCase)) findings.Add(new Finding("ioc-hash", "priority-review", "Collected current file SHA256 matches supplied IOC; historical file identity is unproven.", "file-metadata.jsonl"));
        foreach (var file in Directory.EnumerateFiles(e.Root, "*-network.jsonl"))
            foreach (var row in Read<JsonElement>(file).Where(x => x.GetProperty("Kind").GetString() == "dns-cache"))
                foreach (string key in new[] { "Entry", "Name", "Data" })
                    if (row.GetProperty("Data").TryGetProperty(key, out var val) && val.ValueKind == JsonValueKind.String && Iocs(opts.Ioc).Contains(val.GetString()?.TrimEnd('.'), StringComparer.OrdinalIgnoreCase)) findings.Add(new Finding("ioc-dns-cache", "review", "Exact supplied IOC in DNS cache; cache has no reliable process attribution or query time.", Path.GetFileName(file)));
        findings = findings.Distinct().OrderByDescending(x => x.Severity == "priority-review").ToList();
        e.Save("process-identities.json", ids); e.Save("findings.json", findings); e.Save("inventory-diff.json", diff); e.Save("session.json", session);
        e.Save("analysis-summary.json", new { ProcessIdentities = ids.Count, RawProcessRecords = raw.Count, FlowObservations = flowCount, UncertainFlowObservations = unresolved, Findings = findings.Count, Rules = new { ManyRemoteIps = 20, ManyRemotePorts = 10, IncidentWindowMinutes = 15, PersistenceChangeCount = 1 }, Limitations = Limitations });
        var sb = new StringBuilder("<!doctype html><html lang=tr><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\"><title>RazeWatch gözlem raporu</title><style>body{font:15px system-ui;background:#111827;color:#e5e7eb;margin:32px;max-width:1400px}a{color:#7dd3fc}h1,h2{color:#a7f3d0}table{border-collapse:collapse;width:100%;margin:16px 0}td,th{border:1px solid #374151;padding:8px;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}.warn{border-left:4px solid #fbbf24;padding:12px}summary{cursor:pointer}small{color:#9ca3af}</style><h1>RazeWatch • canlı gözlem</h1>");
        sb.Append("<p>Offline inceleme raporu. Gözlenen davranışlar güvenlik hükmü değildir.</p><div class=warn>" + Html(Limitations) + "</div>");
        sb.Append("<h2>Oturum ve olay girdisi</h2><pre>" + Html(JsonSerializer.Serialize(session, new JsonSerializerOptions { WriteIndented = true })) + "</pre>");
        sb.Append($"<p>{ids.Count} süreç kimliği · {flowCount} uç gözlemi · {unresolved} belirsiz ilişki · {findings.Count} inceleme kaydı</p><h2>Bulgular</h2><table><tr><th>Kural / öncelik<th>Gerekçe<th>Kanıt");
        foreach (var f in findings.Take(500)) sb.Append("<tr><td>" + Html(f.Rule + " / " + f.Severity) + "<td>" + Html(f.Reason + " " + f.Identity) + "<td><a href='" + Html(Uri.EscapeDataString(f.Evidence)) + "'>" + Html(f.Evidence) + "</a>");
        sb.Append("</table><p>HTML ilk 500 bulguyu gösterir; tam liste findings.json.</p><h2>Süreç ağacı / yaşam aralıkları</h2><table><tr><th>Süreç<th>PID / PPID<th>UTC başlangıç / bitiş<th>Ebeveyn ilişkisi</tr>");
        foreach (var p in ids.Take(1000))
        {
            var parent = ids.Where(x => x.Pid == p.ParentPid && x.Birth <= p.Birth && (!x.End.HasValue || x.End > p.Birth)).ToList();
            sb.Append("<tr><td>" + Html(p.Name) + "<br><small>" + Html(p.Path) + "</small><td>" + p.Pid + " / " + p.ParentPid + "<td>" + Html(p.Birth.ToString("O") + " / " + p.End?.ToString("O")) + "<td>" + Html(parent.Count == 1 ? parent[0].Id : parent.Count == 0 ? "Ebeveyn gözlenmedi / kayıp" : "Belirsiz: birden fazla aday") + "</tr>");
        }
        sb.Append("</table><h2>Zaman çizelgesi</h2><p>Süreç olayları processes.jsonl, kullanıcı işaretleri timeline.jsonl, ağ gözlemleri flows.csv içinde UTC ile korunur.</p><pre>");
        if (File.Exists(e.FilePath("timeline.jsonl"))) foreach (var line in File.ReadLines(e.FilePath("timeline.jsonl"))) sb.Append(Html(line) + "\n");
        sb.Append("</pre><h2>Veri kapsamı ve sensör sağlığı</h2><table><tr><th>Modül<th>Durum / kayıt<th>Açıklama</tr>");
        foreach (var h in e.Health) sb.Append("<tr><td>" + Html(h.Module) + "<td>" + Html(h.Status) + " / " + h.Records + "<td>" + Html(h.Detail) + "</tr>");
        sb.Append("</table><h2>Manuel sonraki adımlar</h2><ol><li>Alarm zamanı ve yerel saat farkını doğrulayın; ±15 dakika kayıtlarını inceleyin.<li>Erişim yok, kapalı kanal ve eksik tarih aralığı olan kaynakları kurumun yetkili prosedürüyle tamamlayın.<li>İşaretlenen program, hedef ve kalıcılık değişikliğini iş bağlamıyla karşılaştırın.<li>ETL sayaçları adaptör/bileşen düzeyindedir; süreç hacmi veya HTTPS içeriği çıkarımı yapmayın.<li>Manifest bütünlüğünü doğrulayın; hassas raporu onaylı saklama alanında koruyun.</ol><h2>Kanıt dosyaları</h2><ul>");
        foreach (var file in Directory.EnumerateFiles(e.Root).Where(p => Path.GetFileName(p) != "report.html")) { var n = Path.GetFileName(file); sb.Append("<li><a href='" + Html(Uri.EscapeDataString(n)) + "'>" + Html(n) + "</a>"); }
        sb.Append("<li><a href='manifest.json'>manifest.json</a></ul></html>");
        e.SaveText("report.html", sb.ToString());
    }
    static string[] Iocs(string text) => text.Split(new[] { ',', ';', '\r', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(x => x.TrimEnd('.')).ToArray();
    static bool ModuleSuccess(Evidence e, string name) => e.Health.Any(h => h.Module == name && h.Status is "success" or "success-empty");
    static List<(string Kind, string Data)> InventoryRows(string path) => Read<JsonElement>(path).Where(x => x.GetProperty("Kind").GetString() != "module-status").Select(x => (x.GetProperty("Kind").GetString()!, x.GetProperty("Data").GetRawText())).ToList();
    static IEnumerable<Flow> StreamFlows(string path) { if (!File.Exists(path)) yield break; foreach (var line in File.ReadLines(path)) { var row = JsonSerializer.Deserialize<Flow>(line); if (row != null) yield return row; } }
    public const string Limitations = "TCP/UDP 1 saniyelik örneklemedir; aradaki bağlantılar kaçabilir. UDP uzak hedefi, DNS-süreç bağı, paket yükü, HTTPS içeriği ve süreç trafik hacmi ölçülmez. WMI olay kaybı sayacı mevcut değildir. İmza güvenlik hükmü değildir. Prefetch/Amcache/SRUM/LNK/Jump Lists yalnızca sınırlı dosya metadatası; içerik ayrıştırması yok. Yüklü olmayan kullanıcı hive'ları açılmaz. Tekrarlanan TCP satırları yeni bağlantı veya periyodiklik sayılmaz. Yerel JobObject CPU/bellek sınırlarının durumu kapsam tablosundadır; sınır aşımları kısmi sonuç üretebilir.";
}
