using System.Xml.Linq;

namespace RazeWatch;
public static class IcmpTests
{
    public static void Run(Action<bool, string> check)
    {
        string Fixture(string protocol = "1", string pid = "0x2a", string provider = "Microsoft-Windows-Security-Auditing", int id = 5156, string destination = "203.0.113.9", string application = @"\device\harddiskvolume3\test.exe")
        {
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            return new XElement(ns + "Event", new XElement(ns + "System", new XElement(ns + "Provider", new XAttribute("Name", provider)),
                new XElement(ns + "EventID", id), new XElement(ns + "Channel", "Security"), new XElement(ns + "EventRecordID", 123),
                new XElement(ns + "TimeCreated", new XAttribute("SystemTime", "2026-09-08T10:00:00Z"))),
                new XElement(ns + "EventData", new[] { ("Protocol", protocol), ("ProcessID", pid), ("Application", application),
                    ("Direction", "%%14593"), ("SourceAddress", "192.0.2.1"), ("DestAddress", destination) }
                    .Select(x => new XElement(ns + "Data", new XAttribute("Name", x.Item1), x.Item2)))).ToString();
        }
        var r = Icmp.Parse(Fixture(), "fixture")!;
        check(r.Pid == 42 && r.Protocol == "ICMPv4" && r.Direction == "Outbound" && r.Decision == "Allowed", "ICMP WFP hex PID, direction and allow parsing");
        check(Icmp.Parse(Fixture(pid: "43", id: 5157), "fixture") is { Pid: 43, Decision: "Blocked" }, "ICMP decimal PID and blocked event");
        check(Icmp.Parse(Fixture(pid: "missing"), "fixture")!.Pid == null, "ICMP missing PID not replaced by event provider PID");
        check(Icmp.Parse(Fixture(protocol: "6"), "fixture") == null && Icmp.Parse(Fixture(provider: "untrusted"), "fixture") == null, "ICMP TCP and spoofed provider rejected");
        check(Icmp.Parse(Fixture().Replace(">Security<", ">Application<"), "fixture") == null, "ICMP wrong channel rejected");
        var v6 = Icmp.Parse(Fixture(protocol: "58", destination: "2001:db8::1"), "fixture")!;
        check(Icmp.Matches(v6, "2001:0db8:0:0:0:0:0:1"), "ICMP IPv6 canonical IOC comparison");
        check(!Icmp.Matches(r, "203.0.113.90"), "ICMP IOC exact address only");
        bool rejected = false;
        try { Icmp.Parse(Fixture(destination: "garbage"), "fixture"); } catch (FormatException) { rejected = true; }
        check(rejected, "ICMP malformed address fails explicitly");
        string root = Path.Combine(Path.GetTempPath(), "RazeWatch-icmp-tests-" + Guid.NewGuid().ToString("N"));
        using var e = new Evidence(root, 16);
        string xml = Fixture(application: "<img src=x onerror=alert(1)>");
        e.Write("icmp-live.jsonl", Icmp.Parse(xml, "live-wfp")!);
        e.Write("events-00.jsonl", new { Xml = xml }); e.CloseStreams();
        var findings = new List<Finding>();
        var html = Icmp.Report(e, new Options(Ioc: "203.0.113.9"), findings);
        check(Analysis.Read<System.Text.Json.JsonElement>(e.FilePath("events-00.jsonl")).Count == 1 && findings.Count == 1 && html.Contains("1 kayıt;"), "ICMP live/history deduplicated with IOC finding");
        check(!html.Contains("<img src=x") && html.Contains("&lt;img"), "ICMP application HTML injection escaped");
        check(File.ReadAllLines(e.FilePath("icmp-events.csv")).Length == 2, "ICMP CSV includes one deduplicated record");
    }
}
