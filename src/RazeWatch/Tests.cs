using System.Security.Cryptography;
using System.Text.Json;

namespace RazeWatch;

public static class Tests
{
    public static int Run(string[] args)
    {
        int count = 0;
        void Check(bool ok, string name) { if (!ok) throw new Exception("FAIL: " + name); Console.WriteLine("PASS " + name); count++; }
        var t = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Proc P(string kind, int pid, int sec, DateTimeOffset? birth = null) => new(kind, t.AddSeconds(sec), pid, 1, "fixture.exe", "C:\\örnek\\fixture.exe", birth, null, null, "fixture", "");
        Flow F(int sec) => new(t.AddSeconds(sec), t.AddSeconds(sec).AddMilliseconds(10), "TCP", 4, 42, "127.0.0.1", 2345, "127.0.0.1", 1234, "5", "fixture");
        var raw = new List<Proc> { P("snapshot",42,1,t), P("stop",42,2), P("snapshot",42,4,t.AddSeconds(3)), P("stop",42,5) };
        var ids = Analysis.Identities(raw);
        Check(ids.Count == 2 && ids[0].Id != ids[1].Id, "PID reuse creates distinct identities");
        Check(Analysis.Candidates(F(1),ids).Single().Birth == t, "first lifetime endpoint correlation");
        Check(Analysis.Candidates(F(4),ids).Single().Birth == t.AddSeconds(3), "reused PID endpoint correlation");
        Check(Analysis.Candidates(F(6),ids).Count == 0, "flow after stop unresolved");
        Check(Analysis.Confidence(F(2),Analysis.Candidates(F(2),ids)) == "boundary-ambiguous", "stop boundary uncertain");
        Check(Analysis.Identities(new(){P("start",7,0),P("stop",7,1)}).Count == 1, "short-lived process without enrichment retained");
        Check(Analysis.Identities(new()).Count == 0, "empty process list");
        var nearby=Analysis.Identities(new(){P("snapshot",42,1,t),P("start",42,0) with {Utc=t.AddMilliseconds(1)}});
        Check(nearby.Count==1 && nearby[0].ExactBirth,"near event without enrichment does not truncate known identity");
        var marked=Analysis.CollectorIdentities(ids,new[]{(42,t)});
        Check(marked.Contains(ids[0].Id)&&!marked.Contains(ids[1].Id),"collector PID reuse does not tag unrelated identity");
        var ep=new Analysis.Episodes();ep.Observe("same",t);ep.Observe("same",t.AddSeconds(1));ep.Observe("same",t.AddSeconds(2));
        Check(ep.Results.Single().Count==1,"poll repetition is one observed episode");ep.Observe("same",t.AddSeconds(5));Check(ep.Results.Single().Count==2,"separated episode threshold is explicit");
        Check(!Files.LocalFile(@"\\server\share\file.exe"),"UNC references rejected before filesystem access");
        Check(Analysis.Html("</script><img src=x onerror=alert(1)>\"&").Contains("&lt;"), "HTML untrusted text encoding");
        foreach(string s in new[]{"=1+1"," +cmd","-2","@SUM(A1)","\t=1","\r=1"}) Check(Analysis.Csv(s).StartsWith("\"'"), "CSV formula neutralization");
        Check(Analysis.Csv("şğü\"i").Contains("\"\""), "CSV Unicode and quotes");
        Check(Events.Important("Microsoft-Windows-Security-Auditing","Security",4688), "provider channel id positive");
        Check(!Events.Important("Untrusted","Security",4688) && !Events.Important("Microsoft-Windows-Security-Auditing","Application",4688), "provider/channel confusion rejected");
        Check(Files.Excluded("C:\\out\\şğ.txt", "C:\\out") && !Files.Excluded("C:\\outside\\a", "C:\\out"), "output path boundary exclusion");
        string temp = Path.Combine(Path.GetTempPath(), "RazeWatch-test-" + Guid.NewGuid().ToString("N"));
        using(var e = new Evidence(temp,1)) {
            bool rejected = false; try{e.FilePath("../escape");}catch(ArgumentException){rejected=true;} Check(rejected,"path traversal rejected");
            Check(!e.Write("limit.jsonl",new { Text = new string('x',1100000) }) && e.Limited,"stream byte limit");
            e.Status(new Health("limit-check",t,t,"truncated",0,0,"reserved health survives data exhaustion"));e.CloseStreams();Check(File.Exists(e.FilePath("collection-log.jsonl")),"health retained after data limit");
            e.Save("unicode-şğ.json",new { Text="İstanbul <script>" }); e.Manifest();
        }
        Check(Verify(temp)==0,"manifest roundtrip Unicode");
        File.AppendAllText(Path.Combine(temp,"unicode-şğ.json")," "); Check(Verify(temp)!=0,"manifest detects tampering");
        string bad=Path.Combine(temp,"bad.jsonl"); File.WriteAllText(bad,"not-json");
        bool malformed=false;try{Analysis.Read<Proc>(bad);}catch(JsonException){malformed=true;}Check(malformed,"malformed data is not treated as success-empty");
        var work=Path.Combine(Path.GetTempPath(),"RazeWatch-command-tests-"+Guid.NewGuid().ToString("N"));
        using(var e=new Evidence(work,16)) {
            e.Write("append.jsonl",new {n=1});e.CloseStreams();e.Write("append.jsonl",new {n=2});e.CloseStreams();Check(File.ReadLines(e.FilePath("append.jsonl")).Count()==2,"reopened evidence never overwrites prior records");
            var longScript=Commands.PowerShell(e,"long-script","#"+new string('a',20000)+"\n[pscustomobject]@{Text='İstanbul'} | ConvertTo-Json -Compress",10,CancellationToken.None).GetAwaiter().GetResult();
            Check(longScript.ExitCode==0 && File.ReadAllText(e.FilePath("long-script.stdout.txt")).Contains("İstanbul"),"long Unicode script bypasses command-line length via stdin");
            var fail=Commands.Run(e,"failure",Path.Combine(Environment.SystemDirectory,"cmd.exe"),new[]{"/d","/c","exit","7"},5,CancellationToken.None).GetAwaiter().GetResult();
            Check(fail.ExitCode==7 && fail.Status=="error","nonzero command exit not success");
            var timeout=Commands.PowerShell(e,"timeout","Start-Sleep -Seconds 20",1,CancellationToken.None).GetAwaiter().GetResult();Check(timeout.Status=="timeout","command timeout kills child");
            using var cancel=new CancellationTokenSource(100);var cancelled=Commands.PowerShell(e,"cancel","Start-Sleep -Seconds 20",10,cancel.Token).GetAwaiter().GetResult();Check(cancelled.Status=="cancelled","command cancellation kills child");
        }
        int i=Array.IndexOf(args,"--sample"); if(i>=0) Sample(args[i+1]);
        if(args.Contains("--restricted-test"))Check(RestrictedTest.Run(),"real restricted-token native access denied and endpoint fallback");
        i=Array.IndexOf(args,"--render-ui");
        if(i>=0){ApplicationConfiguration.Initialize();using var form=new MainForm();form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-4000,-4000);form.ShowInTaskbar=false;form.Show();Application.DoEvents();using var bitmap=new Bitmap(form.Width,form.Height);form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height));bitmap.Save(args[i+1]);Check(bitmap.Width>=700,"Turkish GUI layout rendered");}
        i=Array.IndexOf(args,"--cancel-collection");
        if(i>=0){using var stop=new CancellationTokenSource(4000);var c=new Collector();string output=args[i+1];string root=Task.Run(()=>c.Run(new Options(Seconds:30,Output:output,NoPacket:true),stop.Token)).GetAwaiter().GetResult();Check(c.Partial && File.Exists(Path.Combine(root,"report.html")) && Verify(root)==0,"real collection cancellation produces verified partial report");}
        i=Array.IndexOf(args,"--ui-test");
        if(i>=0){ApplicationConfiguration.Initialize();string root=args[i+1];string? opened=null;using var form=new MainForm(new Options(Seconds:20,Output:root,NoPacket:true),p=>opened=p);form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-4000,-4000);form.ShowInTaskbar=false;form.Show();Application.DoEvents();
            Button B(string name)=>(Button)form.Controls.Find(name,true).Single(); B("Start").PerformClick();var timer=System.Diagnostics.Stopwatch.StartNew();bool uiMarked=false,stopped=false;
            while(timer.Elapsed.TotalSeconds<45 && !B("Start").Enabled){Application.DoEvents();if(timer.Elapsed.TotalSeconds>=2 && !uiMarked){B("Mark").PerformClick();uiMarked=true;}if(timer.Elapsed.TotalSeconds>=4 && !stopped){B("Stop").PerformClick();stopped=true;}Thread.Sleep(20);}
            Check(B("Start").Enabled && B("OpenReport").Enabled,"GUI start/stop returns ready and enables report");B("OpenReport").PerformClick();Check(opened!=null && File.Exists(opened),"GUI report action targets generated local file");Check(File.ReadAllText(Path.Combine(root,"timeline.jsonl")).Contains("user-mark"),"GUI mark writes UTC timeline");Check(Verify(root)==0,"GUI partial report manifest valid");
        }
        Console.WriteLine($"{count} assertions passed. Temporary synthetic fixtures retained in {temp}");return 0;
    }
    static void Sample(string root)
    {
        using var e=new Evidence(root,16); var t=new DateTimeOffset(2026,1,1,0,0,0,TimeSpan.Zero);
        e.Write("processes.jsonl",new Proc("snapshot",t,100,4,"EXCEL.EXE","C:\\Synthetic\\EXCEL.EXE",t,null,"S-1-5-21-TEST","fixture",""));
        e.Write("processes.jsonl",new Proc("snapshot",t.AddSeconds(1),101,100,"powershell.exe","C:\\Synthetic\\powershell.exe",t.AddSeconds(1),"<script>alert('fixture')</script>",null,"fixture",""));
        e.Write("flows.jsonl",new Flow(t.AddSeconds(2),t.AddSeconds(2.01),"TCP",4,101,"192.0.2.1",50000,"203.0.113.7",443,"5","fixture"));
        e.Write("timeline.jsonl",new {Utc=t,Kind="user-mark",Text="Sentetik örnek: gerçek müşteri verisi yok. <img onerror=alert(1)>"});
        e.Status(new Health("fixture-sensor",t,t.AddSeconds(600),"success",0,3,"Synthetic only; no real device evidence."));
        var o=new Options(Ioc:"203.0.113.7",Note:"Tamamen sentetik örnek");Analysis.Report(e,o,new {SchemaVersion=1,Synthetic=true,RequestedSeconds=600,MeasuredObservationSeconds=600,Partial=false,Options=o});e.Manifest();
    }
    public static int Verify(string root)
    {
        try
        {
            using var doc=JsonDocument.Parse(File.ReadAllText(Path.Combine(root,"manifest.json")));
            int n=0;var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var entry in doc.RootElement.EnumerateArray()) {
                string name=entry.GetProperty("File").GetString()!;if(Path.GetFileName(name)!=name || name.Contains(':'))throw new IOException("Unsafe manifest path");
                if(!names.Add(name))throw new IOException("Duplicate manifest entry");
                string path=Path.Combine(root,name);using var f=File.OpenRead(path);
                if(f.Length!=entry.GetProperty("Bytes").GetInt64() || Convert.ToHexString(SHA256.HashData(f))!=entry.GetProperty("Sha256").GetString())throw new IOException("Manifest mismatch");n++;
            }
            if(!names.SetEquals(Directory.EnumerateFiles(root).Select(Path.GetFileName).Where(x=>x!="manifest.json")!))throw new IOException("Manifest does not cover exact directory file set");
            foreach(string path in Directory.EnumerateFiles(root,"*.jsonl")) foreach(string line in File.ReadLines(path)){using var j=JsonDocument.Parse(line);Schema.ValidateRecord(Path.GetFileName(path),j.RootElement);}
            Console.WriteLine($"Verified {n} manifest entries, exact file set and core JSONL schema (contents withheld).");return 0;
        }catch(Exception ex){Console.Error.WriteLine("Verification failed: "+ex.GetType().Name);return 1;}
    }
}
