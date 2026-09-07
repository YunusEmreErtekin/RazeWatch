using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RazeWatch;

public record Health(string Module, DateTimeOffset StartUtc, DateTimeOffset EndUtc, string Status,
    int? ExitCode, long Records, string Detail, string? Stdout = null, string? Stderr = null);
public record Proc(string Kind, DateTimeOffset Utc, int Pid, int? ParentPid, string? Name,
    string? Path, DateTimeOffset? StartUtc, string? CommandLine, string? UserSid, string Source, string Detail);
public record Flow(DateTimeOffset Utc, DateTimeOffset EndUtc, string Protocol, int Family, int Pid,
    string LocalAddress, int LocalPort, string? RemoteAddress, int? RemotePort, string State, string Source);
public record Options(int Seconds = 600, int HistoryHours = 24, int EventLimit = 1000,
    int MaxMiB = 256, string? Output = null, string Ioc = "", string Incident = "", string Note = "", bool Synthetic = false, bool NoPacket = false);

public sealed class BudgetExceededException : IOException { public BudgetExceededException() : base("Evidence budget exhausted; partial data retained.") { } }
public sealed class Evidence : IDisposable
{
    public static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    public string Root { get; }
    readonly object gate = new();
    readonly Dictionary<string, StreamWriter> writers = new();
    public readonly List<Health> Health = new();
    long dataBytes, controlBytes;
    public long Bytes { get { lock(gate) return dataBytes + controlBytes; } }
    public long Limit { get; }
    public long ControlReserve { get; }
    public long DataRemaining { get { lock(gate) return Math.Max(0, Limit - ControlReserve - dataBytes); } }
    public bool Limited { get; private set; }
    public Evidence(string root, int maxMiB)
    {
        Root = Path.GetFullPath(root); Limit = (long)maxMiB * 1024 * 1024; ControlReserve = Math.Min(8 * 1024 * 1024, Limit / 4);
        if (Directory.Exists(Root) && Directory.EnumerateFileSystemEntries(Root).Any()) throw new IOException("Çıktı klasörü boş olmalı.");
        Directory.CreateDirectory(Root);
        for(var dir = new DirectoryInfo(Root); dir != null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Çıktı yolu reparse point içeremez.");
    }
    public string FilePath(string name)
    {
        if (Path.GetFileName(name) != name || name.Contains(':') || name is "." or ".." || string.IsNullOrEmpty(name)) throw new ArgumentException("Geçersiz kanıt adı");
        return Path.Combine(Root, name);
    }
    public static bool IsControl(string name) => new[] {"collection-log.jsonl","session.json","manifest.json","report.html","analysis-summary.json","capabilities.json"}.Contains(name);
    bool Spend(int n, bool control)
    {
        lock(gate) {
            if(control) { if(controlBytes+n>ControlReserve) { Limited=true; return false; } controlBytes+=n; }
            else { if(dataBytes+n>Limit-ControlReserve) { Limited=true; return false; } dataBytes+=n; }
            return true;
        }
    }
    sealed class BudgetStream : Stream
    {
        readonly Stream inner; readonly Evidence owner; readonly bool control;
        public BudgetStream(Stream stream,Evidence evidence,bool isControl) {inner=stream;owner=evidence;control=isControl;}
        public override void Write(byte[] b,int o,int n) {if(!owner.Spend(n,control))throw new BudgetExceededException();inner.Write(b,o,n);}
        public override void Write(ReadOnlySpan<byte> b) {if(!owner.Spend(b.Length,control))throw new BudgetExceededException();inner.Write(b);}
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> b,CancellationToken ct=default) {Write(b.Span);return ValueTask.CompletedTask;}
        public override Task WriteAsync(byte[] b,int o,int n,CancellationToken ct) {Write(b,o,n);return Task.CompletedTask;}
        public override void Flush()=>inner.Flush(); public override bool CanRead=>false;public override bool CanSeek=>false;public override bool CanWrite=>true; public override long Length=>inner.Length; public override long Position {get=>inner.Position;set=>throw new NotSupportedException();}
        public override int Read(byte[] b,int o,int n)=>throw new NotSupportedException();public override long Seek(long o,SeekOrigin so)=>throw new NotSupportedException();public override void SetLength(long n)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing){if(disposing)inner.Dispose();base.Dispose(disposing);}
    }
    public StreamWriter OpenText(string name,bool append=false,bool bom=false)
    {
        string path=FilePath(name);
        lock(gate) {
            if(!append && File.Exists(path)) {long old=new FileInfo(path).Length;if(IsControl(name))controlBytes=Math.Max(0,controlBytes-old);else dataBytes=Math.Max(0,dataBytes-old);}
            return new StreamWriter(new BudgetStream(new FileStream(path,append?FileMode.Append:FileMode.Create,FileAccess.Write,FileShare.Read),this,IsControl(name)),new UTF8Encoding(bom)) {AutoFlush=true};
        }
    }
    public Stream OpenBinary(string name) => new BudgetStream(new FileStream(FilePath(name),FileMode.Create,FileAccess.Write,FileShare.Read),this,IsControl(name));
    public bool Write(string name, object data)
    {
        lock (gate)
        {
            string line = JsonSerializer.Serialize(data, Json);
            int n=Encoding.UTF8.GetByteCount(line)+Environment.NewLine.Length;
            if(!IsControl(name) && n>DataRemaining){Limited=true;return false;}
            if (!writers.TryGetValue(name, out var writer)) writers[name] = writer = OpenText(name,true);
            try {writer.WriteLine(line);return true;}catch(BudgetExceededException){return false;}
        }
    }
    public void Status(Health h) { lock (gate) { if(Health.Count<10000)Health.Add(h); Write("collection-log.jsonl", h); } }
    public void Save(string name, object data) => SaveText(name,JsonSerializer.Serialize(data,new JsonSerializerOptions {WriteIndented=true}));
    public void SaveText(string name,string text) {lock(gate){long size=Encoding.UTF8.GetByteCount(text);long old=File.Exists(FilePath(name))?new FileInfo(FilePath(name)).Length:0;long remaining=IsControl(name)?ControlReserve-controlBytes:DataRemaining;if(size>remaining+old){Limited=true;throw new BudgetExceededException();}using var w=OpenText(name);w.Write(text);}}
    public void CloseStreams() { lock (gate) { foreach (var w in writers.Values) {try{w.Dispose();}catch(BudgetExceededException){}} writers.Clear(); } }
    // Reserve BEFORE invoking an external writer. Its own size limit must fit this reservation.
    public ExternalBudget? ReserveExternal(string name,long maximum)
    {
        lock(gate){if(maximum>DataRemaining)return null;dataBytes+=maximum;return new ExternalBudget(this,name,maximum);}
    }
    public sealed class ExternalBudget : IDisposable {
        readonly Evidence e;readonly string name;readonly long maximum;bool disposed;
        internal ExternalBudget(Evidence e,string name,long maximum){this.e=e;this.name=name;this.maximum=maximum;}
        public void Dispose(){if(disposed)return;disposed=true;lock(e.gate){long actual=File.Exists(e.FilePath(name))?new FileInfo(e.FilePath(name)).Length:0;e.dataBytes-=maximum;e.dataBytes+=actual;if(actual>maximum)e.Limited=true;}}
    }
    public void Manifest()
    {
        CloseStreams();
        Save("manifest.json", Directory.EnumerateFiles(Root).Where(p => Path.GetFileName(p) != "manifest.json").OrderBy(p => p).Select(p => {
            using var stream = File.OpenRead(p); return new { File = Path.GetFileName(p), Bytes = stream.Length, Sha256 = Convert.ToHexString(SHA256.HashData(stream)) }; }).ToArray());
    }
    public void Dispose() => CloseStreams();
}

public static class Commands
{
    public static async Task<Health> Run(Evidence e, string module, string exe, IEnumerable<string> args, int timeout, CancellationToken ct, string? stdin = null)
    {
        var start = DateTimeOffset.UtcNow;
        var output = module + ".stdout.txt"; var error = module + ".stderr.txt";
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = stdin != null };
        if (Path.GetFileName(exe).Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { psi.StandardOutputEncoding = Encoding.UTF8; psi.StandardErrorEncoding = Encoding.UTF8; if(stdin != null) psi.StandardInputEncoding = new UTF8Encoding(false); }
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var proc = new Process { StartInfo = psi };
        ResourceLimits? childLimits = null;
        long count = 0; bool truncated = false; int? code = null; string status = "error", detail = "";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(timeout));
        async Task Drain(StreamReader reader, string file)
        {
            using var writer = e.OpenBinary(file);
            byte[] buffer = new byte[4096]; long size = 0; int n;
            while ((n = await reader.BaseStream.ReadAsync(buffer.AsMemory())) > 0)
            {
                size += n;
                if (size <= 4 * 1024 * 1024) { try { await writer.WriteAsync(buffer.AsMemory(0, n)); Interlocked.Add(ref count, n); } catch(BudgetExceededException) { truncated=true; try {proc.Kill(true);} catch {} break; } }
                else { truncated = true; try { proc.Kill(true); } catch { } }
            }
        }
        try
        {
            proc.Start();
            try {childLimits=new ResourceLimits((module.StartsWith("pktmon-stop")?768L:256L)*1024*1024,100,true);childLimits.Assign(proc);}catch(Exception ex){childLimits?.Dispose();childLimits=null;e.Status(new Health(module+"-job",start,DateTimeOffset.UtcNow,"degraded",ex.HResult,0,"Child job unavailable: "+ex.Message));}
            e.Write("collector-children.jsonl", new { Utc = start, BirthUtc = proc.StartTime.ToUniversalTime(), Pid = proc.Id, ParentPid = Environment.ProcessId, Module = module });
            var a = Drain(proc.StandardOutput, output); var b = Drain(proc.StandardError, error);
            if (stdin != null) { await proc.StandardInput.WriteAsync(stdin.AsMemory(),deadline.Token); proc.StandardInput.Close(); }
            try { await proc.WaitForExitAsync(deadline.Token); }
            catch (OperationCanceledException) { try { proc.Kill(true); } catch { } await proc.WaitForExitAsync(); status = ct.IsCancellationRequested ? "cancelled" : "timeout"; }
            await Task.WhenAll(a, b); code = proc.ExitCode;
            if (status is not ("cancelled" or "timeout")) status = truncated ? "truncated" : code == 0 ? count == 0 ? "success-empty" : "success" : "error";
            detail = "Stdout/stderr ham korunur; komut başarısı veri kapsamının doğrulandığı anlamına gelmez.";
        }
        catch (Exception ex) { detail = ex.GetType().Name + ": " + ex.Message; try{if(!proc.HasExited)proc.Kill(true);}catch{} }
        finally {childLimits?.Dispose();}
        var h = new Health(module, start, DateTimeOffset.UtcNow, status, code, 0, detail, output, error); e.Status(h); return h;
    }
    public static Task<Health> PowerShell(Evidence e, string module, string script, int seconds, CancellationToken ct)
    {
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); " + script));
        if (encoded.Length <= 24000) return Run(e, module, exe, new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded }, seconds, ct);
        string bootstrap = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try { & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())))) } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"));
        return Run(e, module, exe, new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", bootstrap }, seconds, ct, Convert.ToBase64String(Encoding.UTF8.GetBytes(script)));
    }
}
