using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RazeWatch;

public static class Files
{
    public static bool LocalFile(string path)
    {
        try {if(!Regex.IsMatch(path,@"^[A-Za-z]:\\") || new DriveInfo(Path.GetPathRoot(path)!).DriveType==DriveType.Network)return false;
            for(var dir=new FileInfo(path).Directory;dir!=null;dir=dir.Parent)if((dir.Attributes&FileAttributes.ReparsePoint)!=0)return false;return true;}catch{return false;}
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct TrustFile { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle, Subject; }
    [StructLayout(LayoutKind.Sequential)] struct TrustData { public uint Size; public IntPtr Callback, Sip; public uint UI, Revocation, Choice; public IntPtr File; public uint Action; public IntPtr State, Url; public uint Flags, Context; public IntPtr Signature; }
    [DllImport("wintrust.dll", ExactSpelling = true)] static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref TrustData data);
    public static object Signature(string path)
    {
        var file = new TrustFile { Size = (uint)Marshal.SizeOf<TrustFile>(), Path = path };
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        Marshal.StructureToPtr(file, p, false);
        var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UI = 2, Choice = 1, File = p, Action = 1, Flags = 0x1000 | 0x10 };
        var guid = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try
        {
            int status = WinVerifyTrust(new IntPtr(-1), ref guid, ref data);
            string? subject = null;
            try { using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); subject = cert.Subject; } catch (CryptographicException) { }
            return new { WinTrustStatus = "0x" + unchecked((uint)status).ToString("X8"), Status = status == 0 ? "valid-offline-policy" : status == unchecked((int)0x800B0100) ? "no-embedded-signature" : "not-validated", Signer = subject, Mode = "Offline cache only; revocation not checked; catalog signatures not resolved; not a malware verdict." };
        }
        finally { data.Action = 2; WinVerifyTrust(new IntPtr(-1), ref guid, ref data); Marshal.DestroyStructure<TrustFile>(p); Marshal.FreeHGlobal(p); }
    }
    public static bool Excluded(string path, string output) => Path.GetFullPath(path).StartsWith(Path.GetFullPath(output).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    public static void Collect(Evidence e, CancellationToken ct)
    {
        var at = DateTimeOffset.UtcNow; var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(e.Root, "*.jsonl").Where(p => Path.GetFileName(p).StartsWith("baseline-") || Path.GetFileName(p) == "processes.jsonl"))
        {
            foreach (var line in File.ReadLines(file))
            {
                if (ct.IsCancellationRequested) return;
                try { using var doc = JsonDocument.Parse(line); Visit(doc.RootElement); } catch (JsonException) { }
            }
        }
        void Visit(JsonElement el)
        {
            if (el.ValueKind == JsonValueKind.Object)
                foreach (var prop in el.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String && new[] { "Path", "PathName", "ExecutablePath", "Execute", "FullName", "ScriptFileName", "Value", "Program" }.Contains(prop.Name))
                    {
                        string s = Environment.ExpandEnvironmentVariables(prop.Value.GetString() ?? "");
                        if (s.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) s = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + s[11..];
                        if (s.StartsWith("\\??\\")) s = s[4..];
                        var m = Regex.Match(s, "^\\s*(?:\"(?<p>[^\"]+)\"|(?<p>.+?\\.(?:exe|dll|sys|ps1|vbs|js|lnk))(?=\\s|$))", RegexOptions.IgnoreCase);
                        string candidate=m.Success?m.Groups["p"].Value:s;
                        if (!LocalFile(candidate)) continue;
                        if (File.Exists(s)) paths.Add(s); else if (m.Success && File.Exists(candidate)) paths.Add(candidate);
                    }
                    else Visit(prop.Value);
                }
            else if (el.ValueKind == JsonValueKind.Array) foreach (var item in el.EnumerateArray()) Visit(item);
        }
        int count = 0; int skipped = 0;
        foreach (var path in paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (ct.IsCancellationRequested || e.Limited || count >= 200 || DateTimeOffset.UtcNow - at > TimeSpan.FromSeconds(45)) break;
            if (Excluded(path, e.Root)) { skipped++; continue; }
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length > 100 * 1024 * 1024 || (fi.Attributes & FileAttributes.ReparsePoint) != 0) { skipped++; e.Write("file-metadata.jsonl", new { Path = path, Status = "skipped-size-or-reparse", fi.Length }); continue; }
                var beforeSize = fi.Length; var beforeTime = fi.LastWriteTimeUtc;
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                string sha = Convert.ToHexString(SHA256.HashData(stream)); var signature = Signature(path); fi.Refresh();
                e.Write("file-metadata.jsonl", new { Utc = DateTimeOffset.UtcNow, Path = path, fi.Length, fi.CreationTimeUtc, fi.LastWriteTimeUtc, Sha256 = sha, Signature = signature,
                    ChangedDuringRead = beforeSize != fi.Length || beforeTime != fi.LastWriteTimeUtc, Provenance = "Current file during collection; historical identity not established. Signature and hash are separate reads." }); count++;
            }
            catch (Exception ex) { e.Write("file-metadata.jsonl", new { Utc = DateTimeOffset.UtcNow, Path = path, Status = "error", Error = ex.Message }); }
        }
        e.Status(new Health("file-metadata", at, DateTimeOffset.UtcNow, count + skipped < paths.Count ? "truncated" : "success", 0, count, $"Candidates={paths.Count}; skipped={skipped}; max 200 files, 100 MiB each, 45 s. Executable/action paths only; command argument parsing is intentionally limited."));
    }
}
