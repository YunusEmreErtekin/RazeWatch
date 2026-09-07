namespace RazeWatch;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--self-test")) return Tests.Run(args);
            if (args.Contains("--verify")) return Tests.Verify(args[Array.IndexOf(args, "--verify") + 1]);
            if (args.Length == 0) { ApplicationConfiguration.Initialize(); Application.Run(new MainForm()); return 0; }
            string? Value(string key) { int i = Array.IndexOf(args, key); return i < 0 ? null : i + 1 < args.Length ? args[i + 1] : throw new ArgumentException(key + " değeri eksik"); }
            int Number(string key, int fallback, int min, int max) { string? s = Value(key); int v = s == null ? fallback : int.Parse(s); if (v < min || v > max) throw new ArgumentOutOfRangeException(key); return v; }
            if (args.Contains("--help")) { Console.WriteLine("RazeWatch --collect [--seconds 600] [--output EMPTY_DIR] [--history-hours 24] [--event-limit 1000] [--max-mib 256] [--ioc IP,domain,SHA256] [--incident ISO8601_WITH_OFFSET] [--note TEXT] [--synthetic] [--no-packet]\n--self-test [--sample DIR] | --verify COLLECTION_DIR\nGUI: no arguments. Ctrl+C cleanly stops and writes partial report. No credentials, packet payload, or upload. Command lines/events may contain incidental sensitive data."); return 0; }
            var allowed = new[] { "--collect", "--seconds", "--output", "--history-hours", "--event-limit", "--max-mib", "--ioc", "--incident", "--note", "--synthetic", "--no-packet" };
            for (int i = 0; i < args.Length; i++) { if (!allowed.Contains(args[i])) throw new ArgumentException("Bilinmeyen argüman: " + args[i]); if (args[i] is not ("--collect" or "--synthetic" or "--no-packet")) i++; }
            string incident = Value("--incident") ?? "";
            if (incident != "" && (!System.Text.RegularExpressions.Regex.IsMatch(incident, "(Z|[+-]\\d{2}:\\d{2})$") || !DateTimeOffset.TryParse(incident, out _))) throw new ArgumentException("Olay zamanı ISO8601 ve Z veya ±hh:mm saat dilimi içermeli.");
            var opts = new Options(Number("--seconds", 600, 5, 3600), Number("--history-hours", 24, 1, 168), Number("--event-limit", 1000, 1, 5000), Number("--max-mib", 256, 32, 1024), Value("--output"), Value("--ioc") ?? "", incident, Value("--note") ?? "", args.Contains("--synthetic"), args.Contains("--no-packet"));
            using var stop = new CancellationTokenSource(); Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
            var collector = new Collector(); int last = -1;
            collector.Progress += s => { int now = Environment.TickCount / 15000; if (now != last || !s.StartsWith("Gözlem:")) { Console.WriteLine(s); last = now; } };
            collector.Run(opts, stop.Token).GetAwaiter().GetResult(); return collector.Partial ? 2 : 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message); return 1; }
    }
}
