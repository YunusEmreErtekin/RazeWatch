using System.Text.Json;

namespace RazeWatch;

public static class Inventory
{
    public static async Task Collect(Evidence e, string phase, CancellationToken ct, bool full = true, string[]? only = null)
    {
        string script = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "inventory.ps1"));
        var modules = only ?? (full ? new[] { "network", "hosts", "system", "persistence", "registry", "accounts", "security", "firewall", "browser", "files", "artifacts" } : new[] { "network", "hosts", "system", "persistence", "registry", "security", "firewall" });
        foreach (var module in modules)
        {
            if (ct.IsCancellationRequested || e.Limited) break;
            string name = phase + "-" + module;
            var h = await Commands.PowerShell(e, name, "$Module='" + module + "';$Phase='" + phase + "';\n" + script, 40, ct);
            long count = 0; bool parsed = true;
            if (File.Exists(e.FilePath(name + ".stdout.txt")))
            {
                foreach (string line in File.ReadLines(e.FilePath(name + ".stdout.txt")))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        e.Write(name + ".jsonl", doc.RootElement);
                        if (doc.RootElement.GetProperty("Kind").GetString() == "module-status")
                        {
                            var d = doc.RootElement.GetProperty("Data");
                            e.Status(new Health(name + "/" + d.GetProperty("Module").GetString(), h.StartUtc, h.EndUtc, d.GetProperty("Status").GetString()!, h.ExitCode,
                                d.TryGetProperty("Records", out var n) ? n.GetInt64() : 0, d.TryGetProperty("Error", out var err) ? err.GetString() ?? "" : "Structured module output validated."));
                        }
                        else count++;
                    }
                    catch (JsonException) { parsed = false; }
                }
            }
            e.Status(new Health(name + "-validation", h.StartUtc, DateTimeOffset.UtcNow, !parsed ? "parse-error" : h.Status is "success" or "success-empty" ? count == 0 ? "success-empty" : "success" : "partial", h.ExitCode, count, "Per-section statuses determine coverage; transport success alone does not."));
        }
        if (full && !ct.IsCancellationRequested)
        {
            AuditPolicy.Collect(e);
            await Commands.Run(e, "audit-policy", Path.Combine(Environment.SystemDirectory, "auditpol.exe"), new[] { "/get", "/category:*", "/r" }, 15, ct);
        }
    }
}
