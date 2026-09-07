using System.Diagnostics;

namespace RazeWatch;

public sealed class MainForm : Form
{
    readonly Button start = new() { Text = "Başlat • 10 dakika", AutoSize = true };
    readonly Button stop = new() { Text = "Durdur", Enabled = false, AutoSize = true };
    readonly Button open = new() { Text = "Raporu aç", Enabled = false, AutoSize = true };
    readonly Button mark = new() { Text = "İşaretle (UTC)", Enabled = false, AutoSize = true };
    readonly ComboBox marks = new() { Width = 380, DropDownStyle = ComboBoxStyle.DropDown };
    readonly TextBox ioc = new() { Width = 690, PlaceholderText = "IOC: IP, domain veya SHA256 (virgülle ayırın)" };
    readonly TextBox incident = new() { Width = 690, PlaceholderText = "Olay zamanı: 2026-09-07T14:30:00+03:00 (isteğe bağlı)" };
    readonly TextBox note = new() { Width = 690, PlaceholderText = "Olay notu — parola / token yazmayın", MaxLength = 2000 };
    readonly Label status = new() { Text = "Hazır", AutoSize = false, Width = 700, Height = 75 };
    CancellationTokenSource? cancellation;
    Collector? collector; string? report; bool running;
    public MainForm(Options? testOptions = null,Action<string>? testOpen = null)
    {
        Text = "RazeWatch • Windows canlı gözlem"; Size = new Size(820, 860); MinimumSize = new Size(650, 600); StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10); AutoScaleMode = AutoScaleMode.Dpi;
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(22), AutoScroll = true };
        Label LabelText(string text, bool title = false) => new() { Text = text, AutoSize = true, Margin = new Padding(3, 6, 3, 6), Font = title ? new Font(Font.FontFamily, 20, FontStyle.Bold) : Font };
        var title = LabelText("10 dakikalık yerel gözlem", true);
        var privacy = LabelText("Kapsam: süreç olayları, TCP/UDP uçları, sistem/kalıcılık envanteri ve mevcut olay günlükleri. İlk 2 dakika boşta, ardından normal çalışma; son dakikalarda tekrar boşta kalabilirsiniz.\n\nVeriler cihazda kalır. Komut satırı, dosya yolları, IP/DNS, kullanıcı SID ve günlük metni hassas olabilir. Parola/cookie/token/anahtar depoları, paket içeriği, RAM ve disk imajı toplanmaz. Günlüklerde tesadüfen hassas metin bulunabilir. Yönetici yoksa eksik kapsam raporlanır.");
        privacy.Name = "Privacy"; layout.Controls.Add(title); layout.Controls.Add(privacy);
        layout.Controls.Add(LabelText("IOC — IP, domain veya SHA256; virgülle ayırın (isteğe bağlı)")); layout.Controls.Add(ioc);
        layout.Controls.Add(LabelText("Olay zamanı — örnek: 2026-09-07T14:30:00+03:00 (isteğe bağlı)")); layout.Controls.Add(incident);
        layout.Controls.Add(LabelText("Olay notu — parola veya token yazmayın (isteğe bağlı)")); layout.Controls.Add(note);
        start.Name = "Start"; stop.Name = "Stop"; open.Name = "OpenReport"; mark.Name = "Mark"; status.Name = "Status";
        var buttons = new FlowLayoutPanel { AutoSize = true, WrapContents = true }; buttons.Controls.AddRange(new Control[] { start, stop, open }); layout.Controls.Add(buttons);
        marks.Items.AddRange(new[] { "Tarayıcı açıldı", "İş uygulaması açıldı", "VPN değişti", "Boşta çalışma başladı", "Normal çalışma başladı" }); marks.SelectedIndex = 0;
        layout.Controls.Add(LabelText("İşlem işareti — seçin veya kendi açıklamanızı yazın"));
        var marker = new FlowLayoutPanel { AutoSize = true, WrapContents = true }; marker.Controls.AddRange(new Control[] { marks, mark }); layout.Controls.Add(marker);
        status.AutoSize = true; layout.Controls.Add(status); Controls.Add(layout);
        void Reflow() {
            int width = Math.Max(400, layout.ClientSize.Width - layout.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth - 12);
            foreach (Control c in layout.Controls) { c.MaximumSize = new Size(width, 0); if(c is not Label) c.Width = width; }
            marks.Width = Math.Max(230, width - 190);
        }
        layout.SizeChanged += (_, _) => Reflow(); Reflow();
        start.Click += async (_, _) => {
            if (incident.Text != "" && (!System.Text.RegularExpressions.Regex.IsMatch(incident.Text, "(Z|[+-]\\d{2}:\\d{2})$") || !DateTimeOffset.TryParse(incident.Text, out _))) { status.Text = "Olay zamanı saat dilimi içermeli: 2026-09-07T14:30:00+03:00"; return; }
            cancellation = new(); collector = new(); running = true; start.Enabled = false; stop.Enabled = mark.Enabled = true; open.Enabled = false;
            collector.Progress += s => { if (!IsDisposed) BeginInvoke(() => status.Text = s); };
            var options = testOptions ?? new Options(Ioc: ioc.Text, Incident: incident.Text, Note: note.Text);
            try { report = await Task.Run(() => collector.Run(options, cancellation.Token)); open.Enabled = true; }
            catch (Exception ex) { status.Text = "Hata: " + ex.Message + " Ham kısmi veriler: " + collector.OutputRoot; }
            finally { running = false; start.Enabled = true; stop.Enabled = mark.Enabled = false; cancellation.Dispose(); }
        };
        stop.Click += (_, _) => { cancellation?.Cancel(); status.Text = "Kontrollü durdurma ve kısmi rapor hazırlanıyor…"; stop.Enabled = false; };
        mark.Click += (_, _) => collector?.Mark(marks.Text);
        open.Click += (_, _) => { if (report != null) {string path=Path.Combine(report,"report.html");if(testOpen!=null)testOpen(path);else Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });} };
        FormClosing += (_, e) => { if (running) { e.Cancel = true; cancellation?.Cancel(); status.Text = "Önce sensörler kapanıp kısmi rapor kaydedilecek. Tamamlanınca pencereyi kapatabilirsiniz."; } };
    }
}
