# RazeWatch 0.1.0 — Windows gözlem adayı

Windows 10/11 x64 için taşınabilir, yerel çalışan süreç/ağ gözlem aracı. **Bu sürüm üretim sertifikasyonu veya eksiksiz adli toplama iddiası taşımaz.** Doğrulanan sistem ve kalan açıklar `docs/VALIDATION.md` ve `CHECKPOINT.md` içindedir.

## Kullanım

Dağıtım ZIP'ini boş bir klasöre açın ve `RazeWatch.exe` çalıştırın. Python, .NET veya SDK kurulumu gerekmez. Windows PowerShell 5.1, WMI ve IP Helper Windows bileşenleri kullanılır. Uygulama kendiliğinden yükselmez; yönetici olarak başlatılmadığında erişilemeyen kaynakları raporlar.

1. Kapsam/gizlilik metnini okuyun. İsterseniz IOC IP/domain/SHA256, saat dilimi içeren olay zamanı ve not ekleyin.
2. **Başlat**: canlı sensörler envanterden önce başlar. İlk iki dakika boşta kalabilirsiniz.
3. Normal iş uygulamalarınızı kullanın; tarayıcı, iş uygulaması veya VPN değişikliğini **İşaretle** ile kaydedin. Araç bunları sizin yerinize yapmaz.
4. Son dakikalarda tekrar boşta kalabilirsiniz. **Durdur** kontrollü iptal ve kısmi rapor üretir.
5. **Raporu aç** ile offline HTML raporuna gidin. Gözlem 600 saniyedir; başlangıç/bitiş envanteri ve geçmiş günlük işlemleri toplam süreyi uzatır.

Varsayılan çıktı `%LOCALAPPDATA%\RazeWatch\collections\<benzersiz-oturum>` içindedir. Kaynak deposu içine gerçek toplama yapmayın. Klasörü kurumunuzun onaylı saklama/erişim politikasına göre koruyun.

```powershell
.\RazeWatch.exe --collect --seconds 600 --output 'D:\Olaylar\BosKlasor' --incident '2026-09-07T14:30:00+03:00' --ioc '203.0.113.7,example.invalid'
.\RazeWatch.exe --collect --seconds 12 --synthetic --output 'D:\Test\BosKlasor'
.\RazeWatch.exe --verify 'D:\Test\BosKlasor'
.\RazeWatch.exe --self-test
```

`--synthetic` yalnızca kendi localhost TCP/UDP uçlarını ve zararsız `cmd /d /c exit 0` çocuk sürecini üretir. Gerçek hedefe probe yapmaz. `--no-packet` PktMon'u devre dışı bırakır. `--history-hours` 1–168, `--event-limit` kanal başına 1–5000, `--seconds` 5–3600, `--max-mib` 32–1024. Ctrl+C iptal eder. Çıkış kodu 0 rapor üretildi, 2 kısmi/iptal, 1 üst düzey hata anlamındadır; **0 bütün modüllerin başarılı olduğu anlamına gelmez**. Her durumda kapsam tablosunu okuyun.

## Kanıt ve yorumlama

- `processes.jsonl`: ham başlangıç/bitiş olayları, envanter ve ayrı metadata. Kısa süreç olayları metadata eksik olsa da korunur.
- `flows.jsonl` / `flows.csv`: IPv4/IPv6, TCP/UDP yerel uçlar ve TCP uzak uçlar. Bir saniyelik örnekleme; bağlantı sayısı/hacmi değildir.
- `process-identities.json`: PID + doğum zamanı/olay zamanı kimlikleri; yaşam aralığı ve belirsiz ilişkiler.
- `baseline-*.jsonl`, `final-*.jsonl`, `pulse-*.jsonl`: envanter ve yaklaşık 60 saniyede bir ağ durum örneklemesi. Alan bazında erişim hatalarını içeren modül durumları korunur. Görev XML'i task kaydının `Xml` alanındadır; disabled görevler dahildir.
- `events-*.jsonl` / `.evtx`: sınırlı geçmiş kayıtları ve ilgili özgün EVTX kayıt aralığı. `event-coverage.jsonl` kanal/tarih/limit bilgisi verir. Büyük EVTX dışa aktarımları ihtiyatlı boyut kontrolüyle atlanabilir.
- `packet-metadata.etl`: PktMon `0x023` bayraklarıyla hata, bileşen ve sayaç metadatası; **ham paket yükü içermez**. 32 MiB dairesel kayıt eskileri üzerine yazabilir. Drop/sayaç çıktısı ham korunur; ETL'nin anlamsal ayrıştırması yoktur.
- `file-metadata.jsonl`: en fazla 200 dosya, dosya başına 100 MiB, 45 saniye bütçe. Hash toplama anına aittir. İmza offline cache politikasıyla kontrol edilir; sertifika iptali/catalog çözümleme yoktur.
- `collection-log.jsonl`, stdout/stderr dosyaları: zaman, çıkış kodu, kayıt sayısı, hata ve kısmi kapsam. Komut taşıma başarısı ayrıca veri doğrulamasıyla değerlendirilir.
- `manifest.json`: diğer dosyaların SHA256 ve boyutları. Manifest kendini imzalamaz; bütünlük doğrulaması özgünlük kanıtı değildir.

Kurallar: en az 20 farklı uzak IP veya 10 uzak port; tek yaşam aralığıyla uyumlu Office → script → gözlenen TCP bağlantısı; karşılaştırılabilir envanterde en az bir kalıcılık/firewall değişikliği; IOC tam eşleşmeleri; olay zamanı ±15 dakika önceliği. İmzasız=zararlı, imzalı=temiz veya bağlantı=C2 sonucu üretilmez. Tekrarlanan bağlantı/periyodiklik ve süreç hacmi bu sürümde hesaplanmaz.

## Derleme ve test

Geliştirici makinesinde .NET 8 SDK ve ilk NuGet geri yüklemesi için internet gerekir. Çalışan uygulamanın analiz/raporunda CDN, telemetri veya yükleme yoktur.

```powershell
dotnet restore src/RazeWatch/RazeWatch.csproj
dotnet build src/RazeWatch/RazeWatch.csproj -c Release --no-restore
dotnet publish src/RazeWatch/RazeWatch.csproj -c Release -r win-x64 --self-contained true -o dist/win-x64
dist/win-x64/RazeWatch.exe --self-test
```

Test uygulaması sentetik geçici dosyaları `%TEMP%\RazeWatch-test-*` içinde bırakır; otomatik silme yapmaz. `sample-report` tamamen sentetiktir ve dokümantasyon IP'leri kullanır.

Kaynaklar ve tasarım sınırları: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/VALIDATION.md`. GitHub hedefi belirlenmedi; hiçbir dosya yayımlanmadı.
