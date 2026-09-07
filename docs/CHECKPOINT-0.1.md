# Devam noktası — kullanım bütçesi nedeniyle duraklatıldı

2026-09-08 Europe/Istanbul. Son bütçe kontrolü: codex 5 saat used **91%**, haftalık **29%**. Reset kredisi kullanılmadı. Kullanıcı yaklaşık %90 tüketimde güvenli noktada durmayı istedi. Tam %10 kalan garantisi verilmedi.

## Durum

Kaynak proje: `C:\Users\raze01\Documents\Codex\2026-09-07\razewatch\outputs\RazeWatch`.
Çalışma kökü: bunun iki üst dizini olan `...\razewatch`.
Taşınabilir aday: `...\razewatch\work\candidate` (self-contained win-x64 .NET 8.0.25).
**Üretime hazır değildir.** Kaynak, Türkçe GUI, CLI, sensörler, envanter, log toplama, offline rapor, manifest ve testler uygulanmıştır. Henüz GitHub deposu kurulmadı, commit/publish yapılmadı. Hedef repo bilinmiyor; ancak somut paket hazır olduktan sonra sorulmalı.

Eski REVIEW.md okundu. Eski EXE'ler çalıştırılmadı/değiştirilmedi. Müşteri verileri kaynak projeye kopyalanmadı. Gerçek test çıktıları yalnızca `work\private-runs` altında; bunları repoya veya dağıtım ZIP'ine koymayın.

## Doğrulananlar

- Windows 11 Home Single Language x64, build 26200; yönetici token ile test. Windows 10 ve gerçek yönetici olmayan token henüz test edilmedi.
- Release derlemesi 0 hata/0 uyarı; NuGet System.Management 8.0.0 ve System.CodeDom 8.0.0. .NET runtime 8.0.25. Lisans/notice metinleri `licenses` altında. Wireshark/Npcap veya eski araç pakete eklenmedi.
- Son test derlemesinde **30 assertion** geçti: PID reuse, yaşam aralığı, sınır belirsizliği, kısa süreç, boş/hatalı veri, provider/channel/ID, HTML/CSV, Unicode, path traversal, byte limit, manifest/tamper, append sonrası veri koruma, uzun Unicode PS stdin, çıkış kodu, timeout/iptal, GUI render, gerçek collection iptal/kısmi rapor.
- `smoke-02`: ölçülen 12.001667 saniye; 12 ağ poll; sıfır ağ hatası; maksimum poll arası 1.0681037 s; peak collector working set 57,704,448 bayt. 95 manifest girdisi ve JSONL sözdizimi doğrulandı. Sentetik çocuk start=1, stop=1; TCP eşleşen örnek=15, UDP=6. Modül timeout bulundu; 0 çıkış tüm modüllerin eksiksizliği değildir.
- `cancel-02`: kontrollü 4 saniye iptal; partial rapor ve 16 manifest girdisi doğrulandı.
- `sample-report` tamamen sentetik, gerçek IP/kişi/cihaz verisi içermez.
- `docs/ui.png` gerçek WinForms render'ı, cihaz içeriği yok. **Gizlilik paragrafının son satırları kesiliyor; düzeltilecek.** İlk boş render test düzeni hatasıydı; sonraki render incelendi.

## Aktif/son test

`work\private-runs\live-600-01` **tamamlandı**: 600.0031149 s, 595 poll, 0 ağ hatası; kontrollü child start/stop mevcut; PktMon stop=0. 113 manifest girdisi/JSONL sözdizimi doğrulandı. 114 dosya, 83,621,318 bayt. 7 timeout/kapsam eksikleri `docs/VALIDATION.md` içinde. Aktif capture/test kalmadı. Eski session 77036 tamamlandı; yeniden beklemeyin.

## Düzeltilen hatalar

1. Uzun encoded PowerShell Windows komut satırı sınırını aşıyordu. Kısa bootstrap + UTF8/base64 stdin, BOM'suz stdin ve açık UTF8 stdout kullanılıyor. Execution policy değiştirilmedi.
2. Files.Collect açık JSONL okuyordu; Files öncesi stream kapanışı eklendi. Yeniden açılan Evidence stream'leri append eder (truncate regresyonu önlendi).
3. Test GUI oluşturulduktan sonra SynchronizationContext nedeniyle collector `.GetResult()` deadlock oluyordu. Test collector Task.Run ile başlatıldı. `cancel-01` yalnızca test host'u kontrollü sonlandırıldı; PktMon bu testte kapalıydı. Üretim GUI zaten Task.Run kullanıyor.
4. Native TCP/UDP tablo boyutu, dinamik büyüme ve IPv6 alan yerleşimleri kontrol ediliyor.

## Öncelikli kalan işler — devam ederken önce bunlar

1. Gerçek 600 saniye çıktısını doğrula: session süre/partial, manifest, JSONL şema, başlangıç+bitiş WMI health, beklenen ChildPid start/stop, localhost TCP/UDP, output boyutu, ETL stop/varlık. İçerik değil özet sayılar göster. Tamamlandıysa bug gerekmedikçe 10 dakikayı gereksiz tekrarlama.
2. **Ağ envanteri her seferinde `hosts` bölümünde 40 s timeout oluyor.** adapters/addresses/dns/routes yazılıyor, hosts sonrası proxy/PAC bölümleri atlanıyor. Hosts dosyası yalnızca 823 bayt/reparse değil. Get-Content erişimi veya betik davranışını güvenli izole test et; hosts'u ayrı modüle ayırıp proxy'nin engellenmesini önle. Hata kısmi işaretleniyor ama kök neden çözülmedi.
3. GUI sabit 150 px gizlilik Label yüksekliği son satırları kırpıyor; AutoSize/uygun layout + farklı DPI doğrula. Girdi alanlarına kalıcı etiketler ekle (placeholder render'da görünmüyor). Düğme/işaretleme/rapor açma etkileşimini gerçek UI ile tamamla.
4. Gerçek non-admin token smoke ve erişim yok/auditing kapalı ayrımlarını doğrula. Güvenlik ayarını değiştirme, UAC/Defender/firewall müdahalesi yapma.
5. Sert birleşik CPU/RAM/disk/child-process sınırı yok: observation'da soft ölçüm, komut stdout/stderr sınırı ve timeout var. Final analysis/EVTX ek boyutu, dosya hash/WinVerifyTrust/WMI bloklaması ve report bellek kullanımı için JobObject/streaming/deadline tasarımını tamamla. `Evidence.Limited` sonrası health yazılamama riskini gider.
6. Collector soy etiketlemesi yalnız PID tabanlı; PID reuse güvenli yaşam aralığı + bütün alt-process soyuyla etiketle. Ham veriyi silme. Süreç kimliği fallback event/metadata ikililerinin sahte bir sonraki doğumla yaşamı kısaltma riskini test et. Endpoint zamanı ile event gecikmesi belirsizliğini koru.
7. Tekrarlanan bağlantı kuralı yok; poll satırını bağlantı sayısı saymadan gözlenen ayrık endpoint dönemlerini tanımla. Periyodiklik/hacim uydurma. Tarihî IOC alan eşleşmeleri (Sysmon vb.) ve service değişim kurallarını genişlet.
8. Event coverage: Security auditpol CSV henüz otomatik alt-kategori ayrıştırılmıyor. `channel-disabled`, `unavailable`, `access-denied`, `truncated` var; tarih kapsamı flag olarak kalıyor. EVTX export interval kayıt sayısını okuyarak tam doğrula; konservatif boyut tahminini gerçek bütçeyle bağla. İptal export sırasında kesilemeyebilir.
9. Task XML JSON alanında korunuyor; gerekirse ayrı XML kanıt dosyaları. Firewall port/app filtreleri, Run/RunOnce referans dosyaları, browser erişilebilir diğer kullanıcı policy kapsamı eksik. Yakın dosya envanteri yalnız üst seviye ve cap'li. Envanterde yok/erişim yok ayrımlarını her alt bölümde tamamla.
10. PktMon ETL varlık/boyut doğrulaması var, anlamsal parse yok. Drop/counter ham çıktı var; session sahipliği dış müdahalede yarışabilir. Ham paket yükü toplama; HTTPS içeriği, UDP remote ve DNS-process bağını üretme.
11. `Analysis.Read` hatalı JSON'da throw eder; fallback HTML var ama session Partial alanı analiz hatasında eski kalabilir. `Partial` CLI işareti modül degraded ile aynı değil; açık session completeness alanı ekle. Eksik evtx dosyalarını manifestten sonra değişiklik olmadan koru.
12. Kaynak/dağıtım final eşleşmesi: `work/candidate` testlerden önceki yayımlanmış derleme; son kaynak farkı yalnız test harness ekleri. Sonunda yeniden publish, test ve checksum. README/docs/THIRD-PARTY-NOTICES ile ZIP oluştur; canlı veriyi katma. Lisans seçimi kullanıcıya ait; kaynak için varsayımsal açık kaynak lisansı seçilmedi.

## Devam komutları

Çalışma kökünde:

```powershell
dotnet build outputs/RazeWatch/src/RazeWatch/RazeWatch.csproj -c Release --no-restore
outputs/RazeWatch/src/RazeWatch/bin/Release/net8.0-windows/win-x64/RazeWatch.exe --self-test
work/candidate/RazeWatch.exe --verify work/private-runs/live-600-01
dotnet publish outputs/RazeWatch/src/RazeWatch/RazeWatch.csproj -c Release -r win-x64 --self-contained true -o work/final-candidate
```

Önce get_usage_limits kontrol et. Kullanıcı reset sonrası devamı yetkilendirirse bu noktadan sürdür; reset kredisi kendiliğinden kullanma. Kullanıcının yerel test/toplama yetkisi devam ediyor; genel izin sorusunu yineleme. Yeni subagent/otomasyon oluşturulmadı ve gerekli değil. Yayın için ancak somut paket tamamlanınca GitHub hedefini sor.
