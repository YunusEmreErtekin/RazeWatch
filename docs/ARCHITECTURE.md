# Mimari ve kaynaklar

`Collector` sensör → baseline → ölçülen gözlem → sensör kapanışı → final → mevcut loglar → sınırlı dosya metadata → offline rapor/manifest sırasını yönetir. Baseline gözlemle eşzamanlıdır; ağ pulse örnekleri 60 saniye aralık + modül süresiyle alınır. `Evidence` JSONL yazar; dosya başına ham veriyi bellekte biriktirmez. Analiz süreç/kimlik ve envanter kayıtlarını belleğe alır, akışları satır satır okur.

`Processes`: Win32_ProcessStartTrace/StopTrace, 512 kayıtlık metadata kuyruğu, 10 saniyelik Win32_Process yedeği. PID + creation/event zamanı kullanılır. Metadata kuyruğu kaybı raporlanır; WMI sağlayıcı kayıp sayısı mevcut değildir. Endpoint tablosundaki gözlem aralığıyla yaşam aralıkları kesiştirilir. Tek aday dahi yalnızca `consistent-owner-pid` etiketi alır, paket kaynaklı kesin kimlik iddiası yoktur. Event/enrichment eksikliğinde belirsizlik sürebilir.

`Network`: GetExtendedTcpTable/GetExtendedUdpTable OWNER_PID, AF_INET ve AF_INET6; değişen boyut için dört yeniden deneme; native tablo boyut kontrolü. UDP tablosu uzak uç sağlamadığı için alan null kalır.

`inventory.ps1`: seçilmiş yapılandırılmış alanlar, modül içi ayrı durum kayıtları. Uzun betik UTF-8/base64 stdin aktarımıyla çalıştırılır; Windows komut satırı boyut sınırına takılmaz. Hiçbir `Format-Table` dönüşümü yoktur. Registry hive mount yapılmaz; erişilebilir yüklü kullanıcılar ve profil kapsamı yazılır.

`Events`: provider/channel/ID beraber filtrelenir. Kapalı, yok, erişim yok, truncate, timeout durumları ayrılır. Tarih aralığı/logun başlangıcı ayrı coverage kaydıdır. Security auditing alt kategorilerinin açık/kapalı durumunu otomatik yorumlayan analiz yoktur; auditpol CSV ham kanıttır. Varsayılan 24 saat/kanal başına 1000 kayıt, en yeni kayıtlardan başlanır.

`Analysis`: HTML escaping, CSV formül önlemi, IOC tam eşleşmesi, sayısal davranış kuralları, envanter farkı, olay zamanı yakınlığı. Ham kayıtlar toplayıcı süreçlerini içerir; `collector-children.jsonl` yardımcı PID'leri belirtir. CSV'deki collector bayrağı PID bazlıdır ve tam soy/PID-yeniden-kullanım güvenli etiketi olarak yorumlanmamalıdır.

Başvuru belgeleri (2026-09-07 kontrol edildi):

- [Microsoft IP Helper TCP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Microsoft IP Helper UDP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [Microsoft Kernel Trace Provider](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/kernel-trace-provider)
- [Microsoft PktMon start](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start); cihazdaki `pktmon start help` bayrak açıklamalarıyla da doğrulandı.

Eski araçlar çalıştırılmadı/değiştirilmedi; yeni tasarım REVIEW.md bulgularından hareketle bağımsız yazıldı. Eski müşteri çıktıları bu projeye alınmadı.
