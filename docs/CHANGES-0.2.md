# 0.2 değişiklikleri ve test kapsamı

- Hosts okuması düz .NET metni, 1 MiB sınır ve ayrı modül kullanıyor. Get-Content sağlayıcı nesnesinin derin JSON serileştirmesindeki timeout kaldırıldı; proxy/PAC engellenmiyor.
- Gizlilik metni kendiliğinden büyüyor, girişler kalıcı Türkçe etiketlere sahip. GUI Başlat/İşaretle/Durdur/Rapor akışı test edildi.
- Windows JobObject: collector ve miras alan çocuklarda 1 GiB committed memory ve %25 CPU; çocuklar 256 MiB, PktMon kapanışı 768 MiB. Etkinlik veya başarısız kurulum raporlanır. Dış WMI servis maliyeti kapsam dışında.
- Bütün yönetilen çıktı yazıları ortak byte bütçesine bağlandı; kontrol/rapor/manifest için en fazla 8 MiB ayrılıyor. ETL ve EVTX için önceden alan ayrılıyor. Harici EVTX boyutu ihtiyatlı tahmindir; kernel disk kotası değildir. Aşım kısmi rapor doğurur.
- PktMon birleştirme bellek hatası bulundu; kapanış kotası artırıldı ve hata durumunda durum sorgusu/tekrar stop eklendi. Yeni kısa testte stop exit=0.
- Collector PID yeniden kullanımını yanlış etiketlemiyor; yaşam aralığı ve tek ebeveyn adayıyla soy etiketleme yapıyor. Metadata'sız yakın olayın bilinen yaşamı kesmesi giderildi.
- Aynı uzak uca 5 gözlenen ESTABLISHED dönemi kuralı eklendi. En az 3 saniye gözlem arası yeni dönem sayılır; poll boşlukları yanlış ayrım yapabilir. Kesin yeniden bağlantı/periyodiklik iddiası yok.
- Mevcut olayların yapılandırılmış alanlarında tam IOC token eşleşmesi; servis ve Defender exclusion değişimleri için inceleme kayıtları.
- AuditQuerySystemPolicy ile 60 alt kategori bu cihazda GUID/ham bayraklarla okundu; kapalı auditing, OS dilinden bağımsız gösteriliyor. Geçmiş veya kullanıcı override politikasının aynı olduğu varsayılmaz.
- EVTX seçimi Windows XPath karmaşıklık sınırını aşmayan bitişik kayıt aralığı kullanıyor. Dosyadaki kayıt kimlikleri beklenen seçimle tek tek karşılaştırılıyor; boyut nedeniyle daha dar aralık ayrıca belirtiliyor.
- stdout/stderr özgün bayt olarak korunuyor. PowerShell UTF-8; native araçların konsol kodlaması değişebilir. Ham hata verisi kayıplı UTF-8 dönüşümüne sokulmuyor.
- Şema doğrulayıcı process/flow/event/health zorunlu alanlarını ve UDP bilinmeyen uzak hedeflerini kontrol ediyor. Manifest yinelenen adları ve fazladan dosyaları reddediyor.
- UNC ve ağ diski referansları dosya hash aşamasında yerel erişimden önce reddediliyor; çıktı reparse ataları reddediliyor. Yarışlara karşı tam dosya sistemi güvenlik sınırı iddiası yok.

39 test (GUI ve restricted native access dahil) geçti. Sonraki stdout bayt koruma değişimi için son paket testi ayrıca koşulmalıdır. İlk gerçek 600 saniye kaydı yeni manifest/şema doğrulayıcıyla tekrar doğrulandı; 10 dakika gereksiz tekrarlanmadı.

Kısıtlı token testi gerçek native erişim denetimidir: Admin=false, Security erişimi reddedildi, IP Helper çalıştı. Tam standart kullanıcı hesabında GUI/CLI oturumu değildir. Bu cihazdaki Explorer token'ı da elevated olduğu için standart masaüstü token'ı başlatılamadı; güvenlik ayarları değiştirilmedi.
