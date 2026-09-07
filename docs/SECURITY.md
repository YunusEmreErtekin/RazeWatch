# Güvenlik ve gizlilik

Bu araç yetkilendirilmiş yerel gözlem içindir. Toplanan IP/DNS, SID, komut satırı, görev XML'i, script/event metni, yollar ve güvenlik yapılandırmaları hassas olabilir. Parola/cookie/token/anahtar depolarına, Wi-Fi anahtarına, LSASS/SAM/SECURITY içeriğine başvurulmaz. Ancak komut satırı ve mevcut günlüklerde tesadüfen bulunan sırların güvenilir biçimde redakte edildiği **iddia edilmez**. EVTX ve ham metinler paylaşılmadan önce ayrıca gözden geçirilmelidir.

Araç dosya silmez/karantinaya almaz; uygulama kapatmaz; VPN/firewall/UAC/audit/Defender/execution policy değiştirmez; sürücü kurmaz; VSS/hive mount yapmaz. Oluşturduğu yardımcı süreçleri iptal/zaman aşımında sonlandırır. Başarıyla başlattığı PktMon oturumunu kapatır; önceden çalışan PktMon varsa start başarısız olur ve stop çağrılmaz. Dışarıdan PktMon oturumunu aynı anda değiştirmeyin. Stop başarısız olursa `pktmon-stop` çıktısını inceleyerek yetkili manuel işlem yapın.

HTML tüm veri metnini encode eder, script kullanmaz, CSP içerir ve yalnızca üretilmiş yerel kanıt adlarına bağlanır. CSV alanları quote edilir ve formül başlatıcıları apostrofla etkisizleştirilir. Manifest yolu dizin kaçışına karşı kontrol edilir. Yeni çıktı klasörü boş olmalıdır; kök reparse point reddedilir. Üst dizin reparse zinciri/TOCTOU saldırılarına karşı tam bir dosya sistemi güvenlik sınırı yoktur: güvenilmeyen ortak yazılabilir klasörde çalıştırmayın.

Çıktı için ek şifreleme/özel ACL oluşturulmaz; mevcut dizin izinleri miras alınır. Ağ yükleme, CDN veya uygulama telemetrisi yoktur. İmza doğrulaması cache-only/no-revocation ile çalışır. İşletim sistemi/kurumsal güvenlik araçlarının kendi telemetrisi uygulama tarafından yönetilmez.

Kaynak sınırları: JSON akışı yapılandırılan bütçede durur; canlı aşamada tüm çıktı boyutu ve 768 MiB collector working-set eşiği 0,5 saniyede kontrol edilir. Yardımcı stdout/stderr ayrı ayrı 4 milyon karakterde kesilir, modül 40 saniyede sonlandırılır; ETL 32 MiB daireseldir. Final analiz/EVTX/rapor ve yardımcı süreçler için birleşik sert CPU/RAM/disk kotası **henüz yoktur**. Bu, üretim öncesi giderilmesi gereken bir sınırlamadır.

Hash ve imza ayrı okumalarla alınır; dosya boyutu/yazma zamanının değişmesi raporlanır ama değişmeden aynı boyutta yapılan tüm yazmaları kanıtlayamaz. Dosyaları tarihî olay anındaki dosyayla aynı varsaymayın. İmza güven kararı malware kararı değildir.
