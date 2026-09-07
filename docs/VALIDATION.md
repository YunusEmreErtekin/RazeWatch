# Doğrulama sonucu — 2026-09-08

Test edilen: Windows 11 Home Single Language x64 build 26200, yönetici. Windows 10/non-admin henüz doğrulanmadı. 0.1.0 checkpoint adayı; üretim onayı değildir.

## Gerçek 10 dakika

- Ölçülen gözlem: **600.0031149 saniye** (istenen 600).
- Bitiş nedeni `duration-complete`, session Partial=false. Bu alan gözlemin iptal edilmediğini belirtir; modül kapsamının tam olduğu anlamına gelmez.
- Ağ: 595 poll, 0 API hatası; maksimum poll başlangıç aralığı 1.0676261 s.
- WMI: 116 start, 109 stop; enrichment kuyruk kaybı 0. Provider drop sayısı bilinmiyor.
- Kontrollü kısa `cmd` çocuk süreci start=1/stop=1. Kontrollü TCP yerel portunda 42 satır (dinleme/bağlantı/TIME_WAIT örnekleri olabilir, bağlantı sayısı değildir); UDP portunda 6 satır.
- PktMon stop exit=0; metadata ETL varlık/boyut doğrulandı, anlamsal ayrıştırılmadı. Paket yükü bayrağı kapalı.
- Collector tepe working set: 67,452,928 bayt; CPU 15.9375 saniye (çocuklar hariç).
- 114 dosya, 83,621,318 bayt. 113 SHA256 manifest girdisi ve bütün JSONL satırlarının JSON sözdizimi doğrulandı. Tam JSON Schema/EVTX anlamsal doğrulaması henüz yapılmadı.
- Durum kayıtları: 207 success, 28 success-empty, 7 timeout, 8 partial, 2 truncated, 2 channel-disabled, 2 unavailable, 1 scope-gap, 1 cancelled (gözlem sonunda ağ pulse iptali), diğerleri sensör yaşam durumu. Bu sayılar alt modüller/taşıma/validasyon dahil; benzersiz veri kaynağı sayısı değildir.

Gerçek veriler `work/private-runs/live-600-01` içinde kaldı; kaynak ve ZIP paketine alınmadı. Süreç tamamlandı; canlı sensör/PktMon açık bırakılmadı. Yeni bug gerektirmedikçe bu 10 dakika testi tekrarlanmasın.

## Diğer testler

`smoke-02` 12.001667 saniye, 12 poll, sıfır ağ hatası, kontrollü olaylar, 95 manifest girdisi. `cancel-02` gerçek iptal/kısmi rapor, 16 manifest girdisi doğrulandı. Son kaynak test harness'inde 30 assertion geçti. Taşınabilir adayın collector kodu bu testlerle aynı; daha sonra yalnız test harness'ine GUI render/iptal testleri eklendi.

GUI render incelendi: gizlilik paragrafının alt satırları kırpılıyor. Düzeltme bekliyor. Hosts envanteri timeout'u proxy kapsamını engelliyor. Non-admin, tam kaynak kotaları, event/ETL semantik doğrulama ve diğer açıklar `CHECKPOINT.md` içinde. Dağıtım adayı bunlar giderilmeden üretime hazır kabul edilmemeli.
