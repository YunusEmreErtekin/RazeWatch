# Güncel devam noktası — 0.2, 2026-09-08

Kullanıcı gereksiz işleri durdurmamı istedi. Son kullanım: 5 saat %89, haftalık %14. Yeni geliştirme/test başlatma; önce yalnız gerçekten gerekli kalan işi belirle.

Çalışan test/toplama kalmadı. Self-contained son derleme: work/release-0.2. Bu derlemede 39 test geçti (gerçek restricted-token native erişim ve GUI Start/Mark/Stop/Report dahil). Kaynak src/RazeWatch ile eşleşir.

0.2 düzeltmeleri: hosts timeout; GUI kırpılması; ortak çıktı bütçesi ve kontrol alanı rezervi; Windows CPU/bellek job limitleri; PktMon stop bellek/yeniden deneme; PID reuse güvenli collector etiketi; endpoint dönem kuralı; native audit flags; EVTX bitişik aralık/kimlik doğrulaması; ham stdout/stderr baytları; JSONL şema ve tam manifest dosya kümesi. Ayrıntı docs/CHANGES-0.2.md. Oradaki son paket testini koşma notu artık tamamlandı.

Son gerçek kısa test work/private-runs/final-smoke-64m: 8.0216501 s, hata/timeout yok; 10 kanalın EVTX kayıtları doğrulandı; 115 dosya / 12,035,016 bayt (64 MiB bütçe). Önceki work/private-runs/resume-smoke-02 PktMon stop=0. İlk 600.0031149 saniyelik live-600-01 yeni şema/manifest ile doğrulandı; gereksiz 10 dakika tekrar edilmedi. Canlı veriler paketlere/depo kaynaklarına alınmadı.

Önemli kalan sınırlar: tam standart kullanıcı hesabında uçtan uca test yok (masaüstü elevated; gerçek restricted native access testi geçti); Windows 10 test edilmedi; ETL semantik parse ve tarihî artefakt içerik analizi yok; harici EVTX disk rezervi konservatif tahmin, kernel disk kotası değil; WMI servis maliyeti job dışında. README ve eski mimari/gizlilik belgelerindeki 0.1 sınır açıklamaları kısmen eski; 0.2 değişiklik dosyası esas alınmalı. Üretime hazır/eksiksiz iddiası yapılmasın.

Bir sonraki öncelik: kullanıcı isterse yalnız bu kritik sınırlar; doküman cilası, yeniden aynı testler ve gereksiz kapsam genişletme yapılmasın. GitHub hedefi bilinmiyor; hiçbir yayın yapılmadı. Reset otomatik kullanılmadı.
