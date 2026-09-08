# RazeWatch

Windows 10/11 x64 için yerel çalışan gözlem aracı.

## Hazır uygulamayı indir — kurulum gerekmez

1. [RazeWatch 0.3 Windows x64 ZIP'i indir](https://github.com/YunusEmreErtekin/RazeWatch/raw/refs/heads/main/downloads/RazeWatch-0.3-win-x64.zip).
2. ZIP'in tamamını boş bir klasöre çıkarın; EXE'yi tek başına taşımayın.
3. Klasördeki `RazeWatch.exe` dosyasını yönetici olarak çalıştırın. .NET kurmanız gerekmez.
4. ICMP incelemesi için **ICMP denetimini kontrol et / hazırlık** düğmesine basın ve aşağıdaki hazırlık adımlarını izleyin.
5. IOC alanına hedef IP'leri girip **Başlat** düğmesine basın. Sonunda **Raporu aç** ile sonucu görüntüleyin.

Paket bütünlüğü için [SHA256SUMS.txt](downloads/SHA256SUMS.txt) dosyasını kullanabilirsiniz.

## Kaynak koddan derleme — isteğe bağlı

1. GitHub sayfasında **Code → Download ZIP** seçin ve ZIP'i boş bir klasöre çıkarın.
2. Başka bir bilgisayarda kaynak koddan çalıştıracaksanız **.NET 8 SDK** kurun.
3. PowerShell'i çıkarılan klasörde açıp şu komutları çalıştırın:

```powershell
dotnet restore src\RazeWatch\RazeWatch.csproj
dotnet publish src\RazeWatch\RazeWatch.csproj -c Release -r win-x64 --self-contained true -o dist
.\dist\RazeWatch.exe
```

4. Açılan uygulamada **Başlat** düğmesine basın.
5. İncelemek istediğiniz işlemleri normal şekilde yapın. Gerekirse olayları **İşaretle** ile kaydedin.
6. İşiniz bitince **Durdur**, ardından **Raporu aç** düğmesine basın.

## Çıktı

Rapor ve toplama dosyaları, `RazeWatch.exe` dosyasının bulunduğu klasörün içindeki `collections` klasörüne yazılır. Her çalıştırma için ayrı bir oturum klasörü oluşturulur:

```text
<RazeWatch.exe klasörü>\collections\<oturum-klasörü>
```

Özel bir çıktı klasörü belirtmek için örnek:

```powershell
.\dist\RazeWatch.exe --collect --seconds 600 --output "D:\RazeWatch\cikti"
```

Çalışma sonunda oluşturulan oturum klasöründeki dosyalar RazeWatch çıktısıdır.

## ICMP / ping kaynağını bulma

1. Kanıt koruma işlemlerinden sonra RazeWatch'ı yönetici olarak açın. **ICMP denetimini kontrol et / hazırlık** düğmesi mevcut Windows ayarını gösterir.
2. IOC alanına araştırılan IP'leri virgülle ayırarak girin. Başlat'a basın ve trafiği tetikleyen normal işlemleri yapın.
3. Raporun üstündeki **ICMP — uygulama ve hedef** tablosunda olay zamanı, uygulama yolu, PID, yön, hedef ve izin/engel bilgisini inceleyin. Tam kayıtlar `icmp-events.csv` ve `icmp-events.json`; canlı olayların orijinal XML'i `icmp-raw.jsonl` içindedir.

Windows Filtering Platform Connection denetimi kapalıysa yeni ICMP olayları üretilmeyebilir. RazeWatch bu ayarı değiştirmez. İnceleme prosedürünüz kapsamında, yönetici PowerShell'de önce mevcut ayarı kaydedin:

```powershell
auditpol /get /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /r
```

Çıktıyı inceleme notunuza kaydettikten sonra test için izin ve engel olaylarını etkinleştirebilirsiniz:

```powershell
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

Sonrasında `/get` ile doğrulayın. Bu Windows ayarı kalıcıdır ve TCP/UDP dahil Security günlük hacmini artırabilir; test bitince önce kaydettiğiniz başarı/başarısızlık ayarlarını ayrı ayrı geri uygulayın. Her ikisini körlemesine kapatmayın. Kurum politikası veya kullanıcıya özel denetim farklı davranışa neden olabilir.

ICMP tablosu WFP 5156/5157 izin/engel olaylarını kullanır; bunlar paket sayısı, iki saniyelik ping düzeni veya başarılı yanıt kanıtı değildir. Kayıt olmaması cihazın temiz olduğunu göstermez. Paket içeriği için ayrı yakalama gerekir. Geçmiş günlükler varsayılan son 24 saat ve kanal başına 1000 kayıtla sınırlıdır; canlı ICMP dinleyicisi bu tarihsel kayıt sınırından bağımsız çalışır, toplam çıktı bütçesi yine geçerlidir. Erken Durdur kullanılırsa canlı kayıtlar korunur; geçmiş günlük toplama tamamlanmayabilir.
