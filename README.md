# RazeWatch

Windows 10/11 x64 için yerel çalışan gözlem aracı.

## İndirme ve çalıştırma

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

Rapor ve toplama dosyaları varsayılan olarak şu klasöre yazılır:

```text
%LOCALAPPDATA%\RazeWatch\collections\<oturum-klasörü>
```

Özel bir çıktı klasörü belirtmek için örnek:

```powershell
.\dist\RazeWatch.exe --collect --seconds 600 --output "D:\RazeWatch\cikti"
```

Çalışma sonunda oluşturulan oturum klasöründeki dosyalar RazeWatch çıktısıdır.
