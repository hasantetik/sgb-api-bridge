# SGB API Bridge (Tehdit İstihbarat Servisi)

Bu proje, Siber Güvenlik Başkanlığı (SGB / eski USOM) tarafından sunulan siber tehdit istihbaratı verilerini (zararlı alan adları, IP adresleri, URL'ler) otomatik olarak çekerek kurum içi güvenlik cihazlarının (Firewall, SIEM) doğrudan tüketebileceği standart formatlara çeviren kurumsal bir entegrasyon servisidir.

## 🚀 Proje Amacı
* **Firewall Entegrasyonu:** Kurum ağındaki güvenlik duvarlarının, zararlı bağlantıları engelleyebilmesi için düz metin (plain text) formatında dinamik listeler sunar.
* **SIEM Entegrasyonu:** QRadar, Splunk gibi SIEM cihazlarının tehdit istihbaratını okuyabilmesi için uluslararası **STIX / TAXII 2.1** standardında API uç noktaları sağlar.

## 🛠️ Teknolojiler ve Mimari
* **Dil & Framework:** Java 17, Spring Boot 3
* **Veritabanı:** PostgreSQL (B-Tree Kompozit İndeksleme ile yüksek performans)
* **Veri Çekme (Senkronizasyon):**
  * **Smart Delta Sync (Saatlik):** SGB API'sini yormamak için uygulanan akıllı senkronizasyon. Sadece sistemde olmayan en güncel verileri (ID üzerinden) bulana kadar SGB'ye sorgu atar.
  * **Full Sync (Gece 02:00):** Tüm SGB veritabanını tarar, yayından kaldırılmış (artık zararlı olmayan) bağlantıları temizler.
* **Performans Optimizasyonları:**
  * **JDBC Batching:** Binlerce veriyi tekil sorgular yerine toplu (batch) olarak veritabanına kaydeder (Saniyelik upsert hızı).
  * **DB Level Pagination:** STIX objelerini belleğe (RAM) doldurmak yerine doğrudan SQL seviyesinde (LIMIT/OFFSET) sayfalayarak OutOfMemory hatalarının önüne geçer.

## ⚙️ Kurulum ve Çalıştırma (En Kolay Yöntem)

Projeyi ayağa kaldırmak için bilgisayarınızda sadece **Docker** yüklü olması yeterlidir. (Bilgisayarınızda Java veya Maven kurulu olmasına **gerek yoktur**, sistem kendini Docker içinde otomatik derler).

1. Proje dizinine (terminalden) gidin ve şu komutu çalıştırın:
```bash
docker-compose up -d
```
2. Bu komut hem **PostgreSQL** veritabanını oluşturacak hem de **Spring Boot** uygulamasını derleyip veritabanına bağlayarak `localhost:8080` üzerinde hazır hale getirecektir.
3. Uygulamanın arka plan loglarını izlemek isterseniz:
```bash
docker-compose logs -f app
```

*(Not: Eğer projeyi geliştirici ortamında IDE üzerinden çalıştırmak isterseniz, `docker-compose up db -d` ile sadece veritabanını kaldırıp, uygulamayı IDE üzerinden çalıştırabilirsiniz.)*

## 📖 API Uç Noktaları (Endpoints)

Sistem ayağa kalktıktan sonra detaylı API dökümantasyonunu ve test arayüzünü Swagger üzerinden görüntüleyebilirsiniz:
👉 **Swagger UI:** `http://localhost:8080/swagger-ui.html`

### 1. Düz Metin Beslemeleri (Firewall İçin)
Binlerce kaydı `\n` (yeni satır) ile ayırarak saf liste halinde döndürür.
* Oltalama ve zararlı domainler: `GET http://localhost:8080/domain-list.txt`
* Zararlı IP adresleri: `GET http://localhost:8080/ip-list.txt`
* Zararlı URL'ler: `GET http://localhost:8080/url-list.txt`

### 2. TAXII 2.1 Beslemeleri (SIEM İçin)
Uluslararası standartlarda STIX objeleri döndürür.
* **Discovery:** `GET http://localhost:8080/taxii2/index.json`
* **API Root:** `GET http://localhost:8080/api/`
* **Koleksiyonlar:** `GET http://localhost:8080/api/collections/`
* **Veri Çekme (Sayfalı):** `GET http://localhost:8080/api/collections/sgb-phishing/objects/page-0001.json`

*(Koleksiyonlar: `sgb-phishing`, `sgb-botnet-cc`, `sgb-apt-cc`, `sgb-exploit-kit`, `sgb-malware-download`, `sgb-mining`, `sgb-mobile-cc`, `sgb-other`, `sgb-all`)*

## ⚠️ Önemli Notlar (Performans)
- Yüz binlerce kaydı içeren `/domain-list.txt` veya `page-0001.json` uç noktalarını **Swagger UI içinden test etmeyin**. Tarayıcılar bu kadar büyük metinleri arayüze çizmeye çalışırken donabilir. Testlerinizi doğrudan tarayıcının URL çubuğundan veya `curl` komutları ile gerçekleştirin.
