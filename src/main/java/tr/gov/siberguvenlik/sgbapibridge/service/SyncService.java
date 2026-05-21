package tr.gov.siberguvenlik.sgbapibridge.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import tr.gov.siberguvenlik.sgbapibridge.entity.Indicator;
import tr.gov.siberguvenlik.sgbapibridge.repository.IndicatorRepository;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class SyncService {

    private static final Logger log = LoggerFactory.getLogger(SyncService.class);

    private final IndicatorRepository indicatorRepository;
    private final JdbcTemplate jdbcTemplate;
    private final RestTemplate restTemplate;

    // Aynı anda sadece 1 sync işleminin çalışmasını garanti eden mekanizma (Thread-Safe Kilit)
    // Eğer bir işlem bitmeden diğeri başlarsa, kilit sayesinde çakışma önlenir.
    private final AtomicBoolean syncLock = new AtomicBoolean(false);

    @Value("${sgb.api.per-page:1000}")
    private int perPage;

    @Value("${sgb.api.url:https://siberguvenlik.gov.tr/api/address/index}")
    private String apiUrl;

    @Value("${sgb.api.retry-count:3}")
    private int retryCount;

    @Value("${sgb.api.max-consecutive-errors:5}")
    private int maxConsecutiveErrors;

    // SGB API'sinden çekilecek zararlı bağlantı türleri
    private static final List<String> TYPES = List.of("domain", "url", "ip", "ip6", "ip6net");

    // Veritabanına kaydetme komutu (UPSERT)
    // Eğer ID daha önce yoksa INSERT (Yeni kayıt ekle) yapar.
    // Eğer ID zaten varsa ON CONFLICT kısmına düşer ve UPDATE (Veriyi güncelle) yapar.
    private static final String UPSERT_SQL = """
            INSERT INTO indicators(
                id, type, value_raw, value_clean, valid,
                category, connectiontype, source, criticality_level,
                api_date, first_seen_utc, last_seen_utc, last_changed_utc
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(id) DO UPDATE SET
                last_changed_utc = CASE
                    WHEN COALESCE(indicators.value_clean,'')       != COALESCE(excluded.value_clean,'')
                      OR COALESCE(indicators.category,'')          != COALESCE(excluded.category,'')
                      OR COALESCE(indicators.connectiontype,'')    != COALESCE(excluded.connectiontype,'')
                      OR COALESCE(indicators.source,'')            != COALESCE(excluded.source,'')
                      OR COALESCE(indicators.criticality_level,-1) != COALESCE(excluded.criticality_level,-1)
                      OR COALESCE(indicators.api_date,'')          != COALESCE(excluded.api_date,'')
                      OR COALESCE(indicators.valid,false)          != COALESCE(excluded.valid,false)
                      OR indicators.removed_at_utc IS NOT NULL
                    THEN excluded.last_seen_utc
                    ELSE indicators.last_changed_utc
                END,
                type              = excluded.type,
                value_raw         = excluded.value_raw,
                value_clean       = excluded.value_clean,
                valid             = excluded.valid,
                category          = excluded.category,
                connectiontype    = excluded.connectiontype,
                source            = excluded.source,
                criticality_level = excluded.criticality_level,
                api_date          = excluded.api_date,
                last_seen_utc     = excluded.last_seen_utc,
                removed_at_utc    = NULL
            """;

    public SyncService(IndicatorRepository indicatorRepository,
                       JdbcTemplate jdbcTemplate) {
        this.indicatorRepository = indicatorRepository;
        this.jdbcTemplate = jdbcTemplate;
        
        // SGB API cevap vermezse uygulamanın sonsuza kadar donmasını engellemek için zaman aşımları (Timeout) ayarlıyoruz.
        // GOAWAY (HTTP/2 Tarpit) tuzaklarına düşmemek için bağlantıyı zorla HTTP/1.1 sürümüne çekiyoruz.
        java.net.http.HttpClient httpClient = java.net.http.HttpClient.newBuilder()
                .version(java.net.http.HttpClient.Version.HTTP_1_1) // HTTP/2 kaynaklı donmaları engeller
                .connectTimeout(Duration.ofSeconds(15))
                .build();
                
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(Duration.ofSeconds(15));
        this.restTemplate = new RestTemplate(factory);
    }

    /**
     * DELTA SYNC (Saatlik Güncelleme): Sadece yeni eklenen verileri çeker.
     * fixedRateString = 3600000 milisaniye (1 saat)
     */
    @Scheduled(fixedRateString = "${sgb.api.delta-interval:3600000}")
    public void runDeltaSync() {
        // Eğer içeride çalışan başka bir sync işlemi varsa, kilitli olduğundan burası atlanır. (Çakışma engelleme)
        if (!syncLock.compareAndSet(false, true)) {
            log.warn("Delta sync atlandı: Önceki sync hâlâ çalışıyor. Çakışma önlendi.");
            return;
        }
        try {
            log.info("====== DELTA SYNC BAŞLADI ======");
            Instant start = Instant.now(); // İşlem başlangıç saatini kronometreye al
            
            // Sırayla tüm tipleri (domain, ip, vb.) SGB'den çek
            for (String type : TYPES) {
                syncType(type, false); // false = Bu bir Full Sync değil, sadece yeni olanları al
            }
            
            Instant end = Instant.now(); // Bitiş saati
            Duration duration = Duration.between(start, end); // Aradan geçen süreyi hesapla
            log.info("====== DELTA SYNC BİTTİ ====== Toplam Süre: {} dakika {} saniye", duration.toMinutes(), duration.toSecondsPart());
        } finally {
            syncLock.set(false); // İşlem bitince kilit mutlaka kaldırılır (hata çıksa bile)
        }
    }

    /**
     * FULL SYNC (Günlük Tam Tarama): Gece 02:00'da çalışıp tüm listeyi baştan sona tarar ve yayından kalkanları temizler.
     * cron = "0 0 2 * * ?" (Her gün gece saat 02:00)
     */
    @Scheduled(cron = "${sgb.api.full-cron:0 0 2 * * ?}")
    public void runFullSync() {
        if (!syncLock.compareAndSet(false, true)) {
            log.warn("Full sync atlandı: Önceki sync hâlâ çalışıyor. Çakışma önlendi.");
            return;
        }
        try {
            log.info("====== GECE (FULL) SYNC BAŞLADI ======");
            // Cutoff: SGB'de artık yer almayan (silinen) kayıtları tespit etmek için şimdiki zamanı referans alıyoruz
            Instant cutoff = Instant.now();
            Instant start = Instant.now();

            // SGB'deki tüm sayfaları tarıyoruz
            for (String type : TYPES) {
                syncType(type, true); // true = Akıllı durma iptal, tüm sayfaları zorla tara
            }

            // Temizlik Aşaması: Eğer veritabanımızdaki bir kaydın son görülme tarihi (last_seen),
            // yukarıda aldığımız 'cutoff' saatinden daha eskiyse, demek ki bu taramada o kayıt SGB'den gelmemiştir (silinmiştir).
            for (String type : TYPES) {
                try {
                    int removed = indicatorRepository.markRemovedByCutoff(type, cutoff, Instant.now());
                    if (removed > 0) {
                        log.info("Temizlik -> Tür: [{}]. Artık SGB listesinde olmayan {} adet kayıt pasif hale getirildi (False Positive engellendi).", type, removed);
                    }
                } catch (Exception e) {
                    log.error("Tür [{}] için temizlik sırasında hata oluştu: {}", type, e.getMessage(), e);
                }
            }
            
            Instant end = Instant.now();
            Duration duration = Duration.between(start, end);
            log.info("====== GECE (FULL) SYNC BİTTİ ====== Toplam Süre: {} dakika {} saniye", duration.toMinutes(), duration.toSecondsPart());
        } finally {
            syncLock.set(false);
        }
    }

    /**
     * SGB API'sinden ilgili türdeki (örn: domain) verileri sayfa sayfa indiren ana metot.
     */
    public void syncType(String type, boolean isFull) {
        log.info("-> Tür [{}] için indirme işlemi başlatılıyor... (Mod: {})", type, isFull ? "FULL TARAMA" : "YENİLERİ AL");
        int page = 1;
        int totalSaved = 0;
        int consecutiveErrors = 0;
        Long maxId = null;

        // EĞER DELTA SYNC İSE: Veritabanımızdaki en büyük ID değerini alıyoruz (SGB'den eski kayıtları boşuna indirmemek için)
        if (!isFull) {
            maxId = indicatorRepository.getMaxIdByType(type);
            log.debug("Bizdeki son ID: {}", maxId);
        }

        while (true) { // Sayfaları 1'den başlayıp bitene kadar (veya erken kırılana kadar) döner
            String url = UriComponentsBuilder.fromUriString(apiUrl)
                    .queryParam("type", type)
                    .queryParam("page", page)
                    .queryParam("per-page", perPage) // Her sayfada 1000 adet veri istiyoruz
                    .toUriString();

            Map<String, Object> response = null;

            // HATA TOLERANSI (Retry): Eğer ağ bağlantısı koparsa hemen pes etmeyiz, 3 kere tekrar deneriz.
            for (int attempt = 1; attempt <= retryCount; attempt++) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> resp = (Map<String, Object>) restTemplate.getForObject(url, Map.class);
                    response = resp;
                    consecutiveErrors = 0; // İşlem başarılı olduysa ardışık hata sayacını sıfırla
                    break;
                } catch (Exception e) {
                    long waitMs = 1000L * attempt * attempt; // Bekleme süresini katlayarak artırıyoruz (1sn, 4sn, 9sn)
                    log.warn("Sayfa {} alınamadı. (Deneme: {}/{}) Hata: {}. {}ms sonra tekrar denenecek.", page, attempt, retryCount, e.getMessage(), waitMs);
                    if (attempt == retryCount) {
                        consecutiveErrors++; // 3 deneme de başarısız oldu
                    } else {
                        try { Thread.sleep(waitMs); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                    }
                }
            }

            // ÇÖKME KORUMASI (Circuit Breaker): Üst üste 5 sayfa tamamen hata verirse SGB sistemi çökmüş demektir, boşa kürek çekmeyi bırak.
            if (consecutiveErrors >= maxConsecutiveErrors) {
                log.error("Çok fazla ardışık hata! Tür [{}] atlanıyor ve diğer türe geçiliyor.", type);
                break;
            }

            // Gelen yanıtta "models" adında bir veri listesi yoksa işlem bitti demektir (Son sayfa)
            if (response == null || !response.containsKey("models")) break;

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> models = (List<Map<String, Object>>) response.get("models");
            if (models == null || models.isEmpty()) break;

            List<Indicator> batch = new ArrayList<>();
            boolean stopDelta = false; // Akıllı durma bayrağı

            // Sayfanın içindeki tüm kayıtları tek tek okuyoruz
            for (Map<String, Object> m : models) {
                Indicator ind = mapToIndicator(m, type);
                if (ind == null) continue; // Hatalı veriyi atla
                
                // AKILLI DURMA NOKTASI: Eğer Full taramada değilsek ve 
                // gelen kaydın ID'si bizim veritabanımızdaki en büyük ID'den küçük/eşitse;
                // bu kayıttan sonrasının zaten bizde olduğu anlaşılır ve gereksiz sayfa indirmeleri iptal edilir.
                if (!isFull && maxId != null && ind.getId() <= maxId) {
                    stopDelta = true;
                    break; // Satır döngüsünü kır
                }
                batch.add(ind);
            }

            // Topladığımız verileri 1000'erli paketler halinde veritabanına topluca basıyoruz (Performans noktası)
            if (!batch.isEmpty()) {
                try {
                    executeBatchUpsert(batch);
                    totalSaved += batch.size();
                } catch (Exception e) {
                    log.error("Veritabanına kayıt sırasında hata oluştu: {}", e.getMessage());
                }
            }

            // SGB API BUG KORUMASI: Eğer dönen kayıt sayısı istediğimiz sayfa limitinden (1000) küçükse,
            // bu kesinlikle son sayfadır. SGB API'si hatalı bir şekilde sonraki sayfalarda aynı veriyi döndürse bile
            // sonsuz döngüye girmemek için işlemi burada kesiyoruz.
            if (models.size() < perPage) {
                log.info("Gelen kayıt sayısı ({}) limitin ({}) altında. Son sayfaya ulaşıldığı tespit edildi.", models.size(), perPage);
                stopDelta = true;
            }

            // Akıllı durma bayrağı kalktıysa sayfa sayfa gezmeyi komple bırak (Döngüyü kır)
            if (stopDelta) {
                log.info("Akıllı durma (Smart Stop) veya Son Sayfa aktifleşti! Tür [{}] için kalan sayfalar atlanıyor.", type);
                break; // Sayfa döngüsünü kır
            }

            page++; // Bir sonraki sayfaya geç

            // SGB Firewall engeline (Rate Limit) takılmamak için iki sayfa isteği arasında çeyrek saniye nefes alıyoruz
            try {
                Thread.sleep(200);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        log.info("-> Tür [{}] işlemi bitti. Toplam yeni eklenen/güncellenen kayıt: {}", type, totalSaved);
    }

    /**
     * Toplu veritabanı yazım (Batch Upsert) işlemini çalıştıran metod.
     * Tek tek Insert atmak yerine paket halinde yollar (JDBC Batching).
     */
    private void executeBatchUpsert(List<Indicator> batch) {
        jdbcTemplate.batchUpdate(UPSERT_SQL, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                Indicator ind = batch.get(i);
                ps.setLong(1, ind.getId());
                ps.setString(2, ind.getType());
                ps.setString(3, ind.getValueRaw());
                ps.setString(4, ind.getValueClean());
                ps.setBoolean(5, ind.getValid());
                
                if (ind.getCategory() != null) ps.setString(6, ind.getCategory());
                else ps.setNull(6, Types.VARCHAR);
                
                if (ind.getConnectiontype() != null) ps.setString(7, ind.getConnectiontype());
                else ps.setNull(7, Types.VARCHAR);
                
                if (ind.getSource() != null) ps.setString(8, ind.getSource());
                else ps.setNull(8, Types.VARCHAR);
                
                if (ind.getCriticalityLevel() != null) ps.setInt(9, ind.getCriticalityLevel());
                else ps.setNull(9, Types.INTEGER);
                
                if (ind.getApiDate() != null) ps.setString(10, ind.getApiDate());
                else ps.setNull(10, Types.VARCHAR);
                
                ps.setTimestamp(11, Timestamp.from(ind.getFirstSeenUtc()));
                ps.setTimestamp(12, Timestamp.from(ind.getLastSeenUtc()));
                ps.setTimestamp(13, Timestamp.from(ind.getLastChangedUtc()));
            }

            @Override
            public int getBatchSize() {
                return batch.size();
            }
        });
    }

    /**
     * SGB'den gelen JSON verisini bizim veritabanı objemize (Indicator) çeviren yardımcı metod.
     */
    private Indicator mapToIndicator(Map<String, Object> map, String type) {
        try {
            if (map.get("id") == null) return null; // ID'siz bozuk kayıtları reddet
            
            Indicator ind = new Indicator();
            ind.setId(Long.valueOf(map.get("id").toString()));
            ind.setType(type);
            String raw = map.get("url") != null ? map.get("url").toString() : "";
            ind.setValueRaw(raw);
            ind.setValueClean(raw.trim());
            ind.setValid(true);
            ind.setCategory(map.get("desc") != null ? map.get("desc").toString() : null);
            ind.setConnectiontype(map.get("connectiontype") != null ? map.get("connectiontype").toString() : null);
            ind.setSource(map.get("source") != null ? map.get("source").toString() : null);

            Object crit = map.get("criticality_level");
            if (crit != null) ind.setCriticalityLevel(Integer.valueOf(crit.toString()));

            ind.setApiDate(map.get("date") != null ? map.get("date").toString() : null);

            Instant now = Instant.now();
            ind.setFirstSeenUtc(now); // İlk kayıt zamanı
            ind.setLastSeenUtc(now);  // Son görülme (Full sync sırasında da güncellenir)
            ind.setLastChangedUtc(now);
            return ind;
        } catch (Exception e) {
            return null; // Parse hatası olursa sessizce atla
        }
    }
}
