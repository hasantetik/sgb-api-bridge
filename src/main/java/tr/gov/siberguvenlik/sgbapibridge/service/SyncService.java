package tr.gov.siberguvenlik.sgbapibridge.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Service
public class SyncService {

    private final IndicatorRepository indicatorRepository;
    private final JdbcTemplate jdbcTemplate;
    private final RestTemplate restTemplate;

    @Value("${sgb.api.per-page:1000}")
    private int perPage;

    private static final String API_URL = "https://siberguvenlik.gov.tr/api/address/index";
    private static final List<String> TYPES = List.of("domain", "url", "ip", "ip6", "ip6net");

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

    public SyncService(IndicatorRepository indicatorRepository, JdbcTemplate jdbcTemplate) {
        this.indicatorRepository = indicatorRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.restTemplate = new RestTemplate();
    }

    @Scheduled(fixedRateString = "${sgb.api.delta-interval:3600000}")
    public void runDeltaSync() {
        System.out.println("Running delta sync...");
        for (String type : TYPES) {
            syncType(type, false);
        }
        System.out.println("Delta sync complete.");
    }

    @Scheduled(cron = "${sgb.api.full-cron:0 0 2 * * ?}")
    public void runFullSync() {
        System.out.println("Running full sync...");
        Instant cutoff = Instant.now();
        
        for (String type : TYPES) {
            syncType(type, true);
        }

        for (String type : TYPES) {
            int removed = indicatorRepository.markRemovedByCutoff(type, cutoff, Instant.now());
            System.out.println("Type " + type + " full sync cleanup complete. Removed: " + removed);
        }
        System.out.println("Full sync complete.");
    }

    public void syncType(String type, boolean isFull) {
        int page = 1;
        Long maxId = null;
        
        if (!isFull) {
            maxId = indicatorRepository.getMaxIdByType(type);
        }

        while (true) {
            String url = UriComponentsBuilder.fromUriString(API_URL)
                    .queryParam("type", type)
                    .queryParam("page", page)
                    .queryParam("per-page", perPage)
                    .toUriString();

            try {
                Map response = restTemplate.getForObject(url, Map.class);
                if (response == null || !response.containsKey("models")) break;

                List<Map<String, Object>> models = (List<Map<String, Object>>) response.get("models");
                if (models.isEmpty()) break;

                List<Indicator> batch = new ArrayList<>();
                boolean stopDelta = false;

                for (Map<String, Object> m : models) {
                    Indicator ind = mapToIndicator(m, type);
                    if (ind != null) {
                        if (!isFull && maxId != null && ind.getId() <= maxId) {
                            stopDelta = true;
                            break;
                        }
                        batch.add(ind);
                    }
                }
                
                if (!batch.isEmpty()) {
                    executeBatchUpsert(batch);
                }
                
                if (stopDelta) {
                    break;
                }
                page++;
                
                // SGB API'sini yormamak için ufak bir bekleme (Rate limit engeli)
                Thread.sleep(200);
            } catch (Exception e) {
                System.err.println("Error fetching page " + page + " for type " + type + ": " + e.getMessage());
                break;
            }
        }
    }

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

    private Indicator mapToIndicator(Map<String, Object> map, String type) {
        try {
            Indicator ind = new Indicator();
            ind.setId(Long.valueOf(map.get("id").toString()));
            ind.setType(type);
            String raw = map.get("url") != null ? map.get("url").toString() : "";
            ind.setValueRaw(raw);
            ind.setValueClean(raw.trim()); // Assume clean logic
            ind.setValid(true);
            ind.setCategory(map.get("desc") != null ? map.get("desc").toString() : null);
            ind.setConnectiontype(map.get("connectiontype") != null ? map.get("connectiontype").toString() : null);
            ind.setSource(map.get("source") != null ? map.get("source").toString() : null);
            
            Object crit = map.get("criticality_level");
            if (crit != null) ind.setCriticalityLevel(Integer.valueOf(crit.toString()));
            
            ind.setApiDate(map.get("date") != null ? map.get("date").toString() : null);
            
            Instant now = Instant.now();
            ind.setFirstSeenUtc(now);
            ind.setLastSeenUtc(now);
            ind.setLastChangedUtc(now);
            return ind;
        } catch (Exception e) {
            return null;
        }
    }
}
