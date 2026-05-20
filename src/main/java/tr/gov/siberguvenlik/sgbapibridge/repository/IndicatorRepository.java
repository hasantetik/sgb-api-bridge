package tr.gov.siberguvenlik.sgbapibridge.repository;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import tr.gov.siberguvenlik.sgbapibridge.entity.Indicator;

import java.time.Instant;
import java.util.List;

@Repository
public interface IndicatorRepository extends JpaRepository<Indicator, Long> {

    @Query("SELECT MAX(i.id) FROM Indicator i WHERE i.type = :type")
    Long getMaxIdByType(@Param("type") String type);

    @Modifying
    @Transactional
    @Query("UPDATE Indicator i SET i.removedAtUtc = :now WHERE i.type = :type AND i.removedAtUtc IS NULL AND i.lastSeenUtc < :cutoffUtc")
    int markRemovedByCutoff(@Param("type") String type, @Param("cutoffUtc") Instant cutoffUtc, @Param("now") Instant now);

    // Sayfalı sorgular (performanslı - sadece istenen sayfayı RAM'e çeker)
    @Query("SELECT i FROM Indicator i WHERE i.removedAtUtc IS NULL AND i.valid = true AND i.connectiontype = :ct ORDER BY i.id ASC")
    List<Indicator> findByConnectionTypePaged(@Param("ct") String ct, Pageable pageable);

    @Query("SELECT i FROM Indicator i WHERE i.removedAtUtc IS NULL AND i.valid = true ORDER BY i.id ASC")
    List<Indicator> findAllValidPaged(Pageable pageable);

    // Toplam kayıt sayısı (more alanı için)
    @Query("SELECT COUNT(i) FROM Indicator i WHERE i.removedAtUtc IS NULL AND i.valid = true AND i.connectiontype = :ct")
    long countByConnectionType(@Param("ct") String ct);

    @Query("SELECT COUNT(i) FROM Indicator i WHERE i.removedAtUtc IS NULL AND i.valid = true")
    long countAllValid();

    // Feed listeleri (bunlar zaten sadece string döndüğü için hafif)
    @Query("SELECT i.valueClean FROM Indicator i WHERE i.type = :type AND i.removedAtUtc IS NULL AND i.valid = true ORDER BY i.valueClean ASC")
    List<String> findCleanValuesByType(@Param("type") String type);
}
