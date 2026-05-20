package tr.gov.siberguvenlik.sgbapibridge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Entity
@Table(name = "indicators", indexes = {
        @Index(name = "idx_ind_type", columnList = "type"),
        @Index(name = "idx_ind_ct", columnList = "connectiontype"),
        @Index(name = "idx_ind_cat", columnList = "category"),
        @Index(name = "idx_ind_removed", columnList = "removed_at_utc"),
        @Index(name = "idx_ind_type_valid", columnList = "type, valid, removed_at_utc"),
        @Index(name = "idx_ind_taxii_ct", columnList = "removed_at_utc, valid, connectiontype, id"),
        @Index(name = "idx_ind_taxii_all", columnList = "removed_at_utc, valid, id")
})
@Getter
@Setter
public class Indicator {

    @Id
    private Long id;

    @Column(nullable = false)
    private String type;

    @Column(name = "value_raw", nullable = false, columnDefinition = "TEXT")
    private String valueRaw;

    @Column(name = "value_clean", columnDefinition = "TEXT")
    private String valueClean;

    @Column(nullable = false)
    private Boolean valid = false;

    private String category;

    private String connectiontype;

    private String source;

    @Column(name = "criticality_level")
    private Integer criticalityLevel;

    @Column(name = "api_date")
    private String apiDate;

    @Column(name = "first_seen_utc", nullable = false)
    private Instant firstSeenUtc;

    @Column(name = "last_seen_utc", nullable = false)
    private Instant lastSeenUtc;

    @Column(name = "last_changed_utc")
    private Instant lastChangedUtc;

    @Column(name = "removed_at_utc")
    private Instant removedAtUtc;
}
