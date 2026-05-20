package tr.gov.siberguvenlik.sgbapibridge.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import tr.gov.siberguvenlik.sgbapibridge.entity.Indicator;
import tr.gov.siberguvenlik.sgbapibridge.repository.IndicatorRepository;
import tr.gov.siberguvenlik.sgbapibridge.util.StixConvert;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@RestController
@Tag(name = "1. SGB İstihbarat API", description = "Firewall cihazları için Düz Metin (Plain Text) ve SIEM cihazları için TAXII 2.1 STIX formatında siber tehdit beslemeleri (feed) sunar.")
public class TaxiiController {

    private static final String TAXII_JSON = "application/taxii+json;version=2.1";

    private static final List<Map<String, Object>> COLLECTIONS_META = List.of(
        collectionMeta("PH",  "sgb-phishing",         "SGB Phishing",         "Phishing site / kullanici kandirma URL ve domain'leri."),
        collectionMeta("BC",  "sgb-botnet-cc",         "SGB Botnet C&C",       "Botnet komuta-kontrol sunuculari (outbound C2 tespiti)."),
        collectionMeta("AC",  "sgb-apt-cc",            "SGB APT C&C",          "APT komuta-kontrol - yuksek oncelikli tehdit."),
        collectionMeta("EK",  "sgb-exploit-kit",       "SGB Exploit Kit",      "Exploit kit landing / driver sayfalari."),
        collectionMeta("MF",  "sgb-malware-download",  "SGB Malware Download", "Malware dagitim noktalari (payload host)."),
        collectionMeta("MM",  "sgb-mining",            "SGB Cryptomining",     "Tarayicidan veya zararlidan cryptomining noktalari."),
        collectionMeta("MC",  "sgb-mobile-cc",         "SGB Mobile C&C",       "Mobil zararli C2."),
        collectionMeta("OT",  "sgb-other",             "SGB Other",            "Diger / siniflandirilmamis kotucul gostergeler.")
    );

    private static final Map<String, String> ALIAS_TO_CT = Map.of(
        "sgb-phishing",         "PH",
        "sgb-botnet-cc",        "BC",
        "sgb-apt-cc",           "AC",
        "sgb-exploit-kit",      "EK",
        "sgb-malware-download", "MF",
        "sgb-mining",           "MM",
        "sgb-mobile-cc",        "MC",
        "sgb-other",            "OT"
    );

    private final IndicatorRepository indicatorRepository;

    public TaxiiController(IndicatorRepository indicatorRepository) {
        this.indicatorRepository = indicatorRepository;
    }

    @Operation(summary = "Güvenlik Duvarı (Firewall) Beslemesi", 
               description = "Güvenlik duvarları tarafından doğrudan tüketilebilmesi için ilgili türdeki zararlı göstergeleri düz metin (alt alta) formatında döndürür.")
    @ApiResponse(responseCode = "200", description = "Başarılı veri çekimi")
    @GetMapping(value = "/{type}-list.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getFeed(
            @Parameter(description = "İstenen gösterge türü (örn: domain, ip, url)", example = "domain") 
            @PathVariable String type) {
        return String.join("\n", indicatorRepository.findCleanValuesByType(type));
    }

    @Operation(summary = "TAXII 2.1 Discovery (Keşif)", 
               description = "SIEM cihazlarının sisteme ilk bağlandıklarında API root adreslerini keşfetmesini sağlar.")
    @GetMapping(value = "/taxii2/index.json", produces = TAXII_JSON)
    public Map<String, Object> discovery() {
        return Map.of(
            "title",       "SGB Threat Intelligence (TAXII 2.1)",
            "description", "Siber Guvenlik Baskanligi (SGB, eski USOM) acik tehdit beslemesinin TAXII 2.1 sunumu. Anonim erisim, public veri.",
            "default",     "/api/",
            "api_roots",   List.of("/api/")
        );
    }

    @Operation(summary = "TAXII 2.1 API Root", 
               description = "API versiyonunu ve desteklenen formatları belirtir.")
    @GetMapping(value = "/api/", produces = TAXII_JSON)
    public Map<String, Object> apiRoot() {
        return Map.of(
            "title",              "SGB Default API Root",
            "description",        "Tek API root altinda connectiontype bazli koleksiyonlar.",
            "versions",           List.of("application/taxii+json;version=2.1"),
            "max_content_length", 104857600
        );
    }

    @Operation(summary = "TAXII 2.1 Tüm Koleksiyonlar", 
               description = "Sistemde bulunan tüm zararlı bağlantı kategorilerini (phishing, botnet, vb.) listeler.")
    @GetMapping(value = "/api/collections/", produces = TAXII_JSON)
    public Map<String, Object> listCollections() {
        return Map.of("collections", COLLECTIONS_META);
    }

    @Operation(summary = "TAXII 2.1 Tekil Koleksiyon Detayı", 
               description = "İstenen belirli bir koleksiyonun (örn: sgb-phishing) meta verilerini döndürür.")
    @GetMapping(value = "/api/collections/{cid}/", produces = TAXII_JSON)
    public Map<String, Object> collectionDetail(
            @Parameter(description = "Koleksiyon ID'si (örn: sgb-phishing)", example = "sgb-phishing") 
            @PathVariable String cid) {
        return COLLECTIONS_META.stream()
            .filter(m -> cid.equals(m.get("alias")))
            .findFirst()
            .orElse(Map.of("error", "collection not found"));
    }

    @Operation(summary = "TAXII 2.1 STIX Veri İndirme (Sayfalı)", 
               description = "Seçilen koleksiyonun içindeki gerçek siber tehdit göstergelerini (Indicator) STIX 2.1 nesnesi olarak 5000'erli sayfalar halinde döndürür.")
    @GetMapping(value = "/api/collections/{cid}/objects/page-{page}.json", produces = TAXII_JSON)
    public Map<String, Object> getCollectionObjects(
            @Parameter(description = "Koleksiyon ID'si (örn: sgb-phishing, sgb-all)", example = "sgb-phishing") 
            @PathVariable String cid,
            @Parameter(description = "Sayfa numarası (örn: 0001, 0002)", example = "0001") 
            @PathVariable String page) {

        String ct = "sgb-all".equals(cid) ? null : ALIAS_TO_CT.get(cid);

        int pageNum = Integer.parseInt(page);
        int pageSize = 5000;
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);

        List<Indicator> pageItems = (ct == null)
            ? indicatorRepository.findAllValidPaged(pageable)
            : indicatorRepository.findByConnectionTypePaged(ct, pageable);

        long totalCount = (ct == null)
            ? indicatorRepository.countAllValid()
            : indicatorRepository.countByConnectionType(ct);

        boolean more = (long) pageNum * pageSize < totalCount;

        List<Map<String, Object>> stixObjects = new ArrayList<>();
        stixObjects.add(StixConvert.identityObject());
        pageItems.stream()
            .map(StixConvert::toStixIndicator)
            .filter(Objects::nonNull)
            .forEach(stixObjects::add);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("more", more);
        if (more) result.put("next", String.format("%04d", pageNum + 1));
        result.put("objects", stixObjects);
        return result;
    }

    private static Map<String, Object> collectionMeta(String ct, String alias, String title, String desc) {
        return Map.of(
            "id",          collectionUUID(alias),
            "title",       title,
            "description", desc,
            "alias",       alias,
            "can_read",    true,
            "can_write",   false,
            "media_types", List.of("application/stix+json;version=2.1")
        );
    }

    private static String collectionUUID(String cid) {
        try {
            UUID namespace = UUID.fromString("c0ffee00-5664-4b1d-9c1d-5b00b50000d1");
            String name = "taxii-collection:" + cid;
            byte[] nsBytes = toBytes(namespace);
            byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
            byte[] combined = new byte[nsBytes.length + nameBytes.length];
            System.arraycopy(nsBytes, 0, combined, 0, nsBytes.length);
            System.arraycopy(nameBytes, 0, combined, nsBytes.length, nameBytes.length);
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(combined);
            hash[6] = (byte) ((hash[6] & 0x0F) | 0x50);
            hash[8] = (byte) ((hash[8] & 0x3F) | 0x80);
            long msb = 0, lsb = 0;
            for (int i = 0; i < 8; i++) msb = (msb << 8) | (hash[i] & 0xFF);
            for (int i = 8; i < 16; i++) lsb = (lsb << 8) | (hash[i] & 0xFF);
            return new UUID(msb, lsb).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] toBytes(UUID uuid) {
        byte[] b = new byte[16];
        long msb = uuid.getMostSignificantBits(), lsb = uuid.getLeastSignificantBits();
        for (int i = 7; i >= 0; i--) { b[i] = (byte) (msb & 0xFF); msb >>= 8; }
        for (int i = 15; i >= 8; i--) { b[i] = (byte) (lsb & 0xFF); lsb >>= 8; }
        return b;
    }
}
