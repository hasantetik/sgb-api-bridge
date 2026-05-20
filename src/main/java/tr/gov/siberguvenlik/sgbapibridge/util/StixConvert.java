package tr.gov.siberguvenlik.sgbapibridge.util;

import tr.gov.siberguvenlik.sgbapibridge.entity.Indicator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class StixConvert {

    private static final UUID STIX_NS = UUID.fromString("c0ffee00-5664-4b1d-9c1d-5b00b50000d1");
    public static final String SGB_IDENTITY_ID = "identity--" + generateType5UUID(STIX_NS, "sgb-siber-guvenlik-baskanligi").toString();

    private static final Map<String, Integer> SOURCE_CONFIDENCE = Map.of(
            "US", 85,
            "SB", 85,
            "SO", 70,
            "RS", 60,
            "IH", 40
    );

    private static final Map<String, List<String>> CT_TO_INDICATOR_TYPES = Map.of(
            "PH", List.of("malicious-activity"),
            "BC", List.of("malicious-activity"),
            "AC", List.of("malicious-activity"),
            "EK", List.of("malicious-activity"),
            "MF", List.of("malicious-activity"),
            "MM", List.of("malicious-activity"),
            "MC", List.of("malicious-activity"),
            "OT", List.of("unknown")
    );

    private static final Map<String, String> CT_LABELS = Map.of(
            "PH", "phishing",
            "BC", "botnet-c2",
            "AC", "apt-c2",
            "EK", "exploit-kit",
            "MF", "malware-download",
            "MM", "mining",
            "MC", "mobile-c2",
            "OT", "other"
    );

    private static final Map<String, String> DESC_LABELS = Map.of(
            "PH", "phishing",
            "MD", "malware-distribution-domain",
            "MI", "malware-distribution-ip",
            "MU", "malware-distribution-url",
            "MC", "malware-command-center",
            "BP", "financial-phishing",
            "CA", "cyber-attack"
    );

    public static UUID generateType5UUID(UUID namespace, String name) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(toBytes(namespace));
            md.update(name.getBytes(StandardCharsets.UTF_8));
            byte[] sha1Bytes = md.digest();

            sha1Bytes[6] &= 0x0f;  // clear version
            sha1Bytes[6] |= 0x50;  // set to version 5
            sha1Bytes[8] &= 0x3f;  // clear variant
            sha1Bytes[8] |= 0x80;  // set to IETF variant

            long msb = 0;
            long lsb = 0;
            for (int i = 0; i < 8; i++) msb = (msb << 8) | (sha1Bytes[i] & 0xff);
            for (int i = 8; i < 16; i++) lsb = (lsb << 8) | (sha1Bytes[i] & 0xff);
            return new UUID(msb, lsb);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not found", e);
        }
    }

    private static byte[] toBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (msb & 0xff);
            msb >>= 8;
        }
        for (int i = 15; i >= 8; i--) {
            bytes[i] = (byte) (lsb & 0xff);
            lsb >>= 8;
        }
        return bytes;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'");
    }

    private static String stixPattern(String type, String value) {
        if (value == null) return null;
        String escaped = escape(value);
        return switch (type) {
            case "domain" -> "[domain-name:value = '" + escaped + "']";
            case "url" -> "[url:value = '" + escaped + "']";
            case "ip" -> "[ipv4-addr:value = '" + escaped + "']";
            case "ip6", "ip6net" -> "[ipv6-addr:value = '" + escaped + "']";
            default -> null;
        };
    }

    public static Map<String, Object> identityObject() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "identity");
        map.put("spec_version", "2.1");
        map.put("id", SGB_IDENTITY_ID);
        map.put("created", "2020-01-01T00:00:00.000Z");
        map.put("modified", "2020-01-01T00:00:00.000Z");
        map.put("name", "Siber Guvenlik Baskanligi (SGB)");
        map.put("identity_class", "organization");
        map.put("contact_information", "https://siberguvenlik.gov.tr");
        return map;
    }

    public static Map<String, Object> toStixIndicator(Indicator row) {
        String pattern = stixPattern(row.getType(), row.getValueClean());
        if (pattern == null) return null;

        String ct = row.getConnectiontype();
        String cat = row.getCategory();
        String src = row.getSource();

        List<String> labels = new ArrayList<>();
        if (ct != null && CT_LABELS.containsKey(ct)) labels.add(CT_LABELS.get(ct));
        if (cat != null && DESC_LABELS.containsKey(cat) && !labels.contains(DESC_LABELS.get(cat))) labels.add(DESC_LABELS.get(cat));
        if (labels.isEmpty()) labels.add("malicious-activity");

        String validFrom = row.getApiDate() != null ? row.getApiDate() : (row.getFirstSeenUtc() != null ? row.getFirstSeenUtc().toString() : "");
        validFrom = validFrom.replace(" ", "T");
        if (!validFrom.isEmpty() && !validFrom.endsWith("Z") && !validFrom.substring(10).contains("+")) {
            validFrom += "Z";
        }

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "indicator");
        map.put("spec_version", "2.1");
        map.put("id", "indicator--" + generateType5UUID(STIX_NS, "sgb:" + row.getId()).toString());
        map.put("created_by_ref", SGB_IDENTITY_ID);
        map.put("created", row.getFirstSeenUtc() != null ? row.getFirstSeenUtc().toString() : "");
        
        Instant modifiedInst = row.getLastChangedUtc() != null ? row.getLastChangedUtc() : row.getFirstSeenUtc();
        map.put("modified", modifiedInst != null ? modifiedInst.toString() : "");
        
        map.put("name", "SGB " + row.getType() + " indicator #" + row.getId());
        map.put("pattern", pattern);
        map.put("pattern_type", "stix");
        map.put("pattern_version", "2.1");
        map.put("valid_from", validFrom);
        map.put("indicator_types", ct != null ? CT_TO_INDICATOR_TYPES.getOrDefault(ct, List.of("malicious-activity")) : List.of("malicious-activity"));
        map.put("labels", labels);
        map.put("confidence", src != null ? SOURCE_CONFIDENCE.getOrDefault(src, 50) : 50);
        
        Map<String, String> extRef = new HashMap<>();
        extRef.put("source_name", "sgb");
        extRef.put("external_id", String.valueOf(row.getId()));
        extRef.put("url", "https://siberguvenlik.gov.tr");
        map.put("external_references", List.of(extRef));
        
        map.put("x_sgb_id", row.getId());
        map.put("x_sgb_type", row.getType());
        map.put("x_sgb_value", row.getValueClean());
        map.put("x_sgb_connectiontype", ct);
        map.put("x_sgb_description", cat);
        map.put("x_sgb_source", src);
        map.put("x_sgb_criticality", row.getCriticalityLevel());
        map.put("x_sgb_api_date", row.getApiDate());
        
        return map;
    }
}
