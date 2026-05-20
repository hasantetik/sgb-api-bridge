package tr.gov.siberguvenlik.sgbapibridge.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("SGB API Bridge (Tehdit İstihbarat Servisi)")
                        .version("1.0.0")
                        .description("Siber Güvenlik Başkanlığı (SGB) zararlı bağlantı verilerini " +
                                "Firewall (Güvenlik Duvarı) ve SIEM cihazları için uygun formatlara (Plain Text ve STIX/TAXII 2.1) " +
                                "çeviren kurumsal entegrasyon servisi.")
                        .contact(new Contact()
                                .name("SGB API Bridge Geliştirme Ekibi")
                                .url("https://github.com/bilsectr/sgb-api-bridge")));
    }
}
