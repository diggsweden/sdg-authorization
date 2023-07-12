package se.digg.sdg.sample.proof;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;

import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;

/**
 * Application main.
 */
@SpringBootApplication
public class TestEvidenceApplication {
  
  /**
   * Program main.
   *
   * @param args program arguments
   */
  public static void main(final String[] args) {
    System.setProperty("java.net.preferIPv4Stack", "true");
    SpringApplication.run(TestEvidenceApplication.class, args);
  }

  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }  

}
