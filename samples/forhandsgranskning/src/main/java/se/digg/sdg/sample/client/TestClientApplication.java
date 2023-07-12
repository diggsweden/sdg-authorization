package se.digg.sdg.sample.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;

import se.swedenconnect.security.credential.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;

/**
 * Application main.
 */
@SpringBootApplication
public class TestClientApplication {

  /**
   * Program main.
   *
   * @param args program arguments
   */
  public static void main(final String[] args) {
    System.setProperty("java.net.preferIPv4Stack", "true");
    SpringApplication.run(TestClientApplication.class, args);
  }

  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  @Bean
  @ConfigurationPropertiesBinding
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }
  
}
