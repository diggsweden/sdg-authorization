package se.digg.sdg.sample.proof;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import se.digg.sdg.sample.proof.TestEvidenceConfigurationProperties.EvidenceService;

/**
 * Configuration for the test evidence application.
 * 
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties(TestEvidenceConfigurationProperties.class)
public class TestEvidenceConfiguration {

  private final TestEvidenceConfigurationProperties properties;

  /**
   * Constructor.
   * 
   * @param properties the configuration properties
   */
  public TestEvidenceConfiguration(final TestEvidenceConfigurationProperties properties) {
    this.properties = Objects.requireNonNull(properties, "properties must not be null");
  }

  /**
   * Gets the {@link JWSVerifier} that we use to verify the signature of the access token.
   * 
   * @return a {@link JWSVerifier}
   * @throws JOSEException for errors creating the verifier
   */
  @Bean
  JWSVerifier jwsVerifier() throws JOSEException {
    final PublicKey asKey = this.properties.getAuthorizationServer().getAuthorizationServerKey().getPublicKey();
    if ("RSA".equals(asKey.getAlgorithm())) {
      return new RSASSAVerifier((RSAPublicKey) asKey);
    }
    else if ("EC".equals(asKey.getAlgorithm())) {
      return new ECDSAVerifier((ECPublicKey) asKey);
    }
    else {
      throw new IllegalArgumentException("Unsupported key type");
    }
  }

  /**
   * Gets the authorization server ID.
   * 
   * @return the authorization server ID
   */
  @Bean("authorizationServerId")
  String authorizationServerId() {
    return this.properties.getAuthorizationServer().getId();
  }

  /**
   * Gets the configuration for all evidence services (implemented by controller methods).
   * 
   * @return a list of evidence service configuration
   */
  @Bean("evidenceServices")
  List<EvidenceService> evidenceServices() {
    return this.properties.getServices();
  }

  /**
   * Gets a list of all "allowed clients", i.e., the ID:s of all clients that we accept as callers to our API methods.
   * 
   * @return a list of client ID:s
   */
  @Bean("allowedClients")
  List<String> allowedClients() {
    return this.properties.getAllowedClients();
  }

}
