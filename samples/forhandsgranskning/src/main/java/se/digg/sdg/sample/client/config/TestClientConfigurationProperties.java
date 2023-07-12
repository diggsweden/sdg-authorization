package se.digg.sdg.sample.client.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

/**
 * Configuration properties for the client application.
 * 
 * @author Martin Lindström
 */
@ConfigurationProperties("client")
@Slf4j
public class TestClientConfigurationProperties implements InitializingBean {

  /**
   * The client ID.
   */
  @Getter
  @Setter
  private String clientId;

  /**
   * The client credential.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties credential;

  // The credential as created from the above properties ...
  private PkiCredential _credential;

  /**
   * The signature algorithm this client uses. Default is RS256 if the credential holds an RSA key and ES256 if the
   * credential is an EC key.
   */
  @Getter
  @Setter
  private String signatureAlgorithm;

  /**
   * The authorization callback URI.
   */
  @Getter
  @Setter
  private String authzCallbackUri;

  /**
   * The login callback URI.
   */
  @Getter
  @Setter
  private String loginCallbackUri;

  /**
   * The scopes to request.
   */
  @Getter
  private List<String> scopes = new ArrayList<>();

  /**
   * Configuration for the authorization server.
   */
  @Getter
  @Setter
  private AuthorizationServer authorizationServer;

  /**
   * Configuration for the evidence services we may invoke.
   */
  @Getter
  private List<EvidenceService> evidenceServices = new ArrayList<>();

  /**
   * Whether we are in development mode.
   */
  @Getter
  @Setter
  private boolean developmentMode = true;

  /**
   * Asserts that all required settings have been set.
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.clientId, "client.client-id must be set");

    Assert.notNull(this.credential, "client.credential.* must be set");
    final JWSAlgorithm a = this.signatureAlgorithm != null ? JWSAlgorithm.parse(this.signatureAlgorithm) : null;
    final PkiCredential c = this.createPkiCredential();
    if ("RSA".equals(c.getPublicKey().getAlgorithm())) {
      if (a == null) {
        this.signatureAlgorithm = JWSAlgorithm.RS256.getName();
        log.debug("Setting signature-algorithm to " + this.signatureAlgorithm);
      }
      else if (!JWSAlgorithm.Family.RSA.contains(a)) {
        throw new IllegalArgumentException("Invalid signature algorithm - " + this.signatureAlgorithm
            + " can not be used with configured credential");
      }
    }
    else if ("EC".equals(c.getPublicKey().getAlgorithm())) {
      if (a == null) {
        this.signatureAlgorithm = JWSAlgorithm.ES256.getName();
        log.debug("Setting signature-algorithm to " + this.signatureAlgorithm);
      }
      else if (!JWSAlgorithm.Family.EC.contains(a)) {
        throw new IllegalArgumentException("Invalid signature algorithm - " + this.signatureAlgorithm
            + " can not be used with configured credential");
      }
    }
    else {
      throw new IllegalArgumentException("Invalid credential - algorithm not supported");
    }

    Assert.hasText(this.authzCallbackUri, "client.authz-callback-uri must be set");
    Assert.hasText(this.loginCallbackUri, "client.login-callback-uri must be set");
    Assert.notNull(this.authorizationServer, "client.authorization-server.* must be set");
    this.authorizationServer.afterPropertiesSet();
    
    for (final EvidenceService ev : this.evidenceServices) {
      ev.afterPropertiesSet();
    }
  }

  /**
   * Based on the credential settings a {@link PkiCredential} is created and returned.
   * 
   * @return a {@link PkiCredential}
   */
  public PkiCredential createPkiCredential() {
    if (this._credential == null) {
      try {
        final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(this.credential);
        factory.afterPropertiesSet();
        this._credential = factory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to create client credential", e);
      }
    }
    return this._credential;
  }

  /**
   * Creates a {@link JWK} based on the settings for credential and signature algorithm.
   * 
   * @return a {@link JWK}
   */
  public JWK createClientJwk() {
    final PkiCredential clientCredential = this.createPkiCredential();
    try {
      if ("RSA".equals(clientCredential.getPublicKey().getAlgorithm())) {
        return new RSAKey.Builder(RSAPublicKey.class.cast(clientCredential.getPublicKey()))
            .privateKey(clientCredential.getPrivateKey())
            .keyIDFromThumbprint()
            .algorithm(JWSAlgorithm.parse(this.getSignatureAlgorithm()))
            .keyUse(KeyUse.SIGNATURE)
            .build();
      }
      else if ("EC".equals(clientCredential.getPublicKey().getAlgorithm())) {
        return new ECKey.Builder(ECKey.parse(clientCredential.getCertificate()))
            .privateKey(clientCredential.getPrivateKey())
            .keyIDFromThumbprint()
            .algorithm(JWSAlgorithm.parse(this.getSignatureAlgorithm()))
            .keyUse(KeyUse.SIGNATURE)
            .build();
      }
      else {
        throw new SecurityException("Unsupported key type - " + clientCredential.getPublicKey().getAlgorithm());
      }
    }
    catch (final JOSEException e) {
      throw new SecurityException("Failed to create JWK from supplied credential", e);
    }
  }

  /**
   * Configuration for the authorization server/OpenID provider.
   */
  @Data
  public static class AuthorizationServer implements InitializingBean {

    /**
     * The ID (issuer) of the authorization server/OpenID provider.
     */
    private String id;

    /**
     * Endpoint for OIDC authentication and OAuth2 authorization requests.
     */
    private String authorizationEndpoint;

    /**
     * Endpoint for the OIDC/OAuth2 token endpoint.
     */
    private String tokenEndpoint;

    /**
     * Endpoint for the OIDC UserInfo endpoint.
     */
    private String userInfoEndpoint;

    /**
     * The certificate holding the authorization server public key that we use for signature validation.
     */
    private X509Certificate authorizationServerKey;

    @Override
    public void afterPropertiesSet() throws Exception {
      Assert.hasText(this.id, "client.authorization-server.id must be set");
      Assert.hasText(this.authorizationEndpoint, "client.authorization-server.authorization-endpoint must be set");
      Assert.hasText(this.tokenEndpoint, "client.authorization-server.token-endpoint must be set");
      Assert.hasText(this.userInfoEndpoint, "client.authorization-server.user-info-endpoint must be set");
      Assert.notNull(this.authorizationServerKey, "client.authorization-server.authorization-server-key must be set");
    }

    public URI getAuthorizationEndpointUri() {
      try {
        return new URI(this.authorizationEndpoint);
      }
      catch (final URISyntaxException e) {
        throw new RuntimeException("Invalid authorization endpoint", e);
      }
    }

    public URI getTokenEndpointUri() {
      try {
        return new URI(this.tokenEndpoint);
      }
      catch (final URISyntaxException e) {
        throw new RuntimeException("Invalid token endpoint", e);
      }
    }

    public URI getUserInfoEndpointUri() {
      try {
        return new URI(this.userInfoEndpoint);
      }
      catch (final URISyntaxException e) {
        throw new RuntimeException("Invalid userInfo endpoint", e);
      }
    }

  }

}
