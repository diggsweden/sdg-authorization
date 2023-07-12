package se.digg.sdg.sample.proof;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@ConfigurationProperties("evidence")
public class TestEvidenceConfigurationProperties implements InitializingBean {
  
  /**
   * The settings for the authorization server that is trusted by our application.
   */
  @Getter
  @Setter
  private AuthorizationServer authorizationServer;
  
  /**
   * The ID:s of the clients that we accept to invoke us. Their client_id:s need to be
   * present in the signed access tokens that we receive.
   */
  @Getter
  private List<String> allowedClients = new ArrayList<>();
  
  /**
   * Configuration for our evidence services
   */
  @Getter
  private final List<EvidenceService> services = new ArrayList<>();

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authorizationServer, "evidence.authorization-server.* must be set");
    this.authorizationServer.afterPropertiesSet();
    Assert.notEmpty(this.services, "At least of service must be configured");  
    for (final EvidenceService ev : this.services) {
      ev.afterPropertiesSet();
    }
  }

  /**
   * Configuration for an evidence service.
   */
  public static class EvidenceService implements InitializingBean {
    
    /**
     * The ID as assigned by the Authorization Server.
     */
    @Getter
    @Setter
    private String id;
    
    /**
     * The scope(s) that are required by this service. 
     */
    @Getter
    private final List<String> requiredScopes = new ArrayList<>();

    @Override
    public void afterPropertiesSet() throws Exception {
      Assert.hasText(this.id, "evidence.services[].id must be set");
    }
    
  }
  
  /**
   * Configuration for the authorization server.
   */
  @Data
  public static class AuthorizationServer implements InitializingBean {

    /**
     * The ID (issuer) of the authorization server.
     */
    private String id;

    /**
     * The certificate holding the authorization server public key that we use for signature validation.
     */
    private X509Certificate authorizationServerKey;

    @Override
    public void afterPropertiesSet() throws Exception {
      Assert.hasText(this.id, "client.authorization-server.id must be set");
      Assert.notNull(this.authorizationServerKey, "client.authorization-server.authorization-server-key must be set");
    }

  }
  
}
