package se.digg.sdg.sample.client.config;

import java.io.Serializable;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.Data;

/**
 * Configuration for an evidence service.
 */
@Data
public class EvidenceService implements InitializingBean, Serializable {
  
  private static final long serialVersionUID = -7577375676605449817L;

  /**
   * The name of the service.
   */
  private String name;
  
  /**
   * The Resource server ID.
   */
  private String id;
  
  /**
   * The URL for the API endpoint.
   */
  private String apiEndpoint;
  
  /**
   * The required scopes for this service.
   */
  private List<String> requiredScopes;

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.name, "client.evidence-services[].name must be set");
    Assert.hasText(this.id, "client.evidence-services[].id must be set");
    Assert.hasText(this.apiEndpoint, "client.evidence-services[].api-endpoint must be set");
  }
}
