package se.digg.sdg.sample.client.support;

import java.io.Serializable;

import com.nimbusds.oauth2.sdk.Scope;

import lombok.Getter;
import se.digg.sdg.sample.client.config.EvidenceService;

/**
 * Holds information between an authorization request and a token request.
 * 
 * @author Martin Lindström
 */

public class CurrentAuthorizationRequest implements Serializable {

  private static final long serialVersionUID = 8727970034724627362L;
  
  @Getter
  private final EvidenceService evidenceService;
  
  @Getter
  private final Scope scope;

  public CurrentAuthorizationRequest(final EvidenceService evidenceService, final Scope scope) {
    this.evidenceService = evidenceService;
    this.scope = scope;
  }
  
}
