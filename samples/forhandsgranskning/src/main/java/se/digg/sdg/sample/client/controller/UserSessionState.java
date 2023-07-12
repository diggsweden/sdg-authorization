package se.digg.sdg.sample.client.controller;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

/**
 * The state for the logged in user. Stored in the session.
 * 
 * @author Martin Lindström
 */
public class UserSessionState implements Serializable {

  private static final long serialVersionUID = 7305171785964412760L;
  
  /**
   * The current refresh token.
   */
  @Getter
  @Setter
  private String refreshToken;

}
