package se.digg.sdg.sample.client.support;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.token.AccessToken;

/**
 * We store the access tokens received in a session object.
 * 
 * @author Martin Lindström
 */
public class SessionAccessToken implements Serializable {

  private static final long serialVersionUID = 5480289268110151536L;

  private final AccessToken accessToken;

  private final Instant expiresAt;

  /**
   * Constructor.
   * 
   * @param accessToken the access token
   */
  public SessionAccessToken(final AccessToken accessToken) {
    this.accessToken = Objects.requireNonNull(accessToken, "accessToken must not be null");
    final long expiresIn = this.accessToken.getLifetime();
    this.expiresAt = expiresIn > 0 ? Instant.now().plusSeconds(expiresIn) : null;
  }

  /**
   * Predicate that tells whether the access token is still valid, i.e., it is valid if the access token has not
   * expired.
   * 
   * @return {@code true} if the access token has not expired and {@code false} otherwise
   */
  public boolean isValid() {
    if (this.expiresAt == null) {
      return true;
    }
    return this.expiresAt.isAfter(Instant.now());
  }

  /**
   * Gets the {@link AccessToken}. If the token has expired, an exception will be thrown.
   * 
   * @return the {@link AccessToken}
   */
  public AccessToken getAccessToken() {
    if (!this.isValid()) {
      throw new IllegalArgumentException("Access token is expired");
    }
    return this.accessToken;
  }

}
