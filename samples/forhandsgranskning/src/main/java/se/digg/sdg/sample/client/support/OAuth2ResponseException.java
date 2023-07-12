package se.digg.sdg.sample.client.support;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Exception class for handling errors reported from the authorization and token endpoints.
 * 
 * @author Martin Lindström
 */
public class OAuth2ResponseException extends OAuth2Exception {
  
  private static final long serialVersionUID = 2554843620338246172L;
  
  /** The OAuth2 error. */
  private final ErrorObject error;

  /**
   * Constructor.
   * 
   * @param error the error received from the request
   */
  public OAuth2ResponseException(final ErrorObject error) {
    this(error, getString(Objects.requireNonNull(error, "error must not be null")));
  }

  /**
   * Constructor.
   * 
   * @param error the error received from the request
   * @param message the message
   */
  public OAuth2ResponseException(final ErrorObject error, final String message) {
    super(message);
    this.error = error;
  }

  /**
   * Gets the OAuth2 error object.
   * 
   * @return the error object
   */
  public ErrorObject getError() {
    return this.error;
  }

  private static String getString(final ErrorObject error) {
    final StringBuilder sb = new StringBuilder();
    sb.append(error.getCode());
    if (error.getDescription() != null) {
      sb.append(" - description: \"").append(error.getDescription()).append("\"");
    }
    sb.append(" - HTTP status code: ").append(error.getHTTPStatusCode());
    if (error.getURI() != null) {
      sb.append(" - uri: ").append(error.getURI().toString());
    }
    return sb.toString();
  }

}
