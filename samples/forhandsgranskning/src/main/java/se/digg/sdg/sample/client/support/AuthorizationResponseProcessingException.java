package se.digg.sdg.sample.client.support;

/**
 * Exception that is throw when the processing of an authorization response fails.
 * 
 * @author Martin Lindström
 */
public class AuthorizationResponseProcessingException extends OAuth2Exception {

  private static final long serialVersionUID = 7554099769281798953L;

  /**
   * Constructor.
   * 
   * @param message the error message
   */
  public AuthorizationResponseProcessingException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   * 
   * @param message the error message
   * @param cause the cause of the error
   */
  public AuthorizationResponseProcessingException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
