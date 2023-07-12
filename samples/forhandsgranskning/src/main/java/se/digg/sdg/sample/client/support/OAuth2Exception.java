package se.digg.sdg.sample.client.support;

/**
 * Abstract base class for all OAuth2 and OpenID Connect exceptions.
 * 
 * @author Martin Lindström
 */
public abstract class OAuth2Exception extends Exception {

  private static final long serialVersionUID = -9052524759337212673L;

  /**
   * Constructor.
   * 
   * @param message the error message
   */
  protected OAuth2Exception(final String message) {
    super(message);
  }

  /**
   * Constructor.
   * 
   * @param message the error message
   * @param cause the cause of the error
   */
  protected OAuth2Exception(final String message, final Throwable cause) {
    super(message, cause);
  }

}
