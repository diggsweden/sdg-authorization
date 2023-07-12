package se.digg.sdg.sample.client.controller;

import java.net.URI;
import java.security.Provider;
import java.security.SignatureException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.ACR;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import se.digg.sdg.sample.client.config.EvidenceService;
import se.digg.sdg.sample.client.config.TestClientConfigurationProperties.AuthorizationServer;
import se.digg.sdg.sample.client.support.AuthorizationResponseProcessingException;
import se.digg.sdg.sample.client.support.CurrentAuthorizationRequest;
import se.digg.sdg.sample.client.support.OAuth2ResponseException;
import se.digg.sdg.sample.client.support.SessionAccessToken;
import se.digg.sdg.sample.client.support.TokenSupport;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test controller.
 */
@Controller
@RequestMapping("/")
@Slf4j
public class TestClientController {

  public static final String OAUTH_STATE_SESSION_NAME =
      TestClientController.class.getPackageName() + ".State";

  public static final String OIDC_NONCE_SESSION_NAME =
      TestClientController.class.getPackageName() + ".Nonce";

  public static final String PKCE_CODEVERIFIER_SESSION_NAME =
      TestClientController.class.getPackageName() + ".CodeVerifier";

  public static final String IDTOKEN_TOKEN_SESSION_NAME =
      TestClientController.class.getPackageName() + ".IDToken";

  /**
   * Session name for where we store the access token that was issued during an OIDC authentication request. This token
   * is used to obtain userinfo.
   */
  public static final String OP_ACCESS_TOKEN_SESSION_NAME =
      TestClientController.class.getPackageName() + ".OpAccessToken";

  /**
   * Session name for where we store the access token that was issued during an OAuth2 authorization request. This token
   * is used to make API-calls to resource servers.
   */
  public static final String RESOURCE_ACCESS_TOKEN_SESSION_NAME =
      TestClientController.class.getPackageName() + ".ResourceAccessToken";

  public static final String CURRENT_AUTHZ_REQUEST_SESSION_NAME =
      TestClientController.class.getPackageName() + ".CurrentAuthzRequest";

  /**
   * Session name for where we store the refresh token we are receiving.
   */
  public static final String REFRESH_TOKEN_SESSION_NAME =
      TestClientController.class.getPackageName() + ".RefreshToken";

  /** The registered client ID that our application has at the Authorization Server. */
  @Autowired
  private ClientID clientId;

  /** The client credential. */
  @Autowired
  @Qualifier("clientCredential")
  private PkiCredential clientCredential;

  /** The client JWK (more or less the same as the clientCredential but in JWK format). */
  @Autowired
  private JWK clientJwk;

  /**
   * The URI that we want the Authorization Server to redirect our user's back to when sending authentication requests.
   */
  @Autowired
  @Qualifier("loginRedirectUri")
  private URI loginRedirectUri;

  /**
   * The URI that we want the Authorization Server to redirect our user's back to when sending authorization requests.
   */
  @Autowired
  @Qualifier("authzRedirectUri")
  private URI authzRedirectUri;

  /**
   * The authorizartion server settings.
   */
  @Autowired
  private AuthorizationServer authorizationServer;

  /** The verifier we use to validate AS signatures on tokens. */
  @Autowired
  private JWSVerifier jwsVerifier;

  /**
   * The resource servers.
   */
  @Autowired
  private List<EvidenceService> evidenceServices;

  @Autowired
  @Qualifier("httpRequestCustomizer")
  private Consumer<HTTPRequest> httpRequestCustomizer;

  @Autowired
  private HTTPRequestConfigurator httpRequestConfigurator;

  @Autowired
  private RestTemplate restTemplate;

  @Autowired
  private ObjectMapper objectMapper;

  /**
   * Controller method for start page.
   * 
   * @param httpRequest the HTTP servlet request
   * @return a {@link ModelAndView}
   */
  @RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
  public ModelAndView home(final HttpServletRequest httpRequest) {

    final HttpSession session = httpRequest.getSession();

    // Are we logged in?
    // Normally an application would not use the ID token as its token for handling
    // a logged user, but this is a demo app that isn't meant to teach you how to handle
    // logged in users in your session.
    //
    final JWT idToken = (JWT) session.getAttribute(IDTOKEN_TOKEN_SESSION_NAME);
    final String loggedInUser = Optional.ofNullable(idToken)
        .map(t -> TokenSupport.findUserId(t))
        .orElse(null);

    final ModelAndView mav = new ModelAndView("home");
    if (loggedInUser != null) {
      mav.addObject("loggedInUser", loggedInUser);
      mav.addObject("resources", this.evidenceServices);
    }

    return mav;
  }

  /**
   * Illustrates how we send an OIDC authentication request.
   * 
   * @param httpRequest the servlet request
   * @return a ModelAndView that redirects the user agent to the Authorization Server's authorization endpoint
   */
  @PostMapping("/login")
  public ModelAndView oidcLogin(final HttpServletRequest httpRequest) {

    // Build an authentication request for OIDC login
    //

    // The scope parameter must always include the "openid" scope. This scope tells the
    // Authorization Server to act as an OpenID Provider and treat the request received on
    // the Authorization endpoint as an authentication request.
    // We also add the scopes "https://id.oidc.se/scope/naturalPersonNumber" and
    // "https://id.swedenconnect.se/scope/eidasNaturalPerson". These scopes tells the OP that
    // we are interested in receiving user claims recived from an authentication against a
    // Swedish eID provider or eIDAS.
    //
    final Scope scope = new Scope();
    scope.add(OIDCScopeValue.OPENID);
    scope.add(ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER);
    scope.add("https://id.swedenconnect.se/scope/eidasNaturalPerson");

    // By setting the prompt parameter to "login" we force authentication, i.e., an SSO login
    // is not accepted.
    //
    final Prompt.Type prompt = Prompt.Type.LOGIN;

    // By assigning one, or more, Authentication Context Class Reference:s, we state the
    // type of authentication that is acceptable for us. This is also referred to as the
    // LoA, or Level of Assurance.
    //
    // This application accepts LoA 3 and eIDAS substantial and high.
    //
    final List<ACR> authenticationContexts = List.of(
        new ACR("http://id.elegnamnden.se/loa/1.0/loa3"),
        new ACR("http://id.swedenconnect.se/loa/1.0/uncertified-loa3"),
        new ACR("http://id.elegnamnden.se/loa/1.0/eidas-nf-sub"),
        new ACR("http://id.elegnamnden.se/loa/1.0/eidas-nf-high"));

    // OK, put an authentication request together ...
    //
    final HttpSession session = httpRequest.getSession();

    // The state is an opaque value used to maintain state between the request and the callback. Typically, Cross-Site
    // Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a
    // browser cookie.
    //
    final State state = new State(UUID.randomUUID().toString());
    session.setAttribute(OAUTH_STATE_SESSION_NAME, state);

    // Proof Key for Code Exchange (PKCE) extension, [RFC7636] and include the code_challenge and code_challenge_method
    // parameters.
    //
    final CodeVerifier codeVerifier = new CodeVerifier();
    session.setAttribute(PKCE_CODEVERIFIER_SESSION_NAME, codeVerifier);

    // String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is
    // passed through unmodified from the Authentication Request to the ID Token.
    //
    final Nonce nonce = new Nonce(UUID.randomUUID().toString());
    session.setAttribute(OIDC_NONCE_SESSION_NAME, nonce);

    final AuthenticationRequest authenticationRequest =
        new AuthenticationRequest.Builder(ResponseType.CODE, scope, this.clientId, this.loginRedirectUri)
            .state(state)
            .nonce(nonce)
            .prompt(prompt)
            .acrValues(authenticationContexts)
            .endpointURI(this.authorizationServer.getAuthorizationEndpointUri())
            .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            .build();

    // Build a redirect URI from the AuthenticationRequest ...
    //
    final String redirectUri = authenticationRequest.toURI().toString();

    log.debug("Sending Authentication Request - redirecting to {}", redirectUri);

    return new ModelAndView("redirect:" + redirectUri);
  }

  /**
   * "Logs out" the user.
   * 
   * @param httpRequest the servlet request
   * @return the home view
   */
  @PostMapping("/logout")
  public ModelAndView logout(final HttpServletRequest httpRequest) {
    final HttpSession session = httpRequest.getSession();
    session.removeAttribute(IDTOKEN_TOKEN_SESSION_NAME);
    session.removeAttribute(OP_ACCESS_TOKEN_SESSION_NAME);
    session.removeAttribute(RESOURCE_ACCESS_TOKEN_SESSION_NAME);
    session.removeAttribute(REFRESH_TOKEN_SESSION_NAME);
    return this.home(httpRequest);
  }

  /**
   * Illustrates how an authorization request is constructed.
   * 
   * @param httpRequest the servlet request
   * @param resourceServer the ID of the API we are going to get an access token for
   * @return a redirect to the authorization endpoint
   * @throws Exception for processing errors
   */
  @PostMapping("/authzrequest")
  public ModelAndView initAuthorization(final HttpServletRequest httpRequest,
      @RequestParam("resourceServer") final String resourceServer) throws Exception {

    final HttpSession session = httpRequest.getSession();

    // Get the evidence service to get an access token for ...
    //
    final EvidenceService evidenceService = this.evidenceServices.stream()
        .filter(es -> es.getId().equals(resourceServer))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unknown evidence service: " + resourceServer));

    // Build an authorization request
    //

    // The scope parameter should include the scope(s) (rights) which we need to make the
    // API-call.
    // By including OIDC scopes we also ensure that we get information about the logged in
    // user (i.e., the subject) included in the resulting access token.
    //
    final Scope scope = new Scope();
    evidenceService.getRequiredScopes().stream().forEach(s -> scope.add(s));
    scope.add(ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER);
    scope.add("https://id.swedenconnect.se/scope/eidasNaturalPerson");

    // Save this in the session for use when we make the token request ...
    //
    session.setAttribute(CURRENT_AUTHZ_REQUEST_SESSION_NAME, new CurrentAuthorizationRequest(evidenceService, scope));

    // OK, before we rush ahead and build an Authorization Request we check if we have a refresh token
    // that we can use. By sending a token request and including a "refresh token grant" we can re-use
    // the user's authorization at the AS - This is much simpler...
    //
    final RefreshToken refreshToken = (RefreshToken) session.getAttribute(REFRESH_TOKEN_SESSION_NAME);
    if (refreshToken != null) {
      final RefreshTokenGrant tokenGrant = new RefreshTokenGrant(refreshToken);
      return this.sendTokenRequest(httpRequest, tokenGrant);
    }

    // OK, put an authentication request together ...
    //

    // The state is an opaque value used to maintain state between the request and the callback. Typically, Cross-Site
    // Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a
    // browser cookie.
    //
    final State state = new State(UUID.randomUUID().toString());
    session.setAttribute(OAUTH_STATE_SESSION_NAME, state);

    // Proof Key for Code Exchange (PKCE) extension, [RFC7636] and include the code_challenge and code_challenge_method
    // parameters.
    //
    final CodeVerifier codeVerifier = new CodeVerifier();
    session.setAttribute(PKCE_CODEVERIFIER_SESSION_NAME, codeVerifier);

    final AuthorizationRequest authorizationRequest =
        new AuthorizationRequest.Builder(ResponseType.CODE, this.clientId)
            .state(state)
            .redirectionURI(this.authzRedirectUri)
            .endpointURI(this.authorizationServer.getAuthorizationEndpointUri())
            .scope(scope)
            .resource(new URI(resourceServer))
            .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            .build();

    // Build a redirect URI from the Authrozation request object ...
    //
    final String redirectUri = authorizationRequest.toURI().toString();

    log.debug("Sending Authorization Request - redirecting to {}", redirectUri);

    return new ModelAndView("redirect:" + redirectUri);
  }

  /**
   * Illustrates how we receive an authorization code as a result from an authentication request, and then makes a token
   * request and displays the ID token.
   * 
   * @param httpRequest the servlet request
   * @return a view that presents the ID token
   * @throws Exception for processing errors
   */
  @GetMapping("/logincb")
  public ModelAndView loginCallback(final HttpServletRequest httpRequest) throws Exception {

    final HttpSession session = httpRequest.getSession();

    // First process and validate the authorization (authentication) response and obtain the code ...
    //
    final AuthorizationSuccessResponse authorizationResponse = this.processAuthorizationResponse(httpRequest);
    final AuthorizationCode authorizationCode = authorizationResponse.getAuthorizationCode();

    // Next, send a token request in order to obtain an ID token and an access token ...
    //

    // Get the PKCE code verifier from the session and use it when setting up our AuthorizationCodeGrant ...
    //
    final CodeVerifier codeVerifier = (CodeVerifier) session.getAttribute(PKCE_CODEVERIFIER_SESSION_NAME);
    if (codeVerifier == null) {
      throw new Exception("Session error - missing code verifier");
    }
    session.removeAttribute(PKCE_CODEVERIFIER_SESSION_NAME);

    final AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(
        authorizationCode, authorizationResponse.getRedirectionURI(), codeVerifier);

    // We authenticate using the "private_key_jwt" method ...
    //
    final ClientAuthentication clientAuthentication =
        new PrivateKeyJWT(
            new JWTAuthenticationClaimsSet(
                this.clientId, new Audience(this.authorizationServer.getTokenEndpointUri())),
            (JWSAlgorithm) this.clientJwk.getAlgorithm(),
            this.clientCredential.getPrivateKey(),
            this.clientJwk.getKeyID(),
            null, null, (Provider) null);

    // We put together the token request message.
    // Note that we add one extra (custom) parameter, the "client_id". This parameter is required by
    // our OAuth2 profile.
    //
    final TokenRequest tokenRequest = new TokenRequest(this.authorizationServer.getTokenEndpointUri(),
        clientAuthentication, codeGrant, null, null,
        Collections.singletonMap("client_id", List.of(this.clientId.getValue())));

    // OK, send and receive the token response ...
    //
    final HTTPRequest httpTokenRequest = tokenRequest.toHTTPRequest();
    this.httpRequestConfigurator.configure(httpTokenRequest);

    final HTTPResponse httpResponse = httpTokenRequest.send();

    // Parse the response ...
    //
    final TokenResponse response = OIDCTokenResponseParser.parse(httpResponse);
    if (!response.indicatesSuccess()) {
      throw new OAuth2ResponseException(response.toErrorResponse().getErrorObject());
    }
    final OIDCTokenResponse tokenResponse = (OIDCTokenResponse) response.toSuccessResponse();

    // Verify the signature on the ID token before accepting it ...
    //
    final JWT idToken = tokenResponse.getOIDCTokens().getIDToken();

    final SignedJWT idTokenJws = SignedJWT.parse(idToken.getParsedString());
    if (!idTokenJws.verify(this.jwsVerifier)) {
      throw new SignatureException("Invalid signature on ID token");
    }

    // Make sure that the nonce claim matches the nonce provided in the authentication request.
    //
    final String nonce = (String) idToken.getJWTClaimsSet().getClaims().get("nonce");
    if (nonce == null) {
      throw new Exception("Missing nonce claim in ID token");
    }
    final Nonce savedNonce = (Nonce) session.getAttribute(OIDC_NONCE_SESSION_NAME);
    if (savedNonce == null) {
      throw new Exception("Session error - missing nonce");
    }
    session.removeAttribute(OIDC_NONCE_SESSION_NAME);

    if (!nonce.equals(savedNonce.getValue())) {
      throw new Exception("Nonce mismatch - ID token not accepted");
    }

    // Save the ID token, access and refresh tokens in the session for later use ...
    //
    session.setAttribute(IDTOKEN_TOKEN_SESSION_NAME, idToken);

    final AccessToken accessToken = tokenResponse.getOIDCTokens().getAccessToken();
    session.setAttribute(OP_ACCESS_TOKEN_SESSION_NAME, new SessionAccessToken(accessToken));

    final ModelAndView mav = new ModelAndView("logged_in");
    mav.addObject("idTokenString", DisplayUtils.toJsonDisplayString(idToken));
    mav.addObject("userId", TokenSupport.findUserId(idToken));
    return mav;
  }

  /**
   * Illustrates how we receive an authorization code as a result from an authorization request, and then makes a token
   * request and displays the Access token.
   * 
   * @param httpRequest the servlet request
   * @return a view that presents the access token
   * @throws Exception for processing errors
   */
  @GetMapping("/authzcb")
  public ModelAndView authzCallback(final HttpServletRequest httpRequest) throws Exception {

    final HttpSession session = httpRequest.getSession();

    // First process and validate the authorization response and obtain the code ...
    //
    final AuthorizationSuccessResponse authorizationResponse = this.processAuthorizationResponse(httpRequest);
    final AuthorizationCode authorizationCode = authorizationResponse.getAuthorizationCode();

    // Next, send a token request in order to obtain an ID token and an access token ...
    //

    // Get the PKCE code verifier from the session and use it when setting up our AuthorizationCodeGrant ...
    //
    final CodeVerifier codeVerifier = (CodeVerifier) session.getAttribute(PKCE_CODEVERIFIER_SESSION_NAME);
    if (codeVerifier == null) {
      throw new Exception("Session error - missing code verifier");
    }
    session.removeAttribute(PKCE_CODEVERIFIER_SESSION_NAME);

    final AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(
        authorizationCode, authorizationResponse.getRedirectionURI(), codeVerifier);

    return this.sendTokenRequest(httpRequest, codeGrant);
  }

  /**
   * Illustrates how we send a token request using either a "code grant" or a "refresh token grant".
   * 
   * @param httpRequest the servlet request
   * @param authorizationGrant the authorization grant
   * @return a view that presents the access token
   * @throws Exception for processing errors
   */
  private ModelAndView sendTokenRequest(final HttpServletRequest httpRequest,
      final AuthorizationGrant authorizationGrant) throws Exception {

    final HttpSession session = httpRequest.getSession();

    // We authenticate using the "private_key_jwt" method ...
    //
    final ClientAuthentication clientAuthentication =
        new PrivateKeyJWT(
            new JWTAuthenticationClaimsSet(
                this.clientId, new Audience(this.authorizationServer.getTokenEndpointUri())),
            (JWSAlgorithm) this.clientJwk.getAlgorithm(),
            this.clientCredential.getPrivateKey(),
            this.clientJwk.getKeyID(),
            null, null, (Provider) null);

    // We put together the token request message.
    // Note that we add one extra (custom) parameter, the "client_id". This parameter is required by
    // our OAuth2 profile.
    //
    final CurrentAuthorizationRequest currentAuthzRequest =
        (CurrentAuthorizationRequest) session.getAttribute(CURRENT_AUTHZ_REQUEST_SESSION_NAME);
    if (currentAuthzRequest == null) {
      throw new Exception("Session error");
    }
    session.removeAttribute(CURRENT_AUTHZ_REQUEST_SESSION_NAME);

    final TokenRequest tokenRequest = new TokenRequest(this.authorizationServer.getTokenEndpointUri(),
        clientAuthentication, authorizationGrant, currentAuthzRequest.getScope(),
        List.of(new URI(currentAuthzRequest.getEvidenceService().getId())),
        Collections.singletonMap("client_id", List.of(this.clientId.getValue())));

    // OK, send and receive the token response ...
    //
    final HTTPRequest httpTokenRequest = tokenRequest.toHTTPRequest();
    this.httpRequestConfigurator.configure(httpTokenRequest);

    final HTTPResponse httpResponse = httpTokenRequest.send();

    // Parse the response ...
    //
    final TokenResponse response = TokenResponse.parse(httpResponse);
    if (!response.indicatesSuccess()) {
      throw new OAuth2ResponseException(response.toErrorResponse().getErrorObject());
    }
    final AccessTokenResponse tokenResponse = response.toSuccessResponse();

    final AccessToken accessToken = tokenResponse.getTokens().getAccessToken();
    final JWT accessTokenJwt = SignedJWT.parse(accessToken.getValue());

    log.info("access-token: {}", accessToken.toJSONString());

    // Save the access and refresh tokens in the session for later use ...
    //
    session.setAttribute(RESOURCE_ACCESS_TOKEN_SESSION_NAME, new SessionAccessToken(accessToken));

    final RefreshToken refreshToken = tokenResponse.getTokens().getRefreshToken();
    session.setAttribute(REFRESH_TOKEN_SESSION_NAME, refreshToken);

    final ModelAndView mav = new ModelAndView("make_api_call");
    mav.addObject("accessToken", DisplayUtils.toJsonDisplayString(accessTokenJwt));
    mav.addObject("authorizationHeader", accessToken.toAuthorizationHeader());
    mav.addObject("evidenceService", currentAuthzRequest.getEvidenceService());
    mav.addObject("userId", TokenSupport.findUserId(accessTokenJwt));
    return mav;
  }

  /**
   * Illustrates how a authorization (and authentication) response should be processed and validated.
   * 
   * @param httpRequest the servlet request
   * @return an {@link AuthorizationSuccessResponse} containing the authorization code
   * @throws Exception for processing errors
   */
  private AuthorizationSuccessResponse processAuthorizationResponse(final HttpServletRequest httpRequest)
      throws Exception {
    final HttpSession session = httpRequest.getSession();

    // Get the state value from the session ...
    //
    final State state = (State) session.getAttribute(OAUTH_STATE_SESSION_NAME);
    if (state == null) {
      throw new AuthorizationResponseProcessingException("State error - unexpected invocation of client redirect URI");
    }
    // We don't need the state value in our session anymore ...
    session.removeAttribute(OAUTH_STATE_SESSION_NAME);

    // Validate the authorization/authentication response ...
    //
    final HTTPRequest request = JakartaServletUtils.createHTTPRequest(httpRequest);

    final URI redirectUri = new URI(httpRequest.getRequestURL().toString());

    // Parse the query parameters into an AuthorizationResponse object
    final AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(
        redirectUri, AuthorizationResponse.parseResponseParameters(request));

    // Verify that the state from our request is present and matches our saved value.
    //
    if (authorizationResponse.getState() == null) {
      throw new AuthorizationResponseProcessingException("No state parameter received in authorization response");
    }
    if (!authorizationResponse.getState().equals(state)) {
      throw new AuthorizationResponseProcessingException("State parameter mismatch");
    }

    // Make sure that the issuer of the response is what we expect ...
    //
    if (authorizationResponse.getIssuer() != null) {
      if (!authorizationResponse.getIssuer().getValue().equals(this.authorizationServer.getId())) {
        throw new AuthorizationResponseProcessingException(
            String.format("Issuer of authorization response (%s) does not expected issuer (%s)",
                authorizationResponse.getIssuer().getValue(), this.authorizationServer.getId()));
      }
    }

    if (!authorizationResponse.indicatesSuccess()) {
      final AuthorizationErrorResponse errorResponse = authorizationResponse.toErrorResponse();
      throw new OAuth2ResponseException(errorResponse.getErrorObject());
    }
    return authorizationResponse.toSuccessResponse();
  }

  /**
   * Illustrates how we get user claims from the UserInfo endpoint.
   * 
   * @param httpRequest the servlet request
   * @return a {@link ModelAndView} displaying the result of the UserInfo call
   * @throws Exception for processing errors
   */
  @PostMapping("/userinfo")
  public ModelAndView userInfo(final HttpServletRequest httpRequest) throws Exception {

    final HttpSession session = httpRequest.getSession();

    // We need the access token received from the previous token request in order to
    // call the OP UserInfo endpoint.
    //
    final SessionAccessToken _accessToken = (SessionAccessToken) session.getAttribute(OP_ACCESS_TOKEN_SESSION_NAME);
    if (_accessToken == null) {
      throw new IllegalStateException("No access token exists");
    }
    if (!_accessToken.isValid()) {
      // Access token has expired. We need to obtain a new one using our refresh token ...
      // TODO: This is left as an exercise for the reader ...
      throw new IllegalArgumentException("Access token has expired");
    }
    final AccessToken accessToken = _accessToken.getAccessToken();

    // The ID token is strictly not needed anymore, but we need it for our display page ...
    //
    final JWT idToken = (JWT) session.getAttribute(IDTOKEN_TOKEN_SESSION_NAME);
    if (idToken == null) {
      throw new IllegalStateException("No ID token exists");
    }

    // Create a UserInfo request and pass along the access token ...
    //
    final UserInfoRequest userInfoRequest = new UserInfoRequest(
        this.authorizationServer.getUserInfoEndpointUri(), accessToken);

    // Send it and receive the response ...
    //
    final HTTPRequest request = userInfoRequest.toHTTPRequest();
    this.httpRequestConfigurator.configure(request);

    final HTTPResponse response = request.send();

    // Parse the response to a UserInfoResponse object ...
    //
    final UserInfoResponse userInfoResponse = UserInfoResponse.parse(response);
    if (!userInfoResponse.indicatesSuccess()) {
      throw new OAuth2ResponseException(userInfoResponse.toErrorResponse().getErrorObject());
    }
    final UserInfoSuccessResponse userInfoSuccessResponse = userInfoResponse.toSuccessResponse();

    // We require that the UserInfo is delivered as a signed JWT ...
    //
    if (userInfoSuccessResponse.getUserInfo() != null && userInfoSuccessResponse.getUserInfoJWT() == null) {
      throw new Exception("UserInfo was not signed - this is required");
    }
    final JWT userInfoJwt = userInfoSuccessResponse.getUserInfoJWT();

    // Validate signature and contents ...
    //
    final SignedJWT signedUserInfoJwt = SignedJWT.parse(userInfoJwt.getParsedString());
    if (!signedUserInfoJwt.verify(this.jwsVerifier)) {
      throw new Exception("Signature on UserInfo is not correct");
    }

    // Assert that the "iss" and "aud" claims are present, and matches the correct values.
    //
    final String userInfoIssuer = userInfoJwt.getJWTClaimsSet().getIssuer();
    if (userInfoIssuer == null) {
      throw new Exception("The 'iss' claim is missing from UserInfo - this is required");
    }
    if (!userInfoIssuer.equals(this.authorizationServer.getId())) {
      throw new Exception("Bad 'iss' claim in UserInfo - expected '%s', but was '%s'"
          .formatted(this.authorizationServer.getId(), userInfoIssuer));
    }
    final List<String> userInfoAudience = userInfoJwt.getJWTClaimsSet().getAudience();
    if (userInfoAudience == null || userInfoAudience.isEmpty()) {
      throw new Exception("The 'aud' claim is missing from UserInfo - this is required");
    }
    if (!userInfoAudience.contains(this.clientId.getValue())) {
      throw new Exception("Bad 'aud' claim in UserInfo, expected clientID to be present");
    }

    final ModelAndView mav = new ModelAndView("logged_in");
    mav.addObject("idTokenString", DisplayUtils.toJsonDisplayString(idToken));
    mav.addObject("userInfoString", DisplayUtils.toJsonDisplayString(userInfoJwt));
    mav.addObject("userId", TokenSupport.findUserId(idToken));
    return mav;
  }

  @PostMapping("/invokeapi")
  public ModelAndView invokeApi(final HttpServletRequest httpRequest,
      @RequestParam("authorizationHeader") final String authorizationHeader,
      @RequestParam("apiEndpoint") final String apiEndpoint,
      @RequestParam("userId") final String userId) throws Exception {

    final URI uri = new URI("%s/%s".formatted(apiEndpoint, userId));

    log.debug("Sending request to evidence service: GET {}", uri);
    final RequestEntity<Void> request = RequestEntity
        .get(uri)
        .header("Authorization", authorizationHeader)
        .accept(MediaType.APPLICATION_JSON)
        .build();

    final ResponseEntity<Object> entity = this.restTemplate.exchange(request, Object.class);
    if (entity.getStatusCode() == HttpStatus.OK) {
      final String json = this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(entity.getBody());
      log.debug("Received : {}", json);
      ModelAndView mav = new ModelAndView("api_result");
      mav.addObject("result", json);
      return mav;
    }
    else {
      throw new ResponseStatusException(entity.getStatusCode());
    }
  }

//  @PostMapping("/test/send")
//  public ModelAndView sendToResourceServer(final HttpServletRequest httpRequest,
//      @RequestParam("authorizationHeader") final String authorizationHeader,
//      @RequestParam("operation") final String operation,
//      @RequestParam("userId") final String userId) throws OAuth2Exception, IOException, URISyntaxException {
//
//    final URI uri = new URI(String.format("%s/api/v1/mrecord/%s", this.properties.getResourceServerBaseUri(), userId));
//    final ModelAndView mav = new ModelAndView("result");
//
//    if ("HEAD".equals(operation)) {
//      log.debug("Sending request to ID matching service: HEAD {}", uri);
//      final RequestEntity<Void> request = RequestEntity.head(uri).header("Authorization", authorizationHeader).build();
//      try {
//        final ResponseEntity<Void> entity = this.restTemplate.exchange(request, Void.class);
//        if (entity.getStatusCode() == HttpStatus.OK) {
//          final HttpHeaders headers = entity.getHeaders();
//          log.debug("Headers: {}", headers);
//          mav.addObject("headResult", "msg.result.head.yes");
//        }
//        else if (entity.getStatusCode() == HttpStatus.NOT_FOUND) {
//          mav.addObject("headResult", "msg.result.head.no");
//        }
//        else {
//          throw new ResponseStatusException(entity.getStatusCode());
//        }
//      }
//      catch (RestClientException e) {
//        // HttpClientErrorException
//        mav.addObject("headResult", "msg.result.head.no");
//      }
//    }
//    else {
//      log.debug("Sending request to ID matching service: GET {}", uri);
//      final RequestEntity<Void> request = RequestEntity.get(uri).header("Authorization", authorizationHeader).build();
//      final ResponseEntity<Object> entity = this.restTemplate.exchange(request, Object.class);
//      if (entity.getStatusCode() == HttpStatus.OK) {
//        final String json = this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(entity.getBody());
//        log.debug("Received ID matching record: {}", json);
//        mav.addObject("getResult", "msg.result.get.success");
//        mav.addObject("userRecord", json);
//      }
//      else if (entity.getStatusCode() == HttpStatus.NOT_FOUND) {
//        mav.addObject("getResult", "msg.result.get.fail");
//      }
//      else {
//        throw new ResponseStatusException(entity.getStatusCode());
//      }
//    }
//
//    return mav;
//  }

}
