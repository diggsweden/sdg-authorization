package se.digg.sdg.sample.proof;

import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Data;
import se.digg.sdg.sample.proof.TestEvidenceConfigurationProperties.EvidenceService;
import se.oidc.nimbus.claims.ClaimConstants;

@RestController
public class TestEvidenceController {

  /**
   * Configuration for the simulated evidence service. Each service is implemented
   * by a controller method.
   */
  @Autowired
  @Qualifier("evidenceServices")
  private List<EvidenceService> evidenceServices;

  /**
   * A list of the ID:s of all clients that we accept as callers to our API:s.
   */
  @Autowired
  @Qualifier("allowedClients")
  private List<String> allowedClients;

  /**
   * The verifier that we use to verify the signature on the received access
   * tokens.
   */
  @Autowired
  private JWSVerifier jwsVerifier;

  /**
   * The ID of the Authorization Server that we trust.
   */
  @Autowired
  @Qualifier("authorizationServerId")
  private String authorizationServerId;

  /**
   * Implements the simulated evidence service number 1.
   * 
   * @param httpServletRequest the servlet request
   * @param personalIdNumber   the personal ID number of the user that the service
   *                           is delivering (simulated) data about
   * @return an EvidenceResponse structure (simulated)
   * @throws Exception for errors
   */
  @GetMapping(path = "/service1/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public EvidenceResponse service1(final HttpServletRequest httpServletRequest,
      @PathVariable("userId") final String personalIdNumber) throws Exception {

    final String serviceID = "1";
    final EvidenceService service = this.evidenceServices.stream()
        .filter(s -> s.getId().contains(serviceID))
        .findFirst()
        .orElseThrow(() -> new Exception("Invalid configuration"));

    // Get hold of the Authorization header ...
    //
    final String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

    // Validate the invocation ...
    //
    this.validateCall(authorizationHeader, service, personalIdNumber, UserIdValidators::validateUserId);

    // OK, everything went well, send back a simulated response ...
    //
    return EvidenceResponse.builder()
        .issuer(service.getId())
        .identity(personalIdNumber)
        .build();
  }

  /**
   * Illustrates all steps that needs to be taken to validate the received access
   * token.
   * 
   * @param authorizationHeader the Authorization header (containing the signed
   *                            access token)
   * @param service             the service configuration
   * @param userId              the user ID for this particular invocation
   * @throws Exception for errors
   */
  private void validateCall(
      final String authorizationHeader,
      final EvidenceService service,
      final String userId,
      final BiConsumer<String, SignedJWT> userIdValidator) throws Exception {

    // Step 1: Parse the Authorization header into an OAuth2 access token.
    //
    final AccessToken accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);

    // We only work accept signed JWT:s as access tokens ...
    final SignedJWT accessTokenJwt = SignedJWT.parse(accessToken.getValue());

    // Step 2. Make sure that the token hasn't expired ...
    //
    final Date expirationTime = accessTokenJwt.getJWTClaimsSet().getExpirationTime();
    if (expirationTime != null) {
      if (Instant.now().isAfter(expirationTime.toInstant())) {
        throw new Exception("Invalid access token - expired");
      }
    }

    // Step 3. Verify the signature on the token and assert that it has been issued
    // by the expected issuer (i.e., the Authorization Server that we trust).
    //
    if (!accessTokenJwt.verify(this.jwsVerifier)) {
      throw new SignatureException("Invalid signature on access token");
    }

    final String issuer = accessTokenJwt.getJWTClaimsSet().getIssuer();
    if (!Objects.equals(this.authorizationServerId, issuer)) {
      throw new Exception("Invalid access token - expected issuer to be '%s', but was '%s'"
          .formatted(this.authorizationServerId, issuer));
    }

    // Step 4. Make sure that we are being invoked by a service that we accept
    // (förhandsgranskningstjänsten).
    //
    final String clientId = accessTokenJwt.getJWTClaimsSet().getStringClaim("client_id");
    if (!this.allowedClients.contains(clientId)) {
      throw new Exception("Access denied - %s does not have permissions to access service".formatted(clientId));
    }

    // Step 5. Verify that the ID of our service is among the intended audiences for
    // the token, i.e., assert that the token is intended to us.
    //
    if (!accessTokenJwt.getJWTClaimsSet().getAudience().contains(service.getId())) {
      throw new Exception("Invalid access token - service ID is not listed in 'aud' claim");
    }

    // Step 6. Assert that at least one of our required scopes are present ...
    //
    final List<String> scopes = Optional.ofNullable(accessTokenJwt.getJWTClaimsSet().getStringListClaim("scope"))
        .orElseGet(() -> Collections.emptyList());
    if (!service.getRequiredScopes().stream().anyMatch(s -> scopes.contains(s))) {
      throw new Exception("Invalid access token - Missing required scope");
    }

  

    // Step 7. And finally, and very important, make sure that the subject (i.e.,
    // the user)
    // for the access token matches the userId that is requested in the call ...
    //
    final String subjectId = this.getUserId(accessTokenJwt.getJWTClaimsSet());
    userIdValidator.accept(subjectId, accessTokenJwt);
    // OK, we are done!
  }

  private String getUserId(final JWTClaimsSet jwt) throws ParseException {
    final Map<String, Object> userInfo = jwt.getJSONObjectClaim("user_info");
    if (userInfo == null) {
      return null;
    }
    String id = (String) userInfo.get(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME);
    if (id == null) {
      id = (String) userInfo.get(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME);
    }
    return id;
  }

  // The same as service1 ...
  //
  @GetMapping(path = "/service2/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public EvidenceResponse service2(final HttpServletRequest httpServletRequest,
      @PathVariable("userId") final String personalIdNumber) throws Exception {

    final String serviceID = "2";
    final EvidenceService service = this.evidenceServices.stream()
        .filter(s -> s.getId().contains(serviceID))
        .findFirst()
        .orElseThrow(() -> new Exception("Invalid configuration"));

    final String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

    this.validateCall(authorizationHeader, service, personalIdNumber, UserIdValidators::validateUserId);

    return EvidenceResponse.builder()
        .issuer(service.getId())
        .identity(personalIdNumber)
        .build();
  }

  @GetMapping(path = "/service3", produces = MediaType.APPLICATION_JSON_VALUE)
  public EvidenceResponse service3(final HttpServletRequest httpServletRequest) throws Exception {
    final String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
    final EvidenceService service = this.evidenceServices.stream()
        .filter(s -> s.getId().contains("3"))
        .findFirst()
        .orElseThrow(() -> new Exception("Invalid configuration"));

    validateCall(authorizationHeader, service, null, UserIdValidators::noopValidator);
    return EvidenceResponse.builder()
        .issuer(service.getId())
        .identity("none")
        .build();
  }

  /**
   * Dummy class that represents the response message of an evidence service.
   */
  @Data
  @Builder
  public static class EvidenceResponse {
    private String issuer;
    private String identity;
  }

}
