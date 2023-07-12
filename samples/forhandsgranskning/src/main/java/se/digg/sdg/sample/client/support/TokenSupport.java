package se.digg.sdg.sample.client.support;

import java.text.ParseException;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import se.oidc.nimbus.claims.ClaimConstants;

/**
 * Helper class for working with OAuth2 and OIDC tokens.
 * 
 * @author Martin Lindström
 */
public class TokenSupport {

  public static String findUserId(final JWT jwt) {
    try {
      return findUserId(jwt.getJWTClaimsSet());
    }
    catch (final ParseException e) {
      throw new RuntimeException(e);
    }
  }

  public static String findUserId(final JWTClaimsSet claims) {
    return findUserId(claims.getClaims());
  }

  public static String findUserId(final Map<String, Object> claims) {
    Object id = claims.get(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME);
    if (id == null) {
      id = claims.get(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME);
    }
    if (id == null) {
      id = claims.get("https://id.swedenconnect.se/claim/prid");
    }
    if (id == null) {
      @SuppressWarnings("unchecked")
      final Map<String, Object> map = (Map<String, Object>) claims.get("user_info");
      if (map != null) {
        return findUserId(map);
      }
    }
    return (String) id;
  }

}
