package se.digg.sdg.sample.proof;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.oidc.nimbus.claims.ClaimConstants;

public class UserIdValidators {
    public static void noopValidator(String userId, SignedJWT accessTokenJwt) {

    }

    public static void validateUserId(String userId, SignedJWT accessTokenJwt) {
        try {
            final String subjectId = UserIdValidators.getUserId(accessTokenJwt.getJWTClaimsSet());
            if (subjectId == null) {
                throw new Exception("Invalid access token - Missing ID of subject");
            }
            if (!Objects.equals(subjectId, userId)) {
                throw new Exception(
                        "Invalid subject ID (%s) in access token - Required %s".formatted(subjectId, userId));
            }
        } catch (Exception e) {
            throw new RuntimeException(e); //TODO throw specific
        }
    }

    private static String getUserId(final JWTClaimsSet jwt) throws ParseException {
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
}
