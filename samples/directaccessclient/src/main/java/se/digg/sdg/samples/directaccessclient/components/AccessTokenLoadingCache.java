package se.digg.sdg.samples.directaccessclient.components;

import java.text.ParseException;
import java.time.Instant;

import org.springframework.stereotype.Service;

import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;

/**
 * Loading cache for fetching access token from authorization server when needed
 */
@Slf4j
@Service
/**
 * Responsible of fetching access token from Authorization Server when needed
 */
public class AccessTokenLoadingCache {
    private final AuthorizationServerClient client;
    private SignedJWT accessToken;
    private String jwt;

    public AccessTokenLoadingCache(AuthorizationServerClient client) {
        this.client = client;
    }

    /**
     * Gets access token from cache or authorization-server (when needed)
     * Gets a new access token if any of the following conditions is met
     *  (*) No current access token is present
     *  (*) The current access token has expired
     *  (*) The current token can no longer be parsed
     * 
     * @return Access Token
     */
    public synchronized String getAccessToken() {
        if (this.jwt == null) {
            log.info("No access token found");
            return updateJwt();
        }
        try {
            if (accessToken != null && Instant.now().isAfter(accessToken.getJWTClaimsSet().getExpirationTime().toInstant())) {
                log.info("Access token has expried");
                return updateJwt();
            }
        } catch (ParseException e) {
            log.error("Failed to parse accessToken for expiration time. Requesting a new token", e);
            return updateJwt();
        }
        // JWT from cache is present and has not expired
        return this.jwt;
    }

    /**
     * Update cache with new access-token
     */
    private String updateJwt() {
        try {
            this.jwt = client.getDirectClientAccessToken();
            this.accessToken = SignedJWT.parse(jwt);
            log.info("Fetched new AccessToken {}", this.accessToken);
            return this.jwt;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
