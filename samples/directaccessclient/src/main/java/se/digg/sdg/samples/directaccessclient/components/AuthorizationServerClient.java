package se.digg.sdg.samples.directaccessclient.components;

import java.net.URI;
import java.security.Provider;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;

import se.swedenconnect.security.credential.PkiCredential;

public class AuthorizationServerClient {
        private final ClientProperties properties;
        private final HTTPRequestConfigurator configrator;
        private final JWK clientJwk;

        public AuthorizationServerClient(ClientProperties properties, HTTPRequestConfigurator configurator) {
                this.properties = properties;
                this.configrator = configurator;
                try {
                        this.clientJwk = JWKFactory.create(this.properties.getAsCredential());
                } catch (JOSEException e) {
                        throw new IllegalArgumentException("Failed to create client JWK", e);
                }
        }

        /**
         * Reads configuration from service and requests an access token from
         * authorization server
         * 
         * @return JWT access token
         * @throws Exception
         */
        public String getDirectClientAccessToken() throws Exception {
                // Audience of this request is the authorization server
                Audience audience = new Audience(this.properties.getAuthorizationServer());
                // Requested audience is the intended recipient of our access token when we get
                // it from the authorization-server
                String requestedAudience = this.properties.getRequestedResource();

                ClientAuthentication clientAuthentication = createClientAuthentication(audience,
                                new ClientID(this.properties.getClientId()));
                TokenRequest tokenRequest = new TokenRequest(
                                URI.create(this.properties.getAuthorizationServer()),
                                clientAuthentication, new ClientCredentialsGrant(),
                                scopeFrom(this.properties.getRequestedScopes()), null,
                                Map.of(
                                                "client_id", List.of(this.properties.getClientId()),
                                                "resource", List.of(requestedAudience)));
                HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
                this.configrator.configure(httpRequest);
                httpRequest.setFollowRedirects(false);
                HTTPResponse httpResponse = httpRequest.send();
                return httpResponse.getContentAsJSONObject().getAsString("access_token");
        }

        private PrivateKeyJWT createClientAuthentication(Audience audience, ClientID clientID) throws JOSEException {
                return new PrivateKeyJWT(
                                new JWTAuthenticationClaimsSet(clientID, audience),
                                new JWSAlgorithm("RS256"),
                                this.properties.getAsCredential().getPrivateKey(),
                                this.clientJwk.getKeyID(),
                                null, null, (Provider) null);
        }

        private Scope scopeFrom(List<String> requestedScopes) {
                Scope scope = new Scope();
                requestedScopes.forEach(scope::add);
                return scope;
        }
}
