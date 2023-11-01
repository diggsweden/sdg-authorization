package se.digg.sdg.samples.directaccessclient.components;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

@ConfigurationProperties("directaccessclient")
public class ClientProperties implements InitializingBean {
    /**
     * Credentials for authorization server
     */
    @Getter
    @Setter
    PkiCredentialConfigurationProperties credential;

    @Getter
    @Setter
    private PkiCredential asCredential = null;

    /**
     * URL to token endpoint of authorization server
     */
    @Getter
    @Setter
    private String authorizationServer;

    /**
     * Scopes to request from authorization server
     */
    @Getter
    @Setter
    private List<String> requestedScopes = new ArrayList<>();

    /**
     * Client Id of this client
     */
    @Getter
    @Setter
    private String clientId;

    /**
     * Requested audience of access token (to be used)
     */
    @Getter
    @Setter
    private String requestedResource;

    /**
     * Development mode, disables SSL verification
     */
    @Getter
    @Setter
    private Boolean developmentMode;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.credential, "directaccessclient.credential.* must be assigned");

        // Set the token signature algorithm based on the supplied credential ...
        //
        this.asCredential = this.pkiCredential();
    }

    public PkiCredential pkiCredential() {
        if (this.asCredential == null) {
            try {
                final PkiCredentialFactoryBean credentialFactory = new PkiCredentialFactoryBean(this.credential);
                credentialFactory.afterPropertiesSet();

                this.asCredential = credentialFactory.getObject();
            } catch (final Exception e) {
                throw new IllegalArgumentException("Failed to create AS credential", e);
            }
        }
        return this.asCredential;
    }
}
