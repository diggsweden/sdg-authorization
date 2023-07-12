package se.digg.sdg.sample.client.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.function.Consumer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.tls.TLSVersion;

import se.digg.sdg.sample.client.config.TestClientConfigurationProperties.AuthorizationServer;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Configuration for the test client.
 */
@Configuration
@EnableConfigurationProperties(TestClientConfigurationProperties.class)
public class TestClientConfiguration {

  private final TestClientConfigurationProperties properties;

  public TestClientConfiguration(final TestClientConfigurationProperties properties) {
    this.properties = properties;
  }

  /**
   * Gets the {@link ClientID} bean. This is the registered client ID that our application has at the Authorization
   * Server.
   * 
   * @return the {@link ClientID}
   */
  @Bean
  ClientID clientId() {
    return new ClientID(this.properties.getClientId());
  }

  /**
   * Gets the client login redirect URI bean. This is the URI that we want the Authorization Server to redirect our
   * user's back to when sending authentication requests.
   * 
   * @return the login redirect (callback) URI
   * @throws URISyntaxException if the configured callback URI is invalid
   */
  @Bean("loginRedirectUri")
  URI loginRedirectUri() throws URISyntaxException {
    return new URI(this.properties.getLoginCallbackUri());
  }

  /**
   * Gets the authorization redirect URI bean. This is the URI that we want the Authorization Server to redirect our
   * user's back to when sending authorization requests.
   * 
   * @return the authorization redirect (callback) URI
   * @throws URISyntaxException if the configured callback URI is invalid
   */
  @Bean("authzRedirectUri")
  URI authzRedirectUri() throws URISyntaxException {
    return new URI(this.properties.getAuthzCallbackUri());
  }

  @Bean("clientCredential")  
  PkiCredential clientCredential() {
    return this.properties.createPkiCredential();
  }
  
  @Bean
  JWK clientJwk() {
    return this.properties.createClientJwk();
  }

  @Bean
  AuthorizationServer authorizationServer() {
    return this.properties.getAuthorizationServer();
  }
  
  @Bean
  List<EvidenceService> evidenceServices() {
    return this.properties.getEvidenceServices();
  }
  
  @Bean
  JWSVerifier jwsVerifier() throws JOSEException {
    final PublicKey asKey = this.properties.getAuthorizationServer().getAuthorizationServerKey().getPublicKey();
    if ("RSA".equals(asKey.getAlgorithm())) {
      return new RSASSAVerifier((RSAPublicKey) asKey);
    }
    else if ("EC".equals(asKey.getAlgorithm())) {
      return new ECDSAVerifier((ECPublicKey) asKey);
    }
    else {
      throw new IllegalArgumentException("Unsupported key type");
    }    
  }

  /**
   * A {@link RestTemplate} that is used to communicate with the AS and the resource server.
   *
   * @return a RestTemplate
   */
  @Bean
  RestTemplate restTemplate() {
    if (this.properties.isDevelopmentMode()) {
      try {
        // DO NOT USE IN PRODUCTION!
        //
        final SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(new TrustAllStrategy())
            .build();

        final ClientHttpRequestFactory requestFactory =
            new HttpComponentsClientHttpRequestFactory(
                HttpClientBuilder.create()
                    .disableRedirectHandling()
                    .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                                .setSslContext(sslContext)
                                .build())
                            .build())
                    .build());

        final RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to configure restTemplate", e);
      }
    }
    else {
      return new RestTemplate();
    }
  }

  @Bean
  HTTPRequestConfigurator httpRequestConfigurator() {
    final boolean developmentMode = this.properties.isDevelopmentMode();
    if (developmentMode) {
      return (httpRequest) -> {
        final SSLSocketFactory sslSocketFactory;
        try {
          final SSLContext sslContext = SSLContext.getInstance(TLSVersion.TLS_1_3.toString());

          final TrustManager[] trustAllCerts = {
              new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                  return null;
                }

                @Override
                public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
                }

                @Override
                public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
                }
              }
          };
          sslContext.init(null, trustAllCerts, null);
          sslSocketFactory = sslContext.getSocketFactory();
        }
        catch (final NoSuchAlgorithmException | KeyManagementException e) {
          throw new SecurityException(e);
        }

        final HostnameVerifier noopHostNameVerifier = new HostnameVerifier() {

          @Override
          public boolean verify(final String hostname, final SSLSession session) {
            return true;
          }
        };

        httpRequest.setHostnameVerifier(noopHostNameVerifier);
        httpRequest.setSSLSocketFactory(sslSocketFactory);

      };
    }
    else {
      return (httpRequest) -> {
      };
    }
  }

  @Bean("httpRequestCustomizer")
  Consumer<HTTPRequest> httpRequestCustomizer() {
    if (this.properties.isDevelopmentMode()) {
      final SSLSocketFactory sslSocketFactory;
      try {
        final SSLContext sslContext = SSLContext.getInstance(TLSVersion.TLS_1_3.toString());

        final TrustManager[] trustAllCerts = {
            new X509TrustManager() {
              @Override
              public X509Certificate[] getAcceptedIssuers() {
                return null;
              }

              @Override
              public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
              }

              @Override
              public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
              }
            }
        };
        sslContext.init(null, trustAllCerts, null);
        sslSocketFactory = sslContext.getSocketFactory();
      }
      catch (final NoSuchAlgorithmException | KeyManagementException e) {
        throw new SecurityException(e);
      }

      final HostnameVerifier noopHostNameVerifier = new HostnameVerifier() {

        @Override
        public boolean verify(final String hostname, final SSLSession session) {
          return true;
        }
      };

      return (h) -> {
        h.setHostnameVerifier(noopHostNameVerifier);
        h.setSSLSocketFactory(sslSocketFactory);
      };
    }
    else {
      return (h) -> {
      };
    }
  }

}
