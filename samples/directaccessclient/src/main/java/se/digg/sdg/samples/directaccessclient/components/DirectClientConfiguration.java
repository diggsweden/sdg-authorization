package se.digg.sdg.samples.directaccessclient.components;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.util.tls.TLSVersion;

@Configuration
@EnableConfigurationProperties(ClientProperties.class)
public class DirectClientConfiguration {

    @Autowired
    private ClientProperties properties;

    @Bean
    AuthorizationServerClient authorizationServerClient(ClientProperties properties,
            HTTPRequestConfigurator configurator) throws Exception {
        return new AuthorizationServerClient(properties, configurator);
    }

    /**
     * A {@link RestTemplate} that is used to communicate with the AS and the
     * resource server.
     *
     * @return a RestTemplate
     */
    /**
     * A {@link RestTemplate} that is used to communicate with the AS and the
     * resource server.
     *
     * @return a RestTemplate
     */
    @Bean
    RestTemplate restTemplate() {
        if (this.properties.getDevelopmentMode()) {
            try {
                // DO NOT USE IN PRODUCTION!
                //
                final SSLContext sslContext = SSLContextBuilder.create()
                        .loadTrustMaterial(new TrustAllStrategy())
                        .build();

                final ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(
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
            } catch (final Exception e) {
                throw new IllegalArgumentException("Failed to configure restTemplate", e);
            }
        } else {
            return new RestTemplate();
        }
    }

    @Bean
    HTTPRequestConfigurator httpRequestConfigurator() {
        final boolean developmentMode = this.properties.getDevelopmentMode();
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
                } catch (final NoSuchAlgorithmException | KeyManagementException e) {
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
        } else {
            return (httpRequest) -> {
            };
        }
    }

    @Bean("httpRequestCustomizer")
    Consumer<HTTPRequest> httpRequestCustomizer() {
        if (this.properties.getDevelopmentMode()) {
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
            } catch (final NoSuchAlgorithmException | KeyManagementException e) {
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
        } else {
            return (h) -> {
            };
        }
    }
}
